# -*- coding: utf-8 -*-
"""
main.py — Hybrid Trading Cloud Engine
FastAPI server with single Dhan WebSocket + REST/SSE price API
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from dhan_engine import DhanEngine

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

# ── Globals ───────────────────────────────────────────────────────────────────
engine: Optional[DhanEngine] = None
_sse_clients: Set[asyncio.Queue] = set()
_sse_lock = asyncio.Lock()
_startup_time = time.time()


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    log.info("=" * 60)
    log.info("  Hybrid Trading Cloud Engine — STARTING")
    log.info(f"  PORT = {os.environ.get('PORT', '8000')}")
    log.info("=" * 60)

    # Engine starts background tasks (CSV download, WS connect)
    # These are NON-BLOCKING so /health responds immediately
    engine = DhanEngine(sse_broadcast_fn=_broadcast_tick)
    await engine.start()

    log.info("[STARTUP] Engine tasks launched — /health is now responding")
    log.info("[STARTUP] CSV download will complete in ~60-120s in background")

    yield  # server live here

    log.info("Shutting down...")
    await engine.stop()


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Hybrid Trading Engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic models ───────────────────────────────────────────────────────────
class BatchLtpRequest(BaseModel):
    tokens: List[str]

class SubscribeRequest(BaseModel):
    tokens: List[str]

class TokenRefreshRequest(BaseModel):
    force: bool = False


# ── SSE broadcast ─────────────────────────────────────────────────────────────
async def _broadcast_tick(token: str, ltp: float):
    if not _sse_clients:
        return
    payload = json.dumps({"t": token, "p": round(ltp, 2)})
    dead: set = set()
    async with _sse_lock:
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.add(q)
        for q in dead:
            _sse_clients.discard(q)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """
    Railway health probe.
    Returns 200 immediately — even before CSV loads or WS connects.
    uptime_seconds shows how long the server has been running.
    """
    return {
        "ok": True,
        "ts": int(time.time()),
        "uptime_seconds": int(time.time() - _startup_time),
        "engine_ready": engine is not None,
        "mapper_ready": engine.mapper_ready() if engine else False,
        "ws_connected": engine.ws_connected() if engine else False,
    }


@app.get("/status")
async def status():
    if not engine:
        return {"connected": False, "startup": "in_progress"}
    return engine.get_status()


@app.get("/ltp/{token}")
async def get_ltp(token: str):
    if not engine:
        raise HTTPException(503, "Engine starting up, try again in 30 seconds")
    ltp = engine.get_ltp(token)
    if ltp is None:
        raise HTTPException(404, f"No price for token: {token}")
    return {"token": token, "ltp": ltp}


@app.post("/ltp/batch")
async def get_ltp_batch(req: BatchLtpRequest):
    if not engine:
        raise HTTPException(503, "Engine starting up")
    result: Dict[str, Optional[float]] = {}
    for tok in req.tokens:
        result[tok] = engine.get_ltp(tok)
    return {"prices": result, "ts": int(time.time() * 1000)}


@app.get("/spot")
async def get_spot():
    if not engine:
        raise HTTPException(503, "Engine starting up")
    return engine.get_spot_prices()


@app.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    if not engine:
        raise HTTPException(503, "Engine starting up")
    await engine.subscribe_tokens(req.tokens)
    return {"subscribed": len(req.tokens), "total": engine.subscribed_count()}


@app.post("/unsubscribe")
async def unsubscribe(req: SubscribeRequest):
    if not engine:
        raise HTTPException(503, "Engine starting up")
    await engine.unsubscribe_tokens(req.tokens)
    return {"unsubscribed": len(req.tokens)}


@app.get("/chain/{symbol}/{expiry}")
async def get_chain(symbol: str, expiry: str):
    if not engine:
        raise HTTPException(503, "Engine starting up")

    sym = symbol.upper()
    chain = engine.get_chain_ltps(sym, expiry)

    # Auto-subscribe all tokens for this expiry to Dhan WebSocket
    # so future calls return live LTPs instead of 0
    if chain is not None:
        all_trds = list(engine._mapper._build_trd_list(sym, expiry))
        if all_trds:
            await engine.subscribe_tokens(all_trds)
            # Fetch via REST for any still-zero tokens (deep ITM, low liquidity)
            zero_trds = [t for t in all_trds if engine._prices.get(t, 0) <= 0]
            if zero_trds:
                asyncio.create_task(engine.fetch_zero_price_tokens_rest(zero_trds[:100]))

    return {"symbol": sym, "expiry": expiry, "chain": chain or {}}


@app.post("/ltp/zeros")
async def fetch_zero_prices(req: SubscribeRequest):
    """
    Fetch prices for subscribed tokens that have zero/no price via Dhan REST API.
    Used for deep ITM options that don't tick frequently on WebSocket.
    Populates the price cache and broadcasts via SSE.
    """
    if not engine:
        raise HTTPException(503, "Engine starting up")
    filled = await engine.fetch_zero_price_tokens_rest(req.tokens)
    return {"filled": filled, "requested": len(req.tokens)}


@app.post("/token/refresh")
async def force_token_refresh(req: TokenRefreshRequest):
    if not engine:
        raise HTTPException(503, "Engine starting up")
    success = await engine.refresh_dhan_token(force=req.force)
    return {"success": success}


@app.get("/token/refresh")
async def refresh_token_browser(key: str = ""):
    """
    Browser-accessible token refresh — open URL in any browser.
    URL: https://your-engine.railway.app/token/refresh?key=refresh123
    Set TOKEN_REFRESH_KEY env var on Railway to change the secret key.
    """
    import os
    from fastapi.responses import HTMLResponse
    expected = os.getenv("TOKEN_REFRESH_KEY", "refresh123")

    if key != expected:
        return HTMLResponse("""
<html><body style="font-family:sans-serif;padding:40px;background:#111;color:#fff">
<h2>🔒 Token Refresh</h2>
<p>Add <code style="background:#222;padding:4px 8px;border-radius:4px">?key=YOUR_KEY</code> to the URL</p>
<p style="color:#888">Default key: <code>refresh123</code><br>
Set <code>TOKEN_REFRESH_KEY</code> env var on Railway to change it.</p>
</body></html>""", status_code=401)

    if not engine:
        return HTMLResponse("<html><body style='background:#111;color:#fff;padding:40px'>Engine not ready</body></html>", status_code=503)

    log.info("[TOKEN] Manual browser refresh triggered")
    success = await engine._do_token_refresh()
    status  = engine.status()
    color   = "#00ff88" if success else "#ff4444"
    icon    = "✓" if success else "✗"
    ws_ok   = status.get("ws_connected", False)

    return HTMLResponse(f"""
<html><body style="font-family:sans-serif;padding:40px;background:#111;color:#fff">
<h2 style="color:{color}">{icon} Token Refresh {"Successful" if success else "Failed"}</h2>
<table style="border-collapse:collapse;margin-top:20px;min-width:300px">
  <tr><td style="padding:8px 16px 8px 0;color:#888">WS Status</td>
      <td style="padding:8px;color:{"#00ff88" if ws_ok else "#ff4444"}">
      {"● Connected" if ws_ok else "○ Disconnected"}</td></tr>
  <tr><td style="padding:8px 16px 8px 0;color:#888">Subscribed Tokens</td>
      <td style="padding:8px">{status.get("subscribed_tokens", 0)}</td></tr>
  <tr><td style="padding:8px 16px 8px 0;color:#888">Prices Cached</td>
      <td style="padding:8px">{status.get("prices_cached", 0)}</td></tr>
</table>
<p style="margin-top:30px">
  <a href="/token/refresh?key={key}" style="color:#4af;margin-right:20px">↻ Refresh Again</a>
  <a href="/health" style="color:#4af;margin-right:20px">Health</a>
  <a href="/status" style="color:#4af">Status</a>
</p>
<p style="color:#555;font-size:12px;margin-top:20px">
  Bookmark this URL: /token/refresh?key={key}
</p>
</body></html>""")


@app.get("/token/refresh")
async def refresh_token_browser(key: str = ""):
    """
    Browser-accessible token refresh.
    Open in browser: https://your-engine.railway.app/token/refresh?key=refresh123
    Protected by simple secret key (set TOKEN_REFRESH_KEY env var on Railway,
    default is 'refresh123').
    """
    import os
    expected = os.getenv("TOKEN_REFRESH_KEY", "refresh123")
    if key != expected:
        from fastapi.responses import HTMLResponse
        return HTMLResponse("""
        <html><body style="font-family:sans-serif;padding:40px;background:#111;color:#fff">
        <h2>🔒 Token Refresh</h2>
        <p>Add <code>?key=YOUR_SECRET_KEY</code> to the URL</p>
        <p style="color:#888">Set TOKEN_REFRESH_KEY environment variable on Railway to change the key.<br>
        Default key is: <code>refresh123</code></p>
        </body></html>""", status_code=401)

    if not engine:
        from fastapi.responses import HTMLResponse
        return HTMLResponse("<html><body>Engine not ready</body></html>", status_code=503)

    log.info("[TOKEN] Manual browser refresh requested")
    success = await engine._do_token_refresh()

    from fastapi.responses import HTMLResponse
    status = engine.status()
    color  = "#00ff88" if success else "#ff4444"
    icon   = "✓" if success else "✗"
    return HTMLResponse(f"""
    <html><body style="font-family:sans-serif;padding:40px;background:#111;color:#fff">
    <h2 style="color:{color}">{icon} Token Refresh {'Successful' if success else 'Failed'}</h2>
    <table style="border-collapse:collapse;margin-top:20px">
      <tr><td style="padding:8px;color:#888">WS Connected</td>
          <td style="padding:8px;color:{("#00ff88" if status.get("ws_connected") else "#ff4444")}">
          {"● Connected" if status.get("ws_connected") else "○ Disconnected"}</td></tr>
      <tr><td style="padding:8px;color:#888">Subscribed Tokens</td>
          <td style="padding:8px">{status.get("subscribed_tokens", 0)}</td></tr>
      <tr><td style="padding:8px;color:#888">Prices Cached</td>
          <td style="padding:8px">{status.get("prices_cached", 0)}</td></tr>
    </table>
    <p style="margin-top:30px;color:#888">
      <a href="/token/refresh?key={key}" style="color:#4af">↻ Refresh Again</a>
      &nbsp;|&nbsp;
      <a href="/health" style="color:#4af">Health Check</a>
      &nbsp;|&nbsp;
      <a href="/status" style="color:#4af">Full Status</a>
    </p>
    <p style="color:#555;font-size:12px">Bookmark this URL to refresh token from anywhere</p>
    </body></html>""")


@app.get("/stream")
async def sse_stream(request: Request):
    """
    Server-Sent Events — real-time price ticks to all connected clients.
    Format: data: {"t":"NIFTY2631722500CE","p":120.50}
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    async with _sse_lock:
        _sse_clients.add(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        yield f"data: {json.dumps({'type':'connected','ts':int(time.time())})}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            async with _sse_lock:
                _sse_clients.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    log.info(f"Starting on port {port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
