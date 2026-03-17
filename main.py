# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║              HYBRID TRADING SYSTEM — CENTRAL DATA ENGINE                   ║
║              Cloud Backend  (FastAPI + Single Dhan WebSocket)               ║
╚══════════════════════════════════════════════════════════════════════════════╝

PURPOSE
-------
  • Runs ONE Dhan WebSocket connection on a free cloud server (Railway / Fly.io)
  • Receives live ticks and stores LTP in memory (lightning-fast)
  • Exposes a REST + SSE API so desktop app + mobile app fetch data from HERE
    instead of each opening their own Dhan WebSocket
  • Auto-reconnects, re-subscribes, and refreshes the Dhan token daily

ENDPOINTS
---------
  GET  /health                     — liveness probe (Railway/Fly.io)
  GET  /status                     — connection status + subscribed count
  GET  /ltp/{token}                — single LTP by Kotak pSymbol or trd_symbol
  POST /ltp/batch                  — bulk LTP lookup  { "tokens": [...] }
  GET  /spot                       — NIFTY / BANKNIFTY / SENSEX spot prices
  POST /subscribe                  — add tokens to live subscription
  POST /unsubscribe                — remove tokens
  GET  /stream                     — Server-Sent Events price stream (SSE)
  POST /token/refresh              — force Dhan token refresh
  GET  /chain/{symbol}/{expiry}    — option chain LTPs for a symbol+expiry

DEPLOYMENT
----------
  Railway / Fly.io / Render — see DEPLOYMENT_GUIDE.md
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

# ── Internal modules ──────────────────────────────────────────────────────────
from dhan_engine import DhanEngine

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")

# ── Global engine instance ────────────────────────────────────────────────────
engine: Optional[DhanEngine] = None

# ── SSE subscriber queues ─────────────────────────────────────────────────────
# Each connected SSE client gets a queue. Engine pushes ticks → all queues.
_sse_clients: Set[asyncio.Queue] = set()
_sse_lock = asyncio.Lock()


# ── Lifespan (startup / shutdown) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    log.info("═" * 60)
    log.info("  Hybrid Trading Cloud Engine  —  STARTING")
    log.info("═" * 60)

    engine = DhanEngine(sse_broadcast_fn=_broadcast_tick)
    await engine.start()

    yield  # ← server is running here

    log.info("Shutting down engine...")
    await engine.stop()


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Hybrid Trading Engine",
    description="Central Dhan WebSocket + price cache server",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production if needed
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


# ── SSE broadcast helper ──────────────────────────────────────────────────────

async def _broadcast_tick(token: str, ltp: float):
    """Called by DhanEngine on every price tick — pushes to all SSE clients."""
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
    """Railway / Fly.io health probe — must return 200."""
    return {"ok": True, "ts": int(time.time())}


@app.get("/status")
async def status():
    if not engine:
        return {"connected": False}
    return engine.get_status()


@app.get("/ltp/{token}")
async def get_ltp(token: str):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    ltp = engine.get_ltp(token)
    if ltp is None:
        raise HTTPException(404, f"No price for token: {token}")
    return {"token": token, "ltp": ltp}


@app.post("/ltp/batch")
async def get_ltp_batch(req: BatchLtpRequest):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    result: Dict[str, Optional[float]] = {}
    for tok in req.tokens:
        result[tok] = engine.get_ltp(tok)
    return {"prices": result, "ts": int(time.time() * 1000)}


@app.get("/spot")
async def get_spot():
    """Returns NIFTY / BANKNIFTY / SENSEX spot prices."""
    if not engine:
        raise HTTPException(503, "Engine not ready")
    return engine.get_spot_prices()


@app.post("/subscribe")
async def subscribe(req: SubscribeRequest):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    await engine.subscribe_tokens(req.tokens)
    return {"subscribed": len(req.tokens), "total": engine.subscribed_count()}


@app.post("/unsubscribe")
async def unsubscribe(req: SubscribeRequest):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    await engine.unsubscribe_tokens(req.tokens)
    return {"unsubscribed": len(req.tokens)}


@app.get("/chain/{symbol}/{expiry}")
async def get_chain(symbol: str, expiry: str):
    """
    Return all LTPs for option chain rows matching the given symbol & expiry.
    symbol: NIFTY | BANKNIFTY | SENSEX
    expiry: YYYY-MM-DD
    """
    if not engine:
        raise HTTPException(503, "Engine not ready")
    chain = engine.get_chain_ltps(symbol.upper(), expiry)
    return {"symbol": symbol, "expiry": expiry, "chain": chain}


@app.post("/token/refresh")
async def force_token_refresh(req: TokenRefreshRequest):
    if not engine:
        raise HTTPException(503, "Engine not ready")
    success = await engine.refresh_dhan_token(force=req.force)
    return {"success": success}


@app.get("/stream")
async def sse_stream(request: Request):
    """
    Server-Sent Events endpoint.
    Clients connect once; they receive every price tick in real time.
    Format:  data: {"t":"NIFTY2631722500CE","p":120.50}\n\n
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    async with _sse_lock:
        _sse_clients.add(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send connection confirmation
        yield f"data: {json.dumps({'type':'connected','ts':int(time.time())})}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment every 15s so proxies don't close the connection
                    yield ": keepalive\n\n"
        finally:
            async with _sse_lock:
                _sse_clients.discard(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
