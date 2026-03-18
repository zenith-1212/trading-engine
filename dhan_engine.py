# -*- coding: utf-8 -*-
"""
dhan_engine.py
══════════════════════════════════════════════════════════════════════════════
  Central Dhan WebSocket Engine
  • ONE WebSocket connection — no per-client connections
  • In-memory LTP store (dict) — O(1) reads
  • Token mapper: Dhan security_id ↔ Kotak pSymbol / trd_symbol
  • Exponential back-off on disconnect; 429 gets 120s cooldown
  • Daily 08:00 AM token refresh (TOTP-based)
  • Broadcasts every tick to SSE clients via injected async callback
══════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import asyncio
import base64
import configparser
import csv
import io
import json
import logging
import os
import re
import ssl
import struct
import time
import calendar
from collections import defaultdict
from datetime import date, datetime, timedelta
from typing import Callable, Coroutine, Dict, List, Optional, Set, Tuple

import httpx

log = logging.getLogger("dhan_engine")

# ── Constants ─────────────────────────────────────────────────────────────────
DHAN_WS_URL   = "wss://api-feed.dhan.co"
DHAN_CSV_URL  = "https://images.dhan.co/api-data/api-scrip-master-detailed.csv"
DHAN_LTP_URL  = "https://api.dhan.co/v2/marketfeed/ltp"
DHAN_TOKEN_URL = "https://auth.dhan.co/app/generateAccessToken"

_TO_DHAN_SEG = {
    "NSE_FO" : "NSE_FNO",
    "BSE_FO" : "BSE_FNO",
    "NSE_EQ" : "NSE_EQ",
    "BSE_EQ" : "BSE_EQ",
    "MCX_FO" : "MCX_COMM",
    "NSE_CUR": "NSE_CURRENCY",
    "BSE_CUR": "BSE_CURRENCY",
    "IDX_I"  : "IDX_I",
    "NSE_IDX": "IDX_I",
    "BSE_IDX": "IDX_I",
}

_SEG_MAP = {
    ("NSE", "D"): "NSE_FO",
    ("BSE", "D"): "BSE_FO",
    ("NSE", "E"): "NSE_EQ",
    ("BSE", "E"): "BSE_EQ",
    ("NSE", "C"): "NSE_CUR",
    ("BSE", "C"): "BSE_CUR",
    ("MCX", "M"): "MCX_FO",
}
_WANTED_SEGS = {"NSE_FO", "BSE_FO"}

# Dhan index security IDs
DHAN_IDX = {
    "13" : "NIFTY",
    "25" : "BANKNIFTY",
    "51" : "SENSEX",
}

# Disconnect reason codes
_DISCON_CODES = {
    805: "Too many websocket connections",
    806: "Subscribe to Data APIs",
    807: "Access Token expired",
    808: "Invalid Client ID",
    809: "Authentication Failed",
}

# ── Config loader ─────────────────────────────────────────────────────────────

def _config_path() -> str:
    """Config file path: env var > ./config/dhan_config.ini > ./dhan_config.ini"""
    env = os.environ.get("DHAN_CONFIG_PATH")
    if env and os.path.exists(env):
        return env
    # Cloud: credentials via env vars (no .ini needed)
    return os.path.join(os.path.dirname(__file__), "config", "dhan_config.ini")


def load_credentials() -> dict:
    """
    Load Dhan credentials from environment variables first (recommended for cloud),
    then fall back to dhan_config.ini.
    
    Environment variables (set in Railway / Fly.io dashboard):
        DHAN_CLIENT_ID
        DHAN_ACCESS_TOKEN
        DHAN_PIN
        DHAN_TOTP_SECRET
    """
    creds = {
        "client_id"   : os.environ.get("DHAN_CLIENT_ID", "").strip(),
        "access_token": os.environ.get("DHAN_ACCESS_TOKEN", "").strip(),
        "pin"         : os.environ.get("DHAN_PIN", "").strip(),
        "totp_secret" : os.environ.get("DHAN_TOTP_SECRET", "").strip(),
    }
    if creds["client_id"]:
        log.info("[CREDS] Loaded from environment variables")
        return creds

    # Fall back to .ini file
    path = _config_path()
    if os.path.exists(path):
        cfg = configparser.ConfigParser()
        cfg.read(path)
        sec = cfg.get("DHAN", {}) if cfg.has_section("DHAN") else {}
        creds = {
            "client_id"   : cfg.get("DHAN", "CLIENT_ID",    fallback="").strip(),
            "access_token": cfg.get("DHAN", "ACCESS_TOKEN", fallback="").strip(),
            "pin"         : cfg.get("DHAN", "PIN",          fallback="").strip(),
            "totp_secret" : cfg.get("DHAN", "TOTP_SECRET",  fallback="").strip(),
        }
        log.info(f"[CREDS] Loaded from {path}")
        return creds

    log.warning("[CREDS] No credentials found — set DHAN_CLIENT_ID etc. as env vars")
    return creds


def save_token_to_config(token: str):
    """Persist new token to .ini file (local dev only; in cloud use env var)."""
    path = _config_path()
    if not os.path.exists(path):
        return
    try:
        cfg = configparser.ConfigParser()
        cfg.read(path)
        if not cfg.has_section("DHAN"):
            cfg.add_section("DHAN")
        cfg.set("DHAN", "ACCESS_TOKEN", token)
        with open(path, "w") as f:
            cfg.write(f)
    except Exception as e:
        log.warning(f"[TOKEN] Could not save to .ini: {e}")


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _jwt_expiry(token: str) -> Optional[float]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        pad = "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        return float(payload.get("exp", 0))
    except Exception:
        return None


def _token_valid(token: str, buffer: int = 3600) -> bool:
    if not token or not token.strip().startswith("eyJ"):
        return False
    exp = _jwt_expiry(token)
    return bool(exp and (exp - time.time()) > buffer)


# ── Token refresher ───────────────────────────────────────────────────────────

async def refresh_dhan_token(client_id: str, pin: str, totp_secret: str) -> Optional[str]:
    """
    Generate a fresh Dhan access token via PIN + TOTP.
    Returns new token string or None.
    """
    if not pin or not totp_secret:
        log.warning("[TOKEN] PIN or TOTP_SECRET not set — cannot auto-refresh")
        return None
    try:
        import pyotp
        totp = pyotp.TOTP(totp_secret).now()
    except ImportError:
        log.error("[TOKEN] pyotp not installed: pip install pyotp")
        return None
    except Exception as e:
        log.error(f"[TOKEN] TOTP error: {e}")
        return None

    params = {"dhanClientId": client_id, "pin": pin, "totp": totp}
    log.info(f"[TOKEN] Generating token for client {client_id}...")

    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(DHAN_TOKEN_URL, params=params)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("accessToken") or data.get("access_token") or data.get("token")
                if token:
                    log.info(f"[TOKEN] ✓ New token received (attempt {attempt})")
                    save_token_to_config(token)
                    return token
                log.error(f"[TOKEN] No token in response: {data}")
            else:
                log.warning(f"[TOKEN] HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            log.warning(f"[TOKEN] Attempt {attempt} error: {e}")
        if attempt < 3:
            await asyncio.sleep(5)
    return None


# ── Binary packet parser ──────────────────────────────────────────────────────

def parse_binary_packet(data: bytes) -> Optional[dict]:
    """
    Parse Dhan v2 binary response.
    Layout: '<BHBIfI'  (little-endian)
      [0]   uint8   response_code
      [1-2] uint16  message_length
      [3]   uint8   exchange_segment_byte
      [4-7] uint32  security_id
      [8-11]float32 LTP
      [12-15]uint32 LTT
    """
    if len(data) < 8:
        return None
    try:
        rc  = data[0]
        seg = data[3]
        sid = struct.unpack_from("<I", data, 4)[0]
        result = {"rc": rc, "sid": str(sid), "seg": seg, "ltp": None}

        if rc in (2, 4, 8) and len(data) >= 12:
            ltp = struct.unpack_from("<f", data, 8)[0]
            result["ltp"] = float(ltp) if ltp > 0 else None

        elif rc == 50 and len(data) >= 10:
            code = struct.unpack_from("<H", data, 8)[0]
            msg  = _DISCON_CODES.get(code, f"code={code}")
            log.error(f"[WS] Server disconnect: {msg}")
            result["discon"] = code

        return result
    except Exception:
        return None


# ── Match key helpers ─────────────────────────────────────────────────────────

_MONTHS = {
    "JAN":1,"FEB":2,"MAR":3,"APR":4,"MAY":5,"JUN":6,
    "JUL":7,"AUG":8,"SEP":9,"OCT":10,"NOV":11,"DEC":12,
}
_UNDS   = ["BANKNIFTY", "MIDCPNIFTY", "FINNIFTY", "SENSEX", "NIFTY"]


def _norm_strike(raw) -> str:
    try:
        v = float(raw) if raw not in (None, "", "0", 0) else 0.0
        return str(int(v)) if v > 0 else "0"
    except (ValueError, TypeError):
        return "0"


def _norm_expiry(raw: str) -> str:
    s = (raw or "").strip()
    for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%d-%B-%Y", "%Y%m%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return s


def _make_key(und: str, strike, ot: str, expiry: str) -> str:
    return f"{und.strip().upper()}|{_norm_strike(strike)}|{ot.strip().upper()}|{_norm_expiry(expiry)}"


def _parse_trd_symbol(trd: str) -> Optional[Tuple[str, int, str, str]]:
    """
    Parse Kotak trd_symbol → (underlying, strike_int, option_type, expiry_YYYY-MM-DD).
    Handles both weekly (NIFTY2631722500CE) and monthly (BANKNIFTY26MAY60000PE) formats.
    """
    sym = next((u for u in _UNDS if trd.upper().startswith(u)), None)
    if not sym:
        return None
    rest = trd[len(sym):]
    if len(rest) < 5:
        return None
    ot = rest[-2:].upper()
    if ot not in ("CE", "PE"):
        return None
    body = rest[:-2]

    # Monthly: YYMON + STRIKE
    m = re.match(r"^(\d{2})([A-Za-z]{3})(\d+)$", body)
    if m:
        yy, mon, strk = m.groups()
        mon = mon.upper()
        if mon in _MONTHS:
            year = 2000 + int(yy)
            mo   = _MONTHS[mon]
            last = calendar.monthrange(year, mo)[1]
            dt   = date(year, mo, last)
            while dt.weekday() != 3:  # last Thursday
                dt -= timedelta(days=1)
            return (sym, int(strk), ot, dt.strftime("%Y-%m-%d"))

    # Weekly: YY + M(1 digit) + DD + STRIKE
    try:
        yy = int(body[:2])
    except ValueError:
        return None
    for mo_len in (1, 2):
        tail = body[2:]
        if len(tail) < mo_len + 3:
            continue
        try:
            mo   = int(tail[:mo_len])
            dd   = int(tail[mo_len:mo_len + 2])
            strk = int(tail[mo_len + 2:])
            if 1 <= mo <= 12 and 1 <= dd <= 31 and strk > 0:
                dt = date(2000 + yy, mo, dd)
                return (sym, strk, ot, dt.strftime("%Y-%m-%d"))
        except (ValueError, OverflowError):
            continue
    return None


# ── Token mapper ──────────────────────────────────────────────────────────────

class TokenMapper:
    """
    Bidirectional map: Dhan security_id ↔ (trd_symbol, psym)
    Built from Dhan instrument CSV + Kotak scrip cache.
    """

    def __init__(self):
        # Dhan security_id → (internal seg name, match_key)
        self._sid_to_meta  : Dict[str, Tuple[str, str]] = {}
        # match_key → (sid, dhan_seg_string)
        self._key_to_sid   : Dict[str, Tuple[str, str]] = {}
        # Kotak trd_symbol → sid
        self._trd_to_sid   : Dict[str, str] = {}
        # Kotak psym (pSymbol) → sid
        self._psym_to_sid  : Dict[str, str] = {}
        # Dhan sid → Kotak trd_symbol (for tick routing)
        self._sid_to_trd   : Dict[str, str] = {}
        # Nearest-expiry index: "UND|STRIKE|OT" → sorted [(date, sid, seg)]
        self._nei           : Dict[str, list] = {}
        self.csv_loaded     = False

    # ── CSV build ─────────────────────────────────────────────

    async def build_from_csv(self):
        """
        Download and parse Dhan instrument master CSV.
        Safe to call multiple times — clears old data before rebuilding
        so stale expiries from yesterday are removed.
        """
        log.info("[MAP] Downloading Dhan instrument CSV (fresh daily copy)...")
        for attempt in range(1, 5):
            try:
                async with httpx.AsyncClient(
                    timeout=180,
                    headers={"User-Agent": "Mozilla/5.0"},
                ) as client:
                    resp = await client.get(DHAN_CSV_URL)
                    resp.raise_for_status()
                text = resp.content.decode("utf-8", errors="ignore")
                # Clear old data before parsing — removes expired contracts
                self._sid_to_meta.clear()
                self._key_to_sid.clear()
                self._trd_to_sid.clear()
                self._psym_to_sid.clear()
                self._sid_to_trd.clear()
                self._nei.clear()
                self._parse_csv(text)
                log.info(f"[MAP] ✓ CSV loaded — {len(self._key_to_sid)} FO instruments")
                self.csv_loaded = True
                return
            except Exception as e:
                wait = attempt * 15
                log.warning(f"[MAP] CSV attempt {attempt}/4 failed: {e} — retry in {wait}s")
                await asyncio.sleep(wait)
        log.error("[MAP] All CSV download attempts failed — mapper may be stale")

    def _parse_csv(self, text: str):
        reader = csv.DictReader(io.StringIO(text))
        headers = list(reader.fieldnames or [])
        hl = {h.upper(): h for h in headers}

        def pick(*names):
            for n in names:
                if n in headers:           return n
                if n.upper() in hl:        return hl[n.upper()]
            return None

        col_exch   = pick("EXCH_ID",           "SEM_EXM_EXCH_ID")
        col_seg    = pick("SEGMENT",            "SEM_SEGMENT")
        col_sid    = pick("SECURITY_ID",        "SEM_SMST_SECURITY_ID")
        col_und    = pick("UNDERLYING_SYMBOL",  "SYMBOL_NAME")
        col_strike = pick("STRIKE_PRICE",       "SEM_STRIKE_PRICE")
        col_ot     = pick("OPTION_TYPE",        "SEM_OPTION_TYPE")
        col_exp    = pick("SM_EXPIRY_DATE",     "SEM_EXPIRY_DATE")

        if not col_sid:
            log.error("[MAP] SECURITY_ID column not found in CSV!")
            return

        count = 0
        nei_raw: Dict[str, list] = {}

        for row in reader:
            exch = (row.get(col_exch) or "").strip().upper()
            seg  = (row.get(col_seg)  or "").strip().upper()
            seg_name = _SEG_MAP.get((exch, seg))
            if not seg_name or seg_name not in _WANTED_SEGS:
                continue

            sid    = (row.get(col_sid)    or "").strip()
            und    = (row.get(col_und)    or "").strip().upper()   if col_und    else ""
            strike = (row.get(col_strike) or "0").strip()          if col_strike else "0"
            ot     = (row.get(col_ot)     or "").strip().upper()   if col_ot     else ""
            exp    = (row.get(col_exp)    or "").strip()           if col_exp    else ""

            if not sid or ot not in ("CE", "PE"):
                continue

            mkey     = _make_key(und, strike, ot, exp)
            dhan_seg = _TO_DHAN_SEG.get(seg_name, seg_name)

            self._sid_to_meta[sid]  = (seg_name, mkey)
            self._key_to_sid[mkey]  = (sid, dhan_seg)
            count += 1

            # Build nearest-expiry index
            exp_norm = _norm_expiry(exp)
            base = f"{und}|{_norm_strike(strike)}|{ot}"
            try:
                dt = datetime.strptime(exp_norm, "%Y-%m-%d").date()
                nei_raw.setdefault(base, []).append((dt, sid, dhan_seg))
            except ValueError:
                pass

        # Sort each list by date
        for k, v in nei_raw.items():
            self._nei[k] = sorted(v, key=lambda x: x[0])

        log.info(f"[MAP] Parsed {count} FO instruments, {len(self._nei)} strike groups")

    # ── Kotak scrip cache enrichment ──────────────────────────

    def enrich_from_scrip_cache(self, scrip_cache: dict):
        """
        Cross-reference Kotak scrip cache with Dhan map.
        scrip_cache: {trd_symbol: {"pSymbol":..., "underlying":...,
                                   "strike":..., "option_type":..., "expiry":...}}
        """
        matched = 0
        for trd, info in scrip_cache.items():
            psym = info.get("pSymbol", "")
            ot   = info.get("option_type", "")
            if ot not in ("CE", "PE"):
                continue

            # Strategy 1: composite key from scrip_cache fields
            key = _make_key(
                info.get("underlying", ""),
                info.get("strike", 0),
                ot,
                str(info.get("expiry", "")),
            )
            entry = self._key_to_sid.get(key)
            if not entry:
                entry = self._find_nearest(
                    info.get("underlying", ""),
                    info.get("strike", 0),
                    ot,
                    str(info.get("expiry", "")),
                )

            # Strategy 2: parse trd_symbol directly
            if not entry:
                parsed = _parse_trd_symbol(trd)
                if parsed:
                    und, strk, ot2, exp2 = parsed
                    key2 = f"{und}|{strk}|{ot2}|{exp2}"
                    entry = self._key_to_sid.get(key2)
                    if not entry:
                        entry = self._find_nearest(und, strk, ot2, exp2)

            if entry:
                sid, _ = entry
                self._trd_to_sid[trd]  = sid
                self._sid_to_trd[sid]  = trd
                if psym:
                    self._psym_to_sid[psym] = sid
                matched += 1

        log.info(f"[MAP] Enriched: {matched}/{len(scrip_cache)} Kotak → Dhan")
        return matched

    def _find_nearest(self, und, strike, ot, expiry_raw) -> Optional[Tuple[str, str]]:
        """Find Dhan entry with nearest expiry (±7 days) for monthly contracts."""
        s   = _norm_strike(strike)
        ot2 = ot.strip().upper()
        exp = _norm_expiry(str(expiry_raw))
        base = f"{und.strip().upper()}|{s}|{ot2}"
        candidates = self._nei.get(base, [])
        if not candidates or not exp:
            return None
        try:
            target_dt = datetime.strptime(exp, "%Y-%m-%d").date()
        except ValueError:
            return None
        best_sid, best_seg, best_delta = None, None, 8
        for (dt, sid, seg) in candidates:
            diff = abs((dt - target_dt).days)
            if diff < best_delta:
                best_delta = diff
                best_sid   = sid
                best_seg   = seg
        return (best_sid, best_seg) if best_sid else None

    # ── Lookup helpers ─────────────────────────────────────────

    def get_sid_by_trd(self, trd: str) -> Optional[str]:
        return self._trd_to_sid.get(trd)

    def get_sid_by_psym(self, psym: str) -> Optional[str]:
        return self._psym_to_sid.get(psym)

    def get_trd_by_sid(self, sid: str) -> Optional[str]:
        return self._sid_to_trd.get(sid)

    def get_dhan_seg(self, trd: str) -> Optional[str]:
        sid = self._trd_to_sid.get(trd)
        if not sid:
            return None
        _, mkey = self._sid_to_meta.get(sid, (None, None))
        if not mkey:
            return None
        _, seg = self._key_to_sid.get(mkey, (None, None))
        return seg

    def resolve_tokens_to_sids(
        self, trds: List[str]
    ) -> Dict[str, List[str]]:
        """
        Returns {dhan_seg: [sid, ...]} for a list of trd_symbols.

        Works in TWO ways:
        1. Direct lookup in _trd_to_sid (populated by enrich_from_scrip_cache)
        2. Parse trd_symbol directly from Kotak format → build match key → lookup in CSV
           This is the PRIMARY path in cloud mode because enrich_from_scrip_cache
           is never called — the desktop app sends Kotak trd_symbols directly.

        Kotak trd_symbol formats:
          Weekly : NIFTY2631722500CE   (YY + single-digit-month + DD + strike + OT)
          Monthly: BANKNIFTY26MAY60000PE (YY + 3-letter-month + strike + OT)
        """
        result: Dict[str, List[str]] = defaultdict(list)
        unresolved = []

        for trd in trds:
            # Path 1: pre-built cross-reference (from enrich_from_scrip_cache)
            sid = self._trd_to_sid.get(trd)
            if sid:
                _, mkey = self._sid_to_meta.get(sid, (None, None))
                if mkey:
                    _, seg = self._key_to_sid.get(mkey, (None, None))
                    if seg:
                        result[seg].append(sid)
                        continue

            # Path 2: parse trd_symbol directly → match key → Dhan CSV lookup
            parsed = _parse_trd_symbol(trd)
            if not parsed:
                unresolved.append(trd)
                continue
            und, strike, ot, expiry_ymd = parsed
            mkey = f"{und}|{strike}|{ot}|{expiry_ymd}"

            entry = self._key_to_sid.get(mkey)
            if not entry:
                # Try nearest-expiry (±7 days) for monthly contracts
                entry = self._find_nearest_for_trd(und, strike, ot, expiry_ymd)

            if entry:
                sid, seg = entry
                # Cache for future lookups
                self._trd_to_sid[trd] = sid
                self._sid_to_trd[sid] = trd
                result[seg].append(sid)
            else:
                unresolved.append(trd)

        if unresolved:
            log.debug(f"[MAP] {len(unresolved)} trd_symbols unresolved: {unresolved[:3]}")

        return dict(result)

    def _find_nearest_for_trd(self, und: str, strike: int, ot: str, expiry_ymd: str):
        """Find nearest Dhan entry within ±7 days (handles monthly expiry offsets)."""
        base = f"{und}|{strike}|{ot}"
        candidates = self._nei.get(base, [])
        if not candidates:
            return None
        try:
            target_dt = datetime.strptime(expiry_ymd, "%Y-%m-%d").date()
        except ValueError:
            return None
        best_entry, best_delta = None, 8
        for (dt, sid, seg) in candidates:
            diff = abs((dt - target_dt).days)
            if diff < best_delta:
                best_delta = diff
                best_entry = (sid, seg)
        return best_entry

    def chain_sids_for(self, symbol: str, expiry: str) -> Dict[str, str]:
        """Return {sid: trd_symbol} for all chain tokens of symbol+expiry."""
        result: Dict[str, str] = {}
        for trd, sid in self._trd_to_sid.items():
            _, mkey = self._sid_to_meta.get(sid, (None, None))
            if not mkey:
                continue
            parts = mkey.split("|")
            if len(parts) == 4 and parts[0] == symbol and parts[3] == expiry:
                result[sid] = trd
        return result


# ── Main DhanEngine class ─────────────────────────────────────────────────────

class DhanEngine:
    """
    Manages the single Dhan WebSocket + in-memory price store.
    All apps query this instead of connecting to Dhan directly.
    """

    _BATCH_SIZE  = 100
    _MAX_BACKOFF = 60

    def __init__(self, sse_broadcast_fn: Optional[Callable] = None):
        self._creds              = load_credentials()
        self._access_token       = self._creds.get("access_token", "")
        self._client_id          = self._creds.get("client_id", "")
        self._pin                = self._creds.get("pin", "")
        self._totp_secret        = self._creds.get("totp_secret", "")

        # In-memory price store  {key → float}
        # Keys can be: trd_symbol, psym (pSymbol), or "__IDX_NIFTY" etc.
        self._prices             : Dict[str, float] = {}

        self._mapper             = TokenMapper()
        self._subscribed_sids    : Set[str]          = set()  # confirmed by server
        self._pending_sub        : Dict[str, str]    = {}     # sid → seg (queued)
        self._pending_unsub      : Set[str]          = set()  # sids to unsub on next connect

        self._ws                 = None
        self._ws_running         = False
        self._retry_count        = 0
        self._stop               = False
        self._429_until          = 0.0   # Unix timestamp when 429 cooldown ends

        # Async broadcast to SSE clients
        self._broadcast          = sse_broadcast_fn

        # Tasks
        self._ws_task            : Optional[asyncio.Task] = None
        self._refresh_task       : Optional[asyncio.Task] = None
        self._spot_task          : Optional[asyncio.Task] = None

        # Spot price cache
        self._spot_prices        : Dict[str, float] = {}
        self._spot_ok            = False
        self._spot_cooldown      = 0.0

        log.info(f"[ENGINE] Initialized for client_id={self._client_id}")

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self):
        """Start CSV download, WebSocket, daily refresh, spot poller."""
        # Load instrument map in background (don't block startup)
        asyncio.create_task(self._init_mapper(), name="mapper-init")

        # Start WebSocket loop
        self._ws_task = asyncio.create_task(self._ws_lifecycle(), name="ws-loop")

        # Start daily 08:00 token refresh
        self._refresh_task = asyncio.create_task(
            self._daily_refresh_loop(), name="token-refresh"
        )

        # Start spot price poller
        self._spot_task = asyncio.create_task(
            self._spot_poll_loop(), name="spot-poll"
        )

        log.info("[ENGINE] All tasks started")

    async def stop(self):
        self._stop = True
        for task in [self._ws_task, self._refresh_task, self._spot_task]:
            if task:
                task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        log.info("[ENGINE] Stopped")

    async def _init_mapper(self):
        await self._mapper.build_from_csv()
        # If we have any pending subscriptions from before CSV loaded, flush them
        if self._pending_sub:
            log.info(f"[ENGINE] Flushing {len(self._pending_sub)} pending sub after CSV load")
            # They'll be sent when WS is next connected

    # ── WebSocket lifecycle ────────────────────────────────────────────────────

    async def _ws_lifecycle(self):
        while not self._stop:
            try:
                await self._ws_connect_and_stream()
                self._retry_count = 0
            except Exception as exc:
                if self._stop:
                    break
                s = str(exc)
                self._retry_count += 1
                self._ws_running = False

                if "429" in s:
                    wait = min(120 * self._retry_count, 600)
                    self._429_until = time.time() + wait
                    log.error(f"[WS] 429 rate-limited — waiting {wait}s (attempt {self._retry_count})")
                elif "807" in s or "expired" in s.lower():
                    log.warning("[WS] Token expired — refreshing before reconnect...")
                    await self._do_token_refresh()
                    wait = 5
                elif "no close frame" in s or "1006" in s:
                    wait = 30
                    log.warning(f"[WS] Abnormal close — retry in {wait}s")
                else:
                    wait = min(5 * (2 ** (self._retry_count - 1)), self._MAX_BACKOFF)
                    log.warning(f"[WS] Disconnected ({exc.__class__.__name__}: {exc}) — retry in {wait}s")

                await asyncio.sleep(wait)

    async def _ws_connect_and_stream(self):
        try:
            import websockets
        except ImportError:
            raise RuntimeError("pip install websockets")

        # Ensure token is valid before connecting
        if not _token_valid(self._access_token):
            log.info("[WS] Token expired — refreshing...")
            await self._do_token_refresh()

        import urllib.parse
        ws_url = (
            f"{DHAN_WS_URL}?"
            + urllib.parse.urlencode({
                "version" : "2",
                "token"   : self._access_token,
                "clientId": self._client_id,
                "authType": "2",
            })
        )
        log_url = ws_url.replace(self._access_token, self._access_token[:20] + "...")
        log.info(f"[WS] Connecting: {log_url}")

        ssl_ctx = ssl.create_default_context()
        ver_str = getattr(websockets, "__version__", "16")
        major   = int(ver_str.split(".")[0])

        kw = dict(ssl=ssl_ctx, ping_interval=20, ping_timeout=30)
        if major >= 13:
            kw["open_timeout"] = 15
        else:
            kw["close_timeout"] = 10

        async with websockets.connect(ws_url, **kw) as ws:
            self._ws = ws
            self._ws_running = True
            self._retry_count = 0
            log.info("[WS] ✓ Connected")

            # 1. Subscribe index tokens first
            await self._send_sub_batch(
                list(DHAN_IDX.keys()), "IDX_I"
            )
            log.info("[WS] ✓ Index tokens subscribed (NIFTY/BANKNIFTY/SENSEX)")

            # 2. Re-subscribe all confirmed sids (handles reconnect)
            if self._subscribed_sids:
                # Batch them by segment
                by_seg: Dict[str, List[str]] = defaultdict(list)
                for sid in self._subscribed_sids:
                    _, mkey = self._mapper._sid_to_meta.get(sid, (None, None))
                    if mkey:
                        _, seg = self._mapper._key_to_sid.get(mkey, (None, None))
                        if seg:
                            by_seg[seg].append(sid)
                self._subscribed_sids.clear()  # will be refilled as batches sent
                for seg, sids in by_seg.items():
                    await self._flush_sids(sids, seg)
                log.info(f"[WS] ✓ Re-subscribed {sum(len(v) for v in by_seg.values())} sids")

            # 3. Flush any pending new subscriptions
            if self._pending_sub:
                pending = dict(self._pending_sub)
                self._pending_sub.clear()
                by_seg = defaultdict(list)
                for sid, seg in pending.items():
                    by_seg[seg].append(sid)
                for seg, sids in by_seg.items():
                    await self._flush_sids(sids, seg)

            # 4. Main message loop
            async for raw in ws:
                if self._stop:
                    break
                await self._on_raw(raw)

    async def _flush_sids(self, sids: List[str], seg: str):
        for i in range(0, len(sids), self._BATCH_SIZE):
            batch = sids[i:i + self._BATCH_SIZE]
            await self._send_sub_batch(batch, seg)
            for sid in batch:
                self._subscribed_sids.add(sid)
            if i + self._BATCH_SIZE < len(sids):
                await asyncio.sleep(0.3)

    async def _send_sub_batch(self, sids: List[str], exchange_segment: str):
        if not self._ws or not self._ws_running:
            return
        packet = json.dumps({
            "RequestCode"    : 15,
            "InstrumentCount": len(sids),
            "InstrumentList" : [
                {"ExchangeSegment": exchange_segment, "SecurityId": sid}
                for sid in sids
            ],
        })
        try:
            await self._ws.send(packet)
            log.debug(f"[WS] Subscribed {len(sids)} tokens on {exchange_segment}")
        except Exception as e:
            log.warning(f"[WS] Sub send failed: {e}")
            self._ws_running = False
            for sid in sids:
                self._pending_sub[sid] = exchange_segment

    async def _send_unsub_batch(self, sids: List[str], exchange_segment: str):
        if not self._ws or not self._ws_running:
            return
        packet = json.dumps({
            "RequestCode"    : 16,   # UNSUB
            "InstrumentCount": len(sids),
            "InstrumentList" : [
                {"ExchangeSegment": exchange_segment, "SecurityId": sid}
                for sid in sids
            ],
        })
        try:
            await self._ws.send(packet)
            log.debug(f"[WS] Unsubscribed {len(sids)} tokens on {exchange_segment}")
        except Exception as e:
            log.warning(f"[WS] Unsub send failed: {e}")

    # ── Tick processing ────────────────────────────────────────────────────────

    async def _on_raw(self, raw):
        if isinstance(raw, bytes):
            parsed = parse_binary_packet(raw)
            if not parsed:
                return
            ltp = parsed.get("ltp")
            if not ltp or ltp <= 0:
                return
            sid = parsed.get("sid", "")
            await self._route_tick(sid, ltp)
        elif isinstance(raw, str):
            log.debug(f"[WS] Text frame: {raw[:200]}")

    async def _route_tick(self, sid: str, ltp: float):
        # Index tokens
        if sid in DHAN_IDX:
            sym = DHAN_IDX[sid]
            self._prices[f"__IDX_{sym}"] = ltp
            self._spot_prices[sym] = ltp
            self._spot_ok = True
            if self._broadcast:
                await self._broadcast(f"__IDX_{sym}", ltp)
            return

        # Option / equity tokens
        # Step 1: look up trd_symbol from _sid_to_trd
        # (populated when subscribe_tokens resolves via Path 2)
        trd = self._mapper.get_trd_by_sid(sid)

        if trd:
            self._prices[trd] = ltp
            if self._broadcast:
                await self._broadcast(trd, ltp)
            # Also update by psym if cross-referenced
            psym = next(
                (p for p, s in self._mapper._psym_to_sid.items() if s == sid), None
            )
            if psym:
                self._prices[psym] = ltp
                if self._broadcast:
                    await self._broadcast(psym, ltp)
        else:
            # Step 2: sid received a tick but not yet in _sid_to_trd
            # This means the tick arrived before subscribe built the mapping
            # Store price by sid key so get_ltp(sid) still works as fallback
            self._prices[f"__SID_{sid}"] = ltp

    # ── Public API ─────────────────────────────────────────────────────────────

    def mapper_ready(self) -> bool:
        """Called by /health — is the Dhan CSV loaded?"""
        return self._mapper.csv_loaded

    def ws_connected(self) -> bool:
        """Called by /health — is the WebSocket connected?"""
        return self._ws_running

    def get_ltp(self, token: str) -> Optional[float]:
        return self._prices.get(token)

    def get_spot_prices(self) -> dict:
        return {
            "NIFTY"    : self._spot_prices.get("NIFTY"),
            "BANKNIFTY": self._spot_prices.get("BANKNIFTY"),
            "SENSEX"   : self._spot_prices.get("SENSEX"),
            "live"     : self._spot_ok,
            "ts"       : int(time.time() * 1000),
        }

    def subscribed_count(self) -> int:
        return len(self._subscribed_sids) + len(DHAN_IDX)

    def get_status(self) -> dict:
        return {
            "connected"        : self._ws_running,
            "subscribed_tokens": self.subscribed_count(),
            "price_cache_size" : len(self._prices),
            "retry_count"      : self._retry_count,
            "rate_limited"     : time.time() < self._429_until,
            "mapper_ready"     : self._mapper.csv_loaded,
            "ts"               : int(time.time()),
        }

    def get_chain_ltps(self, symbol: str, expiry: str) -> dict:
        """
        Return {trd_symbol: ltp} for the option chain of symbol+expiry.
        trd_symbol format: NIFTY2631722500CE etc.
        """
        sids = self._mapper.chain_sids_for(symbol, expiry)
        result = {}
        for sid, trd in sids.items():
            ltp = self._prices.get(trd)
            if ltp is not None:
                result[trd] = ltp
        return result

    async def subscribe_tokens(self, trds: List[str]):
        """Subscribe a list of trd_symbols to the live feed."""
        if not self._mapper.csv_loaded:
            log.warning("[ENGINE] Mapper not ready — tokens queued until CSV loads")

        by_seg = self._mapper.resolve_tokens_to_sids(trds)

        total_resolved = sum(len(v) for v in by_seg.values())
        log.info(f"[SUB] Received {len(trds)} trd_symbols → resolved {total_resolved} Dhan sids "
                 f"(sample: {trds[:2]})")

        if total_resolved == 0 and trds:
            log.warning(f"[SUB] ⚠ ZERO resolved — mapper may not have these expiries. "
                        f"Sample unresolved: {trds[:3]}")

        for seg, sids in by_seg.items():
            new_sids = [s for s in sids if s not in self._subscribed_sids]
            if not new_sids:
                continue
            if self._ws_running:
                await self._flush_sids(new_sids, seg)
                log.info(f"[SUB] ✓ Subscribed {len(new_sids)} sids on {seg}")
            else:
                for sid in new_sids:
                    self._pending_sub[sid] = seg
                log.info(f"[SUB] WS not ready — queued {len(new_sids)} sids for {seg}")

    async def unsubscribe_tokens(self, trds: List[str]):
        """Unsubscribe tokens to free up slots."""
        by_seg = self._mapper.resolve_tokens_to_sids(trds)
        for seg, sids in by_seg.items():
            to_unsub = [s for s in sids if s in self._subscribed_sids]
            if to_unsub and self._ws_running:
                await self._send_unsub_batch(to_unsub, seg)
            for sid in to_unsub:
                self._subscribed_sids.discard(sid)
            # Clean price cache for unsubscribed tokens
            for trd in trds:
                sid = self._mapper.get_sid_by_trd(trd)
                if sid and sid not in self._subscribed_sids:
                    self._prices.pop(trd, None)

    async def refresh_dhan_token(self, force: bool = False) -> bool:
        """Public endpoint to trigger token refresh."""
        if not force and _token_valid(self._access_token):
            return True
        return await self._do_token_refresh()

    # ── Internal token refresh ─────────────────────────────────────────────────

    async def _do_token_refresh(self) -> bool:
        new_token = await refresh_dhan_token(
            self._client_id, self._pin, self._totp_secret
        )
        if new_token:
            self._access_token = new_token
            log.info("[TOKEN] ✓ Token refreshed")
            return True
        return False

    async def _daily_refresh_loop(self):
        """
        Every day at 08:00 AM IST:
          1. Refresh Dhan access token (TOTP-based)
          2. Re-download Dhan instrument CSV  ← CRITICAL: new weekly expiries appear daily
          3. Re-enrich token mapper with fresh instrument data
          4. Re-subscribe all active tokens with updated security_ids

        Why CSV must be re-downloaded daily:
          - New weekly options are added every Thursday
          - Expired contracts are removed
          - Security IDs can change for rolled contracts
          Without this, the mapper goes stale and option LTPs stop working
          after the first expiry day.
        """
        while not self._stop:
            now = datetime.now()
            target = now.replace(hour=8, minute=0, second=0, microsecond=0)
            if target <= now:
                target += timedelta(days=1)
            wait = (target - now).total_seconds()
            log.info(f"[DAILY] Next refresh at {target.strftime('%d-%b %H:%M')} ({wait/3600:.1f}h)")
            await asyncio.sleep(wait)
            if self._stop:
                break

            log.info("[DAILY] 08:00 AM — starting daily refresh sequence...")

            # Step 1: Refresh Dhan access token
            log.info("[DAILY] Step 1/3 — Refreshing Dhan access token...")
            token_ok = await self._do_token_refresh()
            log.info(f"[DAILY] Token refresh: {'✓ OK' if token_ok else '✗ FAILED (using existing)'}")

            # Step 2: Re-download Dhan instrument CSV (fresh expiries for today)
            log.info("[DAILY] Step 2/3 — Re-downloading Dhan instrument CSV...")
            try:
                old_count = len(self._mapper._key_to_sid)
                await self._mapper.build_from_csv()
                new_count = len(self._mapper._key_to_sid)
                log.info(f"[DAILY] CSV refreshed: {old_count} → {new_count} instruments")
            except Exception as e:
                log.error(f"[DAILY] CSV re-download failed: {e} — keeping old mapper")

            # Step 3: Re-subscribe all active tokens with fresh security_ids
            # (some security_ids may have changed for rolled contracts)
            log.info("[DAILY] Step 3/3 — Re-subscribing active tokens...")
            if self._subscribed_sids:
                log.info(f"[DAILY] Re-subscribing {len(self._subscribed_sids)} tokens...")
                # Force reconnect so server gets fresh subscriptions
                if self._ws and self._ws_running:
                    try:
                        await self._ws.close()
                    except Exception:
                        pass
                # The ws_lifecycle will reconnect and re-subscribe automatically
            
            log.info("[DAILY] ✓ Daily refresh sequence complete")

    # ── Spot price poller (fallback if WS index ticks missing) ────────────────

    async def _spot_poll_loop(self):
        """
        Poll Dhan REST for index spot prices every 30s during market hours.

        This is a FALLBACK only — the WebSocket already delivers NIFTY/BANKNIFTY/SENSEX
        ticks directly via IDX_I subscription. REST is only needed on first startup
        before the WS delivers its first tick.

        Fix: on 401, refresh token immediately instead of hammering expired token.
        Skip REST entirely once WS index ticks are flowing (_spot_ok = True).
        """
        _consecutive_401 = 0

        while not self._stop:
            await asyncio.sleep(30)

            # Skip REST if WS is already delivering index ticks — no need to poll
            if self._spot_ok and self._ws_running:
                continue

            if not self._is_market_open():
                continue

            if time.time() < self._spot_cooldown:
                continue

            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.post(
                        DHAN_LTP_URL,
                        json={"NSE_IDX": ["13", "25"], "BSE_IDX": ["51"]},
                        headers={
                            "Content-Type": "application/json",
                            "client-id"   : self._client_id,
                            "access-token": self._access_token,
                        },
                    )

                if resp.status_code == 401:
                    _consecutive_401 += 1
                    log.warning(f"[SPOT] 401 Unauthorized (#{_consecutive_401}) — refreshing token...")
                    # Refresh token immediately, then stop hammering
                    await self._do_token_refresh()
                    self._spot_cooldown = time.time() + 60  # wait 60s after refresh
                    if _consecutive_401 >= 3:
                        log.warning("[SPOT] 3 consecutive 401s — disabling REST spot poller. WS handles index prices.")
                        break  # Stop the loop entirely; WS delivers index ticks anyway
                    continue

                _consecutive_401 = 0  # reset on any non-401

                if resp.status_code == 429:
                    self._spot_cooldown = time.time() + 120
                    log.warning("[SPOT] 429 — pausing REST for 120s")
                    continue

                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    nse = data.get("NSE_IDX", {})
                    bse = data.get("BSE_IDX", {})
                    for sid, sym in DHAN_IDX.items():
                        src = bse if sid == "51" else nse
                        entry = src.get(sid, {})
                        ltp = float(entry.get("last_price", 0) or 0)
                        if ltp > 0:
                            self._spot_prices[sym] = ltp
                            self._prices[f"__IDX_{sym}"] = ltp
                    log.debug(f"[SPOT] REST fallback: {self._spot_prices}")

            except Exception as e:
                log.debug(f"[SPOT] Poll error: {e}")

    @staticmethod
    def _is_market_open() -> bool:
        from datetime import timezone
        ist_offset = timezone(timedelta(hours=5, minutes=30))
        now = datetime.now(ist_offset)
        if now.weekday() >= 5:
            return False
        mins = now.hour * 60 + now.minute
        return 555 <= mins <= 930  # 9:15 – 15:30 IST
