import asyncio
import httpx
import logging
import time
import aiosqlite
import os
import random
from typing import TypedDict, Dict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ChainSentinel-V19")

# --- DATA STRUCTURES (Fix #15) ---
class HuntData(TypedDict):
    hunt_id: str
    target_addr: str
    label: str
    amount: float
    sweep_time: int
    expiry_time: int

# --- CONFIGURATION ---
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_TOKEN")
CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
HELIUS_KEYS = os.getenv("HELIUS_KEYS", "KEY_1,KEY_2").split(",")
DB_PATH = "forensic_vault.db"

TARGETS = {
    "TARGET_ADDRESS_1": {"label": "Person A"},
    "TARGET_ADDRESS_2": {"label": "Person B"}
}
CB_WALLETS = [
    "wallet_1", "wallet_2",
    "wallet_3"
]

# --- GLOBAL STATE ---
active_hunts: Dict[str, asyncio.Task] = {}
active_hunts_lock = asyncio.Lock()
tg_queue = asyncio.Queue(maxsize=1000)

# Fix #2: True Rate Limiter (Token Bucket Pattern)
class TokenBucket:
    def __init__(self, rps: float):
        self.capacity = rps
        self.tokens = rps
        self.updated_at = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self):
        async with self.lock:
            while self.tokens < 1:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated_at) * self.capacity)
                self.updated_at = now
                if self.tokens < 1:
                    await asyncio.sleep(0.1)
            self.tokens -= 1

# Throttled at 3 Requests Per Second
api_limiter = TokenBucket(3.0)

# Fix #8: Connection Retry Transport
transport = httpx.AsyncHTTPTransport(retries=3)
helius_client = httpx.AsyncClient(transport=transport, timeout=30.0, limits=httpx.Limits(max_keepalive_connections=20, max_connections=50))

# --- DATABASE LAYER ---

class ForensicVault:
    def __init__(self, path):
        self.path = path
        self.conn = None
        self.write_lock = asyncio.Lock()
        self.sig_counter = 0

    async def connect(self):
        self.conn = await aiosqlite.connect(self.path)
        # Fix #1: DB Optimizations
        await self.conn.execute("PRAGMA foreign_keys=ON")
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA synchronous=NORMAL")
        await self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.row_factory = aiosqlite.Row
        
        async with self.write_lock:
            await self.conn.execute("CREATE TABLE IF NOT EXISTS processed_sigs (sig TEXT PRIMARY KEY, ts INTEGER)")
            await self.conn.execute("""
                CREATE TABLE IF NOT EXISTS hunts (
                    hunt_id TEXT PRIMARY KEY, target_addr TEXT, label TEXT, 
                    amount REAL, sweep_time INTEGER, expiry_time INTEGER
                )
            """)
            await self.conn.execute("CREATE TABLE IF NOT EXISTS hunt_cursors (hunt_id TEXT, wallet TEXT, last_sig TEXT, PRIMARY KEY (hunt_id, wallet))")
            await self.conn.commit()

    async def startup_cleanup(self):
        """Fix #10: Purge stale state on boot."""
        async with self.write_lock:
            now = int(time.time())
            await self.conn.execute("DELETE FROM hunts WHERE expiry_time < ?", (now,))
            await self.conn.execute("DELETE FROM hunt_cursors WHERE hunt_id NOT IN (SELECT hunt_id FROM hunts)")
            await self.conn.commit()
            logger.info("Vault maintenance: Stale hunts and cursors purged.")

    async def is_new_sig(self, sig: str) -> bool:
        async with self.write_lock:
            cursor = await self.conn.execute("INSERT OR IGNORE INTO processed_sigs VALUES (?, ?)", (sig, int(time.time())))
            is_new = cursor.rowcount > 0
            if is_new:
                self.sig_counter += 1
                if self.sig_counter % 500 == 0:
                    await self.conn.execute("DELETE FROM processed_sigs WHERE ts < ?", (int(time.time()) - 86400,))
            await self.conn.commit()
            return is_new

    async def register_hunt(self, h: HuntData) -> bool:
        async with self.write_lock:
            cursor = await self.conn.execute("INSERT OR IGNORE INTO hunts VALUES (?, ?, ?, ?, ?, ?)", 
                                            (h['hunt_id'], h['target_addr'], h['label'], h['amount'], h['sweep_time'], h['expiry_time']))
            await self.conn.commit()
            return cursor.rowcount > 0

    async def cleanup_investigation(self, h_id: str):
        async with self.write_lock:
            await self.conn.execute("DELETE FROM hunts WHERE hunt_id=?", (h_id,))
            await self.conn.execute("DELETE FROM hunt_cursors WHERE hunt_id=?", (h_id,))
            await self.conn.commit()

vault = ForensicVault(DB_PATH)

# --- TELEGRAM WORKER ---

async def tg_worker():
    """Fix #14: Telegram retry logic."""
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            while True:
                text = await tg_queue.get()
                for attempt in range(3):
                    try:
                        r = await client.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                                          json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})
                        if r.status_code == 200: break
                        await asyncio.sleep(2 ** attempt)
                    except Exception as e:
                        logger.error("Telegram attempt %s failed: %s", attempt + 1, e)
                tg_queue.task_done()
        except asyncio.CancelledError:
            pass

# --- SCANNER ENGINE ---

async def scan_wallet_for_hunt(wallet: str, api_key: str, hunt: HuntData, found_event: asyncio.Event):
    hunt_id = hunt['hunt_id']
    try:
        async with vault.conn.execute("SELECT last_sig FROM hunt_cursors WHERE hunt_id=? AND wallet=?", (hunt_id, wallet)) as cursor:
            row = await cursor.fetchone()
            local_cursor = row['last_sig'] if row else None

        last_sig, new_top_sig, scan_verified = None, None, False
        tolerance = max(0.01, hunt['amount'] * 0.02)
        min_amt, max_amt = hunt['amount'] - tolerance, hunt['amount'] + tolerance

        for page in range(15):
            if found_event.is_set(): return

            url = f"https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key={api_key}"
            if last_sig: url += f"&before={last_sig}"

            for retry in range(4):
                try:
                    await api_limiter.consume() 
                    resp = await helius_client.get(url)
                    
                    # Fix #4: Re-include 5xx retry handling
                    if resp.status_code == 429 or 500 <= resp.status_code < 600:
                        logger.warning("Network pressure | status=%s wallet=%s retry=%s", resp.status_code, wallet, retry)
                        await asyncio.sleep(10 * (retry + 1))
                        continue
                    
                    if resp.status_code != 200: break
                    
                    txs = resp.json()
                    if not isinstance(txs, list) or not txs:
                        scan_verified = True
                        break

                    if page == 0: new_top_sig = txs[0].get('signature')

                    for tx in txs:
                        curr_sig, tx_ts = tx.get('signature'), tx.get('timestamp', 0)
                        if curr_sig == local_cursor or tx_ts < hunt['sweep_time']:
                            scan_verified = True
                            break

                        # Fix #5: Structured attribute check
                        for transfer in tx.get('nativeTransfers', []):
                            amt = transfer.get('amount', 0) / 1e9
                            dest = transfer.get('toUserAccount')
                            if not dest: continue

                            if min_amt <= amt <= max_amt and dest not in CB_WALLETS:
                                if not found_event.is_set():
                                    found_event.set()
                                    msg = f"🎯 <b>MATCH: {hunt['label']}</b>\nAmt: {amt:.6f} SOL\nTo: <a href='https://solscan.io/account/{dest}'>{dest}</a>"
                                    try: tg_queue.put_nowait(msg) # Fix #2
                                    except asyncio.QueueFull: logger.warning("Telegram queue full, alert dropped.")
                                    return 
                    
                    if scan_verified: break
                    last_sig = txs[-1].get('signature')
                    break 
                except Exception as e:
                    logger.exception("Scan error on %s: %s", wallet, e)
                    await asyncio.sleep(2)

        if scan_verified and new_top_sig:
            async with vault.write_lock:
                await vault.conn.execute("INSERT OR REPLACE INTO hunt_cursors VALUES (?, ?, ?)", (hunt_id, wallet, new_top_sig))
                await vault.conn.commit()
                
    except asyncio.CancelledError: # Fix #6: Proper propagation
        raise
    except Exception as e:
        logger.error("Fatal worker error on %s: %s", wallet, e)

async def manage_investigation(hunt: HuntData):
    h_id = hunt['hunt_id']
    found_event = asyncio.Event()
    try:
        # Fix #9: Align expiry logic with real timestamps
        while int(time.time()) < hunt['expiry_time'] and not found_event.is_set():
            logger.info("[%s] Polling investigation delta...", hunt['label'])
            tasks = [asyncio.create_task(scan_wallet_for_hunt(w, HELIUS_KEYS[i % len(HELIUS_KEYS)], hunt, found_event)) for i, w in enumerate(CB_WALLETS)]
            
            try:
                # Fix #8: gather with timeout and cleanup
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=150)
            except asyncio.TimeoutError:
                for t in tasks: t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True) # Fix #7: Cleanup cancelled tasks

            if not found_event.is_set():
                # Fix #12: Add jitter to prevent traffic synchronization spikes
                sleep_duration = 180 + random.uniform(0, 45)
                await asyncio.sleep(sleep_duration)
    finally:
        await vault.cleanup_investigation(h_id)
        async with active_hunts_lock:
            active_hunts.pop(h_id, None)

# --- LIFECYCLE ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    await vault.connect()
    await vault.startup_cleanup() # Maintenance
    tg_task = asyncio.create_task(tg_worker())
    
    async with vault.conn.execute("SELECT * FROM hunts") as cursor:
        stored_hunts = await cursor.fetchall() 

    for row in stored_hunts:
        h: HuntData = {"hunt_id": row[0], "target_addr": row[1], "label": row[2], 
                       "amount": row[3], "sweep_time": row[4], "expiry_time": row[5]}
        if h['expiry_time'] > int(time.time()):
            async with active_hunts_lock:
                # Fix #13: Racing task check
                existing = active_hunts.get(h['hunt_id'])
                if not existing or existing.done():
                    active_hunts[h['hunt_id']] = asyncio.create_task(manage_investigation(h))
    
    yield
    tg_task.cancel()
    await asyncio.gather(tg_task, return_exceptions=True)
    await helius_client.aclose()
    await vault.conn.close()

app = FastAPI(lifespan=lifespan)

# Fix #11: Health endpoint for monitoring
@app.get("/health")
async def health():
    return {"status": "ok", "active_hunts": len(active_hunts), "queue_depth": tg_queue.qsize()}

@app.post("/webhook")
async def webhook(request: Request):
    try:
        data = await request.json()
        if not isinstance(data, list): return {"status": "invalid_payload"}
    except Exception: return {"status": "parse_error"}

    for tx in data:
        sig, ts = tx.get('signature'), tx.get('timestamp')
        if not sig or not await vault.is_new_sig(sig): continue

        transfers = tx.get('nativeTransfers', [])
        if not isinstance(transfers, list): continue

        for transfer in transfers:
            f, t, amt = transfer.get('fromUserAccount'), transfer.get('toUserAccount'), transfer.get('amount', 0) / 1e9
            if f in TARGETS and t in CB_WALLETS:
                lbl = TARGETS[f]['label']
                h_id = f"{f}_{ts}"
                
                try: # Fix #2
                    tg_queue.put_nowait(f"🔄 Sweep Detected: <a href='https://solscan.io/account/{f}'>{lbl}</a>\nAmt: {amt:.6f} SOL")
                except asyncio.QueueFull: pass
                
                hunt: HuntData = {"hunt_id": h_id, "target_addr": f, "label": lbl, "amount": amt, "sweep_time": ts, "expiry_time": int(time.time()) + 3600}
                if await vault.register_hunt(hunt):
                    async with active_hunts_lock:
                        existing = active_hunts.get(h_id)
                        if not existing or existing.done():
                            active_hunts[h_id] = asyncio.create_task(manage_investigation(hunt))
                break
    return {"status": "ok"}
