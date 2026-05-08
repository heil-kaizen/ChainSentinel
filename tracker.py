import asyncio
import httpx
import logging
import time
import aiosqlite
from collections import deque
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request

# --- LOGGING ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("v15-final")

# --- CONFIGURATION ---
TELEGRAM_TOKEN = "YOUR_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"
HELIUS_KEYS = ["KEY_1", "KEY_2"] # Supports up to 10 keys
DB_PATH = "forensic_vault.db"

TARGETS = {
    "Address_For_A_Here": {"label": "Person A"},
    "Address_For_B_Here": {"label": "Person B"}
}

CB_WALLETS = [
    "wallet_1", "wallet_2",
    "wallet_3"
]

# --- GLOBAL STATE ---
active_hunts = {} 
active_hunts_lock = asyncio.Lock()
tg_queue = asyncio.Queue(maxsize=1000)
helius_client = httpx.AsyncClient(timeout=25.0, limits=httpx.Limits(max_keepalive_connections=20, max_connections=50))

# --- DATABASE ARCHITECTURE ---

class ForensicVault:
    def __init__(self, path):
        self.path = path
        self.conn = None
        self.db_lock = asyncio.Lock()
        self.sig_counter = 0

    async def connect(self):
        self.conn = await aiosqlite.connect(self.path)
        await self.conn.execute("PRAGMA journal_mode=WAL")
        async with self.db_lock:
            await self.conn.execute("CREATE TABLE IF NOT EXISTS processed_sigs (sig TEXT PRIMARY KEY, ts INTEGER)")
            await self.conn.execute("""
                CREATE TABLE IF NOT EXISTS hunts (
                    hunt_id TEXT PRIMARY KEY, target_addr TEXT, label TEXT, 
                    amount REAL, sweep_time INTEGER, expiry_time INTEGER
                )
            """)
            await self.conn.execute("CREATE TABLE IF NOT EXISTS hunt_cursors (hunt_id TEXT, wallet TEXT, last_sig TEXT, PRIMARY KEY (hunt_id, wallet))")
            await self.conn.commit()

    async def is_new_sig(self, sig) -> bool:
        """Atomic Deduplication (Fix #3)."""
        async with self.db_lock:
            # Atomic INSERT OR IGNORE returns rowcount=1 if unique
            cursor = await self.conn.execute("INSERT OR IGNORE INTO processed_sigs VALUES (?, ?)", (sig, int(time.time())))
            is_new = cursor.rowcount > 0
            if is_new:
                self.sig_counter += 1
                # Maintenance: Purge every 500 new signatures (Fix #4)
                if self.sig_counter % 500 == 0:
                    await self.conn.execute("DELETE FROM processed_sigs WHERE ts < ?", (int(time.time()) - 86400,))
            await self.conn.commit()
            return is_new

    async def register_hunt(self, h_id, addr, label, amt, sweep, expiry) -> bool:
        """Restored Method (Fix #1)."""
        async with self.db_lock:
            cursor = await self.conn.execute("INSERT OR IGNORE INTO hunts VALUES (?, ?, ?, ?, ?, ?)", (h_id, addr, label, amt, sweep, expiry))
            await self.conn.commit()
            return cursor.rowcount > 0

    async def cleanup_investigation(self, h_id):
        async with self.db_lock:
            await self.conn.execute("DELETE FROM hunts WHERE hunt_id=?", (h_id,))
            await self.conn.execute("DELETE FROM hunt_cursors WHERE hunt_id=?", (h_id,))
            await self.conn.commit()

vault = ForensicVault(DB_PATH)

# --- TELEGRAM WORKER ---

async def tg_worker():
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            while True:
                text = await tg_queue.get()
                payload = {"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
                try:
                    await client.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json=payload)
                except Exception as e:
                    logger.error(f"TG Worker: {e}")
                finally:
                    tg_queue.task_done()
        except asyncio.CancelledError:
            logger.info("Telegram worker shutting down.")
            raise

# --- ATTRIBUTION SCORING ---

def calculate_score(obs_amt, target_amt, tx_ts, sweep_ts):
    diff = abs(obs_amt - target_amt)
    s_amt = max(0, 60 - (diff * 2500)) 
    delta = tx_ts - sweep_ts
    s_time = 40 - (abs(delta - 600) / 60) if 120 <= delta <= 3000 else 0
    return max(0, s_amt + s_time)

# --- MANAGED SCANNER ---

async def scan_wallet_for_hunt(wallet, api_key, hunt, found_event):
    hunt_id = hunt['hunt_id']
    async with vault.db_lock:
        async with vault.conn.execute("SELECT last_sig FROM hunt_cursors WHERE hunt_id=? AND wallet=?", (hunt_id, wallet)) as cursor:
            row = await cursor.fetchone()
            local_cursor = row[0] if row else None

    last_sig, new_top_sig, scan_verified = None, None, False
    tolerance = max(0.01, hunt['amount'] * 0.02)
    min_amt, max_amt = hunt['amount'] - tolerance, hunt['amount'] + tolerance

    for page in range(15):
        if found_event.is_set(): return
        url = f"https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key={api_key}"
        if last_sig: url += f"&before={last_sig}"

        # Resilience Loop (Fix #6: Handle 429 and 5xx)
        for retry in range(3):
            try:
                await asyncio.sleep(0.15)
                resp = await helius_client.get(url)
                
                if resp.status_code == 429 or (500 <= resp.status_code < 600):
                    await asyncio.sleep(2 * (retry + 1))
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

                    for transfer in tx.get('nativeTransfers', []):
                        amt = transfer['amount'] / 1e9
                        if min_amt <= amt <= max_amt and transfer['toUserAccount'] not in CB_WALLETS:
                            score = calculate_score(amt, hunt['amount'], tx_ts, hunt['sweep_time'])
                            if score > 88 and not found_event.is_set():
                                found_event.set()
                                try:
                                    tg_queue.put_nowait(f"🎯 <b>V15 MATCH: {hunt['label']}</b> (Score: {score:.0f})\nTo: <a href='https://solscan.io/account/{transfer['toUserAccount']}'>{transfer['toUserAccount']}</a>")
                                except asyncio.QueueFull:
                                    logger.warning("Telegram queue full (Fix #5)") # Fix #5
                                return 
                
                if scan_verified: break
                last_sig = txs[-1].get('signature')
                break 
            except asyncio.CancelledError:
                raise
            except Exception as e:
                if retry == 2: logger.error(f"Failed {wallet}: {e}")
                await asyncio.sleep(2)

    if scan_verified and new_top_sig:
        async with vault.db_lock:
            await vault.conn.execute("INSERT OR REPLACE INTO hunt_cursors VALUES (?, ?, ?)", (hunt_id, wallet, new_top_sig))
            await vault.conn.commit()

async def manage_investigation(hunt):
    h_id = hunt['hunt_id']
    found_event = asyncio.Event()
    try:
        while time.time() < hunt['expiry_time'] and not found_event.is_set():
            tasks = [asyncio.create_task(scan_wallet_for_hunt(w, HELIUS_KEYS[i % len(HELIUS_KEYS)], hunt, found_event)) for i, w in enumerate(CB_WALLETS)]
            await asyncio.gather(*tasks, return_exceptions=True)
            if found_event.is_set(): break
            await asyncio.sleep(180)
    finally:
        await vault.cleanup_investigation(h_id)
        async with active_hunts_lock: active_hunts.pop(h_id, None)

# --- LIFECYCLE (Fix #2, #7) ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    await vault.connect()
    tg_task = asyncio.create_task(tg_worker())
    
    async with vault.db_lock:
        async with vault.conn.execute("SELECT * FROM hunts") as cursor:
            stored_hunts = await cursor.fetchall() 

    for row in stored_hunts:
        h = {"hunt_id": row[0], "target_addr": row[1], "label": row[2], "amount": row[3], "sweep_time": row[4], "expiry_time": row[5]}
        if h['expiry_time'] > time.time():
            async with active_hunts_lock:
                active_hunts[h['hunt_id']] = asyncio.create_task(manage_investigation(h))
        else:
            await vault.cleanup_investigation(h['hunt_id'])
    
    yield
    
    logger.info("Shutting down...")
    tg_task.cancel()
    await asyncio.gather(tg_task, return_exceptions=True) # Fix #7
    await helius_client.aclose()
    await vault.conn.close()

app = FastAPI(lifespan=lifespan) # Fix #2

@app.post("/webhook")
async def webhook(request: Request):
    try:
        data = await request.json()
    except Exception: return {"status": "error"}

    for tx in data:
        sig, ts = tx.get('signature'), tx.get('timestamp')
        if not sig: continue

        # Fix #3: Atomic Check-and-Insert
        if not await vault.is_new_sig(sig): continue

        for transfer in tx.get('nativeTransfers', []):
            f_addr, t_addr, amt = transfer.get('fromUserAccount'), transfer.get('toUserAccount'), transfer.get('amount', 0) / 1e9
            if f_addr in TARGETS and t_addr in CB_WALLETS:
                h_id = f"{f_addr}_{ts}"
                # Lock Hierarchy: DB Registration first
                if await vault.register_hunt(h_id, f_addr, TARGETS[f_addr]['label'], amt, ts, int(time.time()) + 3600):
                    async with active_hunts_lock:
                        if h_id not in active_hunts:
                            h_data = {"hunt_id": h_id, "target_addr": f_addr, "label": TARGETS[f_addr]['label'], "amount": amt, "sweep_time": ts, "expiry_time": int(time.time()) + 3600}
                            active_hunts[h_id] = asyncio.create_task(manage_investigation(h_data))
                break
    return {"status": "ok"}
