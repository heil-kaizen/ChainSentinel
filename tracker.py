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
logger = logging.getLogger("v16-resilient")

# --- CONFIGURATION ---
TELEGRAM_TOKEN = "USE_YOUR_OLD_BOT_TOKEN_HERE"
CHAT_ID = "YOUR_CHAT_ID"
HELIUS_KEYS = ["KEY_1", "KEY_2", "KEY_3"] # Supports up to 10 keys
DB_PATH = "forensic_vault.db"

# IMPORTANT: Ensure addresses are EXACT
TARGETS = {
    "TARGET_ADDRESS_1": {"label": "Person A"},
    "TARGET_ADDRESS_2": {"label": "Person B"}
}

CB_WALLETS = [
    "wallet_1", "wallet_2",
    "wallet_3"
]

# --- GLOBAL STATE ---
active_hunts = {} 
active_hunts_lock = asyncio.Lock()
tg_queue = asyncio.Queue(maxsize=1000)
helius_client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_keepalive_connections=20, max_connections=50))

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
        async with self.db_lock:
            cursor = await self.conn.execute("INSERT OR IGNORE INTO processed_sigs VALUES (?, ?)", (sig, int(time.time())))
            is_new = cursor.rowcount > 0
            if is_new:
                self.sig_counter += 1
                if self.sig_counter % 500 == 0:
                    await self.conn.execute("DELETE FROM processed_sigs WHERE ts < ?", (int(time.time()) - 86400,))
            await self.conn.commit()
            return is_new

    async def register_hunt(self, h_id, addr, label, amt, sweep, expiry) -> bool:
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
                    r = await client.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json=payload)
                    if r.status_code != 200:
                        logger.error(f"Telegram API Error: {r.text}")
                except Exception as e:
                    logger.error(f"TG Worker Failed: {e}")
                finally:
                    tg_queue.task_done()
        except asyncio.CancelledError:
            raise

# --- ATTRIBUTION SCORING ---

def calculate_score(obs_amt, target_amt, tx_ts, sweep_ts):
    diff = abs(obs_amt - target_amt)
    s_amt = max(0, 60 - (diff * 3000)) # Strict amount scoring
    delta = tx_ts - sweep_ts
    # Peak score at 5-15 mins
    s_time = 40 - (abs(delta - 600) / 60) if 0 <= delta <= 3600 else 0
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

    for page in range(20):
        if found_event.is_set(): return
        url = f"https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key={api_key}"
        if last_sig: url += f"&before={last_sig}"

        # FIX: Robust Retry Loop for 429 and 5xx
        success = False
        for retry in range(4):
            try:
                await asyncio.sleep(0.2) # Base delay to respect rate limits
                resp = await helius_client.get(url)
                
                if resp.status_code == 429:
                    wait = 5 * (retry + 1)
                    logger.warning(f"Rate Limit (429) on {wallet}. Waiting {wait}s...")
                    await asyncio.sleep(wait)
                    continue
                
                if 500 <= resp.status_code < 600:
                    await asyncio.sleep(2)
                    continue

                if resp.status_code != 200: 
                    logger.error(f"Helius Error {resp.status_code} on {wallet}")
                    break
                
                txs = resp.json()
                if not isinstance(txs, list) or not txs:
                    scan_verified = True
                    success = True
                    break

                if page == 0: new_top_sig = txs[0].get('signature')

                for tx in txs:
                    curr_sig, tx_ts = tx.get('signature'), tx.get('timestamp', 0)
                    
                    if curr_sig == local_cursor or tx_ts < hunt['sweep_time']:
                        scan_verified = True
                        success = True
                        break

                    for transfer in tx.get('nativeTransfers', []):
                        amt = transfer['amount'] / 1e9
                        if min_amt <= amt <= max_amt and transfer['toUserAccount'] not in CB_WALLETS:
                            score = calculate_score(amt, hunt['amount'], tx_ts, hunt['sweep_time'])
                            
                            # DEBUG: Log potential matches that are close
                            if score > 50:
                                logger.info(f"Potential Match Found: {amt} SOL | Score: {score:.1f}")

                            if score > 80 and not found_event.is_set(): # Lowered to 80 for tests
                                found_event.set()
                                try:
                                    tg_queue.put_nowait(f"🎯 <b>V16 MATCH: {hunt['label']}</b> (Score: {score:.0f})\nAmt: {amt:.4f} SOL\nTo: <a href='https://solscan.io/account/{transfer['toUserAccount']}'>{transfer['toUserAccount']}</a>")
                                except: pass
                                return 
                
                if scan_verified: 
                    success = True
                    break
                
                last_sig = txs[-1].get('signature')
                success = True
                break 
            except Exception as e:
                logger.error(f"Network error on {wallet}: {e}")
                await asyncio.sleep(2)

        if not success: break # Stop scanning this wallet if we failed multiple retries

    if scan_verified and new_top_sig:
        async with vault.db_lock:
            await vault.conn.execute("INSERT OR REPLACE INTO hunt_cursors VALUES (?, ?, ?)", (hunt_id, wallet, new_top_sig))
            await vault.conn.commit()

async def manage_investigation(hunt):
    h_id = hunt['hunt_id']
    found_event = asyncio.Event()
    try:
        # Increase Hunt to 25 attempts (75 mins) to catch slow batching
        for attempt in range(25):
            if time.time() > hunt['expiry_time'] or found_event.is_set(): break
            
            logger.info(f"[{hunt['label']}] Attempt {attempt+1}/25. Scanning...")
            tasks = [asyncio.create_task(scan_wallet_for_hunt(w, HELIUS_KEYS[i % len(HELIUS_KEYS)], hunt, found_event)) for i, w in enumerate(CB_WALLETS)]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            if found_event.is_set(): break
            await asyncio.sleep(180)
    finally:
        await vault.cleanup_investigation(h_id)
        async with active_hunts_lock: active_hunts.pop(h_id, None)

# --- LIFECYCLE ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    await vault.connect()
    tg_task = asyncio.create_task(tg_worker())
    
    # STARTUP PING: Prove Telegram is working
    try:
        await tg_queue.put("🚀 <b>Sentinel V16 Online</b>\nSystem is armed and monitoring targets.")
    except: pass
    
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
    tg_task.cancel()
    await asyncio.gather(tg_task, return_exceptions=True)
    await helius_client.aclose()
    await vault.conn.close()

app = FastAPI(lifespan=lifespan)

@app.post("/webhook")
async def webhook(request: Request):
    try:
        data = await request.json()
    except: return {"status": "error"}

    for tx in data:
        sig, ts = tx.get('signature'), tx.get('timestamp')
        if not sig: continue

        if not await vault.is_new_sig(sig): continue

        for transfer in tx.get('nativeTransfers', []):
            f_addr, t_addr, amt = transfer.get('fromUserAccount'), transfer.get('toUserAccount'), transfer.get('amount', 0) / 1e9
            
            if f_addr in TARGETS and t_addr in CB_WALLETS:
                t = TARGETS[f_addr]
                h_id = f"{f_addr}_{ts}"
                
                if await vault.register_hunt(h_id, f_addr, t['label'], amt, ts, int(time.time()) + 4500):
                    async with active_hunts_lock:
                        if h_id not in active_hunts:
                            h_data = {"hunt_id": h_id, "target_addr": f_addr, "label": t['label'], "amount": amt, "sweep_time": ts, "expiry_time": int(time.time()) + 4500}
                            active_hunts[h_id] = asyncio.create_task(manage_investigation(h_data))
                            try:
                                tg_queue.put_nowait(f"🔄 <b>Sweep Detected: {t['label']}</b>\nAmt: {amt} SOL\nID: {h_id[:8]}")
                            except: pass
                break
    return {"status": "ok"}
