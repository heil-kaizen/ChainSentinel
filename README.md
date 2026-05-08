# ChainSentinel: Async Onchain Forensic Engine

ChainSentinel is an event-driven forensic tracking system for monitoring on-chain wallet activity, correlating transactions, and attributing fund movements across predefined wallet clusters. 

It is built using FastAPI, asyncio, and SQLite with persistent state recovery and real-time Telegram alerting.

## Features

* Real-time webhook ingestion for transaction events
* Async multi-wallet scanning engine
* Persistent investigation state (survives restarts)
* Atomic signature deduplication
* Heuristic-based transaction attribution scoring
* Telegram alert pipeline (async queue-based)
* Rate-limit and retry resilient API integration
* SQLite WAL mode for improved concurrency

## Architecture Overview

Webhook -> Dedup Layer -> Hunt Registry -> Async Scanner Pool
|
Attribution Engine
|
Telegram Notification Queue

## Core Components

### 1. Webhook Processor
Receives transaction events and triggers investigations when predefined conditions are met.

### 2. ForensicVault (Database Layer)
Handles:
* Processed signature tracking
* Hunt lifecycle persistence
* Cursor tracking per wallet

### 3. Scanner Engine
* Concurrent wallet scanning (async tasks)
* Pagination-based transaction retrieval
* Sweep detection logic
* Historical cursor checkpointing

### 4. Attribution Engine
Scores transactions based on:
* Amount proximity
* Time delta from sweep event
Returns confidence score on a 0 to 100 scale.

### 5. Telegram Worker
* Async queue-based notification system
* Prevents API blocking
* Ensures non-blocking alert delivery

## Tech Stack

* Python 3.10+
* FastAPI
* httpx (async HTTP client)
* aiosqlite (async database layer)
* asyncio (core concurrency model)

## Configuration

Edit the following values in the main script:

```python
TELEGRAM_TOKEN = "YOUR_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"

HELIUS_KEYS = ["KEY_1", "KEY_2"]

TARGETS = {
    "wallet_address": {"label": "Entity Name"}
}

CB_WALLETS = [
    "wallet_1",
    "wallet_2"
]

```

## Database Schema

### processed_sigs

Stores deduplicated transaction signatures to prevent re-processing events.

### hunts

Stores active investigation metadata and expiration timers.

### hunt_cursors

Stores per-wallet scan progress checkpoints to enable incremental scanning.

## How It Works

1. A webhook receives a transaction event from the blockchain.
2. The signature is checked against the database for duplication.
3. If a target condition is met, a hunt is registered in the vault.
4. Scanner workers analyze related wallets in parallel tasks.
5. Transactions are filtered and scored using the attribution model.
6. High-confidence matches are added to the Telegram queue for delivery.
7. The system persists all state to ensure recovery after a restart.

## Reliability Features

* WAL-mode SQLite: Enables concurrent reads and writes for improved performance.
* Atomic Deduplication: Prevents race conditions during webhook ingestion.
* Error Resilience: Implements retry handling for API failures including 429 and 5xx errors.
* Task Isolation: Each investigation runs in its own async task environment.
* Graceful Shutdown: Cleans up connections and flushes database state on exit.

## Limitations

* SQLite is not optimized for high-concurrency workloads with hundreds of targets.
* Heavy scan workloads may introduce latency depending on system resources.
* Attribution is heuristic-based and does not constitute cryptographic proof.

## Future Improvements

* Migration to PostgreSQL or Redis-backed event store for scaling.
* WebSocket-based streaming integration.
* Distributed worker architecture for high-volume monitoring.
* Machine learning models for advanced attribution scoring.

## License

For personal and educational use only. This software is not intended for production financial or custodial systems.
