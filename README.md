# UNG-HELIOS

Secure hub-and-spoke relay for UNG internal systems.

## Run locally

```bash
pip install -r requirements.txt
export HELIOS_ADMIN_KEY='replace-with-a-secret'
uvicorn api:app --host 0.0.0.0 --port 8000
```

## Test

```bash
python -m unittest -v
```

The original handoff contained 45 passing tests for core/storage/security/client. This restored package adds an HTTP-layer regression test for FastAPI/SQLite threadpool compatibility, bringing the suite to 46 tests.

## Railway

The Railway service should use `/health` as its health check and start with:

```bash
uvicorn api:app --host 0.0.0.0 --port $PORT
```

For persistent SQLite in production, mount persistent storage and set `HELIOS_DB_PATH` to a path on that volume (for example `/data/helios.db`).
