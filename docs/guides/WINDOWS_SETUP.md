# TriageMate — Windows Setup Guide

> **Target:** Windows 10/11 (x64)
> **Python:** 3.10–3.12
> **Time:** ~15 minutes

## Prerequisites

1. **Install Python 3.10+** from [python.org](https://www.python.org/downloads/).
   - During installation, check **"Add Python to PATH"**.
   - After install, verify:
     ```batch
     python --version
     ```

2. **Install Git** (optional, for cloning) from [git-scm.com](https://git-scm.com/download/win).

## Setup

Open **Command Prompt** or **PowerShell** and run:

### 1. Clone or extract the project

```batch
git clone <repo-url> triagemate
cd triagemate
```

Or extract the ZIP archive and `cd` into the extracted folder.

### 2. Create a virtual environment

```batch
python -m venv venv
```

### 3. Activate the virtual environment

```batch
venv\Scripts\activate
```

You should see `(venv)` in the prompt.

### 4. Install dependencies

First install PyTorch (CPU-only — no CUDA needed):

```batch
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Then install the remaining requirements:

```batch
cd backend
pip install -r requirements.txt
```

> **Note:** The `sentence-transformers` package will download the `all-MiniLM-L6-v2` model on first run (~90 MB). This is a one-time download.

### 5. (Optional) Configure environment

```batch
copy .env.example .env
```

Edit `.env` with a text editor if you want to configure:
- `TRIAGEMATE_LLM_API_KEY` — for Tier 2 LLM analysis (optional — fallback used if unset)
- `TRIAGEMATE_ADMIN_USER` / `TRIAGEMATE_ADMIN_PASS` — JWT auth credentials (optional — leave unset for localhost)
- `NVD_API_KEY` — NVD API key for rate limiting (optional)

### 6. Seed the database

```batch
python seed_data.py
```

This creates `triagemate.db` with 7 demo rows.

### 7. Start the server

```batch
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 8. Open the app

Open your browser to **http://localhost:8000**

## Accessing the App

| URL | What you see |
|---|---|
| `http://localhost:8000` | TriageMate Queue view |
| `http://localhost:8000/docs` | Swagger API documentation |
| `http://localhost:8000/api/health` | Health check (JSON) |

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` not found | Reinstall Python, check "Add to PATH" |
| `pip` not found | Use `python -m pip install ...` instead |
| Permission errors | Run Command Prompt **as Administrator** |
| Port 8000 in use | Add `--port 8001` to the uvicorn command and use `http://localhost:8001` |
| SentenceTransformer download fails | Retry — the HuggingFace CDN is reliable. Ensure internet is connected. |
| `uvicorn` not found | Ensure `venv\Scripts\activate` ran successfully, then `pip install uvicorn` |

## Docker on Windows

If you have Docker Desktop installed:

```batch
docker compose up --build
```

This builds the container (pre-caches the ML model) and starts the app on port 8000.
