# Chapter 13: Security, Authentication, and Rate Limiting

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

You've seen the pipeline, the scoring engine, the frontend, the ML models. Now let's talk about the boring stuff that keeps attackers out and your server from getting accidentally DoS'd by an overeager scanner. Security in TriageMate is pragmatic — it's built for a local-first, small-team SOC, not a FAANG-grade zero-trust architecture. But that doesn't mean we ignored it. Let's walk through authentication, rate limiting, CORS, input validation, and what's coming next.

---

## Authentication: JWT, Optional by Design

Let's get the most important thing out of the way first: **authentication is optional.** If you don't set `TRIAGEMATE_ADMIN_USER` in your `.env`, the system runs entirely without auth. Every protected endpoint just returns `"anonymous"` as the current user. This wasn't laziness — it was deliberate. When you're hacking on a tool locally, the last thing you want is to fight a login screen every time the server restarts. Auth is a production concern, not a development concern.

But when you need it, it's real.

### The JWT Flow

TriageMate uses a standard JWT token pair pattern — access tokens and refresh tokens. Here's how it works:

1. **POST `/api/auth/login`** — send a username and password. The server hashes the password with bcrypt, compares it against the stored hash, and if it matches, returns two tokens:
   - An **access token** that expires in 30 minutes
   - A **refresh token** that expires in 7 days

2. **Bearer token on every request** — the client attaches the access token as `Authorization: Bearer <token>` on every API call. The `get_current_user()` FastAPI dependency decodes the token, validates the signature and expiry, and extracts the `sub` claim (the username).

3. **POST `/api/auth/refresh`** — when the access token expires (the client gets a 401), it sends the refresh token to this endpoint and gets back a fresh access token. The refresh token itself stays the same until it expires. This means the client never needs to re-enter credentials as long as they interact at least once every 7 days.

4. **Logout** — there's no server-side logout. The client just discards the tokens from localStorage. Short-lived access tokens mean that even if someone steals a token, the window of vulnerability is at most 30 minutes.

All of this lives in two files: `backend/auth.py` (123 lines) and `backend/routers/auth.py` (100 lines). The auth module handles token creation, verification, password hashing, and the `get_current_user` dependency. The router module has just the two endpoints — login and refresh.

### Password Hashing with bcrypt

Passwords are never stored in plaintext. The system uses bcrypt with a generated salt:

```python
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
```

You can set the password either as a plain-text env var (`TRIAGEMATE_ADMIN_PASS`) which gets hashed at startup, or as a pre-hashed value (`TRIAGEMATE_ADMIN_PASS_HASH`) which is the more secure option. If you set the plain-text version, the server logs a warning telling you to switch to the pre-hashed form.

```python
admin_pass = os.getenv("TRIAGEMATE_ADMIN_PASS", "")
admin_pass_hash = os.getenv("TRIAGEMATE_ADMIN_PASS_HASH", "")
if admin_pass and not admin_pass_hash:
    hashed = bcrypt.hashpw(admin_pass.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    logger.warning(
        "TRIAGEMATE_ADMIN_PASS is set as plain text. "
        "Set TRIAGEMATE_ADMIN_PASS_HASH=%s instead for better security.",
        hashed,
    )
```

### JWT Configuration

The JWT secret key defaults to `"dev-secret-change-me"`. Yes, that's a terrible secret. It's meant to be changed in production via `TRIAGEMATE_JWT_SECRET`. The algorithm is HS256. The token payload includes three claims:

- `sub` — the username
- `exp` — the expiration timestamp
- `type` — either `"access"` or `"refresh"`, so the refresh endpoint only accepts refresh tokens and vice versa

The `verify_token()` function catches all `PyJWTError` exceptions and returns `None` on any failure — expired, malformed, wrong signature, doesn't matter. The caller then raises a 401.

### Router-Level Protection

The protection is applied at the router level in `main.py`:

```python
app.include_router(auth.router)
app.include_router(queue.router, dependencies=[Depends(get_current_user)])
app.include_router(cases.router, dependencies=[Depends(get_current_user)])
app.include_router(ingest.router, dependencies=[Depends(get_current_user)])
```

Notice that `auth.router` has no `Depends(get_current_user)`. That's deliberate — you can't require authentication to hit the login endpoint, or you'd have a chicken-and-egg problem. The queue, cases, and ingest routers all require `get_current_user()`, which means every endpoint under those routers gets the auth check automatically.

### When Auth is Disabled

When `TRIAGEMATE_ADMIN_USER` is not set, `AUTH_DISABLED = True` and `get_current_user()` simply returns `"anonymous"` without doing any token check. The login and refresh endpoints return 401 with "Authentication is not configured on this server" if called while auth is disabled. The health endpoint at `/api/health` reports `auth_required: false`, and the frontend checks this at startup to decide whether to show the login modal.

This is all surfaced in the startup logs:

```python
if AUTH_DISABLED:
    logger.warning("AUTH IS DISABLED — set TRIAGEMATE_ADMIN_USER in .env to enable")
```

### Frontend Auth Flow

The frontend side of auth lives in `frontend/js/components/auth.js`. Here's what it does:

1. **Startup check** — when the page loads, `initAuth()` calls `/api/health`. If the response says `auth_required: true` and the user has no stored tokens, it shows the login modal. If `auth_required: false`, it proceeds immediately.

2. **Token storage** — tokens go into `localStorage` under the key `triagemate_auth`. The stored object includes `accessToken`, `refreshToken`, and `expiresAt` set to 25 minutes from now (a conservative buffer on the 30-minute server expiry).

3. **Auto-refresh on 401** — the `_authFetch()` wrapper in `api.js` intercepts 401 responses and tries to refresh the token before giving up. If the refresh also fails, it clears the tokens and reloads the page, forcing the user to log in again.

4. **Login modal** — a simple overlay with username/password fields and a Sign In button. Enter key in the username field moves focus to password; Enter in password triggers login. Error messages appear inline.

5. **No password storage** — the password is never stored on the client. Only the tokens are stored. This means the password lives in memory only during the login request and is discarded immediately after.

The system is pragmatic — no OAuth, no SSO, no multi-factor. For an MVP that runs on localhost, this is the right level of complexity.

---

## Rate Limiting: Token Buckets

Rate limiting in TriageMate is implemented as an HTTP middleware in `app.middleware("http")`. It uses a classic **token bucket** algorithm — think of it as a bucket that fills with tokens at a steady rate. Each request consumes a token. If the bucket is empty, the request is rejected with a 429 Too Many Requests.

### The TokenBucket Class

The implementation lives in `backend/middleware/rate_limit.py` — just 29 lines:

```python
class TokenBucket:
    def __init__(self, rate_per_minute: int, burst_size: int):
        self.rate = rate_per_minute / 60.0
        self.burst = burst_size
        self.tokens = float(burst_size)
        self.last_refill = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> float:
        if self.tokens >= 1.0:
            return 0.0
        return max(0.0, (1.0 - self.tokens) / self.rate)
```

The math is straightforward:
- `rate_per_minute / 60.0` gives the refill rate in tokens per second
- On each check, we calculate elapsed time and refill accordingly, capped at `burst_size`
- If there's at least one token, we consume it and return `True`; otherwise `False`
- `retry_after()` tells the caller how many seconds until the next token is available

### The Three Buckets

Three global bucket instances are created at module load time:

```python
ingest_bucket = TokenBucket(rate_per_minute=30, burst_size=50)
demo_bucket = TokenBucket(rate_per_minute=10, burst_size=15)
clear_bucket = TokenBucket(rate_per_minute=2, burst_size=3)
```

**Ingest bucket** — 30 requests per minute, burst up to 50. This applies to `POST /api/ingest`, `/api/ingest/batch`, and `/api/ingest/tenable`. These are the endpoints that scanners and demos hit to push vulnerabilities into the system. The relatively generous limit reflects the fact that a legitimate scanner may send a batch of vulns at once, but we still want to prevent an infinite loop or a runaway script.

**Demo bucket** — 10 requests per minute, burst 15. This applies to `POST /api/demo/generate`, the endpoint that creates synthetic demo data. The tighter limit prevents accidentally generating hundreds of demo records with a single mis-typed command.

**Clear bucket** — 2 requests per minute, burst 3. This applies to `POST /api/ingest/clear`, which wipes all ingested data. The aggressive limit is intentional — you don't want to accidentally (or maliciously) clear the database twice in quick succession.

### The Middleware

The middleware itself in `main.py` is a simple path-and-method check:

```python
@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    path = request.url.path
    if request.method == "POST":
        if path in ("/api/ingest", "/api/ingest/batch", "/api/ingest/tenable"):
            if not ingest_bucket.allow():
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Too many ingest requests."},
                    headers={"Retry-After": str(int(ingest_bucket.retry_after()))},
                )
        elif path == "/api/demo/generate":
            if not demo_bucket.allow():
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Slow down demo generation."},
                    headers={"Retry-After": str(int(demo_bucket.retry_after()))},
                )
        elif path == "/api/ingest/clear":
            if not clear_bucket.allow():
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Clear is limited to 2/minute."},
                    headers={"Retry-After": str(int(clear_bucket.retry_after()))},
                )
    return await call_next(request)
```

If a request exceeds the rate limit, the client gets a `429 Too Many Requests` with a JSON body explaining which limit was hit and a `Retry-After` header in seconds.

### Inline Rate Limiting for Demo and Clear

Beyond the middleware-level token buckets, there's additional inline rate limiting in the demo and clear endpoints themselves. The demo endpoint enforces a minimum 2-second interval between calls, and the clear endpoint enforces a minimum 30-second interval. These act as a secondary safety net — even if the middleware is somehow bypassed or misconfigured, the inline checks prevent rapid-fire calls.

### What the Token Bucket Is Not

The current implementation is process-local. If you scale TriageMate to multiple workers (e.g., with Gunicorn + multiple Uvicorn workers), each worker has its own token bucket, so the effective rate limit multiplies by the number of workers. This is fine for a single-process MVP but would need a shared store (Redis, or an in-memory database) for multi-worker production deployments.

---

## CORS: Wide Open

Cross-Origin Resource Sharing in TriageMate is configured as wide-open as it gets:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

`allow_origins=["*"]` means any origin can make requests to the API. `allow_methods=["*"]` means any HTTP method is permitted. `allow_headers=["*"]` means any custom header passes through.

For an MVP that runs entirely on localhost, this is fine. The frontend and backend are served from different ports (the frontend via `python -m http.server` and the backend via Uvicorn), so without CORS they couldn't talk to each other at all. Setting specific origins would just add friction during development.

In production, you'd want to restrict this to the actual frontend origin — something like `allow_origins=["https://triagemate.soc.wa.gov.au"]` — and set `allow_credentials=True` if you ever switch to cookie-based auth.

---

## Input Validation with Pydantic

All API inputs are validated through Pydantic models with a custom `BaseModelConfig` that applies camelCase aliasing:

```python
def camel_case(s: str) -> str:
    """Convert snake_case to camelCase for API responses."""
    parts = s.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])

class BaseModelConfig(BaseModel):
    model_config = {
        "alias_generator": camel_case,
        "populate_by_name": True,
        "protected_namespaces": (),
    }
```

This means the Python code uses `snake_case` internally, while the JSON API uses `camelCase`. Pydantic handles the translation automatically. The frontend sends `accessToken` in requests, and the backend sees `access_token`. Clean and consistent.

### IngestRequest

The most important validation model is `IngestRequest`, which validates every vulnerability that comes into the pipeline:

```python
class IngestRequest(BaseModelConfig):
    vulnerability_id: str
    hostname: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    cisa_kev: bool = False
    epss_score: Optional[float] = None
    target_ip: str = ""
    raw_description: str = ""
    scanner_output_raw: str = ""
    weakness_template_raw: str = ""
    exploit_maturity: int = 0
    has_public_poc: bool = False
    vendor_patch_status: int = 0
```

Fields are type-checked by Pydantic — you can't pass a string where a float is expected, or an integer where a boolean is expected. The `exploit_maturity` field is constrained to 0–3 (none, poc, active, weaponised), and `vendor_patch_status` is constrained to 0–2 (unknown, available, unavailable). But these are only constrained at the code level, not at the Pydantic schema level — there's no `Field(ge=0, le=3)` validator. That's a future hardening opportunity.

### LoginRequest and RefreshRequest

```python
class LoginRequest(BaseModelConfig):
    username: str
    password: str

class RefreshRequest(BaseModelConfig):
    refresh_token: str
```

Minimal but sufficient. Username and password are just strings. No length limits, no character restrictions. Again, adequate for an MVP, but production would want minimum lengths, rate limiting on login attempts, and perhaps a CAPTCHA after N failed attempts.

### ReviewRequest

```python
class ReviewRequest(BaseModelConfig):
    analyst_decision: str
    override_score: int | None = None
    override_band: str | None = None
    notes: str = ""
    analyst_name: str
```

This captures the analyst's feedback on a vulnerability. The `override_score` is an optional integer (the score override), and `override_band` is an optional string (the band label). Notes default to empty string, which prevents the "notes is required" problem when an analyst just wants to agree with the system.

---

## SQL Injection and ORM

There's no ORM in TriageMate. All database interaction uses raw SQL with parameterized queries via the `?` placeholder, which is then converted to `%s` for PostgreSQL compatibility. Here's the pattern:

```python
cursor.execute(
    "SELECT * FROM queue WHERE vulnerability_id = ?",
    (vuln_id,)
)
```

Because all user-supplied values go through parameterized queries, there's no SQL injection risk. The database driver handles escaping. This is safer than many ORM setups where developers inadvertently use string interpolation on query parameters.

No ORM also means no N+1 query problem, no migration headaches from ORM-level schema mismatches, and no ORM-specific locking issues. The trade-off is more boilerplate, but for a focused tool like this, raw SQL is the right call.

---

## Cross-Site Scripting (XSS)

The frontend uses a homegrown `escHtml()` function defined in `frontend/js/components/queue.js`:

```javascript
function escHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

Every piece of user-displayed data in the queue view, case view, and review queue is run through `escHtml()` before being inserted into the DOM. This includes vulnerability IDs, hostnames, scanner output, analyst notes, and any other field that could contain attacker-controlled content.

The pattern is consistent across all three view components (queue.js, caseView.js, reviewQueue.js) — every `innerHTML` assignment wraps its dynamic content in `escHtml()`. This is the single most important XSS mitigation, and it's applied universally.

---

## Secrets Management

Secrets live in a `.env` file at the project root, which is gitignored. An `.env.example` file provides a template. The supported environment variables for security are:

- `TRIAGEMATE_ADMIN_USER` — enables auth
- `TRIAGEMATE_ADMIN_PASS` — plain-text password (hashed at startup)
- `TRIAGEMATE_ADMIN_PASS_HASH` — pre-hashed password (preferred)
- `TRIAGEMATE_JWT_SECRET` — JWT signing key (default: dev-secret-change-me)

The `.env` file is loaded at the very top of `main.py` before any other module imports run, so all environment variables are available system-wide:

```python
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))
```

Production deployments should replace the default JWT secret with a strong random value. A reasonable approach is `openssl rand -hex 32` piped into the environment variable.

---

## Security Architecture — The Big Picture

Let me lay this out in one place so you can see how all the pieces fit together.

| Layer | Mechanism | Status |
|-------|-----------|--------|
| Authentication | JWT (access 30m + refresh 7d), bcrypt | ✅ Implemented |
| Auth enforcement | FastAPI Depends on router includes | ✅ Implemented |
| Auth optional | Disabled when TRIAGEMATE_ADMIN_USER unset | ✅ Implemented |
| Rate limiting | Token bucket, per-path (ingest/demo/clear) | ✅ Implemented |
| Inline rate limiting | Min interval checks in demo and clear | ✅ Implemented |
| CORS | allow_origins=["*"] | ✅ Implemented (MVP) |
| Input validation | Pydantic models with camelCase | ✅ Implemented |
| SQL injection | Parameterized queries, no ORM | ✅ Mitigated |
| XSS | escHtml() on all user-displayed data | ✅ Mitigated |
| Secrets | .env file, gitignored, .env.example | ✅ Implemented |
| Rate limit config | Environment variables | 🔄 Planned (Sprint NEXT) |
| RBAC | Roles (analyst/admin/viewer) | 📅 Post-MVP |
| API keys | Scanner integration auth | 📅 Post-MVP |
| Audit logging | Comprehensive event trail | 📅 Post-MVP |
| PostgreSQL network auth | pg_hba.conf, SSL connections | 📅 Post-MVP |

---

## What's Planned (Sprint NEXT)

The roadmap has one immediate security item and several longer-term hardening tasks.

### Sprint NEXT: Rate Limiting Configurability

Item 16 in `SPRINT_NEXT_PLAN.md` is about making the token bucket parameters configurable through environment variables. Right now, the ingest rate of 30/minute, demo rate of 10/minute, and clear rate of 2/minute are hard-coded in `backend/middleware/rate_limit.py`:

```python
ingest_bucket = TokenBucket(rate_per_minute=30, burst_size=50)
demo_bucket = TokenBucket(rate_per_minute=10, burst_size=15)
clear_bucket = TokenBucket(rate_per_minute=2, burst_size=3)
```

The plan is to expose these as environment variables like `TRIAGEMATE_RATE_INGEST`, `TRIAGEMATE_RATE_DEMO`, `TRIAGEMATE_RATE_CLEAR`, and their associated burst sizes. This means operators can tune the rate limits without touching source code — essential for deployments that need to accommodate faster scanners or stricter controls.

The implementation would look something like:

```python
ingest_bucket = TokenBucket(
    rate_per_minute=int(os.getenv("TRIAGEMATE_RATE_INGEST", 30)),
    burst_size=int(os.getenv("TRIAGEMATE_RATE_INGEST_BURST", 50)),
)
```

Simple change, big impact on operational flexibility.

### Post-MVP: Auth Hardening

Authentication for production is a bigger lift. Here's what's on the roadmap:

**Role-Based Access Control (RBAC).** Currently there's a single admin user. Production needs at least three roles:
- **Analyst** — can view the queue, review cases, submit feedback
- **Admin** — can do everything including ingesting data, clearing the database, and managing users
- **Viewer** — read-only access to dashboards, no mutations

Roles would be encoded in the JWT payload as a custom claim, and checked per-endpoint through a FastAPI dependency chain.

**API Keys for Scanner Integration.** Automated scanners need to authenticate without a human in the loop. The plan is to support static API keys for machine-to-machine auth. An API key would be a long, random string stored in the database and hashed with bcrypt (same as passwords). The ingest endpoints would accept either a Bearer JWT token or an `X-API-Key` header.

**Comprehensive Audit Logging.** Every security-relevant event should be logged with a structured payload — who did what, when, from what IP, and what the outcome was. Currently, login attempts are logged (both success and failure), but there's no unified audit trail. Production needs an audit_log table and a dedicated log stream.

**Rate Limiting on Login.** The login endpoint currently has no rate limiting. An attacker can brute-force passwords indefinitely. The plan is to apply the token bucket to `/api/auth/login` with a very conservative limit — say 5 attempts per minute per IP — and to log every failed attempt.

### Post-MVP: PostgreSQL Network Security

When TriageMate migrates to PostgreSQL in production, the network layer adds another security dimension:
- **`pg_hba.conf`** — restrict database connections to only the application server's IP address
- **SSL connections** — encrypt the database connection to prevent credential sniffing on the wire
- **Database-level roles** — separate read-only and read-write database users, mapped to application-level RBAC

These are standard PostgreSQL security practices and are well-documented in the PostgreSQL manual. The application code already supports both SQLite and PostgreSQL via the `?` → `%s` placeholder conversion; adding network-level auth is purely a deployment configuration concern.

---

## Closing Thoughts

Security in TriageMate is honest about its scope. The MVP isn't trying to be a hardened production security appliance — it's trying to be a tool that works for a small SOC team and that doesn't introduce obvious vulnerabilities while doing so.

The authentication system gives you real JWT-based auth with bcrypt password hashing, but makes it optional so you don't fight it during development. The rate limiting prevents accidental DoS from misconfigured scanners without adding the complexity of Redis or external rate limit stores. The input validation catches type errors and structural problems before they reach the database. The XSS protection in the frontend covers the most common web vulnerability vector.

What's missing — RBAC, API keys, audit logging, configurable rate limits — are all designed and scoped for the next development cycle. They're not afterthoughts; they're sequenced deliberately to match the maturity of the system.

If you're deploying TriageMate in a real SOC today, here's what I'd recommend:
1. **Set a strong `TRIAGEMATE_JWT_SECRET`** — `openssl rand -hex 32`
2. **Enable authentication** by setting `TRIAGEMATE_ADMIN_USER` and `TRIAGEMATE_ADMIN_PASS_HASH`
3. **Don't expose the API directly to the internet** — put it behind a reverse proxy (nginx, Caddy) with TLS termination
4. **Configure the reverse proxy for additional rate limiting** at the network edge
5. **Monitor the logs** for failed login attempts and rate limit warnings

That's enough for a responsible internal deployment. The Sprint NEXT configurability will make tuning easier, and the post-MVP hardening will close the remaining gaps. But for a tool that started as a single HTML file and now runs a production-grade triage pipeline, the security story is already solid — and getting stronger.

---

*Next up: Chapter 14 — we'll dive into the testing strategy, CI/CD pipeline, and how we keep the codebase healthy as it grows.*
