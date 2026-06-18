from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, Field
from supabase import create_client
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from cachetools import TTLCache
from dotenv import load_dotenv
import structlog
import time
import os
import uuid
import re

load_dotenv()

SUPABASE_URL      = os.getenv("SUPABASE_URL")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY")      # service_role — verifica tokens
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY") # anon key — respeta RLS

IS_PROD = os.getenv("ENVIRONMENT", "development") == "production"

# ─── Logging estructurado ───────────────────
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ]
)
logger = structlog.get_logger()

# ─── Rate limiter ───────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── Caché TTL (30 segundos por usuario) ────
task_cache: TTLCache = TTLCache(maxsize=500, ttl=30)
subtask_cache: TTLCache = TTLCache(maxsize=500, ttl=30)

# ─── Seguridad: IPs baneadas y conteo de fallos ───
banned_ips: TTLCache    = TTLCache(maxsize=1000, ttl=900)   # ban 15 min
auth_failures: TTLCache = TTLCache(maxsize=5000, ttl=300)   # ventana 5 min

# ─── Scanners conocidos (user-agent) ────────
SCANNER_UA_BLACKLIST = frozenset({
    "sqlmap", "nikto", "nmap", "zgrab", "masscan",
    "whatweb", "wpscan", "dirsearch", "gobuster",
    "nuclei", "zap", "burpsuite", "acunetix",
    "appscan", "nessus", "openvas", "w3af",
    "metasploit", "hydra", "medusa", "aircrack",
})

# ─── Honeypot: paths que solo un scanner tocaría ─
HONEYPOT_PATHS = frozenset({
    "/admin", "/wp-login", "/wp-admin", "/phpmyadmin",
    "/.env", "/config", "/backup", "/shell", "/console",
    "/.git", "/server-status", "/actuator",
})

# ─── CORS según entorno ──────────────────────
PROD_ORIGINS = ["https://todo-frontend-opal-chi.vercel.app"]
DEV_ORIGINS  = ["http://127.0.0.1:5500", "http://localhost:5500"]
CORS_ORIGINS = PROD_ORIGINS if IS_PROD else PROD_ORIGINS + DEV_ORIGINS

app = FastAPI(
    title="Todo List API",
    version="1.0.0",
    docs_url=None if IS_PROD else "/docs",
    redoc_url=None if IS_PROD else "/redoc",
    openapi_url=None if IS_PROD else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(GZipMiddleware, minimum_size=500)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer()


# ─── Middleware: honeypot (primero para bloquear antes de todo) ───
@app.middleware("http")
async def honeypot_middleware(request: Request, call_next):
    if request.url.path in HONEYPOT_PATHS:
        ip = get_remote_address(request)
        banned_ips[ip] = True
        logger.warning("honeypot_triggered", ip=ip, path=request.url.path)
        return Response(status_code=404)
    return await call_next(request)


# ─── Middleware: bloquear IPs baneadas ───────
@app.middleware("http")
async def ip_ban_middleware(request: Request, call_next):
    ip = get_remote_address(request)
    if ip in banned_ips:
        return Response(
            status_code=429,
            headers={"Retry-After": "900"},
            content="Too Many Requests",
        )
    return await call_next(request)


# ─── Middleware: filtro de user-agent de scanners ─
@app.middleware("http")
async def block_scanner_agents(request: Request, call_next):
    ua = (request.headers.get("user-agent") or "").lower()
    if any(tool in ua for tool in SCANNER_UA_BLACKLIST):
        logger.warning("scanner_ua_blocked", ua=ua[:80], path=request.url.path)
        return Response(status_code=404)  # 404 no confirma la detección
    return await call_next(request)


# ─── Middleware: Content-Type en mutaciones ──
@app.middleware("http")
async def require_json_content_type(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("content-type", "")
        if "application/json" not in ct:
            return Response(status_code=415, content="Unsupported Media Type")
    return await call_next(request)


# ─── Middleware: logging + seguridad + fail2ban ───
@app.middleware("http")
async def security_and_logging_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    start = time.time()

    response = await call_next(request)

    duration = round((time.time() - start) * 1000)
    ip = get_remote_address(request)

    logger.info(
        "request",
        id=request_id,
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=duration,
        ip=ip,
        ua=(request.headers.get("user-agent") or "")[:100],
    )

    # Fail2ban: acumular errores 401 por IP
    if response.status_code == 401:
        count = auth_failures.get(ip, 0) + 1
        auth_failures[ip] = count
        if count >= 10:
            banned_ips[ip] = True
            logger.warning("ip_auto_banned", ip=ip, failures=count)

    # Security headers
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"]     = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Request-ID"]           = request_id
    response.headers["X-Robots-Tag"]           = "noindex, nofollow, noarchive"
    response.headers["Server"]                 = "Apache/2.4"  # ofuscación de fingerprint

    # No-cache en endpoints autenticados
    if request.url.path.startswith("/tasks"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Vary"]          = "Authorization"

    return response


# ─────────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────────

class TaskInput(BaseModel):
    text: str = Field(min_length=1, max_length=500)

    @field_validator('text')
    @classmethod
    def clean_text(cls, v: str) -> str:
        return v.strip()


class TaskUpdate(BaseModel):
    text: str = Field(min_length=1, max_length=500)

    @field_validator('text')
    @classmethod
    def clean_text(cls, v: str) -> str:
        return v.strip()


class TaskToggle(BaseModel):
    completed: bool


class TaskOrderUpdate(BaseModel):
    id: int
    order_index: int


class ReorderPayload(BaseModel):
    tasks: list[TaskOrderUpdate]


class SubtaskInput(BaseModel):
    text: str = Field(min_length=1, max_length=200)

    @field_validator('text')
    @classmethod
    def clean_text(cls, v: str) -> str:
        return v.strip()


class SubtaskToggle(BaseModel):
    done: bool


class SubtaskUpdate(BaseModel):
    text: str = Field(min_length=1, max_length=200)

    @field_validator('text')
    @classmethod
    def clean_text(cls, v: str) -> str:
        return v.strip()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

TASK_ID_RE = re.compile(r"^\d{1,10}$")


def validate_task_id(task_id: int) -> int:
    if task_id <= 0 or task_id > 2_147_483_647:
        raise HTTPException(status_code=400, detail="ID inválido")
    return task_id


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        admin = create_client(SUPABASE_URL, SUPABASE_KEY)
        response = admin.auth.get_user(credentials.credentials)
        return response.user.id
    except Exception as e:
        raise HTTPException(status_code=401, detail="Credenciales inválidas") from e


def get_db(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    client.postgrest.auth(credentials.credentials)
    return client


def invalidate_cache(user_id: str) -> None:
    task_cache.pop(user_id, None)
    subtask_cache.pop(user_id, None)


async def verify_task_owner(task_id: int, user_id: str, db) -> None:
    res = db.table("tasks").select("user_id").eq("id", task_id).execute()
    if not res.data or res.data[0].get("user_id") != user_id:
        raise HTTPException(status_code=404, detail="Tarea no encontrada")


# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/")
@limiter.limit("120/minute")
def home(request: Request):
    return {"status": "ok"}


@app.get("/tasks")
@limiter.limit("60/minute")
def get_tasks(
    request: Request,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    if user_id in task_cache:
        return task_cache[user_id]
    try:
        res = (
            db.table("tasks")
            .select("*")
            .order("order_index", desc=False)
            .order("created_at", desc=True)
            .execute()
        )
        tasks = res.data
        for t in tasks:
            try:
                sub_res = db.table("subtasks").select("*").eq("task_id", t["id"]).order("order_index").order("created_at").execute()
                t["subtasks"] = sub_res.data
            except Exception:
                t["subtasks"] = []
        task_cache[user_id] = tasks
        return tasks
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor")


@app.post("/tasks", status_code=201)
@limiter.limit("20/minute")
def create_task(
    request: Request,
    task: TaskInput,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").insert({"text": task.text, "user_id": user_id}).execute()
        invalidate_cache(user_id)
        return res.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.put("/tasks/reorder")
@limiter.limit("30/minute")
def reorder_tasks(
    request: Request,
    payload: ReorderPayload,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        for t in payload.tasks:
            validate_task_id(t.id)
            db.table("tasks").update({"order_index": t.order_index}).eq("id", t.id).eq("user_id", user_id).execute()
        invalidate_cache(user_id)
        return {"message": "Orden actualizado"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.put("/tasks/{task_id}")
@limiter.limit("60/minute")
async def update_task_state(
    request: Request,
    task_id: int,
    payload: TaskToggle,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("tasks").update({"completed": payload.completed}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.patch("/tasks/{task_id}")
@limiter.limit("30/minute")
async def update_task_text(
    request: Request,
    task_id: int,
    payload: TaskUpdate,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("tasks").update({"text": payload.text}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.delete("/tasks/{task_id}")
@limiter.limit("30/minute")
async def delete_task(
    request: Request,
    task_id: int,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("tasks").delete().eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return {"message": "Tarea eliminada"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


# ─────────────────────────────────────────────
# SUBTASK ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/tasks/{task_id}/subtasks")
@limiter.limit("60/minute")
async def get_subtasks(
    request: Request,
    task_id: int,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("subtasks").select("*").eq("task_id", task_id).order("order_index").order("created_at").execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.post("/tasks/{task_id}/subtasks", status_code=201)
@limiter.limit("30/minute")
async def create_subtask(
    request: Request,
    task_id: int,
    payload: SubtaskInput,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("subtasks").insert({
            "task_id": task_id,
            "user_id": user_id,
            "text": payload.text,
        }).execute()
        invalidate_cache(user_id)
        return res.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.patch("/tasks/{task_id}/subtasks/{subtask_id}")
@limiter.limit("60/minute")
async def toggle_subtask(
    request: Request,
    task_id: int,
    subtask_id: int,
    payload: SubtaskToggle,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("subtasks").update({"done": payload.done}).eq("id", subtask_id).eq("task_id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Subtarea no encontrada")
        invalidate_cache(user_id)
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e


@app.delete("/tasks/{task_id}/subtasks/{subtask_id}")
@limiter.limit("30/minute")
async def delete_subtask(
    request: Request,
    task_id: int,
    subtask_id: int,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    validate_task_id(task_id)
    await verify_task_owner(task_id, user_id, db)
    try:
        res = db.table("subtasks").delete().eq("id", subtask_id).eq("task_id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Subtarea no encontrada")
        invalidate_cache(user_id)
        return {"message": "Subtarea eliminada"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor") from e
