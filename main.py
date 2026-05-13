from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
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

load_dotenv()

SUPABASE_URL      = os.getenv("SUPABASE_URL")
SUPABASE_KEY      = os.getenv("SUPABASE_KEY")      # service_role — verifica tokens
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY") # anon key — respeta RLS

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

app = FastAPI(title="Todo List API", version="3.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(GZipMiddleware, minimum_size=500)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://todo-frontend-opal-chi.vercel.app",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer()


# ─── Middleware: logging + cabeceras de seguridad ───
@app.middleware("http")
async def logging_and_security_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000)
    logger.info(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=duration,
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
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


# ─────────────────────────────────────────────
# AUTH: verifica el JWT de Supabase y extrae el user_id
# ─────────────────────────────────────────────

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    try:
        admin = create_client(SUPABASE_URL, SUPABASE_KEY)
        response = admin.auth.get_user(credentials.credentials)
        return response.user.id
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Auth error: {str(e)}")


def get_db(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    client.postgrest.auth(credentials.credentials)
    return client


def invalidate_cache(user_id: str) -> None:
    task_cache.pop(user_id, None)


# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/")
def home():
    return {"message": "API de Todo List funcionando correctamente"}


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
        res = db.table("tasks").select("*").order("order_index", desc=False).order("created_at", desc=True).execute()
        task_cache[user_id] = res.data
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        raise HTTPException(status_code=500, detail=str(e))


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
            db.table("tasks").update({"order_index": t.order_index}).eq("id", t.id).execute()
        invalidate_cache(user_id)
        return {"message": "Orden actualizado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/tasks/{task_id}")
@limiter.limit("60/minute")
def update_task_state(
    request: Request,
    task_id: int,
    payload: TaskToggle,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").update({"completed": payload.completed}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/tasks/{task_id}")
@limiter.limit("30/minute")
def update_task_text(
    request: Request,
    task_id: int,
    payload: TaskUpdate,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").update({"text": payload.text}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/tasks/{task_id}")
@limiter.limit("30/minute")
def delete_task(
    request: Request,
    task_id: int,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").delete().eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        invalidate_cache(user_id)
        return {"message": f"Tarea {task_id} eliminada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
