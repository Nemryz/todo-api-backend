from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from supabase import create_client
from dotenv import load_dotenv
import jwt
from jwt.exceptions import PyJWTError
import os

load_dotenv()

SUPABASE_URL        = os.getenv("SUPABASE_URL")
SUPABASE_KEY        = os.getenv("SUPABASE_KEY")        # service_role (reservado para admin)
SUPABASE_ANON_KEY   = os.getenv("SUPABASE_ANON_KEY")   # anon key (para usuarios autenticados)
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET") # JWT Secret del proyecto

app = FastAPI(title="Todo List API", version="3.0.0")

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


# ─────────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────────

class TaskInput(BaseModel):
    text: str

class TaskUpdate(BaseModel):
    text: str

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
        payload = jwt.decode(
            credentials.credentials,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
        )
        return payload["sub"]  # UUID del usuario
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


def get_db(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Cliente Supabase con el JWT del usuario → RLS aplica automáticamente."""
    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    client.postgrest.auth(credentials.credentials)
    return client


# ─────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────

@app.get("/")
def home():
    return {"message": "API de Todo List funcionando correctamente 🚀"}


@app.get("/tasks")
def get_tasks(
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").select("*").order("order_index", desc=False).order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks", status_code=201)
def create_task(
    task: TaskInput,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        if not task.text.strip():
            raise HTTPException(status_code=400, detail="El texto no puede estar vacío")
        res = db.table("tasks").insert({"text": task.text.strip(), "user_id": user_id}).execute()
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/tasks/reorder")
def reorder_tasks(
    payload: ReorderPayload,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        for t in payload.tasks:
            db.table("tasks").update({"order_index": t.order_index}).eq("id", t.id).execute()
        return {"message": "Orden actualizado exitosamente"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/tasks/{task_id}")
def update_task_state(
    task_id: int,
    payload: TaskToggle,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").update({"completed": payload.completed}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/tasks/{task_id}")
def update_task_text(
    task_id: int,
    payload: TaskUpdate,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        if not payload.text.strip():
            raise HTTPException(status_code=400, detail="El texto no puede estar vacío")
        res = db.table("tasks").update({"text": payload.text.strip()}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/tasks/{task_id}")
def delete_task(
    task_id: int,
    user_id: str = Depends(get_current_user),
    db=Depends(get_db),
):
    try:
        res = db.table("tasks").delete().eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return {"message": f"Tarea {task_id} eliminada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
