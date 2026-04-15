from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from dotenv import load_dotenv
import os

# Carga las variables del archivo .env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Crea el cliente de Supabase (se conecta via HTTPS, no TCP)
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI(title="Todo List API", version="2.0.0")

# ─────────────────────────────────────────────
# CONFIGURACIÓN DE CORS
# Permite que tu frontend HTML pueda llamar a esta API
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelo para crear una tarea
class TaskInput(BaseModel):
    text: str

# Modelo para actualizar el texto de una tarea
class TaskUpdate(BaseModel):
    text: str


# ─────────────────────────────────────────────
# RUTAS (ENDPOINTS) DE LA API
# ─────────────────────────────────────────────

@app.get("/")
def home():
    return {"message": "API de Todo List funcionando correctamente 🚀"}


@app.get("/test-db")
def test_db():
    """Diagnóstico: verifica conexión a Supabase."""
    try:
        res = supabase.table("tasks").select("id").limit(1).execute()
        return {"status": "✅ Conexión exitosa a Supabase", "data": res.data}
    except Exception as e:
        return {"status": "❌ Error de conexión", "detalle": str(e)}


@app.get("/tasks")
def get_tasks():
    """Retorna todas las tareas ordenadas por fecha de creación."""
    try:
        res = supabase.table("tasks").select("*").order("created_at", desc=True).execute()
        return res.data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/tasks", status_code=201)
def create_task(task: TaskInput):
    """Crea una nueva tarea y la guarda en Supabase."""
    try:
        res = supabase.table("tasks").insert({"text": task.text}).execute()
        return res.data[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class TaskToggle(BaseModel):
    completed: bool

@app.put("/tasks/{task_id}")
def update_task_state(task_id: int, payload: TaskToggle):
    """Actualiza el estado completado de una tarea con un valor explícito."""
    try:
        res = supabase.table("tasks").update({"completed": payload.completed}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/tasks/{task_id}")
def update_task_text(task_id: int, payload: TaskUpdate):
    """Actualiza el texto de una tarea existente."""
    try:
        if not payload.text.strip():
            raise HTTPException(status_code=400, detail="El texto no puede estar vacío")
        res = supabase.table("tasks").update({"text": payload.text.strip()}).eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return res.data[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/tasks/{task_id}")
def delete_task(task_id: int):
    """Elimina una tarea permanentemente."""
    try:
        res = supabase.table("tasks").delete().eq("id", task_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Tarea no encontrada")
        return {"message": f"Tarea {task_id} eliminada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
