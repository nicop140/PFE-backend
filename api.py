from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile, Form, BackgroundTasks
from pydantic import BaseModel
import pandas as pd 
import io
from datetime import datetime
from typing import List
import uuid
from fastapi.middleware.cors import CORSMiddleware
from database import connect_to_mongo, close_mongo_connection, db_connection
from contextlib import asynccontextmanager
from auth import (
    load_users, save_users, verify_password, 
    get_password_hash, create_access_token, get_current_user, get_current_admin,
    get_user_by_username_db, create_user_db, get_all_users_db,
    update_user_role_db, delete_user_db
)
from ollama import AIService

# -------------------------
# MODELS
# -------------------------
class UserAuth(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserUpdate(BaseModel):
    role: str

class UserView(BaseModel):
    username: str
    role: str

# -------------------------
# FASTAPI LIFESPAN
# -------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    yield
    await close_mongo_connection()

app = FastAPI(lifespan=lifespan)

# -------------------------
# CORS
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# TEST DB
# -------------------------
@app.get("/test-db")
async def check_db():
    stats = await db_connection.db.command("dbStats")
    return {"status": "connected", "db_stats": stats}

# -------------------------
# AUTH ROUTES (JSON FILE - ANCIEN)
# -------------------------
@app.post("/auth/register", status_code=201)
async def register(user: UserAuth):
    users = load_users()
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    new_user = {
        "username": user.username,
        "password": get_password_hash(user.password),
        "role": "user"
    }
    users.append(new_user)
    save_users(users)
    return {"message": "Utilisateur créé avec succès"}

@app.post("/auth/login")
async def login(user: UserAuth):
    users = load_users()
    db_user = next((u for u in users if u["username"] == user.username), None)
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    
    token = create_access_token({"sub": db_user["username"], "role": db_user["role"]})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/register-db", status_code=201)
async def register_db(user: UserAuth):
    """Inscription avec MongoDB"""
    # Vérifier si l'utilisateur existe déjà
    existing_user = await get_user_by_username_db(user.username)
    if existing_user:
        raise HTTPException(
            status_code=400, 
            detail="Ce nom d'utilisateur existe déjà"
        )
    
    # Valider le mot de passe (minimum 6 caractères)
    if len(user.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Le mot de passe doit contenir au moins 6 caractères"
        )
    
    # Créer l'utilisateur dans MongoDB
    try:
        user_id = await create_user_db(user.username, user.password, role="user")
        return {
            "message": "Utilisateur créé avec succès",
            "username": user.username
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la création de l'utilisateur: {str(e)}"
        )

@app.post("/auth/login-db")
async def login_db(user: UserAuth):
    """Connexion avec MongoDB"""
    # Récupérer l'utilisateur depuis MongoDB
    db_user = await get_user_by_username_db(user.username)
    
    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )
    
    # Vérifier le mot de passe
    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )
    
    # Créer le token d'accès
    token = create_access_token({
        "sub": db_user["username"],
        "role": db_user.get("role", "user")
    })
    
    # Retourner le token ET les infos utilisateur
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(db_user["_id"]),
            "username": db_user["username"],
            "role": db_user.get("role", "user"),
            "created_at": db_user.get("created_at")
        }
    }

@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

# -------------------------
# AUDIT ROUTES
# -------------------------
@app.post("/audit/add")
async def launch_audit(
    background_tasks: BackgroundTasks,
    nom: str = Form(...),
    auteur: str = Form(...),
    file: UploadFile = File(...)
):
    # Création de l'entrée audit
    audit_id = str(uuid.uuid4())
    new_audit = {
        "_id": audit_id,
        "nom": nom,
        "auteur": auteur,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "status": "UPLOADING",
        "created_at": datetime.utcnow()
    }
    await db_connection.db.PFE.insert_one(new_audit)

    # Lecture rapide CSV
    content = await file.read()
    df = pd.read_csv(io.BytesIO(content))
    data_json = df.to_dict(orient='records')

    background_tasks.add_task(AIService.generate_audit_report, audit_id, data_json)
    for row in data_json:
        row["audit_id"] = audit_id
    # await db_connection.db.dataset_raw.insert_many(data_json)
    # await db_connection.db.PFE.update_one({"_id": audit_id}, {"$set": {"status": "READY"}})

    # Lancer pipeline en arrière-plan si besoin
    # background_tasks.add_task(run_ai_pipeline, audit_id, data_json[:10])

    return {"status": "started", "audit_id": audit_id, "message": "L'audit est en cours de génération par l'IA."}

@app.get("/audits")
async def list_audits():
    audits = await db_connection.db.PFE.find().sort("created_at", -1).to_list(length=100)
    return audits

@app.get("/audit/{id}")
async def get_audit_detail(id: str):
    audit = await db_connection.db.PFE.find_one({"_id": id})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return audit

@app.get("/audit/{id}/status")
async def get_audit_status(id: str):
    audit = await db_connection.db.PFE.find_one({"_id": id}, {"status": 1})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return {"status": audit.get("status")}

@app.delete("/audit/{id}")
async def delete_audit(id: str):
    res1 = await db_connection.db.PFE.delete_one({"_id": id})
    res2 = await db_connection.db.dataset_raw.delete_many({"audit_id": id})
    
    if res1.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Audit non trouvé")
        
    return {"message": f"Audit {id} et ses {res2.deleted_count} lignes de données ont été supprimés."}

# -------------------------
# ADMIN ROUTES (JSON FILE - ANCIEN)
# -------------------------
@app.get("/admin/users", response_model=List[UserView])
async def list_users(admin: dict = Depends(get_current_admin)):
    users = load_users()
    return [{"username": u["username"], "role": u["role"]} for u in users]

@app.post("/admin/users", status_code=201)
async def admin_create_user(user: UserCreate, admin: dict = Depends(get_current_admin)):
    users = load_users()
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    new_user = {
        "username": user.username,
        "password": get_password_hash(user.password),
        "role": user.role
    }
    users.append(new_user)
    save_users(users)
    return {"message": f"Utilisateur {user.username} créé avec le rôle {user.role}"}

@app.put("/admin/users/{username}")
async def update_user_role(username: str, update: UserUpdate, admin: dict = Depends(get_current_admin)):
    users = load_users()
    for u in users:
        if u["username"] == username:
            u["role"] = update.role
            save_users(users)
            return {"message": f"Rôle de {username} mis à jour en {update.role}"}
    
    raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

@app.delete("/admin/users/{username}")
async def delete_user(username: str, admin: dict = Depends(get_current_admin)):
    if admin["username"] == username:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous supprimer vous-même")
        
    users = load_users()
    new_users = [u for u in users if u["username"] != username]
    
    if len(new_users) == len(users):
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        
    save_users(new_users)
    return {"message": f"Utilisateur {username} supprimé avec succès"}

# ⭐ -------------------------
# ⭐ ADMIN ROUTES MONGODB (NOUVEAU)
# ⭐ -------------------------

@app.get("/admin/users-db", response_model=List[UserView])
async def list_users_db(admin: dict = Depends(get_current_admin)):
    """Liste tous les utilisateurs depuis MongoDB"""
    users = await get_all_users_db()
    return [{"username": u["username"], "role": u.get("role", "user")} for u in users]

@app.post("/admin/users-db", status_code=201)
async def admin_create_user_db(user: UserCreate, admin: dict = Depends(get_current_admin)):
    """Créer un utilisateur depuis l'interface admin (MongoDB)"""
    existing_user = await get_user_by_username_db(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    user_id = await create_user_db(user.username, user.password, role=user.role)
    return {"message": f"Utilisateur {user.username} créé avec le rôle {user.role}"}

@app.put("/admin/users-db/{username}")
async def update_user_role_db(username: str, update: UserUpdate, admin: dict = Depends(get_current_admin)):
    """Mettre à jour le rôle d'un utilisateur (MongoDB)"""
    success = await update_user_role_db(username, update.role)
    if not success:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    return {"message": f"Rôle de {username} mis à jour en {update.role}"}

@app.delete("/admin/users-db/{username}")
async def delete_user_db_route(username: str, admin: dict = Depends(get_current_admin)):
    """Supprimer un utilisateur (MongoDB)"""
    if admin["username"] == username:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous supprimer vous-même")
    
    success = await delete_user_db(username)
    if not success:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    
    return {"message": f"Utilisateur {username} supprimé avec succès"}