from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile, Form, BackgroundTasks
from pydantic import BaseModel
import pandas as pd 
import io
from datetime import datetime
from typing import List, Optional
import uuid
from fastapi.middleware.cors import CORSMiddleware
from database import connect_to_mongo, close_mongo_connection, db_connection
from contextlib import asynccontextmanager
from auth import (
    load_users, save_users, verify_password, 
    get_password_hash, create_access_token, get_current_user, get_current_admin
)

class AuditCreate(BaseModel):
    nom: str
    auteur: str
    date: str

@asynccontextmanager
async def lifespan(app: FastAPI):
    # exécute au démarrage
    await connect_to_mongo()
    yield
    # exécute à l'extinction
    await close_mongo_connection()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/test-db")
async def check_db():
    # Petit test pour vérifier que la DB répond
    stats = await db_connection.db.command("dbStats")
    return {"status": "connected", "db_stats": stats}

@app.post("/audit/add")
async def create_audit(audit_data: AuditCreate):
    try:
        new_audit = audit_data.model_dump()
        collection = db_connection.db.PFE
        
        # Ajouter des métadonnées internes
        new_audit["_id"] = str(uuid.uuid4()) # ID unique pour le suivi
        new_audit["created_at"] = datetime.utcnow()
        new_audit["status"] = "PENDING" # Statut initial de l'audit
        
        # Insertion dans la collection "audits" de MongoDB
        await collection.insert_one(new_audit)
        
        print(f"Audit créé avec succès : {new_audit['_id']}")
        
        return {
            "status": "success",
            "audit_id": new_audit["_id"],
            "message": "Audit enregistré en base de données"
        }
        
    except Exception as e:
        print(f" Erreur lors de l'insertion : {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur lors de la création")


######################
###AUTHENTIFICATION###
######################

class UserAuth(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str

# --- ROUTES  ---

#Permet de creer un user
@app.post("/auth/register", status_code=201)
async def register(user: UserAuth):
    users = load_users()
    if any(u["username"] == user.username for u in users):
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    new_user = {
        "username": user.username,
        "password": get_password_hash(user.password),
        "role": "user" # Par défaut
    }
    users.append(new_user)
    save_users(users)
    return {"message": "Utilisateur créé avec succès"}

#Permet de ce connecter (recup token)
@app.post("/auth/login")
async def login(user: UserAuth):
    users = load_users()
    db_user = next((u for u in users if u["username"] == user.username), None)
    
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    
    token = create_access_token({"sub": db_user["username"], "role": db_user["role"]})
    return {"access_token": token, "token_type": "bearer"}

#Profil user, recup d'info
@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

######################
########AUDIT#########
######################

#Permet de lancer l'audit
@app.post("/audit/add")
async def launch_audit(
    background_tasks: BackgroundTasks,
    nom: str = Form(...),
    auteur: str = Form(...),
    file: UploadFile = File(...)
):
    # Création de l'entrée dans la collection PFE (a changer ou non)
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

    # Lecture rapide et stockage des données brutes
    content = await file.read()
    df = pd.read_csv(io.BytesIO(content))
    data_json = df.to_dict(orient='records')
    for row in data_json:
        row["audit_id"] = audit_id
    # A DETERMINER CE QUE L'ON FAIT ICI 
    # await db_connection.db.dataset_raw.insert_many(data_json)
    # await db_connection.db.PFE.update_one({"_id": audit_id}, {"$set": {"status": "READY"}})

    # LANCEMENT DU PIPELINE EN ARRIÈRE-PLAN
    #background_tasks.add_task(run_ai_pipeline, audit_id, data_json[:10]) # On passe un échantillon pour le test

    return {"status": "success", "audit_id": audit_id, "message": "Audit lancé avec succès"}

#Permet d'aller chercher l'historiques des audits
@app.get("/audits")
async def list_audits():
    # On récupère tous les audits de la collection PFE, triés par date
    audits = await db_connection.db.PFE.find().sort("created_at", -1).to_list(length=100)
    return audits

#Permet d'obtenir la prediction + rapport Ollama d'un audit passer
@app.get("/audit/{id}")
async def get_audit_detail(id: str):
    audit = await db_connection.db.PFE.find_one({"_id": id})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return audit

#Permet de suivre l'etat d'avancement d'une audit en cour
@app.get("/audit/{id}/status")
async def get_audit_status(id: str):
    audit = await db_connection.db.PFE.find_one({"_id": id}, {"status": 1})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    return {"status": audit.get("status")}

#Permet de supprimer une audite
@app.delete("/audit/{id}")
async def delete_audit(id: str):
    # Supprimer les métadonnées
    res1 = await db_connection.db.PFE.delete_one({"_id": id})
    # Supprimer TOUTES les données brutes liées dans dataset_raw
    res2 = await db_connection.db.dataset_raw.delete_many({"audit_id": id})
    
    if res1.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Audit non trouvé")
        
    return {"message": f"Audit {id} et ses {res2.deleted_count} lignes de données ont été supprimés."}

######################
########ADMIN#########
######################

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class UserUpdate(BaseModel):
    role: str

class UserView(BaseModel):
    username: str
    role: str

#Permet d'avoir la list des users 
@app.get("/admin/users", response_model=List[UserView])
async def list_users(admin: dict = Depends(get_current_admin)):
    users = load_users()
    return [{"username": u["username"], "role": u["role"]} for u in users]

#Permet d'ajouter un user manuellement
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

#Permet de changer le role
@app.put("/admin/users/{username}")
async def update_user_role(username: str, update: UserUpdate, admin: dict = Depends(get_current_admin)):
    users = load_users()
    for u in users:
        if u["username"] == username:
            u["role"] = update.role
            save_users(users)
            return {"message": f"Rôle de {username} mis à jour en {update.role}"}
    
    raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

#Permet de supp un user (t banni mgl)
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