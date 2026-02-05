from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile, Form, BackgroundTasks, Request
from pydantic import BaseModel
import pandas as pd 
import io
from datetime import datetime
from typing import List
import uuid
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.encoders import jsonable_encoder
from database import connect_to_mongo, close_mongo_connection, db_connection
from contextlib import asynccontextmanager
from typing import List, Optional  
from auth import (
    load_users, save_users, verify_password, 
    get_password_hash, create_access_token, get_current_user, get_current_admin,
    get_user_by_username_db, create_user_db, get_all_users_db,
    update_user_role_db, delete_user_db
)
from llm import AIService

# -------------------------
# MODELS
# -------------------------
class UserAuth(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    nom: str
    prenom: str
    email: str
    entreprise: Optional[str] = None
    role: str

class UserCreate(BaseModel):
    username: str
    password: str
    nom: str
    prenom: str
    email: str
    entreprise: Optional[str] = None
    role: str = "user"

class UserUpdate(BaseModel):
    role: str

class UserView(BaseModel):
    username: str
    nom: str
    prenom: str
    email: str
    entreprise: Optional[str] = None
    role: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class UserProfileUpdate(BaseModel):
    nom: str
    prenom: str
    email: str
    entreprise: Optional[str] = None

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

####################
### AUTH  ROUTES ###
####################
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
async def register_db(user: UserCreate):
    """Inscription avec MongoDB - avec email et entreprise"""
    
    # Vérifier si le username existe déjà
    existing_user = await get_user_by_username_db(user.username)
    if existing_user:
        raise HTTPException(
            status_code=400, 
            detail="Ce nom d'utilisateur existe déjà"
        )
    
    # Vérifier si l'email existe déjà
    existing_email = await db_connection.db.users.find_one({"email": user.email})
    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Cet email est déjà utilisé"
        )
    
    if len(user.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Le mot de passe doit contenir au moins 6 caractères"
        )
    
    # Validation entreprise pour les admins
    if user.role == "admin" and not user.entreprise:
        raise HTTPException(
            status_code=400,
            detail="Le champ Entreprise est obligatoire pour les administrateurs"
        )
    
    try:
        user_id = await create_user_db(
            username=user.username,
            password=user.password,
            nom=user.nom,
            prenom=user.prenom,
            email=user.email,
            entreprise=user.entreprise,
            role=user.role
        )
        return {
            "message": "Utilisateur créé avec succès",
            "username": user.username,
            "nom": user.nom,
            "prenom": user.prenom,
            "email": user.email
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la création de l'utilisateur: {str(e)}"
        )

@app.put("/auth/update-profile")
async def update_profile(
    profile_data: UserProfileUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Met à jour les informations du profil utilisateur (MongoDB)
    L'utilisateur ne peut modifier que son propre profil
    """
    username = current_user["username"]
    
    # Récupérer l'utilisateur actuel
    db_user = await get_user_by_username_db(username)
    
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    
    # Vérifier si l'email est déjà utilisé par un autre utilisateur
    if profile_data.email != db_user.get("email"):
        existing_email = await db_connection.db.users.find_one({
            "email": profile_data.email,
            "username": {"$ne": username}
        })
        if existing_email:
            raise HTTPException(
                status_code=400,
                detail="Cet email est déjà utilisé par un autre utilisateur"
            )
    
    # Validation entreprise pour les admins
    if db_user.get("role") == "admin" and not profile_data.entreprise:
        raise HTTPException(
            status_code=400,
            detail="Le champ Entreprise est obligatoire pour les administrateurs"
        )
    
    # Préparer les données à mettre à jour
    update_data = {
        "nom": profile_data.nom,
        "prenom": profile_data.prenom,
        "email": profile_data.email,
    }
    
    # Ajouter entreprise si fournie
    if profile_data.entreprise:
        update_data["entreprise"] = profile_data.entreprise
    elif db_user.get("role") == "user":
        update_data["entreprise"] = None
    
    # Mettre à jour dans MongoDB
    result = await db_connection.db.users.update_one(
        {"username": username},
        {"$set": update_data}
    )
    
    if result.modified_count == 0 and result.matched_count == 0:
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la mise à jour du profil"
        )
    
    return {
        "message": "Profil mis à jour avec succès",
        "updated_fields": update_data
    }

@app.post("/auth/login-db")
async def login_db(user: UserAuth):
    """Connexion avec MongoDB"""
    db_user = await get_user_by_username_db(user.username)
    
    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )
    
    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect"
        )
    
    token = create_access_token({
        "sub": db_user["username"],
        "role": db_user.get("role", "user")
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(db_user["_id"]),
            "username": db_user["username"],
            "nom": db_user.get("nom", ""),
            "prenom": db_user.get("prenom", ""),
            "email": db_user.get("email", ""),
            "entreprise": db_user.get("entreprise"),
            "role": db_user.get("role", "user"),
            "created_at": db_user.get("created_at")
        }
    }

@app.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    """Récupère les infos de l'utilisateur connecté"""
    db_user = await get_user_by_username_db(current_user["username"])
    
    return {
        "username": db_user["username"],
        "nom": db_user.get("nom", ""),
        "prenom": db_user.get("prenom", ""),
        "email": db_user.get("email", ""),
        "entreprise": db_user.get("entreprise"),
        "role": db_user.get("role", "user")
    }

@app.put("/auth/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user)
):
    """Changement de mot de passe (MongoDB)"""
    
    # Récupérer l'utilisateur depuis MongoDB
    db_user = await get_user_by_username_db(current_user["username"])
    
    if not db_user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    # Vérifier le mot de passe actuel
    if not verify_password(password_data.current_password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")

    # Vérifier que le nouveau mot de passe est différent
    if verify_password(password_data.new_password, db_user["password"]):
        raise HTTPException(
            status_code=400, 
            detail="Le nouveau mot de passe doit être différent de l'ancien"
        )
    
    # Vérifier la longueur du nouveau mot de passe
    if len(password_data.new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Le mot de passe doit contenir au moins 6 caractères"
        )

    # Mettre à jour dans MongoDB
    hashed_password = get_password_hash(password_data.new_password)
    result = await db_connection.db.users.update_one(
        {"username": current_user["username"]},
        {"$set": {"password": hashed_password}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la mise à jour du mot de passe"
        )

    return {"message": "Mot de passe modifié avec succès"}

@app.get("/auth/stats")
async def get_user_stats(current_user: dict = Depends(get_current_user)):
    """
    Récupère les statistiques d'audits de l'utilisateur connecté.
    Utilise une recherche insensible à la casse pour gérer les variations de nom.
    """
    username = current_user["username"]
    
    # Recherche insensible à la casse : match "bankole", "Bankole", "BANKOLE", etc.
    query = {"auteur": {"$regex": f"^{username}$", "$options": "i"}}
    
    # Comptage total des audits de l'utilisateur
    total = await db_connection.db.PFE.count_documents(query)
    
    # Comptage des audits complétés
    completed = await db_connection.db.PFE.count_documents({
        "auteur": {"$regex": f"^{username}$", "$options": "i"},
        "status": "COMPLETED"
    })
    
    # Comptage des audits en cours
    in_progress = await db_connection.db.PFE.count_documents({
        "auteur": {"$regex": f"^{username}$", "$options": "i"},
        "status": "PROCESSING"
    })
    
    return {
        "total": total,
        "completed": completed,
        "in_progress": in_progress
    }

####################
### AUDIT ROUTES ###
####################

import pandas as pd
import io
import uuid
from datetime import datetime
from fastapi import APIRouter, Form, Depends, HTTPException

# ... vos autres imports et dépendances (db_connection, AIService, get_current_user)

@app.post("/audit/add")
async def launch_audit(
    nom: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """
    Crée un nouvel audit en utilisant le fichier local enriched_predictions_report.csv
    """
    file_path = "enriched_predictions_report.csv"
    
    try:
        # Lecture du fichier local
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Le fichier CSV local est introuvable.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la lecture du fichier : {str(e)}")

    audit_id = str(uuid.uuid4())
    username = current_user["username"]

    # Création du document initial
    new_audit = {
        "_id": audit_id,
        "nom": nom,
        "auteur": username,
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "status": "PROCESSING",
        "report_text": {"titre": "", "description": "", "recommandations": ""},
        "created_at": datetime.utcnow()
    }
    
    # Insertion dans la base de données
    await db_connection.db.PFE.insert_one(new_audit)

    # Conversion des données pour l'IA
    data_json = df.to_dict(orient='records')

    # Analyse par l'IA
    analysis = await AIService.generate_structured_analysis(data_json)

    if analysis:
        # Mise à jour avec les résultats
        await db_connection.db.PFE.update_one(
            {"_id": audit_id},
            {
                "$set": {
                    "status": "COMPLETED",
                    "report_text.titre": analysis.get("titre", ""),
                    "report_text.description": analysis.get("description", ""),
                    "report_text.recommandations": analysis.get("recommandations", "")
                }
            }
        )
        return {"status": "success", "audit_id": audit_id, "analysis": analysis}
    
    # En cas d'échec de l'IA, on met à jour le statut en erreur
    await db_connection.db.PFE.update_one(
        {"_id": audit_id},
        {"$set": {"status": "FAILED"}}
    )
    return {"status": "error", "message": "L'analyse a échoué"}

@app.post("/audit/test-stream")
async def test_stream_audit(file: UploadFile = File(...)):
    # 1. Préparation des données
    content = await file.read()
    df = pd.read_csv(io.BytesIO(content))
    data_json = df.to_dict(orient='records')

    # 2. On retourne la réponse en flux continu
    return StreamingResponse(
        AIService.stream_structured_analysis(data_json),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/audits/all")
async def list_all_audits(admin: dict = Depends(get_current_admin)):
    """
    Liste TOUS les audits (réservé aux admins uniquement)
    """
    raw_audits = await db_connection.db.PFE.find().sort("created_at", -1).to_list(length=1000)
    
    cleaned_audits = []
    for audit in raw_audits:
        if "_id" in audit:
            audit["_id"] = str(audit["_id"])
        
        for key, value in audit.items():
            if isinstance(value, bytes):
                audit[key] = value.decode('utf-8', errors='replace')
        
        cleaned_audits.append(audit)

    return jsonable_encoder(cleaned_audits)

@app.get("/audits/my")
async def list_my_audits(current_user: dict = Depends(get_current_user)):
    """
    Liste uniquement MES audits (utilisateur connecté)
    """
    username = current_user["username"]
    
    # Recherche insensible à la casse
    query = {"auteur": {"$regex": f"^{username}$", "$options": "i"}}
    
    raw_audits = await db_connection.db.PFE.find(query).sort("created_at", -1).to_list(length=1000)
    
    cleaned_audits = []
    for audit in raw_audits:
        if "_id" in audit:
            audit["_id"] = str(audit["_id"])
        
        for key, value in audit.items():
            if isinstance(value, bytes):
                audit[key] = value.decode('utf-8', errors='replace')
        
        cleaned_audits.append(audit)

    return jsonable_encoder(cleaned_audits)

@app.get("/audits")
async def list_audits(current_user: dict = Depends(get_current_user)):
    """
    Liste les audits selon le rôle :
    - Admin : TOUS les audits
    - User : Uniquement ses audits
    """
    # Si admin, retourner tous les audits
    if current_user.get("role") == "admin":
        raw_audits = await db_connection.db.PFE.find().sort("created_at", -1).to_list(length=1000)
    else:
        # Sinon, uniquement les audits de l'utilisateur
        username = current_user["username"]
        query = {"auteur": {"$regex": f"^{username}$", "$options": "i"}}
        raw_audits = await db_connection.db.PFE.find(query).sort("created_at", -1).to_list(length=1000)
    
    cleaned_audits = []
    for audit in raw_audits:
        if "_id" in audit:
            audit["_id"] = str(audit["_id"])
        
        for key, value in audit.items():
            if isinstance(value, bytes):
                audit[key] = value.decode('utf-8', errors='replace')
        
        cleaned_audits.append(audit)

    return jsonable_encoder(cleaned_audits)

@app.get("/audit/{id}")
async def get_audit_detail(id: str, current_user: dict = Depends(get_current_user)):
    """
    Récupère les détails d'un audit spécifique
    - Admin : peut voir tous les audits
    - User : peut voir uniquement ses propres audits
    """
    audit = await db_connection.db.PFE.find_one({"_id": id})
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    
    # Vérification des permissions
    if current_user.get("role") != "admin":
        # Si pas admin, vérifier que c'est bien son audit
        username = current_user["username"]
        audit_author = audit.get("auteur", "")
        
        # Comparaison insensible à la casse
        if audit_author.lower() != username.lower():
            raise HTTPException(
                status_code=403, 
                detail="Vous n'avez pas l'autorisation d'accéder à cet audit"
            )
    
    return audit

@app.get("/audit/{id}/status")
async def get_audit_status(id: str, current_user: dict = Depends(get_current_user)):
    """
    Récupère uniquement le statut d'un audit (pour polling)
    """
    audit = await db_connection.db.PFE.find_one({"_id": id}, {"status": 1, "auteur": 1})
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    
    # Vérification des permissions
    if current_user.get("role") != "admin":
        username = current_user["username"]
        audit_author = audit.get("auteur", "")
        
        if audit_author.lower() != username.lower():
            raise HTTPException(
                status_code=403, 
                detail="Vous n'avez pas l'autorisation d'accéder à cet audit"
            )
    
    return {"status": audit.get("status")}

@app.delete("/audit/{id}")
async def delete_audit(id: str, current_user: dict = Depends(get_current_user)):
    """
    Supprime un audit et ses données associées
    - Admin : peut supprimer tous les audits
    - User : peut supprimer uniquement ses propres audits
    """
    audit = await db_connection.db.PFE.find_one({"_id": id})
    
    if not audit:
        raise HTTPException(status_code=404, detail="Audit introuvable")
    
    # Vérification des permissions
    if current_user.get("role") != "admin":
        username = current_user["username"]
        audit_author = audit.get("auteur", "")
        
        if audit_author.lower() != username.lower():
            raise HTTPException(
                status_code=403, 
                detail="Vous n'avez pas l'autorisation de supprimer cet audit"
            )
    
    # Suppression
    res1 = await db_connection.db.PFE.delete_one({"_id": id})
    res2 = await db_connection.db.dataset_raw.delete_many({"audit_id": id})
    
    return {
        "message": f"Audit {id} et ses {res2.deleted_count} lignes de données ont été supprimés."
    }

# ========================================
# ENDPOINT DE DIAGNOSTIC TEMPORAIRE
# ========================================
@app.get("/debug/audit-check")
async def debug_audit_check(current_user: dict = Depends(get_current_user)):
    """
    Diagnostic pour comprendre pourquoi les stats sont à 0
    ⚠️ À SUPPRIMER après résolution
    """
    username = current_user["username"]
    
    # Tous les audits
    all_audits = await db_connection.db.PFE.find().to_list(length=100)
    
    # Analyse
    with_author = [a for a in all_audits if "auteur" in a]
    without_author = [a for a in all_audits if "auteur" not in a]
    
    # Auteurs uniques
    authors_list = list(set([a.get("auteur") for a in with_author if "auteur" in a]))
    
    # Tests de recherche
    exact = await db_connection.db.PFE.count_documents({"auteur": username})
    case_insensitive = await db_connection.db.PFE.count_documents({
        "auteur": {"$regex": f"^{username}$", "$options": "i"}
    })
    
    return {
        "your_username": username,
        "total_audits": len(all_audits),
        "with_author_field": len(with_author),
        "without_author_field": len(without_author),
        "unique_authors": authors_list,
        "match_results": {
            "exact_match": exact,
            "case_insensitive_match": case_insensitive
        },
        "sample_audits": [
            {
                "nom": a.get("nom"),
                "auteur": a.get("auteur", "❌ MANQUANT"),
                "status": a.get("status")
            }
            for a in all_audits[:5]
        ]
    }

@app.post("/admin/fix-audits-author")
async def fix_audits_author(admin: dict = Depends(get_current_admin)):
    """
    Ajoute le champ 'auteur' aux audits qui n'en ont pas
    Utilise le username de l'admin connecté
    """
    username = admin["username"]
    
    # Mettre à jour les audits sans auteur
    result = await db_connection.db.PFE.update_many(
        {"auteur": {"$exists": False}},
        {"$set": {"auteur": username}}
    )
    
    return {
        "message": "Audits corrigés",
        "updated_count": result.modified_count,
        "assigned_to": username
    }

####################
### ADMIN ROUTES ###
####################
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

#  -------------------------
#  ADMIN ROUTES MONGODB 
#  -------------------------

@app.get("/admin/users-db", response_model=List[UserView])
async def list_users_db(admin: dict = Depends(get_current_admin)):
    """Liste tous les utilisateurs depuis MongoDB"""
    users = await get_all_users_db()
    return [
        {
            "username": u["username"],
            "nom": u.get("nom", ""),
            "prenom": u.get("prenom", ""),
            "email": u.get("email", ""),
            "entreprise": u.get("entreprise"),
            "role": u.get("role", "user")
        } 
        for u in users
    ]

@app.post("/admin/users-db", status_code=201)
async def admin_create_user_db(user: UserCreate, admin: dict = Depends(get_current_admin)):
    """Créer un utilisateur depuis l'interface admin (MongoDB)"""
    existing_user = await get_user_by_username_db(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="L'utilisateur existe déjà")
    
    user_id = await create_user_db(
        username=user.username,
        password=user.password,
        nom=user.nom,
        prenom=user.prenom,
        email=user.email,
        entreprise=user.entreprise,
        role=user.role
    )
    return {
        "message": f"Utilisateur {user.prenom} {user.nom} créé avec le rôle {user.role}"
    }

@app.put("/admin/users-db/{username}")
async def update_user_role_db_route(username: str, update: UserUpdate, admin: dict = Depends(get_current_admin)):
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