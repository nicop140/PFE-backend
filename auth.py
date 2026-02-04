import json
import os
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from database import db_connection

# -------------------------
# CONFIGURATION
# -------------------------
SECRET_KEY = "TON_SECRET_TRES_SECURISE"  # ⚠️ Changez cette clé en production !
ALGORITHM = "HS256"
USERS_FILE = "users.json"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# -------------------------
# FONCTIONS FICHIER JSON (Legacy)
# -------------------------
def load_users():
    """Charge les utilisateurs depuis users.json (legacy)"""
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    """Sauvegarde les utilisateurs dans users.json (legacy)"""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

# -------------------------
# FONCTIONS DE HACHAGE
# -------------------------
def get_password_hash(password):
    """Hash un mot de passe en clair"""
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """Vérifie qu'un mot de passe correspond au hash"""
    return pwd_context.verify(plain_password, hashed_password)

# -------------------------
# GESTION DES TOKENS JWT
# -------------------------
def create_access_token(data: dict):
    """Crée un token JWT avec expiration de 8 heures"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=8)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -------------------------
# DÉPENDANCES POUR ROUTES PROTÉGÉES
# -------------------------
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Valide le token JWT et retourne l'utilisateur connecté.
    Utilisé par toutes les routes protégées.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return {"username": username, "role": payload.get("role")}
    except JWTError:
        raise credentials_exception
    
async def get_current_admin(current_user: dict = Depends(get_current_user)):
    """
    Vérifie que l'utilisateur connecté est un administrateur.
    Utilisé pour protéger les routes admin.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs"
        )
    return current_user

# ========================================
# FONCTIONS MONGODB POUR GESTION USERS
# ========================================

async def get_user_by_username_db(username: str):
    """
    Récupère un utilisateur par son username depuis MongoDB.
    Retourne le document complet ou None si introuvable.
    """
    user = await db_connection.db.users.find_one({"username": username})
    return user

async def create_user_db(
    username: str, 
    password: str, 
    nom: str, 
    prenom: str,
    email: str,
    entreprise: str = None,
    role: str = "user"
):
    """
    Crée un nouvel utilisateur dans MongoDB avec tous les champs requis.
    
    Args:
        username: Nom d'utilisateur unique
        password: Mot de passe en clair (sera hashé)
        nom: Nom de famille
        prenom: Prénom
        email: Adresse email
        entreprise: Nom de l'entreprise (optionnel, requis pour admin)
        role: Rôle de l'utilisateur (user/admin)
    
    Returns:
        ObjectId: ID du document inséré
    """
    hashed_password = get_password_hash(password)
    new_user = {
        "username": username,
        "password": hashed_password,
        "nom": nom,
        "prenom": prenom,
        "email": email,
        "role": role,
        "created_at": datetime.utcnow()
    }
    
    # Ajouter entreprise seulement si fournie
    if entreprise:
        new_user["entreprise"] = entreprise
    
    result = await db_connection.db.users.insert_one(new_user)
    return result.inserted_id

async def get_all_users_db():
    """
    Récupère tous les utilisateurs depuis MongoDB (sans les mots de passe).
    Utilisé par l'interface admin.
    """
    users = await db_connection.db.users.find({}, {"password": 0}).to_list(length=100)
    return users

async def update_user_role_db(username: str, role: str):
    """
    Met à jour le rôle d'un utilisateur dans MongoDB.
    Retourne True si la modification a réussi, False sinon.
    """
    result = await db_connection.db.users.update_one(
        {"username": username},
        {"$set": {"role": role}}
    )
    return result.modified_count > 0

async def delete_user_db(username: str):
    """
    Supprime un utilisateur de MongoDB.
    Retourne True si la suppression a réussi, False sinon.
    """
    result = await db_connection.db.users.delete_one({"username": username})
    return result.deleted_count > 0

async def get_user_by_email_db(email: str):
    """
    Récupère un utilisateur par son email depuis MongoDB.
    Retourne le document complet ou None si introuvable.
    """
    user = await db_connection.db.users.find_one({"email": email})
    return user