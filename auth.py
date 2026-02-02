import json
import os
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from database import db_connection
# Configuration
SECRET_KEY = "TON_SECRET_TRES_SECURISE" 
ALGORITHM = "HS256"
USERS_FILE = "users.json"

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=8)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Fonction pour valider le token et récupérer l'utilisateur (utilisée par /auth/me)
async def get_current_user(token: str = Depends(oauth2_scheme)):
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
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs"
        )
    return current_user




# ========================================
# AJOUT : Support MongoDB pour les users
# ========================================

async def get_user_by_username_db(username: str):
    """Récupère un utilisateur par son username depuis MongoDB"""
    user = await db_connection.db.users.find_one({"username": username})
    return user

async def create_user_db(username: str, password: str, role: str = "user"):
    """Crée un nouvel utilisateur dans MongoDB"""
    hashed_password = get_password_hash(password)
    new_user = {
        "username": username,
        "password": hashed_password,
        "role": role,
        "created_at": datetime.utcnow()
    }
    result = await db_connection.db.users.insert_one(new_user)
    return result.inserted_id

async def get_all_users_db():
    """Récupère tous les utilisateurs depuis MongoDB (pour l'admin)"""
    users = await db_connection.db.users.find({}, {"password": 0}).to_list(length=100)
    return users

async def update_user_role_db(username: str, role: str):
    """Met à jour le rôle d'un utilisateur dans MongoDB"""
    result = await db_connection.db.users.update_one(
        {"username": username},
        {"$set": {"role": role}}
    )
    return result.modified_count > 0

async def delete_user_db(username: str):
    """Supprime un utilisateur de MongoDB"""
    result = await db_connection.db.users.delete_one({"username": username})
    return result.deleted_count > 0


