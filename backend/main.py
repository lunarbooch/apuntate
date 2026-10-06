from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3
import bcrypt
import os

app = FastAPI(title="Apúntate API Segura")

SECRET_KEY = "apuntate_secreto_super_seguro_2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DB_PATH = "../database/apuntate.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    with open("../database/schema.sql", "r") as f:
        cursor.executescript(f.read())
    
    cursor.execute("SELECT * FROM usuarios WHERE identificador='admin'")
    if not cursor.fetchone():
        # Encriptación directa con bcrypt
        hashed_pw = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO usuarios (identificador, nombre_completo, password_hash, rol) VALUES (?, ?, ?, ?)", 
                       ("admin", "Administrador Principal", hashed_pw, "admin"))
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE identificador=?", (form_data.username,))
    usuario = cursor.fetchone()

    # Validación directa con bcrypt
    if not usuario or not bcrypt.checkpw(form_data.password.encode('utf-8'), usuario["password_hash"].encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": usuario["identificador"], "rol": usuario["rol"]}, 
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "rol": usuario["rol"],
        "nombre": usuario["nombre_completo"]
    }
