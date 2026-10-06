from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import sqlite3
import os

app = FastAPI(title="Apúntate API Segura")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DB_PATH = "../database/apuntate.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    with open("../database/schema.sql", "r") as f:
        cursor.executescript(f.read())
    
    cursor.execute("SELECT * FROM usuarios WHERE identificador='admin'")
    if not cursor.fetchone():
        hashed_pw = pwd_context.hash("admin123")
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

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE identificador=?", (form_data.username,))
    usuario = cursor.fetchone()

    if not usuario or not pwd_context.verify(form_data.password, usuario["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "access_token": "token_generado_proximamente", 
        "token_type": "bearer",
        "rol": usuario["rol"],
        "nombre": usuario["nombre_completo"]
    }
