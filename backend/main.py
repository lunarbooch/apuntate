from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import sqlite3
import os

app = FastAPI(title="Apúntate API Segura")

# Configuración del Token JWT
SECRET_KEY = "apuntate_secreto_super_seguro_2026" # Clave maestra para firmar los tokens
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # El token expirará en 1 hora

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

# Función que empaqueta y encripta los datos en un Token
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

    # Verificamos que el usuario exista y que Bcrypt valide la contraseña
    if not usuario or not pwd_context.verify(form_data.password, usuario["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Creamos el token inyectando el identificador y el rol
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
