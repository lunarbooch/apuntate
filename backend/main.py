from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class RegistroAlumno(BaseModel):
    matricula: str
    nombre: str
    correo: str
    password: str

class RegistroProfesor(BaseModel):
    correo: str
    nombre: str
    password: str

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    with open("../database/schema.sql", "r") as f:
        cursor.executescript(f.read())
    
    cursor.execute("SELECT * FROM usuarios WHERE identificador='admin'")
    if not cursor.fetchone():
        hashed_pw = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO usuarios (identificador, correo, nombre_completo, password_hash, rol) VALUES (?, ?, ?, ?, ?)", 
                       ("admin", "admin@apuntate.com", "Administrador Principal", hashed_pw, "admin"))
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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_usuario_actual(token: str = Depends(oauth2_scheme), db: sqlite3.Connection = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    cursor = db.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE identificador=?", (username,))
    usuario = cursor.fetchone()
    if usuario is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return dict(usuario)

@app.get("/")
def leer_index():
    return FileResponse("../frontend/index.html")

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE identificador=?", (form_data.username,))
    usuario = cursor.fetchone()

    if not usuario or not bcrypt.checkpw(form_data.password.encode('utf-8'), usuario["password_hash"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    
    access_token = create_access_token(
        data={"sub": usuario["identificador"], "rol": usuario["rol"]}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer", "rol": usuario["rol"], "nombre": usuario["nombre_completo"]}

@app.post("/api/alumnos/registro")
def registrar_alumno(alumno: RegistroAlumno, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    try:
        hashed_pw = bcrypt.hashpw(alumno.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO usuarios (identificador, correo, nombre_completo, password_hash, rol) VALUES (?, ?, ?, ?, ?)",
                       (alumno.matricula, alumno.correo, alumno.nombre, hashed_pw, "alumno"))
        db.commit()
        return {"mensaje": "Alumno registrado con éxito. Ya puedes iniciar sesión."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="La matrícula o correo ya existen.")

@app.post("/api/profesores")
def registrar_profesor(profesor: RegistroProfesor, current_user: dict = Depends(get_usuario_actual), db: sqlite3.Connection = Depends(get_db)):
    if current_user["rol"] != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores pueden crear profesores.")
    
    cursor = db.cursor()
    try:
        hashed_pw = bcrypt.hashpw(profesor.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO usuarios (identificador, correo, nombre_completo, password_hash, rol) VALUES (?, ?, ?, ?, ?)",
                       (profesor.correo, profesor.correo, profesor.nombre, hashed_pw, "profesor"))
        db.commit()
        return {"mensaje": f"Profesor {profesor.nombre} creado con éxito."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="El correo ya está registrado.")
