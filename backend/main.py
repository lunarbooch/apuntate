from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI(title="Apúntate API")

# Ruta para servir la página web
@app.get("/")
def leer_index():
    return FileResponse("../frontend/index.html")

# Ruta de prueba para la API
@app.get("/api/estado")
def estado_api():
    return {"estado": "En línea", "proyecto": "Apúntate"}
