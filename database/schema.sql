CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identificador TEXT UNIQUE NOT NULL,
    nombre_completo TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK(rol IN ('admin', 'profesor', 'alumno')),
    activo BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS materias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    tolerancia_minutos INTEGER NOT NULL,
    profesor_id INTEGER,
    FOREIGN KEY(profesor_id) REFERENCES usuarios(id)
);

CREATE TABLE IF NOT EXISTS sesiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    materia_id INTEGER NOT NULL,
    fecha_hora DATETIME DEFAULT CURRENT_TIMESTAMP,
    codigo_qr TEXT UNIQUE NOT NULL,
    FOREIGN KEY(materia_id) REFERENCES materias(id)
);

CREATE TABLE IF NOT EXISTS asistencias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sesion_id INTEGER NOT NULL,
    alumno_id INTEGER NOT NULL,
    hora_llegada DATETIME DEFAULT CURRENT_TIMESTAMP,
    estatus TEXT NOT NULL CHECK(estatus IN ('Asistencia', 'Retardo', 'Falta')),
    FOREIGN KEY(sesion_id) REFERENCES sesiones(id),
    FOREIGN KEY(alumno_id) REFERENCES usuarios(id)
);
