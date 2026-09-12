"""
SQL Injection Lab - Laboratorio academico local.

ESTADO: CORREGIDO (commit "despues" para el analisis SAST).
Los endpoints *-vulnerable ahora usan consultas parametrizadas; se
mantienen los nombres de ruta para comparar el mismo sink antes/despues.

Ejecutar solo en localhost. No desplegar.
"""

from pathlib import Path
import os
import sqlite3

from flask import Flask, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
DB_PATH = ROOT / "sqli_lab.db"

# NOTA: SonarQube marcara esto como S2068 (hardcoded credentials).
# Es intencional: son datos semilla del laboratorio, no credenciales reales.
SEED_USERS = [
    ("admin", "admin123", "admin", "admin@example.test"),
    ("ana", "pass123", "qa", "ana@example.test"),
    ("carlos", "hunter2", "developer", "carlos@example.test"),
    ("maria", "letmein", "analyst", "maria@example.test"),
]

app = Flask(__name__, static_folder=None)


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def reset_database():
    with get_connection() as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL
            );
            """
        )
        conn.executemany(
            "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
            SEED_USERS,
        )


def rows_to_dicts(rows):
    return [dict(row) for row in rows]


# --------------------------------------------------------------------------
# Frontend estatico
# --------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(PUBLIC_DIR, filename)


# --------------------------------------------------------------------------
# ENDPOINTS VULNERABLES  ->  deben ser detectados por S3649
# --------------------------------------------------------------------------
@app.post("/api/login-vulnerable")
def login_vulnerable():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")   # <-- TAINT SOURCE
    password = payload.get("password", "")   # <-- TAINT SOURCE

    # CORREGIDO: consulta parametrizada, el input nunca se interpreta como SQL.
    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username = ? AND password = ?"
    )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()

    return jsonify(
        ok=bool(user),
        mode="vulnerable",
        query=query,
        user=dict(user) if user else None,
    )


@app.get("/api/users-vulnerable")
def users_vulnerable():
    search = request.args.get("q", "")        # <-- TAINT SOURCE

    # CORREGIDO: parametros con marcadores de posicion, no texto interpolado.
    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username LIKE ? OR email LIKE ? "
        "ORDER BY id"
    )
    like = f"%{search}%"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, (like, like))
    rows = cursor.fetchall()
    conn.close()

    return jsonify(
        ok=True,
        mode="vulnerable",
        query=query,
        count=len(rows),
        users=rows_to_dicts(rows),
    )


# --------------------------------------------------------------------------
# ENDPOINTS SEGUROS  ->  Sonar NO debe marcarlos (control de falsos positivos)
# --------------------------------------------------------------------------
@app.post("/api/login-safe")
def login_safe():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")

    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username = ? AND password = ?"
    )

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()

    return jsonify(
        ok=bool(user),
        mode="safe",
        query=query,
        params=[username, password],
        user=dict(user) if user else None,
    )


@app.get("/api/users-safe")
def users_safe():
    search = request.args.get("q", "")

    query = (
        "SELECT id, username, role, email FROM users "
        "WHERE username LIKE ? OR email LIKE ? "
        "ORDER BY id"
    )
    like = f"%{search}%"

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query, (like, like))
    rows = cursor.fetchall()
    conn.close()

    return jsonify(
        ok=True,
        mode="safe",
        query=query,
        params=[like, like],
        count=len(rows),
        users=rows_to_dicts(rows),
    )


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------
@app.get("/api/schema")
def schema():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    conn.close()

    return jsonify(
        table="users",
        columns=rows_to_dicts(columns),
        sample_users=[{"username": u[0], "password": u[1]} for u in SEED_USERS],
    )


@app.post("/api/reset")
def reset():
    reset_database()
    return jsonify(ok=True, message="Base de datos reiniciada.")


@app.errorhandler(sqlite3.Error)
def handle_sqlite_error(exc):
    return jsonify(ok=False, error=str(exc)), 400


def main():
    if not DB_PATH.exists():
        reset_database()
    port = int(os.environ.get("PORT", "8000"))
    print(f"SQL Injection Lab listo en http://127.0.0.1:{port}")
    print("Usalo solo como laboratorio local/controlado.")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
