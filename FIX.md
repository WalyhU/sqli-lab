# Corrección — commit "DESPUÉS"

Aplicar en la rama `fix/sqli-parametrizado`, sobre `app.py`.

## 1. `login_vulnerable()`

**Antes (vulnerable):**

```python
query = (
    "SELECT id, username, role, email FROM users "
    f"WHERE username = '{username}' AND password = '{password}'"
)
cursor.execute(query)
```

**Después (parametrizado):**

```python
query = (
    "SELECT id, username, role, email FROM users "
    "WHERE username = ? AND password = ?"
)
cursor.execute(query, (username, password))
```

## 2. `users_vulnerable()`

**Antes (vulnerable):**

```python
query = (
    "SELECT id, username, role, email FROM users "
    f"WHERE username LIKE '%{search}%' OR email LIKE '%{search}%' "
    "ORDER BY id"
)
cursor.execute(query)
```

**Después (parametrizado):**

```python
query = (
    "SELECT id, username, role, email FROM users "
    "WHERE username LIKE ? OR email LIKE ? "
    "ORDER BY id"
)
like = f"%{search}%"
cursor.execute(query, (like, like))
```

Nota importante para el reporte: los comodines `%` van **dentro del valor del
parámetro**, no dentro del string SQL. El driver los trata como texto literal,
nunca como sintaxis. Esa es la diferencia estructural: en la versión vulnerable
el input del usuario podía *convertirse en código SQL*; en la parametrizada el
motor recibe la sentencia ya compilada y el input solo puede ser *dato*.

## 3. Renombrar (opcional pero recomendado)

Cambia las rutas `-vulnerable` a nombres neutros (`/api/login`, `/api/users`)
y elimina los duplicados `-safe`, ya que ahora son idénticos. Actualiza
`public/app.js` y `public/index.html` en consecuencia.

## Lo que NO arregla la parametrización

Para la sección de conclusiones de tu informe, vale la pena que digas que
SonarQube seguirá reportando problemas reales que la parametrización no toca:

- **S2068** — contraseñas hardcodeadas en `SEED_USERS`.
- Contraseñas almacenadas en texto plano en la tabla `users` (deberían ser
  hashes con bcrypt/argon2).
- El endpoint `/api/schema` expone credenciales de ejemplo.
- Devolver el SQL ejecutado en la respuesta JSON es *information disclosure*
  (útil en un lab, inaceptable en producción).

Esto demuestra que SAST detecta clases de defecto, no "el bug"; y que
remediar una vulnerabilidad no implica que el componente sea seguro.
