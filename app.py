#!/usr/bin/env python3
"""
CivilPM — Project Manager for Civil Engineering Firms
Flask + SQLite backend for shared multi-user access on a local network.

Usage:
    pip install flask
    python app.py

The app will be accessible at http://<NAS-IP>:5100 from any device on the LAN.
"""

APP_VERSION = "0.1.3"

import os
import sqlite3
import hashlib
import secrets
import json
from datetime import datetime
from functools import wraps
from flask import (
    Flask, request, jsonify, session, send_from_directory, g
)

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'civilpm.db')

# ──────────────────────────────────────────────────
#  DATABASE
# ──────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            name TEXT NOT NULL,
            property_address TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'plan',
            status TEXT NOT NULL DEFAULT 'pending',
            billing_amount INTEGER DEFAULT 0,
            billing_status TEXT NOT NULL DEFAULT 'none',
            sort_order INTEGER DEFAULT 0,
            last_updated_by TEXT DEFAULT '',
            last_updated_at TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS task_history (
            id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
        );
    """)
    # Migrations for existing databases
    cols = [r[1] for r in db.execute("PRAGMA table_info(tasks)").fetchall()]
    if 'billing_amount' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_amount INTEGER DEFAULT 0")
    if 'billing_status' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_status TEXT NOT NULL DEFAULT 'none'")
    if 'sort_order' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN sort_order INTEGER DEFAULT 0")
    db.commit()
    db.close()

def gen_id():
    return secrets.token_hex(8)

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def now_iso():
    return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows]

# ──────────────────────────────────────────────────
#  AUTH MIDDLEWARE
# ──────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autorizado'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not user:
            return jsonify({'error': 'No autorizado'}), 401
        g.user = row_to_dict(user)
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'No autorizado'}), 401
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Se requiere acceso de administrador'}), 403
        g.user = row_to_dict(user)
        return f(*args, **kwargs)
    return decorated

# ──────────────────────────────────────────────────
#  STATIC FILES
# ──────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/version', methods=['GET'])
def get_version():
    return jsonify({'version': APP_VERSION})

# ──────────────────────────────────────────────────
#  AUTH ROUTES
# ──────────────────────────────────────────────────

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    logged_in = False
    user_data = None
    if 'user_id' in session:
        user = db.execute("SELECT id, name, username, role FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if user:
            logged_in = True
            user_data = row_to_dict(user)
    return jsonify({'logged_in': logged_in, 'user': user_data, 'has_users': user_count > 0})

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    name = (data.get('name') or '').strip()
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    if not name or not username or len(password) < 3:
        return jsonify({'error': 'Todos los campos son requeridos (contraseña mínimo 3 caracteres)'}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Ese nombre de usuario ya existe'}), 400

    user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    role = 'admin' if user_count == 0 else 'user'
    uid = gen_id()

    db.execute("INSERT INTO users (id, name, username, password_hash, role, created_at) VALUES (?,?,?,?,?,?)",
               (uid, name, username, hash_password(password), role, now_iso()))
    db.commit()
    return jsonify({'ok': True, 'message': 'Cuenta creada exitosamente'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? AND password_hash=?",
                      (username, hash_password(password))).fetchone()
    if not user:
        return jsonify({'error': 'Usuario o contraseña incorrecta'}), 401
    session['user_id'] = user['id']
    return jsonify({'ok': True, 'user': {'id': user['id'], 'name': user['name'], 'username': user['username'], 'role': user['role']}})

@app.route('/api/auth/logout', methods=['POST'])
def logout_route():
    session.pop('user_id', None)
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  CLIENTS
# ──────────────────────────────────────────────────

@app.route('/api/clients', methods=['GET'])
@login_required
def get_clients():
    db = get_db()
    clients = rows_to_list(db.execute("SELECT * FROM clients ORDER BY name").fetchall())
    for cl in clients:
        cl['project_count'] = db.execute("SELECT COUNT(*) as c FROM projects WHERE client_id=?", (cl['id'],)).fetchone()['c']
    return jsonify(clients)

@app.route('/api/clients', methods=['POST'])
@login_required
def create_client():
    data = request.json
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nombre del cliente es requerido'}), 400
    cid = gen_id()
    db = get_db()
    db.execute("INSERT INTO clients (id, name, email, phone, address, created_at) VALUES (?,?,?,?,?,?)",
               (cid, name, data.get('email','').strip(), data.get('phone','').strip(), data.get('address','').strip(), now_iso()))
    db.commit()
    return jsonify({'ok': True, 'id': cid})

@app.route('/api/clients/<cid>', methods=['GET'])
@login_required
def get_client(cid):
    db = get_db()
    cl = row_to_dict(db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone())
    if not cl:
        return jsonify({'error': 'Cliente no encontrado'}), 404
    cl['projects'] = rows_to_list(db.execute("SELECT * FROM projects WHERE client_id=? ORDER BY created_at DESC", (cid,)).fetchall())
    for pr in cl['projects']:
        total = db.execute("SELECT COUNT(*) as c FROM tasks WHERE project_id=?", (pr['id'],)).fetchone()['c']
        done = db.execute("SELECT COUNT(*) as c FROM tasks WHERE project_id=? AND status='completed'", (pr['id'],)).fetchone()['c']
        pr['task_count'] = total
        pr['done_count'] = done
    return jsonify(cl)

@app.route('/api/clients/<cid>', methods=['PUT'])
@login_required
def update_client(cid):
    data = request.json
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nombre del cliente es requerido'}), 400
    db = get_db()
    db.execute("UPDATE clients SET name=?, email=?, phone=?, address=? WHERE id=?",
               (name, data.get('email','').strip(), data.get('phone','').strip(), data.get('address','').strip(), cid))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/clients/<cid>', methods=['DELETE'])
@login_required
def delete_client(cid):
    db = get_db()
    db.execute("DELETE FROM clients WHERE id=?", (cid,))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  PROJECTS
# ──────────────────────────────────────────────────

@app.route('/api/projects', methods=['POST'])
@login_required
def create_project():
    data = request.json
    client_id = data.get('client_id')
    name = (data.get('name') or '').strip()
    if not name or not client_id:
        return jsonify({'error': 'Nombre y cliente son requeridos'}), 400

    pid = gen_id()
    db = get_db()
    db.execute("INSERT INTO projects (id, client_id, name, property_address, created_at) VALUES (?,?,?,?,?)",
               (pid, client_id, name, data.get('property_address','').strip(), now_iso()))

    # Create tasks from selected items
    tasks = data.get('tasks', [])
    for i, t in enumerate(tasks):
        tid = gen_id()
        db.execute("INSERT INTO tasks (id, project_id, name, category, status, sort_order, created_at) VALUES (?,?,?,?,?,?,?)",
                   (tid, pid, t['name'], t.get('category', 'plan'), 'pending', i, now_iso()))
    db.commit()
    return jsonify({'ok': True, 'id': pid})

@app.route('/api/projects/<pid>', methods=['GET'])
@login_required
def get_project(pid):
    db = get_db()
    pr = row_to_dict(db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
    if not pr:
        return jsonify({'error': 'Proyecto no encontrado'}), 404
    cl = row_to_dict(db.execute("SELECT id, name FROM clients WHERE id=?", (pr['client_id'],)).fetchone())
    pr['client'] = cl
    pr['tasks'] = rows_to_list(db.execute("SELECT * FROM tasks WHERE project_id=? ORDER BY category, sort_order, created_at", (pid,)).fetchall())
    for t in pr['tasks']:
        t['notes'] = rows_to_list(db.execute("SELECT * FROM notes WHERE task_id=? ORDER BY created_at DESC", (t['id'],)).fetchall())
    # Project-level activity log
    pr['log'] = rows_to_list(db.execute("""
        SELECT h.*, t.name as task_name FROM task_history h
        JOIN tasks t ON h.task_id = t.id
        WHERE t.project_id=?
        ORDER BY h.created_at DESC LIMIT 50
    """, (pid,)).fetchall())
    return jsonify(pr)

@app.route('/api/projects/<pid>', methods=['DELETE'])
@login_required
def delete_project(pid):
    db = get_db()
    db.execute("DELETE FROM projects WHERE id=?", (pid,))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  TASKS
# ──────────────────────────────────────────────────

@app.route('/api/tasks', methods=['POST'])
@login_required
def create_task():
    data = request.json
    project_id = data.get('project_id')
    name = (data.get('name') or '').strip()
    category = data.get('category', 'plan')
    if not name or not project_id:
        return jsonify({'error': 'Nombre y proyecto son requeridos'}), 400
    tid = gen_id()
    db = get_db()
    max_order = db.execute("SELECT COALESCE(MAX(sort_order),0) FROM tasks WHERE project_id=? AND category=?", (project_id, category)).fetchone()[0]
    db.execute("INSERT INTO tasks (id, project_id, name, category, status, sort_order, created_at) VALUES (?,?,?,?,?,?,?)",
               (tid, project_id, name, category, 'pending', max_order + 1, now_iso()))
    db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
               (gen_id(), tid, g.user['name'], 'creó tarea', name, now_iso()))
    db.commit()
    return jsonify({'ok': True, 'id': tid})

@app.route('/api/tasks/<tid>/status', methods=['PUT'])
@login_required
def update_task_status(tid):
    data = request.json
    new_status = data.get('status', 'pending')
    db = get_db()
    old = row_to_dict(db.execute("SELECT status FROM tasks WHERE id=?", (tid,)).fetchone())
    status_labels = {'pending':'Pendiente','in-progress':'En Progreso','completed':'Completada','blocked':'Bloqueada'}
    db.execute("UPDATE tasks SET status=?, last_updated_by=?, last_updated_at=? WHERE id=?",
               (new_status, g.user['name'], now_iso(), tid))
    db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
               (gen_id(), tid, g.user['name'], 'cambió estado',
                f"{status_labels.get(old['status'] if old else '','?')} → {status_labels.get(new_status,'?')}", now_iso()))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/tasks/<tid>', methods=['DELETE'])
@login_required
def delete_task(tid):
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id=?", (tid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/tasks/<tid>/history', methods=['GET'])
@login_required
def get_task_history(tid):
    db = get_db()
    history = rows_to_list(db.execute("SELECT * FROM task_history WHERE task_id=? ORDER BY created_at DESC", (tid,)).fetchall())
    return jsonify(history)

@app.route('/api/tasks/<tid>/billing', methods=['PUT'])
@login_required
def update_task_billing(tid):
    data = request.json
    db = get_db()
    old = row_to_dict(db.execute("SELECT billing_amount, billing_status FROM tasks WHERE id=?", (tid,)).fetchone())
    new_amount = int(data.get('billing_amount', 0))
    new_status = data.get('billing_status', 'none')
    db.execute("UPDATE tasks SET billing_amount=?, billing_status=?, last_updated_by=?, last_updated_at=? WHERE id=?",
               (new_amount, new_status, g.user['name'], now_iso(), tid))
    billing_labels = {'none':'No Facturado','invoiced':'Facturado-Esperando Pago','paid':'Pagado'}
    details = []
    if old and old['billing_amount'] != new_amount:
        details.append(f"monto ${old['billing_amount']:,} → ${new_amount:,}")
    if old and old['billing_status'] != new_status:
        details.append(f"{billing_labels.get(old['billing_status'],'?')} → {billing_labels.get(new_status,'?')}")
    if details:
        db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
                   (gen_id(), tid, g.user['name'], 'cambió facturación', ', '.join(details), now_iso()))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/tasks/<tid>/reorder', methods=['PUT'])
@login_required
def reorder_task(tid):
    data = request.json
    direction = data.get('direction')  # 'up' or 'down'
    db = get_db()
    task = row_to_dict(db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone())
    if not task:
        return jsonify({'error': 'Tarea no encontrada'}), 404
    siblings = rows_to_list(db.execute(
        "SELECT id, sort_order FROM tasks WHERE project_id=? AND category=? ORDER BY sort_order, created_at",
        (task['project_id'], task['category'])).fetchall())
    # Normalize sort_order to sequential indices first
    for i, s in enumerate(siblings):
        db.execute("UPDATE tasks SET sort_order=? WHERE id=?", (i, s['id']))
    idx = next((i for i, s in enumerate(siblings) if s['id'] == tid), -1)
    swap_idx = idx - 1 if direction == 'up' else idx + 1
    if swap_idx < 0 or swap_idx >= len(siblings):
        db.commit()
        return jsonify({'ok': True})
    db.execute("UPDATE tasks SET sort_order=? WHERE id=?", (swap_idx, tid))
    db.execute("UPDATE tasks SET sort_order=? WHERE id=?", (idx, siblings[swap_idx]['id']))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/history/<hid>', methods=['DELETE'])
@admin_required
def delete_history_entry(hid):
    db = get_db()
    db.execute("DELETE FROM task_history WHERE id=?", (hid,))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  NOTES
# ──────────────────────────────────────────────────

@app.route('/api/notes', methods=['POST'])
@login_required
def create_note():
    data = request.json
    task_id = data.get('task_id')
    text = (data.get('text') or '').strip()
    if not text or not task_id:
        return jsonify({'error': 'Texto y tarea son requeridos'}), 400
    nid = gen_id()
    db = get_db()
    ts = now_iso()
    db.execute("INSERT INTO notes (id, task_id, text, author, created_at) VALUES (?,?,?,?,?)",
               (nid, task_id, text, g.user['name'], ts))
    db.execute("UPDATE tasks SET last_updated_by=?, last_updated_at=? WHERE id=?",
               (g.user['name'], ts, task_id))
    db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
               (gen_id(), task_id, g.user['name'], 'añadió nota', text[:100], ts))
    db.commit()
    return jsonify({'ok': True, 'id': nid})

# ──────────────────────────────────────────────────
#  ADMIN
# ──────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    db = get_db()
    users = rows_to_list(db.execute("SELECT id, name, username, role, created_at FROM users ORDER BY created_at").fetchall())
    return jsonify(users)

@app.route('/api/admin/reset-password', methods=['POST'])
@admin_required
def reset_password():
    data = request.json
    user_id = data.get('user_id')
    new_pass = data.get('new_password', '')
    if len(new_pass) < 3:
        return jsonify({'error': 'La contraseña debe tener al menos 3 caracteres'}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_pass), user_id))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  DASHBOARD STATS
# ──────────────────────────────────────────────────

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    db = get_db()
    stats = {
        'clients': db.execute("SELECT COUNT(*) as c FROM clients").fetchone()['c'],
        'projects': db.execute("SELECT COUNT(*) as c FROM projects").fetchone()['c'],
        'tasks_total': db.execute("SELECT COUNT(*) as c FROM tasks").fetchone()['c'],
        'tasks_completed': db.execute("SELECT COUNT(*) as c FROM tasks WHERE status='completed'").fetchone()['c'],
        'tasks_pending': db.execute("SELECT COUNT(*) as c FROM tasks WHERE status='pending'").fetchone()['c'],
        'tasks_in_progress': db.execute("SELECT COUNT(*) as c FROM tasks WHERE status='in-progress'").fetchone()['c'],
        'tasks_blocked': db.execute("SELECT COUNT(*) as c FROM tasks WHERE status='blocked'").fetchone()['c'],
    }
    recent = rows_to_list(db.execute("""
        SELECT n.*, t.name as task_name, p.name as project_name, c.name as client_name
        FROM notes n
        JOIN tasks t ON n.task_id = t.id
        JOIN projects p ON t.project_id = p.id
        JOIN clients c ON p.client_id = c.id
        ORDER BY n.created_at DESC LIMIT 8
    """).fetchall())
    stats['recent_notes'] = recent
    return jsonify(stats)

# ──────────────────────────────────────────────────
#  RUN
# ──────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print("\n╔══════════════════════════════════════════════╗")
    print("║         CivilPM — Gestor de Proyectos        ║")
    print("║                                               ║")
    print("║   Servidor activo en: http://0.0.0.0:5100     ║")
    print("║   Acceda desde cualquier equipo en la red     ║")
    print("║   usando la IP de este equipo, puerto 5100    ║")
    print("║                                               ║")
    print("╚══════════════════════════════════════════════╝\n")
    app.run(host='0.0.0.0', port=5100, debug=True, use_reloader=True)
