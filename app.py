#!/usr/bin/env python3
"""
CivilPM — Project Manager for Civil Engineering Firms
Flask + SQLite backend for shared multi-user access on a local network.

Usage:
    pip install flask
    python app.py

The app will be accessible at http://<NAS-IP>:5100 from any device on the LAN.
"""

APP_VERSION = "1.0.5"

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
_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
if os.path.exists(_key_file):
    with open(_key_file) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_key_file, 'w') as f:
        f.write(app.secret_key)
app.permanent_session_lifetime = 60 * 60 * 24 * 30  # 30 days

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
            billing_label TEXT DEFAULT '',
            billing_amount2 INTEGER DEFAULT 0,
            billing_status2 TEXT NOT NULL DEFAULT 'none',
            billing_label2 TEXT DEFAULT '',
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

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_name TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            project_id TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS project_notes (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
        );
    """)
    # Default settings
    existing = db.execute("SELECT key FROM settings WHERE key='registration_open'").fetchone()
    if not existing:
        db.execute("INSERT INTO settings (key, value) VALUES ('registration_open', '1')")
    # Migrations for existing databases
    cols = [r[1] for r in db.execute("PRAGMA table_info(tasks)").fetchall()]
    if 'billing_amount' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_amount INTEGER DEFAULT 0")
    if 'billing_status' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_status TEXT NOT NULL DEFAULT 'none'")
    if 'billing_label' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_label TEXT DEFAULT ''")
    if 'billing_amount2' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_amount2 INTEGER DEFAULT 0")
    if 'billing_status2' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_status2 TEXT NOT NULL DEFAULT 'none'")
    if 'billing_label2' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN billing_label2 TEXT DEFAULT ''")
    if 'sort_order' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN sort_order INTEGER DEFAULT 0")
    if 'paid_date1' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN paid_date1 TEXT DEFAULT ''")
    if 'paid_date2' not in cols:
        db.execute("ALTER TABLE tasks ADD COLUMN paid_date2 TEXT DEFAULT ''")
    proj_cols = [r[1] for r in db.execute("PRAGMA table_info(projects)").fetchall()]
    if 'catastro' not in proj_cols:
        db.execute("ALTER TABLE projects ADD COLUMN catastro TEXT DEFAULT ''")
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
    reg_open = db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()
    registration_open = (reg_open['value'] == '1') if reg_open else True
    return jsonify({'logged_in': logged_in, 'user': user_data, 'has_users': user_count > 0, 'registration_open': registration_open})

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    name = (data.get('name') or '').strip()
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    if not name or not username or len(password) < 3:
        return jsonify({'error': 'Todos los campos son requeridos (contraseña mínimo 3 caracteres)'}), 400

    db = get_db()
    user_count = db.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    if user_count > 0:
        reg_open = db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()
        if reg_open and reg_open['value'] != '1':
            return jsonify({'error': 'El registro de nuevas cuentas está deshabilitado'}), 403
    existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Ese nombre de usuario ya existe'}), 400
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
    session.permanent = True
    session['user_id'] = user['id']
    return jsonify({'ok': True, 'user': {'id': user['id'], 'name': user['name'], 'username': user['username'], 'role': user['role']}})

@app.route('/api/auth/zoom', methods=['GET'])
@login_required
def get_zoom():
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (f"zoom_{g.user['id']}",)).fetchone()
    return jsonify({'zoom': float(row['value']) if row else 1.0})

@app.route('/api/auth/zoom', methods=['PUT'])
@login_required
def set_zoom():
    data = request.json
    zoom = max(0.5, min(4.0, float(data.get('zoom', 1.0))))
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (f"zoom_{g.user['id']}", str(zoom)))
    db.commit()
    return jsonify({'ok': True, 'zoom': zoom})

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
    cl['projects'] = rows_to_list(db.execute("SELECT * FROM projects WHERE client_id=? ORDER BY name COLLATE NOCASE", (cid,)).fetchall())
    for pr in cl['projects']:
        total = db.execute("SELECT COUNT(*) as c FROM tasks WHERE project_id=?", (pr['id'],)).fetchone()['c']
        done = db.execute("SELECT COUNT(*) as c FROM tasks WHERE project_id=? AND status='completed'", (pr['id'],)).fetchone()['c']
        pr['task_count'] = total
        pr['done_count'] = done
    # Client billing summary
    billing = db.execute("""
        SELECT
            COALESCE(SUM(t.billing_amount), 0) + COALESCE(SUM(t.billing_amount2), 0) as total,
            COALESCE(SUM(CASE WHEN t.billing_status='none' THEN t.billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN t.billing_status2='none' THEN t.billing_amount2 ELSE 0 END), 0) as not_billed,
            COALESCE(SUM(CASE WHEN t.billing_status='invoiced' THEN t.billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN t.billing_status2='invoiced' THEN t.billing_amount2 ELSE 0 END), 0) as invoiced,
            COALESCE(SUM(CASE WHEN t.billing_status='paid' THEN t.billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN t.billing_status2='paid' THEN t.billing_amount2 ELSE 0 END), 0) as paid
        FROM tasks t
        JOIN projects p ON t.project_id = p.id
        WHERE p.client_id=?
    """, (cid,)).fetchone()
    cl['billing'] = {
        'total': billing['total'],
        'not_billed': billing['not_billed'],
        'invoiced': billing['invoiced'],
        'paid': billing['paid']
    }
    # Yearly payment breakdown for this client
    yearly_rows = rows_to_list(db.execute("""
        SELECT
            year,
            SUM(amount) as total
        FROM (
            SELECT SUBSTR(t.paid_date1, 1, 4) as year, t.billing_amount as amount FROM tasks t
            JOIN projects p ON t.project_id = p.id WHERE p.client_id=? AND t.billing_status='paid' AND t.paid_date1 != ''
            UNION ALL
            SELECT SUBSTR(t.paid_date2, 1, 4) as year, t.billing_amount2 as amount FROM tasks t
            JOIN projects p ON t.project_id = p.id WHERE p.client_id=? AND t.billing_status2='paid' AND t.paid_date2 != ''
        )
        WHERE year != ''
        GROUP BY year
        ORDER BY year DESC
    """, (cid, cid)).fetchall())
    cl['billing']['yearly'] = yearly_rows
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
    db.execute("INSERT INTO projects (id, client_id, name, property_address, catastro, created_at) VALUES (?,?,?,?,?,?)",
               (pid, client_id, name, data.get('property_address','').strip(), data.get('catastro','').strip(), now_iso()))

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
    # Project-level general notes
    pr['project_notes'] = rows_to_list(db.execute("SELECT * FROM project_notes WHERE project_id=? ORDER BY created_at DESC", (pid,)).fetchall())
    # Project-level activity log (task history + project notes combined)
    task_log = rows_to_list(db.execute("""
        SELECT h.id, h.user_name, h.action, h.detail, h.created_at, t.name as task_name FROM task_history h
        JOIN tasks t ON h.task_id = t.id
        WHERE t.project_id=?
    """, (pid,)).fetchall())
    note_log = rows_to_list(db.execute("""
        SELECT id, author as user_name, 'añadió nota general' as action, text as detail, created_at, 'Proyecto' as task_name
        FROM project_notes WHERE project_id=?
    """, (pid,)).fetchall())
    combined = task_log + note_log
    combined.sort(key=lambda x: x['created_at'], reverse=True)
    pr['log'] = combined[:50]
    return jsonify(pr)

@app.route('/api/projects/<pid>', methods=['PUT'])
@login_required
def update_project(pid):
    data = request.json
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Nombre es requerido'}), 400
    db = get_db()
    db.execute("UPDATE projects SET name=?, property_address=?, catastro=? WHERE id=?",
               (name, (data.get('property_address') or '').strip(), (data.get('catastro') or '').strip(), pid))
    db.commit()
    return jsonify({'ok': True})

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
    task = row_to_dict(db.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone())
    status_labels = {'pending':'Pendiente','in-progress':'En Progreso','completed':'Completada'}
    db.execute("UPDATE tasks SET status=?, last_updated_by=?, last_updated_at=? WHERE id=?",
               (new_status, g.user['name'], now_iso(), tid))
    detail = f"{status_labels.get(task['status'] if task else '','?')} → {status_labels.get(new_status,'?')}"
    db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
               (gen_id(), tid, g.user['name'], 'cambió estado', detail, now_iso()))
    create_notification(db, g.user['name'], 'cambió estado', f"{task['name']}: {detail}", task['project_id'])
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
    old = row_to_dict(db.execute("SELECT billing_amount, billing_status, billing_label, billing_amount2, billing_status2, billing_label2, paid_date1, paid_date2 FROM tasks WHERE id=?", (tid,)).fetchone())
    new_amount = int(data.get('billing_amount', 0))
    new_status = data.get('billing_status', 'none')
    new_label = (data.get('billing_label') or '').strip()
    new_amount2 = int(data.get('billing_amount2', 0))
    new_status2 = data.get('billing_status2', 'none')
    new_label2 = (data.get('billing_label2') or '').strip()
    # Handle paid dates: keep date if paid, clear if not
    new_paid_date1 = (data.get('paid_date1') or '').strip() if new_status == 'paid' else ''
    new_paid_date2 = (data.get('paid_date2') or '').strip() if new_status2 == 'paid' else ''
    db.execute("UPDATE tasks SET billing_amount=?, billing_status=?, billing_label=?, billing_amount2=?, billing_status2=?, billing_label2=?, paid_date1=?, paid_date2=?, last_updated_by=?, last_updated_at=? WHERE id=?",
               (new_amount, new_status, new_label, new_amount2, new_status2, new_label2, new_paid_date1, new_paid_date2, g.user['name'], now_iso(), tid))
    billing_labels = {'none':'No Facturado','invoiced':'Facturado-Esperando Pago','paid':'Pagado'}
    details = []
    if old and old['billing_amount'] != new_amount:
        details.append(f"monto1 ${old['billing_amount']:,} → ${new_amount:,}")
    if old and old['billing_status'] != new_status:
        details.append(f"status1 {billing_labels.get(old['billing_status'],'?')} → {billing_labels.get(new_status,'?')}")
    if old and old.get('billing_amount2', 0) != new_amount2:
        details.append(f"monto2 ${old.get('billing_amount2', 0):,} → ${new_amount2:,}")
    if old and old.get('billing_status2', 'none') != new_status2:
        details.append(f"status2 {billing_labels.get(old.get('billing_status2','none'),'?')} → {billing_labels.get(new_status2,'?')}")
    if details:
        task = row_to_dict(db.execute("SELECT name, project_id FROM tasks WHERE id=?", (tid,)).fetchone())
        db.execute("INSERT INTO task_history (id, task_id, user_name, action, detail, created_at) VALUES (?,?,?,?,?,?)",
                   (gen_id(), tid, g.user['name'], 'cambió facturación', ', '.join(details), now_iso()))
        create_notification(db, g.user['name'], 'cambió facturación', f"{task['name']}: {', '.join(details)}", task['project_id'])
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
    task = row_to_dict(db.execute("SELECT name, project_id FROM tasks WHERE id=?", (task_id,)).fetchone())
    create_notification(db, g.user['name'], 'añadió nota', f"{task['name']}: {text[:80]}", task['project_id'])
    db.commit()
    return jsonify({'ok': True, 'id': nid})

@app.route('/api/notes/<nid>', methods=['DELETE'])
@login_required
def delete_note(nid):
    db = get_db()
    note = row_to_dict(db.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone())
    if not note:
        return jsonify({'error': 'Nota no encontrada'}), 404
    if note['author'] != g.user['name'] and g.user['role'] != 'admin':
        return jsonify({'error': 'Solo puedes eliminar tus propias notas'}), 403
    db.execute("DELETE FROM notes WHERE id=?", (nid,))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  PROJECT NOTES (Notas Generales)
# ──────────────────────────────────────────────────

@app.route('/api/projects/<pid>/notes', methods=['GET'])
@login_required
def get_project_notes(pid):
    db = get_db()
    notes = rows_to_list(db.execute("SELECT * FROM project_notes WHERE project_id=? ORDER BY created_at DESC", (pid,)).fetchall())
    return jsonify(notes)

@app.route('/api/projects/<pid>/notes', methods=['POST'])
@login_required
def create_project_note(pid):
    data = request.json
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'Texto es requerido'}), 400
    db = get_db()
    pr = row_to_dict(db.execute("SELECT name FROM projects WHERE id=?", (pid,)).fetchone())
    if not pr:
        return jsonify({'error': 'Proyecto no encontrado'}), 404
    nid = gen_id()
    ts = now_iso()
    db.execute("INSERT INTO project_notes (id, project_id, text, author, created_at) VALUES (?,?,?,?,?)",
               (nid, pid, text, g.user['name'], ts))
    create_notification(db, g.user['name'], 'añadió nota general', f"{pr['name']}: {text[:80]}", pid)
    db.commit()
    return jsonify({'ok': True, 'id': nid})

@app.route('/api/project-notes/<nid>', methods=['DELETE'])
@login_required
def delete_project_note(nid):
    db = get_db()
    note = row_to_dict(db.execute("SELECT * FROM project_notes WHERE id=?", (nid,)).fetchone())
    if not note:
        return jsonify({'error': 'Nota no encontrada'}), 404
    if note['author'] != g.user['name'] and g.user['role'] != 'admin':
        return jsonify({'error': 'Solo puedes eliminar tus propias notas'}), 403
    db.execute("DELETE FROM project_notes WHERE id=?", (nid,))
    db.commit()
    return jsonify({'ok': True})

# ──────────────────────────────────────────────────
#  ADMIN
# ──────────────────────────────────────────────────

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def get_users():
    db = get_db()
    users = rows_to_list(db.execute("SELECT id, name, username, role, created_at FROM users ORDER BY created_at").fetchall())
    return jsonify(users)

@app.route('/api/admin/users/<uid>', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == g.user['id']:
        return jsonify({'error': 'No puedes eliminar tu propia cuenta'}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/admin/registration', methods=['GET'])
@admin_required
def get_registration_setting():
    db = get_db()
    reg = db.execute("SELECT value FROM settings WHERE key='registration_open'").fetchone()
    return jsonify({'registration_open': reg['value'] == '1' if reg else True})

@app.route('/api/admin/registration', methods=['PUT'])
@admin_required
def set_registration_setting():
    data = request.json
    val = '1' if data.get('registration_open') else '0'
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('registration_open', ?)", (val,))
    db.commit()
    return jsonify({'ok': True, 'registration_open': val == '1'})

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

def create_notification(db, user_name, action, detail, project_id):
    db.execute("INSERT INTO notifications (id, user_name, action, detail, project_id, created_at) VALUES (?,?,?,?,?,?)",
               (gen_id(), user_name, action, detail, project_id, now_iso()))

# ──────────────────────────────────────────────────
#  NOTIFICATIONS
# ──────────────────────────────────────────────────

@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    since = request.args.get('since', '')
    db = get_db()
    if since:
        notifs = rows_to_list(db.execute(
            "SELECT * FROM notifications WHERE created_at > ? ORDER BY created_at DESC LIMIT 20",
            (since,)).fetchall())
    else:
        notifs = rows_to_list(db.execute(
            "SELECT * FROM notifications ORDER BY created_at DESC LIMIT 5").fetchall())
    return jsonify(notifs)

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
    }
    task_notes = rows_to_list(db.execute("""
        SELECT n.*, t.name as task_name, p.name as project_name, c.name as client_name, 'task' as note_type
        FROM notes n
        JOIN tasks t ON n.task_id = t.id
        JOIN projects p ON t.project_id = p.id
        JOIN clients c ON p.client_id = c.id
        ORDER BY n.created_at DESC LIMIT 10
    """).fetchall())
    proj_notes = rows_to_list(db.execute("""
        SELECT pn.*, 'Nota General' as task_name, p.name as project_name, c.name as client_name, 'project' as note_type
        FROM project_notes pn
        JOIN projects p ON pn.project_id = p.id
        JOIN clients c ON p.client_id = c.id
        ORDER BY pn.created_at DESC LIMIT 10
    """).fetchall())
    combined_notes = task_notes + proj_notes
    combined_notes.sort(key=lambda x: x['created_at'], reverse=True)
    stats['recent_notes'] = combined_notes[:10]
    # Billing summary
    billing = db.execute("""
        SELECT
            COALESCE(SUM(billing_amount), 0) + COALESCE(SUM(billing_amount2), 0) as total,
            COALESCE(SUM(CASE WHEN billing_status='none' THEN billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN billing_status2='none' THEN billing_amount2 ELSE 0 END), 0) as not_billed,
            COALESCE(SUM(CASE WHEN billing_status='invoiced' THEN billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN billing_status2='invoiced' THEN billing_amount2 ELSE 0 END), 0) as invoiced,
            COALESCE(SUM(CASE WHEN billing_status='paid' THEN billing_amount ELSE 0 END), 0)
              + COALESCE(SUM(CASE WHEN billing_status2='paid' THEN billing_amount2 ELSE 0 END), 0) as paid
        FROM tasks
    """).fetchone()
    stats['billing'] = {
        'total': billing['total'],
        'not_billed': billing['not_billed'],
        'invoiced': billing['invoiced'],
        'paid': billing['paid']
    }
    # Yearly payment breakdown
    yearly_rows = rows_to_list(db.execute("""
        SELECT
            year,
            SUM(amount) as total
        FROM (
            SELECT SUBSTR(paid_date1, 1, 4) as year, billing_amount as amount FROM tasks WHERE billing_status='paid' AND paid_date1 != ''
            UNION ALL
            SELECT SUBSTR(paid_date2, 1, 4) as year, billing_amount2 as amount FROM tasks WHERE billing_status2='paid' AND paid_date2 != ''
        )
        WHERE year != ''
        GROUP BY year
        ORDER BY year DESC
    """).fetchall())
    stats['billing']['yearly'] = yearly_rows
    return jsonify(stats)

# ──────────────────────────────────────────────────
#  PROJECT REPORT
# ──────────────────────────────────────────────────

@app.route('/api/projects/<pid>/report', methods=['GET'])
@login_required
def project_report(pid):
    db = get_db()
    pr = row_to_dict(db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
    if not pr:
        return "Proyecto no encontrado", 404
    cl = row_to_dict(db.execute("SELECT * FROM clients WHERE id=?", (pr['client_id'],)).fetchone())
    proj_notes = rows_to_list(db.execute("SELECT * FROM project_notes WHERE project_id=? ORDER BY created_at DESC", (pid,)).fetchall())
    tasks = rows_to_list(db.execute("SELECT * FROM tasks WHERE project_id=? ORDER BY category, sort_order, created_at", (pid,)).fetchall())
    for t in tasks:
        t['notes'] = rows_to_list(db.execute("SELECT * FROM notes WHERE task_id=? ORDER BY created_at DESC LIMIT 3", (t['id'],)).fetchall())
    plan_tasks = [t for t in tasks if t['category'] == 'plan']
    permit_tasks = [t for t in tasks if t['category'] == 'permit']
    total_billing = sum(t.get('billing_amount', 0) + t.get('billing_amount2', 0) for t in tasks)
    paid = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'paid') + \
           sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'paid')
    invoiced = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'invoiced') + \
               sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'invoiced')
    not_billed = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'none') + \
                 sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'none')
    total = len(tasks)
    done = sum(1 for t in tasks if t['status'] == 'completed')
    pct = round(done / total * 100) if total else 0

    status_labels = {'pending': 'Pendiente', 'in-progress': 'En Progreso', 'completed': 'Completada'}
    billing_labels = {'none': 'No Facturado', 'invoiced': 'Facturado', 'paid': 'Pagado'}

    def task_rows(task_list):
        rows = ''
        for t in task_list:
            sc = '#D97706' if t['status'] == 'pending' else '#1565C0' if t['status'] == 'in-progress' else '#16A34A'
            lbl1 = f' <span style="color:#8896A6;font-size:11px;">({t.get("billing_label","")})</span>' if t.get('billing_label') else ''
            lbl2 = f' <span style="color:#8896A6;font-size:11px;">({t.get("billing_label2","")})</span>' if t.get('billing_label2') else ''
            pd1 = f' <span style="color:#16A34A;font-size:10px;">({t.get("paid_date1","")})</span>' if t.get('paid_date1') else ''
            pd2 = f' <span style="color:#16A34A;font-size:10px;">({t.get("paid_date2","")})</span>' if t.get('paid_date2') else ''
            notes_html = ''
            for n in t.get('notes', []):
                ndate = n.get("created_at","")[:10] if n.get("created_at") else ""
                notes_html += f'<div style="font-size:11px;color:#4A5568;padding:2px 0;"><b>{n["author"]}</b> <span style="color:#8896A6;">({ndate})</span>: {n["text"][:120]}</div>'
            rows += f'''<tr>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;">{t['name']}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;"><span style="color:{sc};font-weight:600;">{status_labels.get(t['status'],'?')}</span></td>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;text-align:right;">${t.get('billing_amount',0):,}{lbl1}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;">{billing_labels.get(t.get('billing_status','none'),'?')}{pd1}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;text-align:right;">${t.get('billing_amount2',0):,}{lbl2}</td>
                <td style="padding:8px 12px;border-bottom:1px solid #E5E7EB;">{billing_labels.get(t.get('billing_status2','none'),'?')}{pd2}</td>
            </tr>'''
            if notes_html:
                rows += f'<tr><td colspan="6" style="padding:4px 12px 8px 24px;border-bottom:1px solid #E5E7EB;">{notes_html}</td></tr>'
        return rows

    # Yearly breakdown for project report
    proj_yearly = rows_to_list(db.execute("""
        SELECT year, SUM(amount) as total FROM (
            SELECT SUBSTR(paid_date1, 1, 4) as year, billing_amount as amount FROM tasks WHERE project_id=? AND billing_status='paid' AND paid_date1 != ''
            UNION ALL
            SELECT SUBSTR(paid_date2, 1, 4) as year, billing_amount2 as amount FROM tasks WHERE project_id=? AND billing_status2='paid' AND paid_date2 != ''
        ) WHERE year != '' GROUP BY year ORDER BY year DESC
    """, (pid, pid)).fetchall())

    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Reporte — {pr['name']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'DM Sans',sans-serif; color:#1E293B; padding:40px; max-width:900px; margin:0 auto; }}
  @media print {{ body {{ padding:20px; }} .no-print {{ display:none !important; }} }}
  .header {{ background:#1565C0; color:white; padding:24px 32px; border-radius:10px; margin-bottom:24px; }}
  .header h1 {{ font-size:22px; margin-bottom:4px; }}
  .header p {{ font-size:13px; opacity:0.9; }}
  .info-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:24px; }}
  .info-box {{ background:#F8FAFC; border:1px solid #E5E7EB; border-radius:8px; padding:16px; }}
  .info-box h3 {{ font-size:12px; text-transform:uppercase; letter-spacing:0.5px; color:#8896A6; margin-bottom:8px; }}
  .info-box p {{ font-size:14px; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }}
  .summary-card {{ background:#F8FAFC; border:1px solid #E5E7EB; border-radius:8px; padding:14px; text-align:center; }}
  .summary-card .num {{ font-size:24px; font-weight:700; }}
  .summary-card .label {{ font-size:11px; color:#8896A6; margin-top:2px; }}
  .section {{ margin-bottom:20px; }}
  .section h2 {{ font-size:16px; font-weight:700; padding:10px 0; border-bottom:2px solid #1565C0; margin-bottom:0; }}
  .section.permit h2 {{ border-bottom-color:#B45309; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; padding:8px 12px; font-size:11px; font-weight:600; text-transform:uppercase;
       letter-spacing:0.5px; color:#8896A6; border-bottom:2px solid #E5E7EB; }}
  .print-btn {{ background:#1565C0; color:white; border:none; padding:10px 24px; border-radius:6px;
               font-size:14px; font-weight:600; cursor:pointer; font-family:inherit; }}
  .print-btn:hover {{ background:#104E95; }}
  .footer {{ text-align:center; font-size:11px; color:#8896A6; margin-top:32px; padding-top:16px; border-top:1px solid #E5E7EB; }}
</style>
</head><body>
<div style="text-align:right;margin-bottom:16px;" class="no-print">
  <button class="print-btn" onclick="window.print()">Imprimir / Guardar PDF</button>
</div>
<div class="header">
  <h1>{pr['name']}</h1>
  <p>{pr.get('property_address','') or 'Sin dirección'}{(' — Catastro: ' + pr['catastro']) if pr.get('catastro') else ''}</p>
</div>
<div class="info-grid">
  <div class="info-box">
    <h3>Cliente</h3>
    <p><b>{cl['name']}</b></p>
    <p>{cl.get('email','') or ''}</p>
    <p>{cl.get('phone','') or ''}</p>
  </div>
  <div class="info-box">
    <h3>Progreso General</h3>
    <p style="font-size:28px;font-weight:700;color:#1565C0;">{pct}%</p>
    <p>{done} de {total} tareas completadas</p>
  </div>
</div>
<div class="summary-grid">
  <div class="summary-card"><div class="num" style="color:#1565C0;">${total_billing:,}</div><div class="label">Total</div></div>
  <div class="summary-card"><div class="num" style="color:#8896A6;">${not_billed:,}</div><div class="label">No Facturado</div></div>
  <div class="summary-card"><div class="num" style="color:#D97706;">${invoiced:,}</div><div class="label">Facturado</div></div>
  <div class="summary-card"><div class="num" style="color:#16A34A;">${paid:,}</div><div class="label">Pagado</div></div>
</div>'''

    if proj_yearly:
        yearly_cards = ''.join(f'<div style="text-align:center;padding:10px 18px;background:#F0FDF4;border:1px solid rgba(22,163,74,0.15);border-radius:8px;"><div style="font-size:18px;font-weight:700;color:#16A34A;">${y["total"]:,}</div><div style="font-size:11px;color:#8896A6;margin-top:2px;">{y["year"]}</div></div>' for y in proj_yearly)
        html += f'''<div style="margin-bottom:24px;">
  <h3 style="font-size:13px;text-transform:uppercase;letter-spacing:0.5px;color:#8896A6;margin-bottom:10px;">Pagos por Año</h3>
  <div style="display:flex;flex-wrap:wrap;gap:10px;">{yearly_cards}</div>
</div>'''

    if plan_tasks:
        html += f'''<div class="section">
  <h2>Planos</h2>
  <table><thead><tr><th>Tarea</th><th>Estado</th><th style="text-align:right;">Monto 1</th><th>Facturación 1</th><th style="text-align:right;">Monto 2</th><th>Facturación 2</th></tr></thead>
  <tbody>{task_rows(plan_tasks)}</tbody></table>
</div>'''

    if permit_tasks:
        html += f'''<div class="section permit">
  <h2>Permisos</h2>
  <table><thead><tr><th>Tarea</th><th>Estado</th><th style="text-align:right;">Monto 1</th><th>Facturación 1</th><th style="text-align:right;">Monto 2</th><th>Facturación 2</th></tr></thead>
  <tbody>{task_rows(permit_tasks)}</tbody></table>
</div>'''

    if proj_notes:
        pn_html = ''
        for pn in proj_notes:
            pndate = pn.get("created_at","")[:10] if pn.get("created_at") else ""
            pn_html += f'<div style="padding:8px 12px;border-bottom:1px solid #E5E7EB;font-size:13px;"><b>{pn["author"]}</b> <span style="color:#8896A6;font-size:11px;">({pndate})</span>: {pn["text"][:200]}</div>'
        html += f'''<div class="section">
  <h2>Notas Generales</h2>
  {pn_html}
</div>'''

    html += f'''<div class="footer">
  CivilPM — Reporte generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}
</div>
</body></html>'''
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

@app.route('/api/clients/<cid>/report', methods=['GET'])
@login_required
def client_report(cid):
    db = get_db()
    cl = row_to_dict(db.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone())
    if not cl:
        return "Cliente no encontrado", 404
    projects = rows_to_list(db.execute("SELECT * FROM projects WHERE client_id=? ORDER BY created_at DESC", (cid,)).fetchall())

    # Build project data, filter out 100% completed
    active_projects = []
    for pr in projects:
        tasks = rows_to_list(db.execute("SELECT * FROM tasks WHERE project_id=? ORDER BY category, sort_order, created_at", (pr['id'],)).fetchall())
        for t in tasks:
            t['notes'] = rows_to_list(db.execute("SELECT * FROM notes WHERE task_id=? ORDER BY created_at DESC LIMIT 2", (t['id'],)).fetchall())
        total = len(tasks)
        done = sum(1 for t in tasks if t['status'] == 'completed')
        if total > 0 and done == total:
            continue  # skip 100% completed
        pr['tasks'] = tasks
        pr['project_notes'] = rows_to_list(db.execute("SELECT * FROM project_notes WHERE project_id=? ORDER BY created_at DESC LIMIT 5", (pr['id'],)).fetchall())
        pr['total'] = total
        pr['done'] = done
        pr['pct'] = round(done / total * 100) if total else 0
        pr['billing_total'] = sum(t.get('billing_amount', 0) + t.get('billing_amount2', 0) for t in tasks)
        pr['billing_paid'] = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'paid') + \
                             sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'paid')
        pr['billing_invoiced'] = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'invoiced') + \
                                 sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'invoiced')
        pr['billing_not_billed'] = sum(t.get('billing_amount', 0) for t in tasks if t.get('billing_status') == 'none') + \
                                   sum(t.get('billing_amount2', 0) for t in tasks if t.get('billing_status2') == 'none')
        active_projects.append(pr)

    # Client-wide billing totals (active projects only)
    grand_total = sum(p['billing_total'] for p in active_projects)
    grand_paid = sum(p['billing_paid'] for p in active_projects)
    grand_invoiced = sum(p['billing_invoiced'] for p in active_projects)
    grand_not_billed = sum(p['billing_not_billed'] for p in active_projects)

    status_labels = {'pending': 'Pendiente', 'in-progress': 'En Progreso', 'completed': 'Completada'}
    billing_labels = {'none': 'No Facturado', 'invoiced': 'Facturado', 'paid': 'Pagado'}

    def task_rows(task_list):
        rows = ''
        for t in task_list:
            sc = '#D97706' if t['status'] == 'pending' else '#1565C0' if t['status'] == 'in-progress' else '#16A34A'
            lbl1 = f' <span style="color:#8896A6;font-size:10px;">({t.get("billing_label","")})</span>' if t.get('billing_label') else ''
            lbl2 = f' <span style="color:#8896A6;font-size:10px;">({t.get("billing_label2","")})</span>' if t.get('billing_label2') else ''
            pd1 = f' <span style="color:#16A34A;font-size:9px;">({t.get("paid_date1","")})</span>' if t.get('paid_date1') else ''
            pd2 = f' <span style="color:#16A34A;font-size:9px;">({t.get("paid_date2","")})</span>' if t.get('paid_date2') else ''
            notes_html = ''
            for n in t.get('notes', []):
                ndate = n.get("created_at","")[:10] if n.get("created_at") else ""
                notes_html += f'<div style="font-size:11px;color:#4A5568;padding:2px 0;"><b>{n["author"]}</b> <span style="color:#8896A6;">({ndate})</span>: {n["text"][:120]}</div>'
            rows += f'''<tr>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;">{t['name']}</td>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;"><span style="color:{sc};font-weight:600;">{status_labels.get(t['status'],'?')}</span></td>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;text-align:right;">${t.get('billing_amount',0):,}{lbl1}</td>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;">{billing_labels.get(t.get('billing_status','none'),'?')}{pd1}</td>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;text-align:right;">${t.get('billing_amount2',0):,}{lbl2}</td>
                <td style="padding:6px 10px;border-bottom:1px solid #E5E7EB;font-size:12px;">{billing_labels.get(t.get('billing_status2','none'),'?')}{pd2}</td>
            </tr>'''
            if notes_html:
                rows += f'<tr><td colspan="6" style="padding:2px 10px 6px 20px;border-bottom:1px solid #E5E7EB;">{notes_html}</td></tr>'
        return rows

    projects_html = ''
    for pr in active_projects:
        plan_tasks = [t for t in pr['tasks'] if t['category'] == 'plan']
        permit_tasks = [t for t in pr['tasks'] if t['category'] == 'permit']
        projects_html += f'''<div style="border:1px solid #E5E7EB;border-radius:8px;padding:20px;margin-bottom:20px;page-break-inside:avoid;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
    <div>
      <h3 style="font-size:16px;margin:0;">{pr['name']}</h3>
      <p style="font-size:12px;color:#8896A6;margin:2px 0 0 0;">{pr.get('property_address','') or 'Sin dirección'}{(' — Catastro: ' + pr['catastro']) if pr.get('catastro') else ''}</p>
    </div>
    <div style="text-align:right;">
      <span style="font-size:22px;font-weight:700;color:#1565C0;">{pr['pct']}%</span>
      <div style="font-size:11px;color:#8896A6;">{pr['done']}/{pr['total']} tareas</div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:14px;">
    <div style="text-align:center;padding:8px;background:#F8FAFC;border-radius:6px;"><div style="font-size:16px;font-weight:700;color:#1565C0;">${pr['billing_total']:,}</div><div style="font-size:10px;color:#8896A6;">Total</div></div>
    <div style="text-align:center;padding:8px;background:#F8FAFC;border-radius:6px;"><div style="font-size:16px;font-weight:700;color:#8896A6;">${pr['billing_not_billed']:,}</div><div style="font-size:10px;color:#8896A6;">No Fact.</div></div>
    <div style="text-align:center;padding:8px;background:#F8FAFC;border-radius:6px;"><div style="font-size:16px;font-weight:700;color:#D97706;">${pr['billing_invoiced']:,}</div><div style="font-size:10px;color:#8896A6;">Facturado</div></div>
    <div style="text-align:center;padding:8px;background:#F8FAFC;border-radius:6px;"><div style="font-size:16px;font-weight:700;color:#16A34A;">${pr['billing_paid']:,}</div><div style="font-size:10px;color:#8896A6;">Pagado</div></div>
  </div>'''
        if plan_tasks:
            projects_html += f'''<div style="margin-bottom:10px;">
    <h4 style="font-size:13px;color:#1565C0;border-bottom:2px solid #1565C0;padding-bottom:4px;margin:0 0 6px 0;">Planos</h4>
    <table style="width:100%;border-collapse:collapse;"><thead><tr>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Tarea</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Estado</th>
      <th style="text-align:right;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Monto 1</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Fact. 1</th>
      <th style="text-align:right;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Monto 2</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Fact. 2</th>
    </tr></thead><tbody>{task_rows(plan_tasks)}</tbody></table></div>'''
        if permit_tasks:
            projects_html += f'''<div>
    <h4 style="font-size:13px;color:#B45309;border-bottom:2px solid #B45309;padding-bottom:4px;margin:0 0 6px 0;">Permisos</h4>
    <table style="width:100%;border-collapse:collapse;"><thead><tr>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Tarea</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Estado</th>
      <th style="text-align:right;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Monto 1</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Fact. 1</th>
      <th style="text-align:right;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Monto 2</th>
      <th style="text-align:left;padding:4px 10px;font-size:10px;font-weight:600;text-transform:uppercase;color:#8896A6;border-bottom:1px solid #E5E7EB;">Fact. 2</th>
    </tr></thead><tbody>{task_rows(permit_tasks)}</tbody></table></div>'''
        if pr.get('project_notes'):
            pn_html = ''
            for pn in pr['project_notes']:
                pndate = pn.get("created_at","")[:10] if pn.get("created_at") else ""
                pn_html += f'<div style="font-size:11px;color:#4A5568;padding:3px 0;"><b>{pn["author"]}</b> <span style="color:#8896A6;">({pndate})</span>: {pn["text"][:150]}</div>'
            projects_html += f'''<div style="margin-top:10px;">
    <h4 style="font-size:13px;color:#4A5568;border-bottom:1px solid #E5E7EB;padding-bottom:4px;margin:0 0 6px 0;">Notas Generales</h4>
    {pn_html}</div>'''
        projects_html += '</div>'

    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Reporte de Cliente — {cl['name']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'DM Sans',sans-serif; color:#1E293B; padding:40px; max-width:900px; margin:0 auto; }}
  @media print {{ body {{ padding:20px; }} .no-print {{ display:none !important; }} }}
  .print-btn {{ background:#1565C0; color:white; border:none; padding:10px 24px; border-radius:6px;
               font-size:14px; font-weight:600; cursor:pointer; font-family:inherit; }}
  .print-btn:hover {{ background:#104E95; }}
</style>
</head><body>
<div style="text-align:right;margin-bottom:16px;" class="no-print">
  <button class="print-btn" onclick="window.print()">Imprimir / Guardar PDF</button>
</div>
<div style="background:#1565C0;color:white;padding:24px 32px;border-radius:10px;margin-bottom:24px;">
  <h1 style="font-size:22px;margin-bottom:4px;">{cl['name']}</h1>
  <p style="font-size:13px;opacity:0.9;">Reporte de Proyectos Activos</p>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
  <div style="background:#F8FAFC;border:1px solid #E5E7EB;border-radius:8px;padding:16px;">
    <h3 style="font-size:12px;text-transform:uppercase;letter-spacing:0.5px;color:#8896A6;margin-bottom:8px;">Contacto</h3>
    <p style="font-size:14px;">{cl.get('email','') or '—'}</p>
    <p style="font-size:14px;">{cl.get('phone','') or '—'}</p>
    <p style="font-size:14px;">{cl.get('address','') or '—'}</p>
  </div>
  <div style="background:#F8FAFC;border:1px solid #E5E7EB;border-radius:8px;padding:16px;">
    <h3 style="font-size:12px;text-transform:uppercase;letter-spacing:0.5px;color:#8896A6;margin-bottom:8px;">Facturación Global</h3>
    <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;">
      <div><div style="font-size:20px;font-weight:700;color:#1565C0;">${grand_total:,}</div><div style="font-size:10px;color:#8896A6;">Total</div></div>
      <div><div style="font-size:20px;font-weight:700;color:#8896A6;">${grand_not_billed:,}</div><div style="font-size:10px;color:#8896A6;">No Facturado</div></div>
      <div><div style="font-size:20px;font-weight:700;color:#D97706;">${grand_invoiced:,}</div><div style="font-size:10px;color:#8896A6;">Facturado</div></div>
      <div><div style="font-size:20px;font-weight:700;color:#16A34A;">${grand_paid:,}</div><div style="font-size:10px;color:#8896A6;">Pagado</div></div>
    </div>
  </div>
</div>
<h2 style="font-size:18px;margin-bottom:16px;">{len(active_projects)} Proyecto{'s' if len(active_projects) != 1 else ''} Activo{'s' if len(active_projects) != 1 else ''}</h2>
{projects_html}
{('<div style="text-align:center;padding:40px;color:#8896A6;">No hay proyectos activos para este cliente.</div>' if not active_projects else '')}
<div style="text-align:center;font-size:11px;color:#8896A6;margin-top:32px;padding-top:16px;border-top:1px solid #E5E7EB;">
  CivilPM — Reporte generado el {datetime.now().strftime('%d/%m/%Y %H:%M')}
</div>
</body></html>'''
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

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
