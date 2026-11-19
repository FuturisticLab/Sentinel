import os
import sys
from flask import send_from_directory, abort

# Ensure current directory is in sys.path so api.index is cleanly importable
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from api.index import app, init_db

# Isolated Public Directory for Static Assets
STATIC_DIR = os.path.abspath(os.path.join(current_dir, "public"))
try:
    os.makedirs(STATIC_DIR, exist_ok=True)
except OSError:
    pass

# Local Static Asset Serving
@app.route('/')
def serve_index():
    return send_from_directory(STATIC_DIR, 'index.html')

@app.route('/exhaust')
def serve_exhaust():
    return send_from_directory(STATIC_DIR, 'exhaust.html')

@app.route('/<path:path>')
def serve_static(path):
    target_path = os.path.normpath(os.path.join(STATIC_DIR, path))
    # Disallow path traversal outside STATIC_DIR
    if not target_path.startswith(STATIC_DIR):
        abort(403)
    if not os.path.isfile(target_path):
        abort(404)
    # Strictly disallow sensitive system, source, database, and config files
    forbidden_extensions = ('.py', '.db', '.sqlite', '.sqlite3', '.env', '.json', '.txt', '.dockerignore', '.gitignore', '.yaml', '.yml')
    if path.startswith('.') or any(path.lower().endswith(ext) for ext in forbidden_extensions):
        abort(403)
    return send_from_directory(STATIC_DIR, path)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 3000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    print(f"Hardened Sentinel server running at http://0.0.0.0:{port} (Debug: {debug_mode})...")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
