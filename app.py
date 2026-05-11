from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes so Vite frontend can access it

DB_FILE = 'vault.db'

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, role TEXT, public_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS records
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id TEXT, 
                  filename TEXT, encrypted_data TEXT, nonce TEXT, tag TEXT, signature TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_requests
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, doctor_id TEXT, record_id INTEGER, 
                  status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS record_keys
                 (record_id INTEGER, user_id TEXT, encrypted_aes_key TEXT,
                  PRIMARY KEY(record_id, user_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, action TEXT, details TEXT)''')
    conn.commit()
    conn.close()

def audit(conn, action, details):
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (timestamp, action, details) VALUES (?, ?, ?)",
              (datetime.now().isoformat(), action, details))
    conn.commit()

init_db()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    role = data.get('role')
    pub_key = data.get('public_key')
    
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, role, public_key) VALUES (?, ?, ?)", (username, role, pub_key))
        conn.commit()
        audit(conn, "REGISTER", f"User {username} registered as {role}")
        return jsonify({"status": "success", "message": "Registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 400
    finally:
        conn.close()

@app.route('/api/public_key/<username>', methods=['GET'])
def get_public_key(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"status": "success", "public_key": row['public_key']})
    return jsonify({"status": "error", "message": "User not found"}), 404

@app.route('/api/upload_record', methods=['POST'])
def upload_record():
    data = request.json
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO records (patient_id, filename, encrypted_data, nonce, tag, signature) VALUES (?, ?, ?, ?, ?, ?)",
                  (data['patient_id'], data['filename'], data['encrypted_data'], data['nonce'], data['tag'], data['signature']))
        record_id = c.lastrowid
        c.execute("INSERT INTO record_keys (record_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
                  (record_id, data['patient_id'], data['encrypted_aes_key']))
        conn.commit()
        audit(conn, "UPLOAD_RECORD", f"Patient {data['patient_id']} uploaded record {record_id}")
        return jsonify({"status": "success", "record_id": record_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()

@app.route('/api/records', methods=['GET'])
def list_records():
    role = request.args.get('role')
    username = request.args.get('username')
    conn = get_db()
    c = conn.cursor()
    if role == 'patient':
        c.execute("SELECT id, filename FROM records WHERE patient_id = ?", (username,))
        records = [{"id": row['id'], "filename": row['filename']} for row in c.fetchall()]
    else:
        c.execute("SELECT id, patient_id, filename FROM records")
        records = [{"id": row['id'], "patient_id": row['patient_id'], "filename": row['filename']} for row in c.fetchall()]
    conn.close()
    return jsonify({"status": "success", "records": records})

@app.route('/api/vault_status', methods=['GET'])
def vault_status():
    """Public metadata-only snapshot for the /status dashboard: ciphertext fingerprints,
    sizes, key wrappers, and request states — never plaintext."""
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) AS n FROM records")
    total_records = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM access_requests WHERE status = 'pending'")
    pending_requests = c.fetchone()["n"]
    c.execute("SELECT COUNT(*) AS n FROM access_requests WHERE status = 'approved'")
    approved_requests = c.fetchone()["n"]
    c.execute("SELECT COUNT(DISTINCT username) AS n FROM users")
    registered_users = c.fetchone()["n"]

    c.execute(
        "SELECT id, patient_id, filename, encrypted_data, nonce, signature FROM records ORDER BY id"
    )
    rows = c.fetchall()
    records_out = []

    for row in rows:
        rid = row["id"]
        enc_b64 = row["encrypted_data"] or ""
        fingerprint = hashlib.sha256(enc_b64.encode("utf-8")).hexdigest()[:16]

        c.execute("SELECT user_id FROM record_keys WHERE record_id = ?", (rid,))
        key_holders = [r["user_id"] for r in c.fetchall()]

        c.execute(
            "SELECT doctor_id, status FROM access_requests WHERE record_id = ?",
            (rid,),
        )
        access_reqs = [
            {"doctor_id": r["doctor_id"], "status": r["status"]}
            for r in c.fetchall()
        ]

        records_out.append(
            {
                "id": rid,
                "patient_id": row["patient_id"],
                "filename": row["filename"],
                "ciphertext_fingerprint": fingerprint,
                "ciphertext_storage_chars": len(enc_b64),
                "nonce_present": bool(row["nonce"]),
                "signature_present": bool(row["signature"]),
                "wrapped_key_holders": key_holders,
                "access_requests": access_reqs,
            }
        )

    conn.close()
    return jsonify(
        {
            "status": "success",
            "summary": {
                "total_encrypted_records": total_records,
                "pending_access_requests": pending_requests,
                "approved_access_requests": approved_requests,
                "registered_users": registered_users,
            },
            "records": records_out,
        }
    )

@app.route('/api/request_access', methods=['POST'])
def request_access():
    data = request.json
    doctor_id = data.get('doctor_id')
    record_id = data.get('record_id')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT patient_id FROM records WHERE id = ?", (record_id,))
    if not c.fetchone():
        return jsonify({"status": "error", "message": "Record not found"}), 404
        
    c.execute("SELECT id FROM access_requests WHERE doctor_id = ? AND record_id = ?", (doctor_id, record_id))
    if c.fetchone():
        return jsonify({"status": "error", "message": "Request already exists"}), 400
        
    c.execute("INSERT INTO access_requests (doctor_id, record_id, status) VALUES (?, ?, 'pending')", (doctor_id, record_id))
    conn.commit()
    audit(conn, "REQUEST_ACCESS", f"Doctor {doctor_id} requested access to record {record_id}")
    conn.close()
    return jsonify({"status": "success", "message": "Request submitted"})

@app.route('/api/pending_requests', methods=['GET'])
def get_pending_requests():
    patient_id = request.args.get('patient_id')
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT a.id, a.doctor_id, a.record_id, r.filename 
                 FROM access_requests a 
                 JOIN records r ON a.record_id = r.id 
                 WHERE r.patient_id = ? AND a.status = 'pending'""", (patient_id,))
    requests = [{"request_id": row['id'], "doctor_id": row['doctor_id'], "record_id": row['record_id'], "filename": row['filename']} for row in c.fetchall()]
    conn.close()
    return jsonify({"status": "success", "requests": requests})

@app.route('/api/my_encrypted_key', methods=['GET'])
def get_my_encrypted_key():
    record_id = request.args.get('record_id')
    user_id = request.args.get('user_id')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT encrypted_aes_key FROM record_keys WHERE record_id = ? AND user_id = ?", (record_id, user_id))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"status": "success", "encrypted_aes_key": row['encrypted_aes_key']})
    return jsonify({"status": "error", "message": "Key not found"}), 404

@app.route('/api/approve_access', methods=['POST'])
def approve_access():
    data = request.json
    request_id = data.get('request_id')
    patient_id = data.get('patient_id')
    enc_aes_key_doctor = data.get('encrypted_aes_key_for_doctor')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("""SELECT a.doctor_id, a.record_id 
                 FROM access_requests a JOIN records r ON a.record_id = r.id 
                 WHERE a.id = ? AND r.patient_id = ?""", (request_id, patient_id))
    row = c.fetchone()
    if row:
        doctor_id = row['doctor_id']
        record_id = row['record_id']
        c.execute("UPDATE access_requests SET status = 'approved' WHERE id = ?", (request_id,))
        c.execute("INSERT OR REPLACE INTO record_keys (record_id, user_id, encrypted_aes_key) VALUES (?, ?, ?)",
                  (record_id, doctor_id, enc_aes_key_doctor))
        conn.commit()
        audit(conn, "APPROVE_ACCESS", f"Patient {patient_id} approved access to record {record_id} for Doctor {doctor_id}")
        conn.close()
        return jsonify({"status": "success", "message": "Access approved"})
    
    conn.close()
    return jsonify({"status": "error", "message": "Invalid request or unauthorized"}), 403

@app.route('/api/download_record', methods=['GET'])
def download_record():
    doctor_id = request.args.get('doctor_id')
    record_id = request.args.get('record_id')
    
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT patient_id, filename, encrypted_data, nonce, tag, signature FROM records WHERE id = ?", (record_id,))
    record_row = c.fetchone()
    if not record_row:
        conn.close()
        return jsonify({"status": "error", "message": "Record not found"}), 404
        
    patient_id = record_row['patient_id']
    is_authorized = False
    
    if doctor_id == patient_id:
        is_authorized = True
    else:
        c.execute("SELECT status FROM access_requests WHERE doctor_id = ? AND record_id = ? AND status = 'approved'", (doctor_id, record_id))
        if c.fetchone():
            is_authorized = True
            
    if is_authorized:
        c.execute("SELECT encrypted_aes_key FROM record_keys WHERE record_id = ? AND user_id = ?", (record_id, doctor_id))
        key_row = c.fetchone()
        if key_row:
            audit(conn, "DOWNLOAD_RECORD", f"User {doctor_id} downloaded record {record_id}")
            resp = {
                "status": "success",
                "patient_id": patient_id,
                "filename": record_row['filename'],
                "encrypted_data": record_row['encrypted_data'],
                "nonce": record_row['nonce'],
                "tag": record_row['tag'],
                "signature": record_row['signature'],
                "encrypted_aes_key": key_row['encrypted_aes_key']
            }
            conn.close()
            return jsonify(resp)
        else:
            conn.close()
            return jsonify({"status": "error", "message": "Decryption key not found for this user"}), 404
            
    audit(conn, "UNAUTHORIZED_ACCESS", f"User {doctor_id} tried to download record {record_id} without approval")
    conn.close()
    return jsonify({"status": "error", "message": "Unauthorized or pending approval"}), 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
