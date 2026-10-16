from flask import Flask, render_template
import os
import sqlite3

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ids_logs.db')


def ensure_database_schema(conn):
    conn.execute(
        '''CREATE TABLE IF NOT EXISTS alerts
           (id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            status TEXT)'''
    )

    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    migrations = {
        'dst_port': 'ALTER TABLE alerts ADD COLUMN dst_port INTEGER DEFAULT 0',
        'confidence': 'ALTER TABLE alerts ADD COLUMN confidence INTEGER DEFAULT 0',
        'alert_reason': "ALTER TABLE alerts ADD COLUMN alert_reason TEXT DEFAULT ''",
    }

    for column, statement in migrations.items():
        if column not in existing_columns:
            conn.execute(statement)

    conn.commit()


def get_db_connection():
    if not os.path.exists(DB_PATH):
        open(DB_PATH, 'a').close()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_database_schema(conn)
    return conn


@app.route('/')
def index():
    try:
        conn = get_db_connection()
        alert_rows = conn.execute(
            '''SELECT id, timestamp, src_ip, dst_ip, protocol, status, dst_port,
                      confidence, alert_reason
               FROM alerts
               ORDER BY id DESC
               LIMIT 50'''
        ).fetchall()
        total_malicious = conn.execute('SELECT COUNT(*) FROM alerts WHERE status="Malicious"').fetchone()[0]
        total_normal = conn.execute('SELECT COUNT(*) FROM alerts WHERE status="Normal"').fetchone()[0]
        conn.close()
    except sqlite3.OperationalError:
        alert_rows, total_malicious, total_normal = [], 0, 0

    alerts = [dict(row) for row in alert_rows]

    return render_template(
        'index.html',
        alerts=alerts,
        malicious=total_malicious,
        normal=total_normal,
    )

if __name__ == '__main__':
    print("[*] Starting UI on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
