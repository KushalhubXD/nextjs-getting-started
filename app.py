import sqlite3
from flask import Flask, g, render_template, jsonify, request, abort
from datetime import datetime, timedelta

DATABASE = 'firewall.db'
SYN_THRESHOLD = 5  # Example threshold: if more than 5 SYN events in the last minute, raise alert

app = Flask(__name__)
app.config['DEBUG'] = True  # Disable in production

# --------------------
# Database Utilities
# --------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
            db.row_factory = sqlite3.Row
        except Exception as e:
            app.logger.error(f"DB connection failed: {e}")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database using schema.sql."""
    try:
        with app.app_context():
            db = get_db()
            with open('schema.sql', 'r') as f:
                db.executescript(f.read())
            db.commit()
    except Exception as e:
        app.logger.error(f"Error initializing the database: {e}")

# --------------------
# Threat Detection Logic
# --------------------

def check_for_threat(ip_address):
    """
    Check whether the given IP has generated too many SYN events
    in the last minute. If the threshold is exceeded, log a threat.
    """
    try:
        db = get_db()
        one_minute_ago = datetime.now() - timedelta(minutes=1)
        cur = db.execute(
            "SELECT COUNT(*) as count FROM logs WHERE ip_address = ? AND event = 'SYN' AND timestamp >= ?",
            (ip_address, one_minute_ago)
        )
        count = cur.fetchone()['count']
        if count >= SYN_THRESHOLD:
            # Log threat if not already logged recently (avoid duplicate alerts)
            db.execute("INSERT INTO threats (ip_address, alert_type, description) VALUES (?, ?, ?)",
                       (ip_address, "SYN Flood", f"{count} SYN events in the last minute"))
            db.commit()
            app.logger.info(f"Threat detected from {ip_address}: SYN Flood ({count} events)")
    except Exception as e:
        app.logger.error(f"Error in threat detection: {e}")

# --------------------
# Routes
# --------------------

@app.route('/')
def index():
    """Home page directs to dashboard (login can be added later)."""
    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    """Render the user dashboard."""
    try:
        return render_template('dashboard.html')
    except Exception as e:
        app.logger.error(f"Error rendering dashboard: {e}")
        abort(500)

@app.route('/api/traffic')
def api_traffic():
    """
    API endpoint to provide real-time IP traffic data.
    For simplicity, we return a dummy dataset.
    In a real scenario, aggregate logs by timestamp.
    """
    try:
        # Example: return last 10 timepoints of random traffic values.
        import random
        data_points = []
        for i in range(10):
            data_points.append({
                'time': (datetime.now() - timedelta(seconds=(10 - i) * 5)).strftime("%H:%M:%S"),
                'traffic': random.randint(10, 100)
            })
        return jsonify(data_points)
    except Exception as e:
        app.logger.error(f"Error returning traffic data: {e}")
        return jsonify({'error': 'Unable to fetch data'}), 500

@app.route('/api/logs')
def api_logs():
    """
    API endpoint to fetch the logs from the database.
    """
    try:
        cur = get_db().execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20")
        logs = [dict(row) for row in cur.fetchall()]
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"Error fetching logs: {e}")
        return jsonify({'error': 'Unable to fetch logs'}), 500

@app.route('/api/threats')
def api_threats():
    """
    API endpoint to fetch active threat alerts.
    """
    try:
        cur = get_db().execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT 20")
        threats = [dict(row) for row in cur.fetchall()]
        return jsonify(threats)
    except Exception as e:
        app.logger.error(f"Error fetching threats: {e}")
        return jsonify({'error': 'Unable to fetch threats'}), 500

@app.route('/simulate', methods=['POST'])
def simulate():
    """
    This endpoint simulates an incoming traffic log.
    Expect JSON: {"ip_address": "xxx.xxx.xxx.xxx", "event": "SYN" or "NORMAL"}
    It logs the event and checks whether it qualifies as a threat.
    Use this endpoint for testing/demonstration.
    """
    data = request.get_json()
    if not data or 'ip_address' not in data or 'event' not in data:
        abort(400, description="Missing required fields: ip_address, event")
    
    ip_address = data['ip_address']
    event = data['event']

    try:
        db = get_db()
        db.execute("INSERT INTO logs (ip_address, event) VALUES (?, ?)", (ip_address, event))
        db.commit()
        # If event is a SYN then check for threat condition.
        if event.upper() == 'SYN':
            check_for_threat(ip_address)
        return jsonify({'status': 'logged'}), 201
    except Exception as e:
        app.logger.error(f"Error during simulation: {e}")
        return jsonify({'error': 'Failed to log event'}), 500

# --------------------
# Error Handlers
# --------------------

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal Server Error'}), 500

# --------------------
# Main
# --------------------

if __name__ == '__main__':
    init_db()  # Initialize DB on first run
    app.run(host='0.0.0.0', port=8000)  # Using port 8000 as required

@app.route('/api/block-ip', methods=['POST'])
def block_ip():
    """
    Block a specific IP address
    """
    data = request.get_json()
    if not data or 'ip_address' not in data:
        abort(400, description="Missing required field: ip_address")
    
    ip_address = data['ip_address']
    
    try:
        db = get_db()
        # Add to logs
        db.execute("INSERT INTO logs (ip_address, event) VALUES (?, ?)", (ip_address, "BLOCKED"))
        # Add to threats
        db.execute("INSERT INTO threats (ip_address, alert_type, description) VALUES (?, ?, ?)",
                   (ip_address, "IP Blocked", f"IP {ip_address} has been blocked"))
        db.commit()
        
        return jsonify({'status': 'blocked', 'message': f'IP {ip_address} has been blocked'}), 201
    except Exception as e:
        app.logger.error(f"Error blocking IP: {e}")
        return jsonify({'error': 'Failed to block IP'}), 500

@app.route('/api/resolve-threat/<int:threat_id>', methods=['POST'])
def resolve_threat(threat_id):
    """
    Resolve a specific threat
    """
    try:
        db = get_db()
        db.execute("DELETE FROM threats WHERE id = ?", (threat_id,))
        db.commit()
        
        return jsonify({'status': 'resolved', 'message': f'Threat {threat_id} has been resolved'}), 200
    except Exception as e:
        app.logger.error(f"Error resolving threat: {e}")
        return jsonify({'error': 'Failed to resolve threat'}), 500

@app.route('/api/stats')
def api_stats():
    """
    Get dashboard statistics
    """
    try:
        db = get_db()
        
        # Total traffic count
        total_traffic = db.execute("SELECT COUNT(*) as count FROM logs").fetchone()['count']
        
        # Active threats count
        active_threats = db.execute("SELECT COUNT(*) as count FROM threats").fetchone()['count']
        
        # Blocked IPs count (last 24 hours)
        from datetime import datetime, timedelta
        yesterday = datetime.now() - timedelta(days=1)
        blocked_ips = db.execute(
            "SELECT COUNT(DISTINCT ip_address) as count FROM logs WHERE event = 'BLOCKED' AND timestamp >= ?",
            (yesterday,)
        ).fetchone()['count']
        
        # Recent activity (last hour)
        last_hour = datetime.now() - timedelta(hours=1)
        recent_activity = db.execute(
            "SELECT COUNT(*) as count FROM logs WHERE timestamp >= ?",
            (last_hour,)
        ).fetchone()['count']
        
        return jsonify({
            'total_traffic': total_traffic,
            'active_threats': active_threats,
            'blocked_ips': blocked_ips,
            'recent_activity': recent_activity
        })
    except Exception as e:
        app.logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': 'Unable to fetch stats'}), 500
