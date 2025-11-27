from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from services import mitigation_service, database_service, summary_service
from user import User

# --- Initialization ---
app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
database_service.init_db()
packet_logs = []

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Web Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_by_username(username)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

# --- API Endpoints ---

@app.route('/api/ingest', methods=['POST'])
def ingest_packet():
    """
    Receives packet data from an external source (the honeypot simulator),
    processes it, and broadcasts the results to all dashboard clients.
    """
    # Add diagnostic print
    print(f"[Dashboard] Received packet at /api/ingest.")

    packet_data = request.json.get('packet_data')
    prediction_data = request.json.get('prediction_data')

    # Add diagnostic print for received packet_data
    print(f"[Dashboard] Received packet data at /api/ingest: {packet_data}")

    if not packet_data or not prediction_data:
        return jsonify({"error": "Invalid data received"}), 400

    # Process the packet using the mitigation service
    response_data = mitigation_service.process_packet(packet_data, prediction_data)
    packet_logs.append(response_data)

    # Broadcast the results to all connected SocketIO clients
    socketio.emit('packet_data_response', response_data)

    return jsonify({"status": "ok"}), 200


@app.route('/api/unblock_ip', methods=['POST'])
@login_required
def unblock_ip_route():
    """Unblock a previously blocked or alerted IP address."""
    data = request.get_json()
    ip_to_unblock = data.get('ip')
    return jsonify(mitigation_service.unblock_ip(ip_to_unblock))

@app.route('/api/blocked_ips', methods=['GET'])
@login_required
def get_blocked_ips_route():
    """Return the list of currently permanently blocked IP addresses."""
    return jsonify(mitigation_service.get_blocked_ips())

@app.route('/api/alerts', methods=['GET'])
@login_required
def get_alerts_route():
    """Return the list of IPs in the alert state with remaining time."""
    return jsonify(mitigation_service.get_alerts())

@app.route('/api/clear_all_blocks', methods=['POST'])
@login_required
def clear_all_blocks_route():
    """Clear all permanent and temporary block lists."""
    return jsonify(mitigation_service.clear_all_blocks())

@app.route('/api/generate_summary', methods=['GET'])
@login_required
def generate_summary_route():
    """Generate a summary of recent network activity."""
    interval = request.args.get('interval', default=15, type=int)
    summary = summary_service.generate_summary_from_llm(interval, packet_logs)
    return jsonify({"summary": summary})

@app.route('/api/get_logs', methods=['GET'])
@login_required
def get_logs_route():
    """Return the list of all packet logs."""
    return jsonify(packet_logs)

@app.route('/api/clear_logs', methods=['POST'])
@login_required
def clear_logs_route():
    """Clear all packet logs."""
    packet_logs.clear()
    return jsonify({"message": "Logs cleared successfully"})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)