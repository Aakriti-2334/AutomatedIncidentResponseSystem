from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import requests
import os
import pandas as pd
import time
import threading
import json

app = Flask(__name__)
socketio = SocketIO(app)

# --- Configuration ---
DASHBOARD_INGEST_URL = "http://127.0.0.1:5000/api/ingest"
HONEYPOT_ATTACK_URL = "http://127.0.0.1:8080/api/attack"
PACKET_INTERVAL_SECONDS = 2
simulation_thread = None
simulation_running = False

# --- Data Loading ---
try:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    HONEYPOT_DATA_PATH = os.path.join(BASE_DIR, '..', 'honeypot_dataset.csv')
    PREDICTION_DATA_PATH = os.path.join(BASE_DIR, '..', 'Models', 'cicids_live_predictions.csv')
    honeypot_df = pd.read_csv(HONEYPOT_DATA_PATH)
    prediction_df = pd.read_csv(PREDICTION_DATA_PATH)
    print("✅ Datasets loaded successfully for simulation.")
except FileNotFoundError as e:
    print(f"❌ CRITICAL ERROR: Could not find dataset files. The simulation cannot run. {e}")
    honeypot_df = None
    prediction_df = None

# --- Simulation Logic ---
def run_simulation_logic():
    """
    The core simulation logic, moved from the old attacker_simulator.py.
    This will run in a background thread.
    """
    global simulation_running
    if honeypot_df is None or prediction_df is None:
        print("❌ Cannot start simulation, datasets not loaded.")
        simulation_running = False
        return

    print("🚀 Starting attack simulation thread...")

    for index, row in honeypot_df.iterrows():
        # Check the flag at the start of each loop
        if not simulation_running:
            print("🛑 Simulation thread received stop signal.")
            break
        try:
            packet_data = row.to_dict()
            prediction_data = prediction_df.iloc[index].to_dict()

            packet_data = {k: v.item() if hasattr(v, 'item') else v for k, v in packet_data.items()}
            prediction_data = {k: v.item() if hasattr(v, 'item') else v for k, v in prediction_data.items()}

            payload = {"packet_data": packet_data, "prediction_data": prediction_data}
            
            # Post the attack to its own endpoint to trigger the synced flow
            requests.post(HONEYPOT_ATTACK_URL, json=payload)
            
            time.sleep(PACKET_INTERVAL_SECONDS)

        except Exception as e:
            print(f"Error during simulation loop: {e}")
            break
    
    print("✅ Simulation thread finished.")
    simulation_running = False


# --- Routes and API Endpoints ---
@app.route('/')
def index():
    """Render the main honeypot company website page."""
    return render_template('honeypot.html')

@app.route('/api/start_simulation', methods=['POST'])
def start_simulation():
    """Starts the simulation in a background thread."""
    global simulation_thread, simulation_running
    if simulation_running:
        return jsonify({"message": "Simulation is already running."}), 400

    simulation_running = True
    simulation_thread = threading.Thread(target=run_simulation_logic)
    simulation_thread.daemon = True
    simulation_thread.start()
    
    return jsonify({"message": "Simulation started."})

@app.route('/api/stop_simulation', methods=['POST'])
def stop_simulation():
    """Stops the currently running simulation."""
    global simulation_running
    if not simulation_running:
        return jsonify({"message": "Simulation is not running."}), 400
    
    print("Received request to stop simulation.")
    simulation_running = False
    return jsonify({"message": "Simulation stopping."})

@app.route('/api/attack', methods=['POST'])
def receive_attack():
    """
    This endpoint receives an attack from the simulator (running in its own thread).
    It then notifies its own frontend via WebSocket and forwards the data
    to the main dashboard for analysis.
    """
    attack_data = request.json
    if not attack_data:
        return jsonify({"error": "Invalid data"}), 400

    # 1. Notify the honeypot's own frontend to display the animation
    socketio.emit('attack_notification', attack_data)
    print(f"[Honeypot] Received attack: {attack_data.get('packet_data', {}).get('attack_type')}. Notifying frontend and forwarding to dashboard.")

    # 2. Forward the exact same data to the main dashboard
    try:
        dashboard_payload = {
            "packet_data": attack_data.get("packet_data"),
            "prediction_data": attack_data.get("prediction_data")
        }
        response = requests.post(DASHBOARD_INGEST_URL, json=dashboard_payload, timeout=2)
        
        if response.status_code == 200:
            print(f"[Honeypot] Successfully forwarded. Dashboard responded with {response.status_code}.")
        else:
            print(f"[Honeypot] ⚠️  Dashboard responded with an error: {response.status_code} {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"[Honeypot] ❌ CRITICAL: Could not forward data to dashboard: {e}")

    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    # Running on port 8080 to avoid conflict with the main dashboard on port 5000
    app.run(debug=True, port=8080, use_reloader=False) # use_reloader=False is important for threading

