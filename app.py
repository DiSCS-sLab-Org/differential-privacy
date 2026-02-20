#!/usr/bin/env python3
"""
Differential Privacy Query Web Application
Simple Flask web interface for querying attack counts with DP

Usage:
    python3 app.py          # Normal mode (clean result only)
    python3 app.py -d       # Debug mode (show all details)
"""

from flask import Flask, render_template, request, jsonify
from datetime import datetime
import numpy as np
import sys
import os
from fetch_day_attacks import fetch_attacks_for_day

app = Flask(__name__)

def env_flag(name, default=False):
    """Parse common truthy/falsey env var values."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# Debug mode can be enabled via CLI flag or env var (useful in Docker)
DEBUG_MODE = (
    '-d' in sys.argv
    or '--debug' in sys.argv
    or env_flag("DP_DEBUG_MODE", default=False)
)


def apply_differential_privacy(attack_data, epsilon):
    """
    Apply Laplace mechanism to attack count

    Args:
        attack_data: List of (IP, count) tuples
        epsilon: Privacy budget

    Returns:
        Dictionary with DP results
    """
    if not attack_data:
        return {
            "true_count": 0,
            "noisy_count": 0,
            "sensitivity": 0,
            "noise": 0,
            "noise_scale": 0,
            "num_ips": 0
        }

    # Calculate true count and sensitivity
    true_count = sum(count for _, count in attack_data)
    sensitivity = max(count for _, count in attack_data)

    # Add Laplace noise: noise ~ Laplace(0, sensitivity/epsilon)
    scale = sensitivity / epsilon
    noise = np.random.laplace(loc=0, scale=scale)

    # Noisy count (ensure non-negative)
    noisy_count = max(0, round(true_count + noise))

    return {
        "true_count": true_count,
        "noisy_count": noisy_count,
        "sensitivity": sensitivity,
        "noise": round(noise, 2),
        "noise_scale": round(scale, 2),
        "num_ips": len(attack_data)
    }


@app.route('/')
def index():
    """Render main dashboard page"""
    return render_template('index.html', debug_mode=DEBUG_MODE)


@app.route('/query', methods=['POST'])
def query():
    """Handle DP query request"""
    try:
        data = request.get_json()
        date_str = data.get('date')
        epsilon = float(data.get('epsilon', 1.0))

        # Validate date format
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return jsonify({
                "error": "Invalid date format. Use YYYY-MM-DD"
            }), 400

        # Validate epsilon
        if epsilon < 0.1 or epsilon > 10:
            return jsonify({
                "error": "Epsilon must be between 0.1 and 10"
            }), 400

        # Fetch data for the day
        attack_data = fetch_attacks_for_day(date_str)

        # Apply differential privacy
        result = apply_differential_privacy(attack_data, epsilon)

        # Prepare response
        response = {
            "success": True,
            "date": date_str,
            "epsilon": epsilon,
            "query_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "noisy_count": result["noisy_count"],
            "debug_mode": DEBUG_MODE  # Send debug mode flag to frontend
        }

        # Include debug information only in debug mode
        if DEBUG_MODE:
            response.update({
                "sensitivity": result["sensitivity"],
                "noise": result["noise"],
                "noise_scale": result["noise_scale"],
                "num_ips": result["num_ips"],
                "true_count": result["true_count"]
            })

        return jsonify(response)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


if __name__ == '__main__':
    import socket

    # Runtime settings (Docker and local friendly)
    PORT = int(os.getenv("APP_PORT", "8889"))
    HOST = os.getenv("APP_HOST", "0.0.0.0")
    FLASK_DEBUG = env_flag("FLASK_DEBUG", default=DEBUG_MODE)

    # Get hostname for network access
    hostname = socket.gethostname()

    print("=" * 60)
    print("🔒 Differential Privacy Attack Query Dashboard")
    print("=" * 60)
    if DEBUG_MODE:
        print("\n⚠️  DEBUG MODE ENABLED")
        print("   Showing all technical details for debugging")
        print("   Run without -d flag for clean production view")
    else:
        print("\n✓  PRODUCTION MODE")
        print("   Showing clean DP-protected results only")
        print("   Run with -d flag to enable debug mode")
    print("\nStarting web server...")
    print(f"\n📡 Access the dashboard:")
    print(f"   Local:   http://localhost:{PORT}")
    print(f"   Network: http://{hostname}:{PORT}")
    print("\nPress CTRL+C to stop the server")
    print("=" * 60)

    app.run(host=HOST, port=PORT, debug=FLASK_DEBUG)
