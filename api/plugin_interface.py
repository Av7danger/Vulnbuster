"""
VSCode Plugin API Stub
Exposes scan start/stop, module status, and report access for VSCode plugin.
"""
from flask import Flask, jsonify, request

app = Flask(__name__)

scan_status = {'running': False, 'modules': {}, 'report': None}

@app.route('/scan/start', methods=['POST'])
def start_scan():
    scan_status['running'] = True
    scan_status['modules'] = {'example_module': 'running'}
    return jsonify({'status': 'started'})

@app.route('/scan/stop', methods=['POST'])
def stop_scan():
    scan_status['running'] = False
    scan_status['modules'] = {k: 'stopped' for k in scan_status['modules']}
    return jsonify({'status': 'stopped'})

@app.route('/scan/status', methods=['GET'])
def get_status():
    return jsonify(scan_status)

@app.route('/scan/report', methods=['GET'])
def get_report():
    # Stub: In production, load real report
    return jsonify({'report': scan_status['report'] or 'No report yet.'})

if __name__ == '__main__':
    app.run(port=5001) 