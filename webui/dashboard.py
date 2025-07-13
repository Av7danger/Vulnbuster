"""
Web Dashboard (FastAPI + SocketIO)
Features: scan status, module toggles, AI console, report viewer.
Usage: --dashboard
"""
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
import uvicorn
import asyncio

app = FastAPI()
scan_status = {'running': False, 'modules': {}, 'report': None}

@app.get('/')
def dashboard():
    html = """
    <html><head><title>WebBlood Dashboard</title></head>
    <body>
    <h1>Scan Dashboard</h1>
    <div id='status'></div>
    <button onclick="fetch('/start').then(()=>location.reload())">Start Scan</button>
    <button onclick="fetch('/stop').then(()=>location.reload())">Stop Scan</button>
    <h2>Report</h2>
    <pre id='report'></pre>
    <script>
    fetch('/status').then(r=>r.json()).then(d=>{
      document.getElementById('status').innerText = JSON.stringify(d);
    });
    fetch('/report').then(r=>r.json()).then(d=>{
      document.getElementById('report').innerText = d.report || 'No report yet.';
    });
    </script>
    </body></html>
    """
    return HTMLResponse(html)

@app.get('/start')
def start_scan():
    scan_status['running'] = True
    scan_status['modules'] = {'example_module': 'running'}
    return {'status': 'started'}

@app.get('/stop')
def stop_scan():
    scan_status['running'] = False
    scan_status['modules'] = {k: 'stopped' for k in scan_status['modules']}
    return {'status': 'stopped'}

@app.get('/status')
def get_status():
    return scan_status

@app.get('/report')
def get_report():
    return {'report': scan_status['report'] or 'No report yet.'}

@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        await websocket.send_json(scan_status)
        await asyncio.sleep(2)

if __name__ == '__main__':
    uvicorn.run(app, port=8000) 