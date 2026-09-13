from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get('Content-Length','0'))
        body=self.rfile.read(n)
        try: json.loads(body)
        except Exception: pass
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(b'{"ok":true}')
    def log_message(self, fmt, *args): pass
HTTPServer(('127.0.0.1',9010),H).serve_forever()
