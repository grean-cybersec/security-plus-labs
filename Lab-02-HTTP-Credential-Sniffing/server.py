from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import datetime


class LoginHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        with open('login.html', 'rb') as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(length).decode('utf-8')
        params = parse_qs(post_data)

        username = params.get('username', [''])[0]
        password = params.get('password', [''])[0]

        # Esto aparecerá en la terminal — simula un log
        print(f"\n{'=' * 40}")
        print(f"[{datetime.datetime.now()}] LOGIN ATTEMPT")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"{'=' * 40}\n")

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Login received - check terminal")

    def log_message(self, format, *args):
        pass  # Silencia logs innecesarios


print("HTTP Server running on http://localhost:8080")
print("WARNING: Credentials transmitted in plaintext!")
HTTPServer(('localhost', 8080), LoginHandler).serve_forever()