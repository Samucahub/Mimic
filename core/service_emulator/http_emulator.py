import asyncio
import random
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs
from .base_service import BaseService

class HTTPService(BaseService):
    
    def __init__(self, port: int, config: Dict[str, Any]):
        super().__init__(port, config)
        self.name = "HTTP Server"
        self.banner = config.get('banner', 'Apache/2.4.29 (Ubuntu)')
        self.fake_pages = config.get('fake_pages', [])
        self.response_codes = config.get('response_codes', {200: 80, 404: 15, 500: 5})
        self.fake_responses = self.create_fake_responses()
        
    def create_fake_responses(self) -> Dict:
        return {
            "/": {
                "status": 200,
                "headers": {"Content-Type": "text/html"},
                "body": """<!DOCTYPE html>
<html>
<head>
    <title>Corporate Portal - Development Server</title>
    <style>body{font-family:Arial;margin:40px;} a{color:#0066cc;}</style>
</head>
<body>
    <h1>Corporate Internal Portal</h1>
    <p>Welcome to the development environment.</p>
    <ul>
        <li><a href="/admin/">Administration Panel</a></li>
        <li><a href="/login.php">User Login</a></li>
        <li><a href="/api/v1/">API Documentation</a></li>
        <li><a href="/uploads/">File Repository</a></li>
    </ul>
    <hr>
    <small>Apache/2.4.29 (Ubuntu) Server at 192.168.1.100 Port 80</small>
</body>
</html>"""
            },
            "/admin": {
                "status": 401,
                "headers": {"WWW-Authenticate": "Basic realm='Admin Area'"},
                "body": "401 Unauthorized - Admin access required"
            },
            "/admin/": {
                "status": 401,
                "headers": {"WWW-Authenticate": "Basic realm='Admin Area'"},
                "body": "401 Unauthorized - Admin access required"
            },
            "/login.php": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=UTF-8"},
                "body": """<!DOCTYPE html>
<html>
<head>
    <title>Login - Corporate Portal</title>
    <style>
        body{font-family:Arial;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
        .login-box{background:white;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:300px}
        h2{margin-top:0;color:#333}
        input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
        button{width:100%;padding:10px;background:#0066cc;color:white;border:none;border-radius:4px;cursor:pointer}
        button:hover{background:#0052a3}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        <form method="POST" action="/login.php">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>"""
            },
            "/config/config.ini": {
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": """[database]
host=10.0.0.10
port=3306
user=webapp_user
password=DbP@ss2024!Secure
dbname=production_db

[redis]
host=10.0.0.11
port=6379
password=R3d1sS3cr3t!

[smtp]
server=mail.company.internal
port=587
username=noreply@company.com
password=Sm7pP@ssw0rd!

[api_keys]
stripe=sk_live_51AbCdEf123456789
aws_access=AKIAIOSFODNN7EXAMPLE
aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
            },
            "/api/v1/": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": '{"status":"ok","version":"1.0","endpoints":["/api/v1/users","/api/v1/products","/api/v1/orders"]}'
            },
            "/uploads/": {
                "status": 200,
                "headers": {"Content-Type": "text/html"},
                "body": """<html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1><hr><pre>
<a href="../">../</a>
<a href="backup_20241220.zip">backup_20241220.zip</a>  15-Dec-2024 10:23  124M
<a href="database.sql">database.sql</a>              18-Dec-2024 14:32   45M
<a href="keys/">keys/</a>                        01-Dec-2024 09:15    -
</pre><hr></body></html>"""
            },
            "/robots.txt": {
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": """User-agent: *
Disallow: /admin/
Disallow: /config/
Disallow: /api/
Disallow: /uploads/backup/
Allow: /"""
            },
            "/phpinfo.php": {
                "status": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<html><body><h1>PHP Version 7.2.24</h1><p>System: Linux web-server 4.15.0-20-generic</p></body></html>"
            }
        }
    
    async def handle_connection(self, reader, writer):
        client_ip = writer.get_extra_info('peername')[0]
        self.log_connection(client_ip)
        
        try:
            data = await reader.read(4096)
            if not data:
                return
            
            request = data.decode('utf-8', errors='ignore')
            self.log_command(client_ip, request.split('\n')[0] if '\n' in request else request)

            response = await self.process_http_request(request, client_ip)
            
            writer.write(response.encode())
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"HTTP error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def process_http_request(self, request: str, client_ip: str) -> str:
        lines = request.strip().split('\n')
        if not lines:
            return self.generate_error_response(400)

        first_line = lines[0].split()
        if len(first_line) < 2:
            return self.generate_error_response(400)
        
        method = first_line[0]
        path = first_line[1]

        parsed = urlparse(path)
        path = parsed.path
        query_params = parse_qs(parsed.query)
        
        if self.detect_attack(path, query_params, request, client_ip):
            self.logger.warning(f"Potential attack detected from {client_ip}: {path}")
            return self.generate_honeypot_response()

        await self.simulate_human_delay()
        
        if path in self.fake_responses:
            response_config = self.fake_responses[path]
            return self.build_http_response(
                response_config["status"],
                response_config["headers"],
                response_config["body"]
            )
        else:
            status_code = self.choose_status_code()
            return self.build_http_response(
                status_code,
                {"Content-Type": "text/html"},
                self.generate_fake_page(status_code, path)
            )
    
    def detect_attack(self, path: str, query_params: dict, request: str, client_ip: str) -> bool:
        attack_patterns = [
            "etc/passwd",
            "../",
            "..\\",
            ".git/",
            ".env",
            "wp-admin",
            "SELECT",
            "UNION",
            "<script>",
            "eval(",
            "base64_decode",
            "phpinfo",
            "shell_exec",
            "cmd.exe"
        ]
        
        request_lower = request.lower()
        path_lower = path.lower()
        
        for pattern in attack_patterns:
            if pattern in path_lower or pattern in request_lower:
                return True
        
        for param_value in query_params.values():
            for value in param_value:
                value_lower = str(value).lower()
                if any(sql_keyword in value_lower 
                       for sql_keyword in ['select', 'union', 'insert', 'delete', 'drop']):
                    return True
        
        return False
    
    def generate_honeypot_response(self) -> str:
        fake_db_response = {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": """
            {
                "success": true,
                "data": {
                    "users": [
                        {"id": 1, "username": "admin", "password": "encrypted_hash"},
                        {"id": 2, "username": "root", "password": "hash_here"}
                    ],
                    "config": {
                        "database": "mysql://admin:password@localhost/app",
                        "api_key": "sk_live_1234567890abcdef",
                        "secret": "very_secret_token_here"
                    }
                }
            }
            """
        }
        return self.build_http_response(**fake_db_response)
    
    def choose_status_code(self) -> int:
        codes = []
        weights = []
        
        for code, weight in self.response_codes.items():
            codes.append(code)
            weights.append(weight)
        
        return random.choices(codes, weights=weights, k=1)[0]
    
    def generate_fake_page(self, status_code: int, path: str) -> str:
        if status_code == 404:
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>404 Not Found</title></head>
            <body>
                <h1>404 Not Found</h1>
                <p>The requested URL {path} was not found on this server.</p>
                <hr>
                <address>Apache/2.4.29 (Ubuntu) Server</address>
            </body>
            </html>
            """
        elif status_code == 500:
            return """
            <!DOCTYPE html>
            <html>
            <head><title>500 Internal Server Error</title></head>
            <body>
                <h1>500 Internal Server Error</h1>
                <p>The server encountered an internal error and was unable to complete your request.</p>
            </body>
            </html>
            """
        else:
            return f"""
            <!DOCTYPE html>
            <html>
            <head><title>Development Server</title></head>
            <body>
                <h1>Development Server</h1>
                <p>Path: {path}</p>
                <p>This is a development server. Content coming soon.</p>
            </body>
            </html>
            """
    
    def build_http_response(self, status_code: int, headers: dict, body: str) -> str:
        status_messages = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        
        response = [f"HTTP/1.1 {status_code} {status_messages.get(status_code, 'Unknown')}"]

        headers["Server"] = self.banner
        headers["Content-Length"] = str(len(body))
        
        for key, value in headers.items():
            response.append(f"{key}: {value}")
        
        response.append("")
        response.append(body)
        
        return "\r\n".join(response)