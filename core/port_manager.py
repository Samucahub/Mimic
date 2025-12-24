import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor

class PortManager:
    def __init__(self, max_workers: int = 10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_ports = {}
        
    def check_port_availability(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result != 0
        except:
            return False
    
    async def bind_port(self, port: int, handler):
        if not self.check_port_availability(port):
            raise ValueError(f"Port {port} is already in use")
        
        server = await asyncio.start_server(
            handler,
            '0.0.0.0',
            port,
            reuse_address=True
        )
        
        self.active_ports[port] = server
        return server