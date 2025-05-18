import time
import os
from datetime import datetime

import nmap
from colorama import init, Fore, Back, Style

# Inicializar colorama
init()

class Device:
    def __init__(self, ip, hostname="Desconocido"):
        self.ip = ip
        self.hostname = hostname
        self.last_seen = datetime.now()
        self.is_active = True


def get_network_interface():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def scan_network():
    nm = nmap.PortScanner()
    network = get_network_interface()
    network_range = '.'.join(network.split('.')[:-1]) + '.0/24'
    
    try:
        nm.scan(hosts=network_range, arguments='-sn')
        devices = []
        
        for host in nm.all_hosts():
            try:
                hostname = nm[host].hostname()
            except:
                hostname = "Desconocido"
            devices.append({'ip': host, 'hostname': hostname})
        
        return devices
    except Exception as e:
        print(f"Error en el escaneo: {e}")
        return []