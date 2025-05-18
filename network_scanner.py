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

