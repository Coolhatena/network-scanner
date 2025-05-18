import time
import os
from datetime import datetime

import nmap
from colorama import init, Fore, Style

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


def scan_network(network_range):
    nm = nmap.PortScanner()
    
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
    

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
    

def main():
    known_devices = {}
    
    while True:
        try:
            network = get_network_interface()
            network_range = '.'.join(network.split('.')[:-1]) + '.0/24'
            current_devices = scan_network(network_range)
            
            current_ips = [device['ip'] for device in current_devices]
            
            # Actualizar estado de dispositivos existentes
            for ip in known_devices:
                if ip in current_ips:
                    known_devices[ip].is_active = True
                    known_devices[ip].last_seen = datetime.now()
                else:
                    known_devices[ip].is_active = False
            
            # Agregar nuevos dispositivos
            for device in current_devices:
                if device['ip'] not in known_devices:
                    known_devices[device['ip']] = Device(device['ip'], device['hostname'])
            
            # Contar dispositivos activos
            active_devices = sum(1 for device in known_devices.values() if device.is_active)
            total_devices = len(known_devices)
            
            # Mostrar resultados
            clear_screen()
            print(f"\n{Fore.CYAN}=== Scanner de Red ===")
            print(f"Última actualización: {datetime.now().strftime('%H:%M:%S')}")
            print(f"Red escaneada: {network_range}")
            print(f"Tu IP: {network}")
            print(f"{Fore.GREEN}Dispositivos activos: {active_devices}/{total_devices}{Style.RESET_ALL}\n")
            
            # Mostrar dispositivos
            print(f"{Fore.YELLOW}{'IP':<16} {'Hostname':<30} {'Estado':<10} {'Última vez visto'}")
            print("-" * 70 + Style.RESET_ALL)
            
            # Ordenar dispositivos
            sorted_devices = sorted(
                known_devices.items(),
                key=lambda x: (not x[1].is_active, x[0])  # Ordenar por estado (activos primero) y luego por IP
            )
            
            for ip, device in sorted_devices:
                status_color = Fore.GREEN if device.is_active else Fore.LIGHTBLACK_EX
                status_text = "ACTIVO" if device.is_active else "INACTIVO"
                print(f"{status_color}{device.ip:<16} {device.hostname:<30} {status_text:<10} {device.last_seen.strftime('%H:%M:%S')}{Style.RESET_ALL}")
            
            
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Escaneo terminado por el usuario{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
            time.sleep(3)
            

if __name__ == "__main__":
    main()