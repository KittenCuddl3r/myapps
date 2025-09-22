#!/usr/bin/env python3
import socket
from scapy.all import ARP, Ether, srp
import os, sys
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed


class concurrent_scanner:
    def __init__(self, IP):
        print('In __init__')
        self.current_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self
        self.IP = IP
        self.ip_scan_path = ""
        self.IP_FILE_NAME = f"{self.current_timestamp}IPSCAN.txt"
        self.COMMON_PORTS = [
    # Essential Services
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    993,   # IMAPS
    995,   # POP3S
    
    # Common Application Ports
    135,   # MS RPC
    139,   # NetBIOS
    445,   # SMB
    1433,  # MSSQL
    1521,  # Oracle DB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    27017, # MongoDB
    
    # Network Equipment
    161,   # SNMP
    162,   # SNMP Trap
    179,   # BGP
    389,   # LDAP
    636,   # LDAPS
    902,   # VMware ESXi
    1723,  # PPTP
    
    # Gaming & Media
    3074,  # Xbox Live
    3478,  # STUN/TURN
    5060,  # SIP
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
    
    # Windows Services
    88,    # Kerberos
    135,   # MS RPC
    139,   # NetBIOS
    389,   # LDAP
    445,   # SMB
    464,   # Kerberos Change/Set password
    636,   # LDAPS
    3268,  # Global Catalog LDAP
    3269,  # Global Catalog LDAPS
    
    # Linux/Unix Services
    111,   # RPCbind
    512,   # Rexec
    513,   # Rlogin
    514,   # Syslog
    2049,
    9998]

        

    def file_creation_path_handling(self):
        try:
            self.PORTSCAN_FOLDER_PATH = os.path.join(
                os.getcwd(), 
                "results",
                self.current_timestamp, 
                "PORTscan")
            os.makedirs(self.PORTSCAN_FOLDER_PATH, exist_ok=True)
            self.IP_ARPSCAN_FOLDER_PATH = os.path.join(os.getcwd(), "results", self.current_timestamp, "IPscan") ##Define the name of the IP path
            os.makedirs(self.IP_ARPSCAN_FOLDER_PATH, exist_ok=True)
            print(self.IP_ARPSCAN_FOLDER_PATH)
            self.IP_ARPSCAN_FILE = os.path.join(self.IP_ARPSCAN_FOLDER_PATH, self.IP_FILE_NAME)
            print(self.IP_ARPSCAN_FILE)
        except (PermissionError, FileNotFoundError, OSError) as er:
            print(er)

    def arp_scan(self):
        try:
            arp_request = ARP(pdst=self.IP)
            ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether_frame / arp_request
            result = srp(packet, timeout=6, verbose=True)[0]
            MAC_PATH = os.path.join(os.getcwd(), "macscan", self.current_timestamp) ##Creating path variable 
            os.makedirs(MAC_PATH, exist_ok=True) ##Creating macscan folder in current directory called macscan and current time and data
            MAC_PATH_FILE = os.path.join(MAC_PATH, f"{self.current_timestamp}MACscan.txt") ##Initialize new variable for creation of file
            if not result:
                print("No ARP responses received")
            else:
                try:
                    with open(self.IP_ARPSCAN_FILE, 'w') as i, open(MAC_PATH_FILE, 'w') as m:
                        for sent, received in result:
                            if received.psrc and received.hwsrc:
                                i.write(f'{received.psrc}\n')
                                m.write(f'{received.hwsrc}\n')
                            else:
                                print("Oopsie")
                except (FileNotFoundError, ConnectionError) as e:
                    print(e)

        except Exception as er:
            print(er)
                
    def single_ip_scan(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                result = s.connect_ex((str(ip), int(port)))
                #print(f'Scanned {ip}, with port{port} and got {result}')
                if result == 0:
                    return (ip, port, True)
        except Exception as e:
            return (ip, port, False)
            
        
    def port_open(self):
        tasks = []
        try:
            with open(self.IP_ARPSCAN_FILE, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]    
                for port in self.COMMON_PORTS:
                        for ip in ips:
                            ip_f = os.path.join(self.PORTSCAN_FOLDER_PATH, f"{ip}_scan.txt")
                            open(ip_f, 'w').close()
                            tasks.append((ip, port))
                with ProcessPoolExecutor(max_workers=15) as executor:
                    future_to_task = {executor.submit(self.single_ip_scan, ip, port): (ip, port) for (ip, port) in tasks} ##For every ip port turple in tasks append it to .submit(single_ip_scan), then store the future in future_to_Ttask
                    for future in as_completed(future_to_task): ##for every future object, that is completed
                        ip, port = future_to_task[future]
                        result = future.result()
                        try:
                            if result == None:
                                self.single_ip_scan(ip, port)
                            else:
                                ip, port, is_open = result
                                if is_open:
                                    print(ip)
                                    ip_f = os.path.join(self.PORTSCAN_FOLDER_PATH, f"{ip}_scan.txt")
                                    print(ip_f, ip, port)
                                    with open(ip_f, 'a') as f:
                                        f.write(f'{port}\n')
                        except Exception as a:
                            print(f"Exception occured in try clause responsible for receiving future.result, exception was {a}")
        except Exception as e:
            print(f"Exception occured in outer clause of port_open, exception was: {e}")


def main():
    try:
        if len(sys.argv) > 1:
            scanner = concurrent_scanner(sys.argv[1])
            scanner.file_creation_path_handling()
            scanner.arp_scan()
            scanner.port_open()
            print('In main')
        else:
            scanner = concurrent_scanner("192.168.1.1/24")
            scanner.file_creation_path_handling()
            scanner.arp_scan()
            scanner.port_open()
    except Exception:
        print(Exception)

if __name__ == "__main__":
    main()

