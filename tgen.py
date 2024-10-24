#!/usr/bin/env python3

# Core imports
import csv
import random
import time
import subprocess
import os
import platform
import paramiko
import requests
import logging
from threading import Thread
from pathlib import Path
from datetime import datetime
import socket
import nmap
import ftplib
import shutil
from io import BytesIO
import winrm
import ssl

# Try to import optional dependencies
HAVE_KERBEROS = False
HAVE_LDAP = False
HAVE_GSSAPI = False
HAVE_DNS = False

try:
    import kerberos
    HAVE_KERBEROS = True
except ImportError:
    pass

try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, KERBEROS
    HAVE_LDAP = True
except ImportError:
    pass

try:
    import gssapi
    HAVE_GSSAPI = True
except ImportError:
    pass

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    pass

class NetworkTrafficSimulator:
    def __init__(self, config_file='network_config.csv'):
        """
        Initialize the traffic simulator with configuration file
        Args:
            config_file (str): Path to CSV configuration file
        """
        self.config_file = config_file
        self.targets = []
        self.logger = self._setup_logging()
        self.running = True
        self.os_type = platform.system().lower()
        self.test_file_path = self._create_test_file()
        self.cleanup_files = []
        
        # Log available features
        self.logger.info("Available features:")
        self.logger.info(f"Kerberos Authentication: {'Yes' if HAVE_KERBEROS else 'No'}")
        self.logger.info(f"LDAP Support: {'Yes' if HAVE_LDAP else 'No'}")
        self.logger.info(f"GSSAPI Support: {'Yes' if HAVE_GSSAPI else 'No'}")
        self.logger.info(f"DNS Resolution: {'Yes' if HAVE_DNS else 'No'}")
        
    def __del__(self):
        """Cleanup any remaining test files"""
        self._cleanup_test_files()

    def _setup_logging(self):
        """Configure logging for the simulator"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_simulator.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('NetworkSimulator')

    def _create_test_file(self, size_kb=100):
        """
        Create a test file with random data if it doesn't exist
        Args:
            size_kb (int): Size of the test file in kilobytes
        Returns:
            str: Path to the test file
        """
        test_file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_data.txt')
        
        if not os.path.exists(test_file_path):
            with open(test_file_path, 'w') as f:
                chunk = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 32
                chunks_needed = (size_kb * 1024) // len(chunk) + 1
                f.write(chunk * chunks_needed)
            
            self.logger.info(f"Created test file: {test_file_path}")
        
        return test_file_path

    def _cleanup_test_files(self):
        """Clean up all test files created during the simulation"""
        try:
            if hasattr(self, 'test_file_path') and os.path.exists(self.test_file_path):
                os.remove(self.test_file_path)
            
            for file_path in self.cleanup_files:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    
            self.logger.info("Cleaned up all test files")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")

    def load_config(self):
        """
        Load target configurations from CSV file
        CSV Format: ip,protocol,username,password,port,share_path,domain,auth_method
        """
        try:
            with open(self.config_file, 'r') as f:
                reader = csv.DictReader(f)
                self.targets = list(reader)
            self.logger.info(f"Loaded {len(self.targets)} targets from configuration")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {str(e)}")
            raise

    def simulate_web_browsing(self, urls):
        """
        Simulate web browsing behavior
        Args:
            urls (list): List of URLs to visit
        """
        try:
            for url in urls:
                self.logger.info(f"Accessing URL: {url}")
                response = requests.get(url, timeout=10)
                time.sleep(random.uniform(1, 5))
        except Exception as e:
            self.logger.error(f"Web browsing error: {str(e)}")

    def simulate_ssh_connection(self, target):
        """
        Simulate SSH connections
        Args:
            target (dict): Target configuration containing connection details
        """
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                target['ip'],
                port=int(target.get('port', 22)),
                username=target['username'],
                password=target['password'],
                timeout=10
            )
            
            commands = ['ls', 'pwd', 'date', 'whoami', 'uptime']
            for cmd in commands:
                ssh.exec_command(cmd)
                time.sleep(random.uniform(0.5, 2))
            
            ssh.close()
            self.logger.info(f"SSH connection completed for {target['ip']}")
        except Exception as e:
            self.logger.error(f"SSH connection error to {target['ip']}: {str(e)}")

    def simulate_winrm(self, target):
        """
        Simulate Windows Remote Management connections
        Args:
            target (dict): Target configuration containing connection details
        """
        try:
            session = winrm.Session(
                target['ip'],
                auth=(target['username'], target['password']),
                transport='ntlm',
                server_cert_validation='ignore'
            )

            commands = [
                "Get-Process | Select-Object -First 5",
                "Get-Service | Select-Object -First 5",
                "Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version",
                "$PSVersionTable.PSVersion",
                "Get-Date",
                "Get-ComputerInfo | Select-Object WindowsProductName, OsVersion",
                "Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias"
            ]

            for cmd in commands:
                self.logger.info(f"Executing WinRM command on {target['ip']}: {cmd}")
                result = session.run_ps(cmd)
                time.sleep(random.uniform(1, 3))

        except Exception as e:
            self.logger.error(f"WinRM connection error to {target['ip']}: {str(e)}")

    def simulate_rdp_connection(self, target):
        """
        Simulate RDP connections using platform-specific commands
        Args:
            target (dict): Target configuration containing connection details
        """
        try:
            if self.os_type == 'windows':
                cmd = f'mstsc /v:{target["ip"]} /w:800 /h:600'
                subprocess.Popen(cmd, shell=True)
                time.sleep(10)
            else:
                cmd = f'xfreerdp /v:{target["ip"]} /u:{target["username"]} /p:{target["password"]} /w:800 /h:600 /cert-ignore'
                subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(10)
            self.logger.info(f"RDP connection simulated to {target['ip']}")
        except Exception as e:
            self.logger.error(f"RDP connection error to {target['ip']}: {str(e)}")

    def simulate_network_share(self, target):
        """
        Simulate network share access using UNC paths and file operations
        Args:
            target (dict): Target configuration containing share details
        """
        try:
            unc_path = target.get('share_path', f'\\\\{target["ip"]}\\share')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            remote_file = f'test_file_{timestamp}.txt'
            
            if self.os_type == 'windows':
                cmd = f'net use "{unc_path}" "{target["password"]}" /user:{target["username"]}'
                subprocess.run(cmd, shell=True, check=True)
                
                remote_path = os.path.join(unc_path, remote_file)
                shutil.copy2(self.test_file_path, remote_path)
                
                time.sleep(random.uniform(1, 3))
                
                shutil.copy2(remote_path, f"backup_{remote_file}")
                self.cleanup_files.append(f"backup_{remote_file}")
                
                os.remove(remote_path)
                cmd = f'net use "{unc_path}" /delete'
                subprocess.run(cmd, shell=True)
                
            else:
                share_path = unc_path.replace('\\\\', '//').replace('\\', '/')
                domain = target.get('domain', '')
                
                safe_name = share_path.replace('/', '_').replace('\\', '_')
                mount_point = f'/tmp/share_{safe_name}'
                os.makedirs(mount_point, exist_ok=True)
                
                if domain:
                    cmd = f'mount -t cifs "{share_path}" "{mount_point}" -o username={target["username"]},password={target["password"]},domain={domain}'
                else:
                    cmd = f'mount -t cifs "{share_path}" "{mount_point}" -o username={target["username"]},password={target["password"]}'
                
                subprocess.run(cmd, shell=True, check=True)
                
                remote_path = os.path.join(mount_point, remote_file)
                shutil.copy2(self.test_file_path, remote_path)
                
                time.sleep(random.uniform(1, 3))
                
                shutil.copy2(remote_path, f"backup_{remote_file}")
                self.cleanup_files.append(f"backup_{remote_file}")
                
                os.remove(remote_path)
                subprocess.run(f'umount "{mount_point}"', shell=True)
                try:
                    os.rmdir(mount_point)
                except:
                    pass
                    
            self.logger.info(f"Network share file operations completed for {unc_path}")
        except Exception as e:
            self.logger.error(f"Network share operation error for {unc_path}: {str(e)}")

    def simulate_ftp(self, target):
        """
        Simulate FTP/SFTP file transfers
        Args:
            target (dict): Target configuration containing FTP details
        """
        try:
            if target['protocol'] == 'sftp':
                transport = paramiko.Transport((target['ip'], int(target.get('port', 22))))
                transport.connect(username=target['username'], password=target['password'])
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                remote_path = f'test_file_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                sftp.put(self.test_file_path, remote_path)
                
                download_path = f'download_{os.path.basename(remote_path)}'
                sftp.get(remote_path, download_path)
                self.cleanup_files.append(download_path)
                
                sftp.remove(remote_path)
                sftp.close()
                transport.close()
                
            else:
                ftp = ftplib.FTP()
                ftp.connect(target['ip'], int(target.get('port', 21)))
                ftp.login(target['username'], target['password'])
                
                with open(self.test_file_path, 'rb') as f:
                    remote_path = f'test_file_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                    ftp.storbinary(f'STOR {remote_path}', f)
                
                download_path = f'download_{os.path.basename(remote_path)}'
                with open(download_path, 'wb') as f:
                    ftp.retrbinary(f'RETR {remote_path}', f.write)
                self.cleanup_files.append(download_path)
                
                ftp.delete(remote_path)
                ftp.quit()
                
            self.logger.info(f"FTP/SFTP operations completed for {target['ip']}")
        except Exception as e:
            self.logger.error(f"FTP/SFTP operation error for {target['ip']}: {str(e)}")

    def simulate_ldap_queries(self, target):
        """
        Simulate LDAP queries to Active Directory
        Args:
            target (dict): Target configuration containing LDAP details
        """
        if not HAVE_LDAP:
            self.logger.warning("LDAP support not available, skipping LDAP queries")
            return

        try:
            server = Server(target['ip'], get_info=ALL, use_ssl=False)
            
            # Try different bind formats
            bind_formats = [
                (f"{target.get('domain', '')}\\{target['username']}", NTLM),              # DOMAIN\user with NTLM
                (f"{target['username']}@{target.get('domain', '')}", NTLM),               # user@domain with NTLM
                (f"{target['username']}@{target.get('domain', '')}", SIMPLE),             # user@domain with SIMPLE
                (f"CN={target['username']},DC={',DC='.join(target.get('domain', '').split('.'))}", SIMPLE)  # DN format
            ]
            
            conn = None
            for bind_user, auth_method in bind_formats:
                try:
                    self.logger.info(f"Attempting LDAP bind with {bind_user} using {auth_method}")
                    conn = Connection(
                        server,
                        user=bind_user,
                        password=target['password'],
                        authentication=auth_method
                    )
                    if conn.bind():
                        self.logger.info(f"LDAP bind successful using {bind_user}")
                        break
                except Exception as bind_error:
                    self.logger.warning(f"Bind attempt failed for {bind_user}: {str(bind_error)}")
                    continue

            if conn and conn.bound:
                queries = [
                    "(objectClass=user)",
                    "(objectClass=group)",
                    "(&(objectClass=user)(mail=*))",
                    "(&(objectClass=group)(member=*))",
                    "(objectClass=computer)"
                ]
                
                bases = [
                    f"DC={',DC='.join(target.get('domain', '').split('.'))}",
                    f"CN=Users,DC={',DC='.join(target.get('domain', '').split('.'))}",
                    f"CN=Computers,DC={',DC='.join(target.get('domain', '').split('.'))}"
                ]

                for base in bases:
                    for query in queries:
                        try:
                            conn.search(base, query)
                            time.sleep(random.uniform(0.5, 2))
                        except Exception as search_error:
                            self.logger.warning(f"Search failed for {base} with {query}: {str(search_error)}")
                            continue

                self.logger.info(f"LDAP queries completed for {target['ip']}")
            else:
                self.logger.error(f"All LDAP bind attempts failed for {target['ip']}")

        except Exception as e:
            self.logger.error(f"LDAP operation error for {target['ip']}: {str(e)}")

    def simulate_kerberos_auth(self, target):
        """
        Simulate Kerberos authentication attempts
        Args:
            target (dict): Target configuration containing domain details
        """
        if not HAVE_KERBEROS or not HAVE_GSSAPI:
            self.logger.warning("Kerberos/GSSAPI support not available, skipping Kerberos auth")
            return

        try:
            service = f"host/{target['ip']}@{target['domain'].upper()}"
            name = gssapi.Name(service, name_type=gssapi.NameType.hostbased_service)
            ctx = gssapi.SecurityContext(name=name, usage='initiate')

            client_token = ctx.step()
            if client_token is not None:
                self.logger.info(f"Kerberos authentication simulated for {target['ip']}")

            if HAVE_DNS:
                self._simulate_dns_queries(target['domain'])

        except Exception as e:
            self.logger.error(f"Kerberos authentication error for {target['ip']}: {str(e)}")

    def _simulate_dns_queries(self, domain):
        """
        Simulate DNS queries that would occur in AD environment
        Args:
            domain (str): Domain name to query
        """
        if not HAVE_DNS:
            return

        try:
            record_types = ['A', 'AAAA', 'SRV', 'MX', 'TXT']
            srv_prefixes = ['_kerberos', '_ldap', '_kpasswd']
            
            for record_type in record_types:
                try:
                    dns.resolver.resolve(domain, record_type)
                    time.sleep(random.uniform(0.1, 0.5))
                except Exception:
                    pass

            for prefix in srv_prefixes:
                try:
                    dns.resolver.resolve(f'{prefix}._tcp.{domain}', 'SRV')
                    time.sleep(random.uniform(0.1, 0.5))
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"DNS query error for {domain}: {str(e)}")

    def discover_network(self, network_range):
        """
        Discover available hosts on the network using nmap
        Args:
            network_range (str): Network range to scan (e.g., '192.168.1.0/24')
        Returns:
            list: List of discovered hosts
        """
        try:
            nm = nmap.PortScanner()
            self.logger.info(f"Starting network discovery on range: {network_range}")
            nm.scan(hosts=network_range, arguments='-sn')
            discovered_hosts = list(nm.all_hosts())
            self.logger.info(f"Discovered {len(discovered_hosts)} hosts")
            return discovered_hosts
        except Exception as e:
            self.logger.error(f"Network discovery error: {str(e)}")
            return []

    def run_simulation(self):
        """Main simulation loop"""
        while self.running:
            try:
                # Add occasional web browsing simulation
                if random.random() < 0.2:  # 20% chance
                    self.simulate_web_browsing(['http://example.com', 'http://google.com'])
                    time.sleep(random.uniform(1, 3))
                
                for target in self.targets:
                    protocol = target['protocol'].lower()  # Get protocol from CSV
                    
                    # Process based on the protocol specified in CSV
                    if protocol == 'ssh':
                        self.simulate_ssh_connection(target)
                    elif protocol == 'rdp':
                        self.simulate_rdp_connection(target)
                    elif protocol == 'smb':
                        self.simulate_network_share(target)
                    elif protocol in ['ftp', 'sftp']:
                        self.simulate_ftp(target)
                    elif protocol == 'winrm':
                        self.simulate_winrm(target)
                    elif protocol == 'ldap' and HAVE_LDAP:
                        self.simulate_ldap_queries(target)
                    elif protocol == 'kerberos' and HAVE_KERBEROS and HAVE_GSSAPI:
                        self.simulate_kerberos_auth(target)
                    
                    time.sleep(random.uniform(5, 15))
            except Exception as e:
                self.logger.error(f"Simulation error: {str(e)}")
                time.sleep(5)

    def start(self):
        """Start the traffic simulation"""
        self.load_config()
        self.logger.info("Starting network traffic simulation")
        simulation_thread = Thread(target=self.run_simulation)
        simulation_thread.daemon = True
        simulation_thread.start()

    def stop(self):
        """Stop the traffic simulation"""
        self.running = False
        self.logger.info("Stopping network traffic simulation")

def main():
    """Main function to run the simulator"""
    try:
        simulator = NetworkTrafficSimulator()
        simulator.start()
        print("Network traffic simulation started. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping simulation...")
        simulator.stop()
        print("Simulation stopped. Cleaning up...")
    except Exception as e:
        print(f"Error during simulation: {str(e)}")
        simulator.stop()
    finally:
        simulator._cleanup_test_files()

if __name__ == "__main__":
    main()
