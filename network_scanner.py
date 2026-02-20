#!/usr/bin/env python3
"""
Network Scanner - Skeniranje mreže i pronalaženje svih uređaja
Pronalazi sve uređaje na mreži sa human-readable opisima
"""

import socket
import subprocess
import ipaddress
import threading
import time
import sys
import platform
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
import json
import re
import csv
import os
import urllib.request
import tempfile

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("⚠️  Rich library not available. Install with: pip install rich")
    print("   Falling back to basic output...\n")

from constants import MAC_VENDORS, PORT_SERVICES

class NetworkDevice:
    def __init__(self, ip: str):
        self.ip = ip
        self.mac = None
        self.hostname = None
        self.vendor = None
        self.open_ports = []
        self.services = []
        self.is_alive = False
        self.response_time = None
        self.device_type = "Unknown"
        
    def identify_device_type(self):
        """Identify device type based on vendor, hostname, and services"""
        hostname_lower = (self.hostname or "").lower()
        vendor_lower = (self.vendor or "").lower()
        
        # Smart TVs
        if any(x in vendor_lower for x in ['samsung', 'lg', 'sony', 'hisense', 'tcl', 'philips', 'panasonic']):
            if any(x in hostname_lower for x in ['tv', 'smart', 'android']):
                self.device_type = "Smart TV"
            else:
                self.device_type = f"TV ({self.vendor})"
        
        # Apple devices
        elif 'apple' in vendor_lower:
            if 'iphone' in hostname_lower or 'ipad' in hostname_lower:
                self.device_type = "iPhone/iPad"
            elif 'macbook' in hostname_lower or 'imac' in hostname_lower or 'mac' in hostname_lower:
                self.device_type = "Mac"
            else:
                self.device_type = "Apple Device"
        
        # Raspberry Pi
        elif 'raspberry' in vendor_lower or 'raspberry' in hostname_lower:
            self.device_type = "Raspberry Pi"
        
        # Virtual machines
        elif any(x in vendor_lower for x in ['vmware', 'virtualbox', 'parallels']):
            self.device_type = "Virtual Machine"
        
        # Routers/Gateways
        elif any(x in hostname_lower for x in ['router', 'gateway', 'modem', 'ap', 'access-point']):
            self.device_type = "Router/Gateway"
        
        # Printers
        elif 9100 in self.open_ports or 515 in self.open_ports or 631 in self.open_ports:
            self.device_type = "Printer"
        elif any(x in hostname_lower for x in ['printer', 'hp', 'canon', 'epson', 'brother']):
            self.device_type = "Printer"
        
        # NAS/Storage
        elif any(x in self.services for x in ['Synology', 'NFS', 'SMB/CIFS', 'Rsync']):
            self.device_type = "NAS/Storage"
        elif any(x in hostname_lower for x in ['nas', 'synology', 'qnap', 'storage']):
            self.device_type = "NAS/Storage"
        
        # Media servers
        elif 32400 in self.open_ports:  # Plex
            self.device_type = "Media Server (Plex)"
        elif 3689 in self.open_ports:  # iTunes/DAAP
            self.device_type = "Media Server (iTunes)"
        
        # Chromecast
        elif 8008 in self.open_ports or 8009 in self.open_ports:
            self.device_type = "Chromecast"
        
        # Mobile devices
        elif any(x in vendor_lower for x in ['xiaomi', 'huawei', 'samsung']):
            if any(x in hostname_lower for x in ['phone', 'mobile', 'android']):
                self.device_type = "Mobile Device"
        
        # Servers
        elif any(x in self.services for x in ['SSH', 'HTTP', 'HTTPS', 'MySQL', 'PostgreSQL']):
            if 'server' in hostname_lower or 'srv' in hostname_lower:
                self.device_type = "Server"
        
        return self.device_type

class NetworkScanner:
    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.console = Console() if RICH_AVAILABLE else None
        self._ieee_db_cache = None  # Cache for IEEE OUI database
        self._ieee_db_path = None  # Path to cached/downloaded database
        
    def get_local_network(self) -> Optional[str]:
        """Get local network CIDR"""
        try:
            # Try to get default gateway and interface
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse output like "default via 192.168.1.1 dev wlan0"
                    match = re.search(r'dev\s+(\w+)', result.stdout)
                    if match:
                        interface = match.group(1)
                        # Get IP and netmask for this interface
                        result = subprocess.run(['ip', 'addr', 'show', interface],
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            # Parse IP and CIDR
                            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
                            if match:
                                ip = match.group(1)
                                cidr = int(match.group(2))
                                # Calculate network
                                network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                                return str(network)
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(['route', '-n', 'get', 'default'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    match = re.search(r'interface:\s+(\w+)', result.stdout)
                    if match:
                        interface = match.group(1)
                        result = subprocess.run(['ifconfig', interface],
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)', result.stdout)
                            if match:
                                ip = match.group(1)
                                netmask_hex = match.group(2)
                                # Convert hex netmask to CIDR
                                netmask_int = int(netmask_hex, 16)
                                cidr = bin(netmask_int).count('1')
                                network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                                return str(network)
            elif platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse Windows ipconfig output
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'IPv4' in line or 'IP Address' in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match and i + 1 < len(lines):
                                subnet_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', lines[i + 1])
                                if subnet_match:
                                    ip = ipaddress.IPv4Address(ip_match.group(1))
                                    subnet = ipaddress.IPv4Address(subnet_match.group(1))
                                    cidr = sum(bin(int(x)).count('1') for x in str(subnet).split('.'))
                                    network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
                                    return str(network)
        except Exception as e:
            if self.console:
                self.console.print(f"[yellow]⚠️  Could not auto-detect network: {e}[/yellow]")
            else:
                print(f"⚠️  Could not auto-detect network: {e}")
        return None
    
    def ping_host(self, ip: str, timeout: float = 1.0) -> Tuple[bool, Optional[float]]:
        """Ping a host and return (is_alive, response_time)"""
        try:
            start = time.time()
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip],
                                      capture_output=True, timeout=timeout + 1)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', str(int(timeout)), ip],
                                      capture_output=True, timeout=timeout + 1)
            elapsed = time.time() - start
            return (result.returncode == 0, elapsed if result.returncode == 0 else None)
        except:
            return (False, None)
    
    def scan_with_arp_scan(self, network_cidr: str) -> Dict[str, str]:
        """Use arp-scan if available to get all devices with MAC addresses"""
        arp_results = {}
        try:
            # Try to use arp-scan (requires sudo)
            result = subprocess.run(['which', 'arp-scan'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                # Run arp-scan
                result = subprocess.run(['sudo', 'arp-scan', '--localnet', '--quiet'],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    # Parse arp-scan output: "192.168.1.1\t50:42:89:79:05:6f\t(Unknown)"
                    for line in result.stdout.split('\n'):
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            ip = parts[0].strip()
                            mac = parts[1].strip()
                            # Validate IP and MAC
                            try:
                                ipaddress.IPv4Address(ip)
                                if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', mac, re.IGNORECASE):
                                    arp_results[ip] = mac.upper().replace('-', ':')
                            except:
                                pass
        except:
            pass
        return arp_results
    
    def get_all_arp_entries(self) -> Dict[str, str]:
        """Get all ARP table entries at once"""
        arp_entries = {}
        try:
            if platform.system() == "Linux":
                # Get all ARP entries
                result = subprocess.run(['ip', 'neigh', 'show'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        # Format: "192.168.1.1 dev wlan0 lladdr 50:42:89:79:05:6f STALE"
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line, re.IGNORECASE)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).upper().replace('-', ':')
                            arp_entries[ip] = mac
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(['arp', '-a'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        # Format: "? (192.168.1.1) at 50:42:89:79:05:6f on en0"
                        match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line, re.IGNORECASE)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).upper().replace('-', ':')
                            arp_entries[ip] = mac
            elif platform.system() == "Windows":
                result = subprocess.run(['arp', '-a'],
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line, re.IGNORECASE)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).upper().replace('-', ':')
                            arp_entries[ip] = mac
        except:
            pass
        return arp_entries
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address using ARP table"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['ip', 'neigh', 'show', ip],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout:
                    match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', result.stdout)
                    if match:
                        return match.group(1).upper().replace('-', ':')
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(['arp', '-n', ip],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout:
                    match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', result.stdout)
                    if match:
                        return match.group(1).upper().replace('-', ':')
            elif platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and result.stdout:
                    match = re.search(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', result.stdout)
                    if match:
                        return match.group(1).upper().replace('-', ':')
        except:
            pass
        return None
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def identify_vendor(self, mac: str) -> Optional[str]:
        """Identify vendor from MAC address using IEEE OUI database or fallback to constants"""
        if not mac:
            return None
        mac_prefix = ':'.join(mac.split(':')[:3]).upper()
        
        # First try IEEE OUI database (much more comprehensive)
        vendor = self._get_vendor_from_ieee_db(mac_prefix)
        if vendor:
            return vendor
        
        # Fallback to hardcoded constants
        return MAC_VENDORS.get(mac_prefix)
    
    def _get_vendor_from_ieee_db(self, mac_prefix: str) -> Optional[str]:
        """Get vendor from IEEE OUI database - tries multiple locations"""
        # Convert MAC prefix to match format (remove colons, uppercase)
        mac_clean = mac_prefix.replace(':', '').upper()
        mac_clean_dash = mac_prefix.replace(':', '-').upper()
        
        # List of possible paths for IEEE OUI database
        possible_paths = []
        
        if platform.system() == "Linux":
            # Linux standard locations
            possible_paths = [
                '/usr/share/ieee-data/oui.csv',
                '/usr/share/ieee-data/oui.txt',
                '/usr/local/share/ieee-data/oui.csv',
                '/usr/local/share/ieee-data/oui.txt',
            ]
        elif platform.system() == "Darwin":  # macOS
            possible_paths = [
                '/usr/local/share/ieee-data/oui.csv',
                '/usr/local/share/ieee-data/oui.txt',
                '/opt/homebrew/share/ieee-data/oui.csv',
                '/opt/homebrew/share/ieee-data/oui.txt',
            ]
        elif platform.system() == "Windows":
            # Windows - try common locations or user's AppData
            appdata = os.getenv('APPDATA', '')
            localappdata = os.getenv('LOCALAPPDATA', '')
            possible_paths = [
                os.path.join(localappdata, 'ieee-data', 'oui.csv') if localappdata else None,
                os.path.join(localappdata, 'ieee-data', 'oui.txt') if localappdata else None,
                os.path.join(appdata, 'ieee-data', 'oui.csv') if appdata else None,
                os.path.join(appdata, 'ieee-data', 'oui.txt') if appdata else None,
                'oui.csv',  # Current directory
                'oui.txt',  # Current directory
            ]
            possible_paths = [p for p in possible_paths if p]  # Remove None values
        
        # Try CSV format first (faster, more reliable)
        for oui_csv_path in possible_paths:
            if oui_csv_path.endswith('.csv'):
                try:
                    with open(oui_csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.reader(f)
                        # Skip header
                        next(reader)
                        
                        for row in reader:
                            if len(row) >= 3:
                                assignment = row[1].strip().upper()
                                org_name = row[2].strip().strip('"')
                                
                                # Check if assignment matches (exact match for first 6 chars for MA-L)
                                if len(assignment) == 6 and assignment == mac_clean[:6]:
                                    return org_name
                        # If we read the file but didn't find a match, don't try other CSV files
                        break
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        
        # Fallback to TXT format if CSV not available
        for oui_txt_path in possible_paths:
            if oui_txt_path.endswith('.txt'):
                try:
                    with open(oui_txt_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            # Format: "00-22-72   (hex)		American Micro-Fuel Device Corp."
                            if mac_clean_dash in line and '(hex)' in line:
                                # Extract organization name (after tab)
                                parts = line.split('\t')
                                if len(parts) >= 2:
                                    org_name = parts[-1].strip()
                                    if org_name:
                                        return org_name
                        # If we read the file but didn't find a match, don't try other TXT files
                        break
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        
        # If no local database found, try to download it (one-time, cached)
        if not self._ieee_db_path:
            self._ieee_db_path = self._download_ieee_db()
        
        if self._ieee_db_path:
            try:
                if self._ieee_db_path.endswith('.csv'):
                    with open(self._ieee_db_path, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.reader(f)
                        next(reader)  # Skip header
                        for row in reader:
                            if len(row) >= 3:
                                assignment = row[1].strip().upper()
                                org_name = row[2].strip().strip('"')
                                if len(assignment) == 6 and assignment == mac_clean[:6]:
                                    return org_name
            except Exception:
                pass
        
        return None
    
    def _download_ieee_db(self) -> Optional[str]:
        """Download IEEE OUI database from official source if not available locally"""
        try:
            # Create cache directory
            cache_dir = os.path.join(tempfile.gettempdir(), 'network_scanner_ieee_db')
            os.makedirs(cache_dir, exist_ok=True)
            cache_file = os.path.join(cache_dir, 'oui.csv')
            
            # Check if already downloaded
            if os.path.exists(cache_file):
                return cache_file
            
            # Try to download from IEEE
            if self.console:
                self.console.print("[dim]Preuzimanje IEEE OUI baze podataka...[/dim]")
            else:
                print("Preuzimanje IEEE OUI baze podataka...")
            
            # IEEE official OUI CSV download URL
            oui_url = "https://standards-oui.ieee.org/oui/oui.csv"
            
            try:
                urllib.request.urlretrieve(oui_url, cache_file)
                if self.console:
                    self.console.print("[green]✓ IEEE OUI baza preuzeta[/green]")
                else:
                    print("✓ IEEE OUI baza preuzeta")
                return cache_file
            except Exception as e:
                if self.console:
                    self.console.print(f"[yellow]⚠ Nije moguće preuzeti IEEE bazu: {e}[/yellow]")
                else:
                    print(f"⚠ Nije moguće preuzeti IEEE bazu: {e}")
                return None
        except Exception:
            return None
    
    def scan_port(self, ip: str, port: int, timeout: float = 0.5) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_common_ports(self, ip: str) -> List[int]:
        """Scan common ports"""
        common_ports = [22, 23, 80, 443, 8080, 21, 25, 53, 110, 143, 993, 995, 3306, 5432, 3389,
                       5900, 5000, 1900, 36669, 9998, 8008, 8009, 32400, 3689, 5353, 631, 9100,
                       515, 161, 162, 427, 548, 62078, 5000, 5001, 873, 2049, 445, 139, 135, 137,
                       138, 389, 636, 1723, 1812, 1813, 5060, 5061, 3478, 1935, 554, 8554]
        open_ports = []
        for port in common_ports:
            if self.scan_port(ip, port):
                open_ports.append(port)
        return open_ports
    
    def scan_network(self, network_cidr: Optional[str] = None, scan_ports: bool = True):
        """Scan network for devices"""
        if not network_cidr:
            network_cidr = self.get_local_network()
            if not network_cidr:
                if self.console:
                    self.console.print("[red]❌ Could not detect network. Please specify with --network option[/red]")
                else:
                    print("❌ Could not detect network. Please specify with --network option")
                return
        
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
        except:
            if self.console:
                self.console.print(f"[red]❌ Invalid network: {network_cidr}[/red]")
            else:
                print(f"❌ Invalid network: {network_cidr}")
            return
        
        if self.console:
            self.console.print(f"[cyan]🔍 Skeniranje mreže: {network_cidr}[/cyan]")
            self.console.print(f"[dim]Pronalaženje aktivnih uređaja...[/dim]\n")
        else:
            print(f"🔍 Skeniranje mreže: {network_cidr}")
            print(f"Pronalaženje aktivnih uređaja...\n")
        
        # Phase 1: Try arp-scan first, then ARP table, then ping scan
        arp_devices = {}
        
        if self.console:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("🔍 Skeniranje mreže...", total=None)
                
                # Try arp-scan first (most reliable)
                progress.update(task, description="🔍 Pokušavam arp-scan...")
                arp_scan_results = self.scan_with_arp_scan(network_cidr)
                if arp_scan_results:
                    arp_devices = arp_scan_results
                    progress.update(task, description=f"✅ arp-scan pronašao {len(arp_devices)} uređaja")
                else:
                    # Fallback to ARP table
                    progress.update(task, advance=1)
                    progress.update(task, description="🔍 Koristim ARP tabelu...")
                    arp_devices = self.get_all_arp_entries()
                    if arp_devices:
                        progress.update(task, description=f"✅ ARP tabela pronašla {len(arp_devices)} uređaja")
        else:
            # Try arp-scan first (most reliable)
            print("Pokušavam arp-scan...", end='\r')
            arp_scan_results = self.scan_with_arp_scan(network_cidr)
            if arp_scan_results:
                arp_devices = arp_scan_results
                print(f"✓ arp-scan pronašao {len(arp_devices)} uređaja")
            else:
                # Fallback to ARP table
                print("Koristim ARP tabelu...", end='\r')
                arp_devices = self.get_all_arp_entries()
                if arp_devices:
                    print(f"✓ ARP tabela pronašla {len(arp_devices)} uređaja")
        
        # If we have ARP results, use them; otherwise fall back to ping
        if arp_devices:
            found_count = 0
            arp_list = list(arp_devices.items())
            total_arp = len(arp_list)
            
            if self.console:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                    task = progress.add_task("📋 Obrada ARP rezultata...", total=total_arp)
                    for ip, mac in arp_list:
                        # Check if IP is in the network
                        try:
                            if ipaddress.IPv4Address(ip) in network:
                                device = NetworkDevice(ip)
                                device.mac = mac
                                device.is_alive = True
                                # Try to ping for response time
                                is_alive, response_time = self.ping_host(ip)
                                device.response_time = response_time
                                self.devices[ip] = device
                                found_count += 1
                        except:
                            pass
                        progress.update(task, advance=1)
            else:
                for ip, mac in arp_list:
                    # Check if IP is in the network
                    try:
                        if ipaddress.IPv4Address(ip) in network:
                            device = NetworkDevice(ip)
                            device.mac = mac
                            device.is_alive = True
                            # Try to ping for response time
                            is_alive, response_time = self.ping_host(ip)
                            device.response_time = response_time
                            self.devices[ip] = device
                            found_count += 1
                    except:
                        pass
        else:
            # Fallback to ping scan
            hosts = list(network.hosts())
            total = len(hosts)
            found_count = 0
            
            if self.console:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                    task = progress.add_task("Skeniranje...", total=total)
                    for host in hosts:
                        ip = str(host)
                        is_alive, response_time = self.ping_host(ip)
                        if is_alive:
                            device = NetworkDevice(ip)
                            device.is_alive = True
                            device.response_time = response_time
                            self.devices[ip] = device
                            found_count += 1
                        progress.update(task, advance=1)
            else:
                for i, host in enumerate(hosts):
                    ip = str(host)
                    is_alive, response_time = self.ping_host(ip)
                    if is_alive:
                        device = NetworkDevice(ip)
                        device.is_alive = True
                        device.response_time = response_time
                        self.devices[ip] = device
                        found_count += 1
                    if (i + 1) % 10 == 0:
                        print(f"Progres: {i + 1}/{total}...", end='\r')
        
        if self.console:
            self.console.print(f"\n[green]✅ Pronađeno {found_count} aktivnih uređaja[/green]\n")
        else:
            print(f"\n✅ Pronađeno {found_count} aktivnih uređaja\n")
        
        # Phase 2: Get details for each device
        device_list = list(self.devices.items())
        total_devices = len(device_list)
        
        if self.console:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=self.console) as progress:
                task = progress.add_task("🔍 Identifikacija uređaja...", total=total_devices)
                for ip, device in device_list:
                    # Get MAC address if not already set
                    if not device.mac:
                        device.mac = self.get_mac_address(ip)
                    
                    # Get hostname
                    device.hostname = self.get_hostname(ip)
                    
                    # Identify vendor
                    if device.mac:
                        device.vendor = self.identify_vendor(device.mac)
                    
                    # Scan ports if requested
                    if scan_ports:
                        device.open_ports = self.scan_common_ports(ip)
                        device.services = [PORT_SERVICES.get(port, f"Port {port}") for port in device.open_ports]
                    
                    # Identify device type
                    device.identify_device_type()
                    
                    progress.update(task, advance=1)
        else:
            for i, (ip, device) in enumerate(device_list):
                # Get MAC address if not already set
                if not device.mac:
                    device.mac = self.get_mac_address(ip)
                
                # Get hostname
                device.hostname = self.get_hostname(ip)
                
                # Identify vendor
                if device.mac:
                    device.vendor = self.identify_vendor(device.mac)
                
                # Scan ports if requested
                if scan_ports:
                    device.open_ports = self.scan_common_ports(ip)
                    device.services = [PORT_SERVICES.get(port, f"Port {port}") for port in device.open_ports]
                
                # Identify device type
                device.identify_device_type()
                
                if (i + 1) % 5 == 0:
                    print(f"Identifikacija: {i + 1}/{total_devices}...", end='\r')
    
    def display_results(self):
        """Display scan results in a nice format"""
        if not self.devices:
            if self.console:
                self.console.print("[yellow]⚠️  Nisu pronađeni aktivni uređaji[/yellow]")
            else:
                print("⚠️  Nisu pronađeni aktivni uređaji")
            return
        
        if self.console:
            table = Table(title="🌐 Rezultati skeniranja mreže", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("IP Adresa", style="cyan", no_wrap=True)
            table.add_column("Hostname", style="green")
            table.add_column("MAC Adresa", style="yellow")
            table.add_column("Proizvođač", style="blue")
            table.add_column("Tip Uređaja", style="magenta", no_wrap=True)
            table.add_column("Servisi", style="dim")
            table.add_column("Ping (ms)", justify="right", style="dim")
            
            for ip, device in sorted(self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
                hostname = device.hostname or "N/A"
                mac = device.mac or "N/A"
                vendor = device.vendor or "Nepoznat"
                device_type = device.device_type
                services = ", ".join(device.services[:3]) if device.services else "N/A"
                if len(device.services) > 3:
                    services += f" (+{len(device.services) - 3})"
                ping_time = f"{device.response_time * 1000:.1f}" if device.response_time else "N/A"
                
                table.add_row(ip, hostname, mac, vendor, device_type, services, ping_time)
            
            self.console.print()
            self.console.print(table)
            self.console.print()
            
            # Summary
            summary = Table(box=box.SIMPLE, show_header=False)
            summary.add_column(style="bold")
            summary.add_column()
            summary.add_row("📊 Ukupno uređaja:", str(len(self.devices)))
            if self.devices:
                first_ip = list(self.devices.keys())[0]
                network_base = '.'.join(first_ip.split('.')[:-1]) + ".0/24"
                summary.add_row("🔍 Skenirana mreža:", network_base)
            else:
                summary.add_row("🔍 Skenirana mreža:", "N/A")
            
            device_types = {}
            for device in self.devices.values():
                device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
            
            for device_type, count in sorted(device_types.items()):
                summary.add_row(f"  • {device_type}:", str(count))
            
            self.console.print(Panel(summary, title="📈 Statistika", border_style="blue"))
        else:
            # Basic output without rich
            print("\n" + "=" * 100)
            print("🌐 REZULTATI SKENIRANJA MREŽE")
            print("=" * 100)
            print(f"{'IP Adresa':<18} {'Hostname':<25} {'MAC Adresa':<20} {'Proizvođač':<20} {'Tip':<20} {'Servisi':<30}")
            print("-" * 100)
            
            for ip, device in sorted(self.devices.items(), key=lambda x: ipaddress.IPv4Address(x[0])):
                hostname = (device.hostname or "N/A")[:24]
                mac = (device.mac or "N/A")[:19]
                vendor = (device.vendor or "Nepoznat")[:19]
                device_type = device.device_type[:19]
                services = ", ".join(device.services[:2]) if device.services else "N/A"
                if len(device.services) > 2:
                    services += f" (+{len(device.services) - 2})"
                services = services[:29]
                
                print(f"{ip:<18} {hostname:<25} {mac:<20} {vendor:<20} {device_type:<20} {services:<30}")
            
            print("=" * 100)
            print(f"\n📊 Ukupno uređaja: {len(self.devices)}")
            
            device_types = {}
            for device in self.devices.values():
                device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
            
            print("\n📈 Statistika po tipovima:")
            for device_type, count in sorted(device_types.items()):
                print(f"  • {device_type}: {count}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Skeniranje mreže i pronalaženje svih uređaja sa human-readable opisima',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primeri:
  %(prog)s                          # Automatski detektuje mrežu i skenira
  %(prog)s --network 192.168.1.0/24 # Skenira specifičnu mrežu
  %(prog)s --no-ports                # Bez skeniranja portova (brže)
  %(prog)s --json                    # Izlaz u JSON formatu
        """
    )
    parser.add_argument('--network', '-n', type=str, help='Mreža za skeniranje (npr. 192.168.1.0/24)')
    parser.add_argument('--no-ports', action='store_true', help='Ne skeniraj portove (brže)')
    parser.add_argument('--json', action='store_true', help='Izlaz u JSON formatu')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner()
    
    if args.json:
        # JSON output mode
        scanner.scan_network(args.network, scan_ports=not args.no_ports)
        devices_json = []
        for ip, device in scanner.devices.items():
            devices_json.append({
                'ip': device.ip,
                'hostname': device.hostname,
                'mac': device.mac,
                'vendor': device.vendor,
                'device_type': device.device_type,
                'open_ports': device.open_ports,
                'services': device.services,
                'response_time_ms': device.response_time * 1000 if device.response_time else None
            })
        print(json.dumps(devices_json, indent=2))
    else:
        # Normal output
        if scanner.console:
            scanner.console.print(Panel.fit(
                "[bold cyan]🌐 Network Scanner[/bold cyan]\n"
                "[dim]Skeniranje mreže i pronalaženje svih uređaja[/dim]",
                border_style="cyan"
            ))
            scanner.console.print()
        else:
            print("🌐 Network Scanner")
            print("Skeniranje mreže i pronalaženje svih uređaja\n")
        
        scanner.scan_network(args.network, scan_ports=not args.no_ports)
        scanner.display_results()

if __name__ == "__main__":
    main()

