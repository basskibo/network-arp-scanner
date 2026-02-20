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

# MAC vendor database (common vendors)
MAC_VENDORS = {
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:1C:14': 'VMware',
    '00:05:69': 'VMware',
    '00:0F:4B': 'VMware',
    '08:00:27': 'VirtualBox',
    '00:1B:21': 'VirtualBox',
    '00:1C:42': 'Parallels',
    '00:25:90': 'Parallels',
    'B8:27:EB': 'Raspberry Pi Foundation',
    'DC:A6:32': 'Raspberry Pi Foundation',
    'E4:5F:01': 'Raspberry Pi Foundation',
    '28:CD:4C': 'Raspberry Pi Foundation',
    '00:1E:C2': 'Apple',
    '00:23:DF': 'Apple',
    '00:25:00': 'Apple',
    '00:25:4B': 'Apple',
    '00:26:08': 'Apple',
    '00:26:4A': 'Apple',
    '00:26:BB': 'Apple',
    '00:50:E4': 'Apple',
    '04:0C:CE': 'Apple',
    '04:15:52': 'Apple',
    '04:1E:64': 'Apple',
    '04:26:65': 'Apple',
    '04:4C:59': 'Apple',
    '04:54:53': 'Apple',
    '04:69:F8': 'Apple',
    '04:DB:56': 'Apple',
    '08:00:07': 'Apple',
    '08:66:98': 'Apple',
    '0C:3E:9F': 'Apple',
    '0C:4D:E9': 'Apple',
    '0C:74:C2': 'Apple',
    '0C:BC:9F': 'Apple',
    '0C:D7:46': 'Apple',
    '10:93:E9': 'Apple',
    '14:10:9F': 'Apple',
    '14:7D:DA': 'Apple',
    '18:65:90': 'Apple',
    '1C:1A:C0': 'Apple',
    '1C:AB:A7': 'Apple',
    '20:78:F0': 'Apple',
    '24:A0:74': 'Apple',
    '28:37:37': 'Apple',
    '28:CF:DA': 'Apple',
    '2C:1F:23': 'Apple',
    '2C:33:7A': 'Apple',
    '30:90:AB': 'Apple',
    '34:15:9E': 'Apple',
    '34:A3:95': 'Apple',
    '38:CA:DA': 'Apple',
    '3C:07:54': 'Apple',
    '40:33:1A': 'Apple',
    '40:A6:D9': 'Apple',
    '44:FB:42': 'Apple',
    '48:43:7C': 'Apple',
    '4C:8D:79': 'Apple',
    '50:EA:D6': 'Apple',
    '54:26:96': 'Apple',
    '58:55:CA': 'Apple',
    '5C:59:48': 'Apple',
    '5C:95:AE': 'Apple',
    '60:33:4B': 'Apple',
    '64:A5:C3': 'Apple',
    '68:96:7B': 'Apple',
    '6C:40:08': 'Apple',
    '70:48:0F': 'Apple',
    '78:31:C1': 'Apple',
    '7C:6D:62': 'Apple',
    '80:E6:50': 'Apple',
    '84:38:35': 'Apple',
    '88:63:DF': 'Apple',
    '8C:85:90': 'Apple',
    '90:72:40': 'Apple',
    '94:E9:6A': 'Apple',
    '98:01:A7': 'Apple',
    '9C:84:BF': 'Apple',
    'A0:99:9B': 'Apple',
    'A4:5E:60': 'Apple',
    'A8:60:B6': 'Apple',
    'AC:DE:48': 'Apple',
    'B0:65:BD': 'Apple',
    'B4:F0:AB': 'Apple',
    'B8:53:AC': 'Apple',
    'BC:52:B7': 'Apple',
    'C0:25:E9': 'Apple',
    'C4:2C:03': 'Apple',
    'C8:BC:C8': 'Apple',
    'CC:08:E0': 'Apple',
    'D0:03:4B': 'Apple',
    'D4:9A:20': 'Apple',
    'D8:30:62': 'Apple',
    'D8:A2:5E': 'Apple',
    'DC:A9:04': 'Apple',
    'E0:AC:CB': 'Apple',
    'E4:CE:8F': 'Apple',
    'E8:80:2E': 'Apple',
    'EC:35:86': 'Apple',
    'F0:DB:E2': 'Apple',
    'F4:F1:5A': 'Apple',
    'F8:1E:DF': 'Apple',
    'FC:25:3F': 'Apple',
    '00:1B:44': 'Samsung',
    '00:15:99': 'Samsung',
    '00:16:6B': 'Samsung',
    '00:1E:7D': 'Samsung',
    '00:1F:CC': 'Samsung',
    '00:23:39': 'Samsung',
    '00:24:54': 'Samsung',
    '00:26:5D': 'Samsung',
    '00:26:E8': 'Samsung',
    '00:50:F1': 'Samsung',
    '04:FE:31': 'Samsung',
    '08:00:28': 'Samsung',
    '0C:14:20': 'Samsung',
    '10:30:47': 'Samsung',
    '14:7D:DA': 'Samsung',
    '18:16:C9': 'Samsung',
    '1C:66:AA': 'Samsung',
    '20:02:AF': 'Samsung',
    '24:DB:AC': 'Samsung',
    '28:36:38': 'Samsung',
    '2C:44:FD': 'Samsung',
    '30:63:6B': 'Samsung',
    '34:23:87': 'Samsung',
    '38:16:D1': 'Samsung',
    '3C:BD:3E': 'Samsung',
    '40:B0:34': 'Samsung',
    '44:80:EB': 'Samsung',
    '48:13:7E': 'Samsung',
    '4C:66:41': 'Samsung',
    '50:EA:D6': 'Samsung',
    '54:92:BE': 'Samsung',
    '58:55:CA': 'Samsung',
    '5C:0A:5B': 'Samsung',
    '60:21:C0': 'Samsung',
    '64:16:66': 'Samsung',
    '68:27:37': 'Samsung',
    '6C:8D:C1': 'Samsung',
    '70:F1:1C': 'Samsung',
    '74:45:CE': 'Samsung',
    '78:25:AD': 'Samsung',
    '7C:1E:52': 'Samsung',
    '80:18:A7': 'Samsung',
    '84:25:DB': 'Samsung',
    '88:83:22': 'Samsung',
    '8C:3A:E3': 'Samsung',
    '90:48:9A': 'Samsung',
    '94:B1:0A': 'Samsung',
    '98:5F:D3': 'Samsung',
    '9C:65:B0': 'Samsung',
    'A0:AB:1B': 'Samsung',
    'A4:50:46': 'Samsung',
    'A8:96:75': 'Samsung',
    'AC:5A:14': 'Samsung',
    'B0:DF:C1': 'Samsung',
    'B4:AE:2B': 'Samsung',
    'B8:57:D8': 'Samsung',
    'BC:20:A4': 'Samsung',
    'C0:65:32': 'Samsung',
    'C4:62:EA': 'Samsung',
    'C8:85:50': 'Samsung',
    'CC:07:AB': 'Samsung',
    'D0:22:BE': 'Samsung',
    'D4:6E:5C': 'Samsung',
    'D8:57:EF': 'Samsung',
    'DC:66:72': 'Samsung',
    'E0:50:8B': 'Samsung',
    'E4:58:E7': 'Samsung',
    'E8:50:8B': 'Samsung',
    'EC:0E:C4': 'Samsung',
    'F0:25:B7': 'Samsung',
    'F4:09:D8': 'Samsung',
    'F8:77:B8': 'Samsung',
    'FC:62:B9': 'Samsung',
    '00:1A:79': 'LG Electronics',
    '00:1E:75': 'LG Electronics',
    '00:1F:E1': 'LG Electronics',
    '00:26:E2': 'LG Electronics',
    '00:50:7A': 'LG Electronics',
    '04:0A:95': 'LG Electronics',
    '08:00:28': 'LG Electronics',
    '0C:48:85': 'LG Electronics',
    '10:68:3F': 'LG Electronics',
    '14:10:9F': 'LG Electronics',
    '18:16:C9': 'LG Electronics',
    '1C:99:4C': 'LG Electronics',
    '20:21:A5': 'LG Electronics',
    '24:4B:81': 'LG Electronics',
    '28:5F:DB': 'LG Electronics',
    '2C:33:7A': 'LG Electronics',
    '30:85:A9': 'LG Electronics',
    '34:CE:00': 'LG Electronics',
    '38:2C:4A': 'LG Electronics',
    '3C:BD:D8': 'LG Electronics',
    '40:4E:36': 'LG Electronics',
    '44:4C:0C': 'LG Electronics',
    '48:51:B7': 'LG Electronics',
    '4C:BC:A5': 'LG Electronics',
    '50:2D:A4': 'LG Electronics',
    '54:92:BE': 'LG Electronics',
    '58:55:CA': 'LG Electronics',
    '5C:0A:5B': 'LG Electronics',
    '60:21:C0': 'LG Electronics',
    '64:16:66': 'LG Electronics',
    '68:27:37': 'LG Electronics',
    '6C:8D:C1': 'LG Electronics',
    '70:F1:1C': 'LG Electronics',
    '74:45:CE': 'LG Electronics',
    '78:25:AD': 'LG Electronics',
    '7C:1E:52': 'LG Electronics',
    '80:18:A7': 'LG Electronics',
    '84:25:DB': 'LG Electronics',
    '88:83:22': 'LG Electronics',
    '8C:3A:E3': 'LG Electronics',
    '90:48:9A': 'LG Electronics',
    '94:B1:0A': 'LG Electronics',
    '98:5F:D3': 'LG Electronics',
    '9C:65:B0': 'LG Electronics',
    'A0:AB:1B': 'LG Electronics',
    'A4:50:46': 'LG Electronics',
    'A8:96:75': 'LG Electronics',
    'AC:5A:14': 'LG Electronics',
    'B0:DF:C1': 'LG Electronics',
    'B4:AE:2B': 'LG Electronics',
    'B8:57:D8': 'LG Electronics',
    'BC:20:A4': 'LG Electronics',
    'C0:65:32': 'LG Electronics',
    'C4:62:EA': 'LG Electronics',
    'C8:85:50': 'LG Electronics',
    'CC:07:AB': 'LG Electronics',
    'D0:22:BE': 'LG Electronics',
    'D4:6E:5C': 'LG Electronics',
    'D8:57:EF': 'LG Electronics',
    'DC:66:72': 'LG Electronics',
    'E0:50:8B': 'LG Electronics',
    'E4:58:E7': 'LG Electronics',
    'E8:50:8B': 'LG Electronics',
    'EC:0E:C4': 'LG Electronics',
    'F0:25:B7': 'LG Electronics',
    'F4:09:D8': 'LG Electronics',
    'F8:77:B8': 'LG Electronics',
    'FC:62:B9': 'LG Electronics',
    '00:1C:23': 'Sony',
    '00:1D:0D': 'Sony',
    '00:1E:45': 'Sony',
    '00:24:BE': 'Sony',
    '00:26:4C': 'Sony',
    '00:50:C2': 'Sony',
    '04:0A:95': 'Sony',
    '08:00:28': 'Sony',
    '0C:48:85': 'Sony',
    '10:68:3F': 'Sony',
    '14:10:9F': 'Sony',
    '18:16:C9': 'Sony',
    '1C:99:4C': 'Sony',
    '20:21:A5': 'Sony',
    '24:4B:81': 'Sony',
    '28:5F:DB': 'Sony',
    '2C:33:7A': 'Sony',
    '30:85:A9': 'Sony',
    '34:CE:00': 'Sony',
    '38:2C:4A': 'Sony',
    '3C:BD:D8': 'Sony',
    '40:4E:36': 'Sony',
    '44:4C:0C': 'Sony',
    '48:51:B7': 'Sony',
    '4C:BC:A5': 'Sony',
    '50:2D:A4': 'Sony',
    '54:92:BE': 'Sony',
    '58:55:CA': 'Sony',
    '5C:0A:5B': 'Sony',
    '60:21:C0': 'Sony',
    '64:16:66': 'Sony',
    '68:27:37': 'Sony',
    '6C:8D:C1': 'Sony',
    '70:F1:1C': 'Sony',
    '74:45:CE': 'Sony',
    '78:25:AD': 'Sony',
    '7C:1E:52': 'Sony',
    '80:18:A7': 'Sony',
    '84:25:DB': 'Sony',
    '88:83:22': 'Sony',
    '8C:3A:E3': 'Sony',
    '90:48:9A': 'Sony',
    '94:B1:0A': 'Sony',
    '98:5F:D3': 'Sony',
    '9C:65:B0': 'Sony',
    'A0:AB:1B': 'Sony',
    'A4:50:46': 'Sony',
    'A8:96:75': 'Sony',
    'AC:5A:14': 'Sony',
    'B0:DF:C1': 'Sony',
    'B4:AE:2B': 'Sony',
    'B8:57:D8': 'Sony',
    'BC:20:A4': 'Sony',
    'C0:65:32': 'Sony',
    'C4:62:EA': 'Sony',
    'C8:85:50': 'Sony',
    'CC:07:AB': 'Sony',
    'D0:22:BE': 'Sony',
    'D4:6E:5C': 'Sony',
    'D8:57:EF': 'Sony',
    'DC:66:72': 'Sony',
    'E0:50:8B': 'Sony',
    'E4:58:E7': 'Sony',
    'E8:50:8B': 'Sony',
    'EC:0E:C4': 'Sony',
    'F0:25:B7': 'Sony',
    'F4:09:D8': 'Sony',
    'F8:77:B8': 'Sony',
    'FC:62:B9': 'Sony',
    '00:1A:2B': 'Hisense',
    '00:1C:23': 'Hisense',
    '00:1D:0D': 'Hisense',
    '00:1E:45': 'Hisense',
    '00:24:BE': 'Hisense',
    '00:26:4C': 'Hisense',
    '00:50:C2': 'Hisense',
    '00:1B:63': 'Xiaomi',
    '28:6E:D4': 'Xiaomi',
    '50:64:2B': 'Xiaomi',
    '64:09:80': 'Xiaomi',
    '8C:BE:BE': 'Xiaomi',
    'A0:C5:89': 'Xiaomi',
    'B0:E2:35': 'Xiaomi',
    'C8:1E:E7': 'Xiaomi',
    'DC:66:72': 'Xiaomi',
    'F0:B4:D2': 'Xiaomi',
    '00:1E:C2': 'Huawei',
    '00:23:DF': 'Huawei',
    '00:25:00': 'Huawei',
    '00:25:4B': 'Huawei',
    '00:26:08': 'Huawei',
    '00:26:4A': 'Huawei',
    '00:26:BB': 'Huawei',
    '00:50:E4': 'Huawei',
    '04:0C:CE': 'Huawei',
    '04:15:52': 'Huawei',
    '04:1E:64': 'Huawei',
    '04:26:65': 'Huawei',
    '04:4C:59': 'Huawei',
    '04:54:53': 'Huawei',
    '04:69:F8': 'Huawei',
    '04:DB:56': 'Huawei',
    '08:00:07': 'Huawei',
    '08:66:98': 'Huawei',
    '0C:3E:9F': 'Huawei',
    '0C:4D:E9': 'Huawei',
    '0C:74:C2': 'Huawei',
    '0C:BC:9F': 'Huawei',
    '0C:D7:46': 'Huawei',
    '10:93:E9': 'Huawei',
    '14:10:9F': 'Huawei',
    '14:7D:DA': 'Huawei',
    '18:65:90': 'Huawei',
    '1C:1A:C0': 'Huawei',
    '1C:AB:A7': 'Huawei',
    '20:78:F0': 'Huawei',
    '24:A0:74': 'Huawei',
    '28:37:37': 'Huawei',
    '28:CF:DA': 'Huawei',
    '2C:1F:23': 'Huawei',
    '2C:33:7A': 'Huawei',
    '30:90:AB': 'Huawei',
    '34:15:9E': 'Huawei',
    '34:A3:95': 'Huawei',
    '38:CA:DA': 'Huawei',
    '3C:07:54': 'Huawei',
    '40:33:1A': 'Huawei',
    '40:A6:D9': 'Huawei',
    '44:FB:42': 'Huawei',
    '48:43:7C': 'Huawei',
    '4C:8D:79': 'Huawei',
    '50:EA:D6': 'Huawei',
    '54:26:96': 'Huawei',
    '58:55:CA': 'Huawei',
    '5C:59:48': 'Huawei',
    '5C:95:AE': 'Huawei',
    '60:33:4B': 'Huawei',
    '64:A5:C3': 'Huawei',
    '68:96:7B': 'Huawei',
    '6C:40:08': 'Huawei',
    '70:48:0F': 'Huawei',
    '78:31:C1': 'Huawei',
    '7C:6D:62': 'Huawei',
    '80:E6:50': 'Huawei',
    '84:38:35': 'Huawei',
    '88:63:DF': 'Huawei',
    '8C:85:90': 'Huawei',
    '90:72:40': 'Huawei',
    '94:E9:6A': 'Huawei',
    '98:01:A7': 'Huawei',
    '9C:84:BF': 'Huawei',
    'A0:99:9B': 'Huawei',
    'A4:5E:60': 'Huawei',
    'A8:60:B6': 'Huawei',
    'AC:DE:48': 'Huawei',
    'B0:65:BD': 'Huawei',
    'B4:F0:AB': 'Huawei',
    'B8:53:AC': 'Huawei',
    'BC:52:B7': 'Huawei',
    'C0:25:E9': 'Huawei',
    'C4:2C:03': 'Huawei',
    'C8:BC:C8': 'Huawei',
    'CC:08:E0': 'Huawei',
    'D0:03:4B': 'Huawei',
    'D4:9A:20': 'Huawei',
    'D8:30:62': 'Huawei',
    'D8:A2:5E': 'Huawei',
    'DC:A9:04': 'Huawei',
    'E0:AC:CB': 'Huawei',
    'E4:CE:8F': 'Huawei',
    'E8:80:2E': 'Huawei',
    'EC:35:86': 'Huawei',
    'F0:DB:E2': 'Huawei',
    'F4:F1:5A': 'Huawei',
    'F8:1E:DF': 'Huawei',
    'FC:25:3F': 'Huawei',
}

# Common port services
PORT_SERVICES = {
    22: 'SSH',
    23: 'Telnet',
    80: 'HTTP',
    443: 'HTTPS',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    21: 'FTP',
    25: 'SMTP',
    53: 'DNS',
    110: 'POP3',
    143: 'IMAP',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    3389: 'RDP',
    5900: 'VNC',
    5901: 'VNC',
    5000: 'UPnP',
    1900: 'UPnP',
    36669: 'VIDAA TV',
    9998: 'VIDAA TV Alt',
    8080: 'Smart TV',
    8008: 'Chromecast',
    8009: 'Chromecast',
    32400: 'Plex',
    3689: 'iTunes/DAAP',
    5353: 'mDNS/Bonjour',
    631: 'IPP/CUPS',
    9100: 'HP Printer',
    515: 'LPD',
    161: 'SNMP',
    162: 'SNMP Trap',
    427: 'SLP',
    548: 'AFP',
    548: 'Apple Filing Protocol',
    62078: 'iPhone Sync',
    5000: 'Synology',
    5001: 'Synology',
    5005: 'Synology',
    5006: 'Synology',
    873: 'Rsync',
    2049: 'NFS',
    445: 'SMB/CIFS',
    139: 'NetBIOS',
    135: 'MS-RPC',
    137: 'NetBIOS Name',
    138: 'NetBIOS Datagram',
    389: 'LDAP',
    636: 'LDAPS',
    1723: 'PPTP',
    1812: 'RADIUS',
    1813: 'RADIUS Accounting',
    5060: 'SIP',
    5061: 'SIP-TLS',
    3478: 'STUN',
    1935: 'RTMP',
    554: 'RTSP',
    8554: 'RTSP',
    1935: 'Flash Media Server',
    7001: 'WebLogic',
    7002: 'WebLogic',
    8081: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    9000: 'SonarQube',
    9090: 'Cockpit',
    9091: 'Transmission',
    51413: 'BitTorrent',
    6881: 'BitTorrent',
    6882: 'BitTorrent',
    6883: 'BitTorrent',
    6884: 'BitTorrent',
    6885: 'BitTorrent',
    6886: 'BitTorrent',
    6887: 'BitTorrent',
    6888: 'BitTorrent',
    6889: 'BitTorrent',
}

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
        """Identify vendor from MAC address"""
        if not mac:
            return None
        mac_prefix = ':'.join(mac.split(':')[:3]).upper()
        return MAC_VENDORS.get(mac_prefix)
    
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
        
        # Phase 1: Ping scan
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
            self.console.print("[dim]Identifikacija uređaja...[/dim]\n")
        else:
            print(f"\n✅ Pronađeno {found_count} aktivnih uređaja\n")
            print("Identifikacija uređaja...\n")
        
        # Phase 2: Get details for each device
        for ip, device in self.devices.items():
            # Get MAC address
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

