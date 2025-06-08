# misp_firewall_proxy.py
from pymisp import PyMISP
import subprocess
from datetime import datetime
import sys
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- CẤU HÌNH ---
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
config_file = "config.ini"
if (not MISP_URL or not MISP_KEY) and os.path.exists(config_file):
    # Nếu chưa có cấu hình qua env, thử đọc file config.ini
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        if not MISP_URL:
            MISP_URL = config.get("MISP", "url", fallback=None)
        if not MISP_KEY:
            MISP_KEY = config.get("MISP", "key", fallback=None)
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)

if not all([MISP_URL, MISP_KEY]):
    print("Missing environment variables: MISP_URL, MISP_KEY")
    sys.exit(1)
VERIFY_CERT = False

# File paths
LAST_FETCH_FILE = '/home/firewall/Desktop/DACN/last_fetch.txt'
IP_FILE = '/etc/iptables/ioc_ips'
DOMAIN_FILE = '/etc/squid/blacklist'

def get_last_fetch_time():
    if os.path.exists(LAST_FETCH_FILE):
        with open(LAST_FETCH_FILE, 'r') as f:
            return f.read().strip()
    return None

def set_last_fetch_time(new_time):
    with open(LAST_FETCH_FILE, 'w') as f:
        f.write(new_time)
        
def fetch_iocs():
    misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_CERT)
    last_fetch = get_last_fetch_time()
    
    search_params = {
        'controller': 'attributes',
        'type_attribute': ['ip-src', 'ip-dst', 'domain'],
        'return_format': 'json'
    }

    if last_fetch:
        search_params['timestamp'] = last_fetch

    result = misp.search(**search_params)
    
    ip_src = set()
    ip_dst = set()
    domains = set()
    max_ts = int(last_fetch) if last_fetch else 0
    
    attributes = result.get('Attribute', []) if isinstance(result, dict) else []

    for attr in attributes:
        attr_type = attr.get('type')
        value = attr.get('value')
        timestamp = int(attr.get('timestamp', 0))
        if timestamp > max_ts:
            max_ts = timestamp
        if attr_type in ['ip-src']:
            ip_src.add(value)
        elif attr_type in ['ip-dst']:
            ip_dst.add(value)
        elif attr_type == 'domain':
            domains.add(value)
            
    set_last_fetch_time(str(max_ts))
    return ip_src, ip_dst, domains


def append_unique_to_file(path, new_data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Đọc dữ liệu đã có
    existing = set()
    if os.path.exists(path):
        with open(path, 'r') as f:
            existing = set(line.strip() for line in f if line.strip())

    # Gộp mới + cũ và ghi lại (hoặc chỉ ghi thêm phần mới)
    combined = existing.union(new_data)

    with open(path, 'w') as f:
        for item in sorted(combined):
            f.write(item + '\n')

def apply_iptables(ip_src, ip_dst):
    # Kiểm tra xem chain MISP_BLOCK đã tồn tại chưa
    result = subprocess.run(['iptables', '-L', 'MISP_BLOCK'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        # Nếu chưa có, tạo mới và chèn vào INPUT và OUTPUT
        subprocess.call(['iptables', '-N', 'MISP_BLOCK'])
        subprocess.call(['iptables', '-I', 'INPUT', '-j', 'MISP_BLOCK'])
        subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'MISP_BLOCK'])

    for ip in ip_src:
        if ip != '192.168.255.100':
            subprocess.call(['iptables', '-A', 'MISP_BLOCK', '-s', ip, '-j', 'DROP'])
    for ip in ip_dst:
        if ip != '192.168.255.100':
            subprocess.call(['iptables', '-A', 'MISP_BLOCK', '-d', ip, '-j', 'DROP'])

def reload_squid():
    subprocess.call(['squid', '-k', 'reconfigure'])

def main():
    ip_src, ip_dst, domains = fetch_iocs()
    append_unique_to_file(IP_FILE, ip_src)
    append_unique_to_file(IP_FILE, ip_dst)
    append_unique_to_file(DOMAIN_FILE, domains)
    apply_iptables(ip_src, ip_dst)
    reload_squid()

if __name__ == '__main__':
    main()
