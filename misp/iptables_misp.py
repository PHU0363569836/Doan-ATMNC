import os
import csv

IP_FILE = "list_ip.csv"
URL_FILE = "list_url.csv"

ip_cache = set()
url_cache = set()

def load_cache_from_csv(field_name, filename):
    cache = set()
    if not os.path.isfile(filename):
        return cache
    with open(filename, mode="r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            val = row.get(field_name)
            if val:
                cache.add(val)
    return cache

def is_ioc_in_csv(ioc, field_name, filename):
    # File chưa tồn tại thì chắc chắn chưa có
    if not os.path.isfile(filename):
        return True
    
    with open(filename, mode="r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row.get(field_name) == ioc:
                return False
    return True

def save_ioc_to_csv(filename, ioc):
    # kiểm tra ioc có tồn tại không
    if not ioc:
        print(f"not ioc")
        return
    
    # Kiểm tra file là url hay ip dựa vào tên
    is_url_file = "url" in filename.lower()

    if is_url_file:
        fields = ["url"]
        value = ioc.get("url", "")

        if not value or value in url_cache:
            return
        
        url_cache.add(value)
        row = {"url": ioc.get("url", "")}
        
    else:
        fields = ["ip_src"]
        value = ioc.get("ip_src", "")

        if not value or value in ip_cache:
            return
        
        ip_cache.add(value)
        row = {"ip_src": ioc.get("ip_src", "")}

    # Kiểm tra nếu file chưa tồn tại thì ghi header
    file_exists = os.path.isfile(filename)
    
    with open(filename, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)

if __name__ == "__main__":
    
    # cache để tránh trung lặp tốc độ cao
    ip_cache = load_cache_from_csv("ip_src", IP_FILE)
    url_cache = load_cache_from_csv("url", URL_FILE)

    ioc = {"ip_src": "192.168.1.10"}
    save_ioc_to_csv(IP_FILE, ioc)