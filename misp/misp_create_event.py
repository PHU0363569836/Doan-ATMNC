import os
import sys
import time
import threading
from misp_snort_gemini import process_snort_log
from misp_clamav_gemini import process_icap_log

if __name__ == "__main__":
    SNORT_LOG_FILE = "/var/log/snort/alert"
    ICAP_LOG_FILE = "/var/log/c-icap/virus_scan.log"
    missing = []
    if not os.path.exists(SNORT_LOG_FILE):
        missing.append(SNORT_LOG_FILE)
    if not os.path.exists(ICAP_LOG_FILE):
        missing.append(ICAP_LOG_FILE)

    if missing:
        print(f"[!] Log file(s) not found: {', '.join(missing)}")
        sys.exit(1)

    print(f"Monitoring {SNORT_LOG_FILE} And {ICAP_LOG_FILE}...")
    
    snort_thread = threading.Thread(target=process_snort_log, args=(SNORT_LOG_FILE,), daemon=True)
    icap_thread = threading.Thread(target=process_icap_log, args=(ICAP_LOG_FILE,), daemon=True)

    snort_thread.start()
    icap_thread.start()

    snort_thread.join()
    icap_thread.join()

    try:
        while True:
            time.sleep(1)  # Giữ cho main thread sống
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")