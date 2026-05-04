# SQL Injection Scanner 🔍

A Python-based SQL Injection Scanner built for ethical security testing on permitted targets like DVWA.

---

## Features
- Automated SQL injection payload testing
- CSRF token handling & session management
- Concurrent scanning (3 workers)
- Rate limiting to avoid server overload
- Detailed logging to `sql_scanner.log`
- JSON & CSV report generation

## Tech Stack
- Python 3.x
- `requests` — HTTP requests
- `beautifulsoup4` — CSRF token parsing
- `tqdm` — Progress bar
- `concurrent.futures` — Multithreading

## Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/J-M-Rawsan/Syntecxhub_SQL_Injection_Scanner.git
cd Syntecxhub_SQL_Injection_Scanner
```

### 2. Install Dependencies
```bash
pip install requests tqdm beautifulsoup4
```

### 3. Setup DVWA
- Install XAMPP → Start Apache & MySQL
- Open `http://localhost:8080`
- Login: `admin / password`
- Set Security Level to **Low**

### 4. Run the Scanner
```bash
python sql_scanner.py
```

## Output Files
| File | Description |
|------|-------------|
| `sql_scanner.log` | Detailed scan logs with timestamps |
| `report_YYYYMMDD_HHMMSS.json` | Full JSON report |
| `report_YYYYMMDD_HHMMSS.csv` | CSV report for spreadsheet viewing |

## Sample Output

```bash
Login SUCCESS!
Security level set to LOW
Starting scan with 3 concurrent workers...
[VULNERABLE] Payload : 1' OR '1'='1
Reason  : SQL result leaked (First Name/Surname visible)
Scan Complete!
Vulnerable : 9
Safe       : 0
Total      : 9
```

## ⚠️ Disclaimer

- This tool is for **educational purposes only**.
- Only test on systems you have **explicit permission** to test.
- Unauthorized use is illegal and unethical.

## Internship
Built as part of the **Syntecxhub Cybersecurity Internship Program**
> CREATE | THINK | SOLVE
<br>
