# Task 1
🔐 Web Application Security Testing 

📌 Project Overview
This project demonstrates security testing of a sample web application to identify common vulnerabilities such as:

SQL Injection (SQLi)
Cross-Site Scripting (XSS)
Authentication & Authorization Flaws

The goal is to understand real-world web vulnerabilities, practice ethical hacking, and learn how attackers exploit weak implementations—while following responsible disclosure principles.

🎯 Objectives
Identify security weaknesses in a web application
Perform manual and automated penetration testing
Analyze vulnerabilities using industry-standard tools
Document findings with proof-of-concept (PoC)
Recommend mitigation techniques

🧠 Skills Gained
Web Application Security
Ethical Hacking & Penetration Testing
Vulnerability Assessment
HTTP/HTTPS Request Analysis
Secure Authentication Practices

🛠 Tools & Technologies Used
Tool
Purpose
OWASP ZAP
Automated vulnerability scanning & proxy
Burp Suite
Manual testing, request interception
SQLMap
Automated SQL injection detection
Browser DevTools
Inspect requests & responses
Linux / Kali Linux
Testing environment

🧪 Testing Methodology
Information Gathering
Identify input fields, parameters, cookies, headers
Automated Scanning
Scan using OWASP ZAP
Manual Testing
Intercept requests using Burp Suite
Exploitation
SQL injection testing using SQLMap
XSS payload testing
Authentication Analysis
Weak login checks
Session handling issues
Reporting
Vulnerability description

Proof of Concept
Fix recommendations

🚨 Vulnerabilities Identified

1️⃣ SQL Injection (SQLi)
Description:
Improper input validation allows attackers to manipulate SQL queries.
Test Payload Example:
Copy code
Sql
' OR '1'='1 --
Tool Used: SQLMap
Impact: Database access, data leakage, authentication bypass

2️⃣ Cross-Site Scripting (XSS)
Description:
User input is reflected without sanitization.
Test Payload Example:
Copy code
Html
<script>alert('XSS')</script>
Tool Used: Burp Suite / Manual
Impact: Session hijacking, defacement

3️⃣ Authentication Flaws
Description:
Weak password validation and improper session handling.
Issues Found:
No account lockout
Predictable session cookies
Missing logout invalidation
Impact: Unauthorized access

🔐 Security Recommendations
Use prepared statements / parameterized queries
Implement input validation & output encoding
Enable HttpOnly & Secure cookies
Apply strong password policies
Use CSRF tokens
Implement rate limiting & account lockout

#Task 2 - 🔐 Security Alert Monitoring & Incident Response (SOC Project)

This project demonstrates Security Operations Center (SOC) fundamentals by simulating real-world security alert monitoring and incident response activities using SIEM tools. The objective is to analyze logs, detect suspicious behavior, classify incidents, and prepare a structured Incident Response Report.

🎯 Project Objectives
Monitor security alerts generated from log data
Identify suspicious activities and potential attacks
Perform alert triage and incident classification
Draft a professional incident response report
Understand SOC analyst workflows

🛠 Tools & Technologies Used
Elastic Stack (ELK)
Elasticsearch
Logstash
Kibana
Splunk (Free Trial)
Sample log files (Web server, authentication, system logs)

🔍 Methodology
1️⃣ Log Ingestion
Imported sample logs into ELK Stack and Splunk
Parsed logs to extract fields such as:
IP address
Username
Timestamp
HTTP status codes
Failed login attempts

2️⃣ Alert Monitoring & Detection
Monitored SIEM dashboards for:
Multiple failed login attempts (Brute Force)
Login attempts from unusual IP locations
Excessive HTTP 404 / 500 errors
Suspicious request patterns
Example:
🔴 5+ failed logins from a single IP within 2 minutes
🔴 Admin login attempt outside business hours

3️⃣ Alert Triage
Each alert was analyzed and categorized as:
True Positive – Confirmed malicious activity
False Positive – Legitimate user behavior
Benign Event – No security impact

4️⃣ Incident Classification
Incidents were classified using standard SOC severity levels:
Severity
Incident Type
Low
Policy violation
Medium
Suspicious login
High
Brute-force attack
Critical
Account compromise

5️⃣ Incident Response Report
A detailed report was created including:
Incident summary
Timeline of events
Indicators of Compromise (IoCs)
Impact analysis
Containment & mitigation steps
Recommendations

🔐 TASK 3 – Secure File Sharing System

# 🔐 Secure File Sharing System (AES Encryption)

## 📌 Project Overview
This project is a secure file upload and download system that uses **AES-256 encryption**
to protect files at rest and during transfer.

Files are encrypted before storage and decrypted only during authorized download.

---

## 🛠 Tech Stack
- Python 3
- Flask
- PyCryptodome
- HTML/CSS
- Git & GitHub

---

## 🔒 Security Features
- AES-256 Encryption
- Secure Key Management
- Encrypted File Storage
- HTTPS-ready Architecture
- No Plaintext File Storage

---

## 📂 Project Structure

Run 
pip install flask pycryptodome
python app.py
