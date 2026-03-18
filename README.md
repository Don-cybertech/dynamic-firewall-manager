## 🔥 Dynamic Firewall Rule Manager (Python)

## 📌 Overview

The Dynamic Firewall Rule Manager is a cybersecurity automation tool built with Python that simulates how Security Operations Center (SOC) teams dynamically manage firewall rules in response to detected threats.

This project demonstrates real-world blue team skills such as:

Log analysis

Threat detection

Automated response

Incident handling

🚀 Features

✅ Real-time log monitoring

✅ Detection of suspicious IP addresses

✅ Automatic blocking of malicious IPs

✅ Rule management (add/remove/update firewall rules)

✅ Alert generation for detected threats

✅ Simulation of SOC response workflow

🛠️ Technologies Used

Python 3

File handling

Regular Expressions (Regex)

Logging module

The system reads incoming logs from a file

It analyzes the logs for suspicious activity

If a malicious IP is detected:

The IP is automatically blocked

A firewall rule is created

The event is logged

Alerts are generated for monitoring

▶️ How to Run

git clone https://github.com/Don-cybertect/dynamic-firewall-manager.git

Navigate to the project folder:

cd dynamic-firewall-manage

Below is an example of how the system detects and responds to threats in real time:
## Sample Output(Demo)
==== Dynamic Firewall Manager ====
1. Analyze Logs
2. Show Blocked IPs
3. Unblock IP
4. Exit
Select option: 1

[LOG ANALYSIS STARTED]

[ALERT] Brute force detected from 192.168.1.20

[FIREWALL] BLOCKED IP: 192.168.1.20

[ALERT] Port scan detected from 45.33.21.9

[FIREWALL] BLOCKED IP: 45.33.21.9

## 🔍 Detection & Response
The system scans logs and detects malicious activities

Identified attacks:

-Brute force attack

-Port scanning

Automatically blocks malicious IP addresses

Select option: 2

## Blocked IPs:
192.168.1.20

45.33.21.9

📋 Visibility

Displays all blocked IP addresses

Helps track active threats

Select option: 3

Enter IP to unblock: 45.33.21.9

[FIREWALL] UNBLOCKED IP: 45.33.21.9

🔓 Manual Control

Allows analysts to unblock IPs

Useful for handling false positives or restoring acces

## This project simulates how SOC analysts:

Monitor logs for threats

Identify malicious behavior

Automatically respond to incidents

Reduce response time using automation
## 📸 Live Demo

### 🔍 Threat Detection
![Detection](screenshots/detection.png)

### 🔥 Firewall Blocking
![Blocking](screenshots/blocking.png)

### 📋 Blocked IP List
![Blocked](screenshots/blocked.png)

👤 Author:Egwu Donatus Achema

GitHub: https://github.com/Don-cybertect

LinkDin: 

⭐ Contribute

Contributions, issues, and feature requests are welcome!

📜 License

This project is open-source and available under the MIT License.
