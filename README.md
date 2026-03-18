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

📂 Project Structure
dynamic-firewall-manager/
│── firewall_manager.py
│── logs.txt
│── blocked_ips.txt
│── README.md
⚙️ How It Works

The system reads incoming logs from a file

It analyzes the logs for suspicious activity

If a malicious IP is detected:

The IP is automatically blocked

A firewall rule is created

The event is logged

Alerts are generated for monitoring

▶️ How to Run

Clone the repository:

git clone https://github.com/Don-cybertect/dynamic-firewall-manager.git

Navigate to the project folder:

cd dynamic-firewall-manager

Run the script:

python firewall_manager.py
🧪 Sample Log Format
192.168.1.10 - Failed login attempt
10.0.0.5 - Multiple requests detected
172.16.0.2 - Suspicious activity detected
🎯 Use Case (SOC Perspective)

This project simulates how SOC analysts:

Monitor logs for threats

Identify malicious behavior

Automatically respond to incidents

Reduce response time using automation

📈 Future Improvements

Integrate with real firewall APIs (e.g., iptables, Windows Firewall)

Add machine learning for threat detection

Build a dashboard using Streamlit

Connect to a SIEM system

👤 Author

Your Name: Egwu Donatus Achema
GitHub: https://github.com/Don-cybertect
LinkDin: 

⭐ Contribute

Contributions, issues, and feature requests are welcome!

📜 License

This project is open-source and available under the MIT License.
