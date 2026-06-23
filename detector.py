from datetime import datetime, timedelta

BASE_TIME = datetime.now().replace(hour=22, minute=0, second=0, microsecond=0)

ALERTS = [
    {
        'id': 'ALT-001',
        'type': 'port_scan',
        'title': 'Port Scan Detected',
        'source_ip': '185.220.101.47',
        'destination': '10.0.0.0/24 (Internal subnet)',
        'timestamp': (BASE_TIME + timedelta(minutes=5)).strftime('%H:%M:%S'),
        'mitre': 'T1046',
        'mitre_name': 'Network Service Discovery',
        'description': 'External IP 185.220.101.47 scanned 1,247 ports across the internal subnet over 3 minutes. Pattern consistent with Nmap SYN scan. No successful connections established.',
        'severity': 'Medium',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'Firewall IDS',
        'raw_log': '22:05:13 WARN firewall: SYN scan 185.220.101.47 -> 10.0.0.0/24, 1247 ports in 180s, 0 established'
    },
    {
        'id': 'ALT-002',
        'type': 'brute_force',
        'title': 'SSH Brute Force Attack',
        'source_ip': '45.33.32.156',
        'destination': '10.0.1.15 (prod-server-01)',
        'timestamp': (BASE_TIME + timedelta(minutes=12)).strftime('%H:%M:%S'),
        'mitre': 'T1110',
        'mitre_name': 'Brute Force',
        'description': '847 failed SSH login attempts from 45.33.32.156 against prod-server-01 over 4 minutes. Usernames targeted: root, admin, ubuntu, deploy. No successful authentication detected.',
        'severity': 'High',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'SIEM / Auth Logs',
        'raw_log': '22:12:44 ERROR sshd: 847 failed auth from 45.33.32.156 in 240s. Last attempt: root@prod-server-01'
    },
    {
        'id': 'ALT-003',
        'type': 'phishing',
        'title': 'Phishing Campaign — 3 Users Clicked',
        'source_ip': 'loser@hotmail.com',
        'destination': '14 staff recipients',
        'timestamp': (BASE_TIME + timedelta(minutes=28)).strftime('%H:%M:%S'),
        'mitre': 'T1566.001',
        'mitre_name': 'Spearphishing Link',
        'description': 'Email gateway flagged phishing campaign to 14 staff. Subject: "Urgent: Password Reset Required". Link resolves to credential harvesting page at onenewzealand-secure.evilcorp.ru. Click logs confirm 3 users accessed the link.',
        'severity': 'Critical',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'Email Gateway',
        'raw_log': '22:28:01 CRITICAL email_filter: PHISH loser@hotmail.com -> 14 staff. URL: http://onenewzealand-secure.evilcorp.ru/reset. Clicks: 3'
    },
    {
        'id': 'ALT-004',
        'type': 'ddos',
        'title': 'DDoS Attack — DNS Infrastructure',
        'source_ip': '312 distributed sources',
        'destination': '203.118.x.x (Public DNS)',
        'timestamp': (BASE_TIME + timedelta(minutes=45)).strftime('%H:%M:%S'),
        'mitre': 'T1498',
        'mitre_name': 'Network Denial of Service',
        'description': 'UDP flood targeting public DNS server. Volume: 4.2 Gbps from 312 source IPs across 22 countries. Packet rate 600k pps. DNS latency degraded from 12ms to 8,400ms. Service impact confirmed.',
        'severity': 'Critical',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'Network Monitor',
        'raw_log': '22:45:33 CRITICAL netmon: UDP flood 4.2Gbps -> 203.118.x.x. 312 sources. 601k pps. DNS latency: 8400ms'
    },
    {
        'id': 'ALT-005',
        'type': 'suspicious_process',
        'title': 'Malicious PowerShell — Word Macro',
        'source_ip': '10.0.2.44 (jsmith)',
        'destination': 'pastebin.com (External)',
        'timestamp': (BASE_TIME + timedelta(minutes=67)).strftime('%H:%M:%S'),
        'mitre': 'T1059.001',
        'mitre_name': 'PowerShell Execution',
        'description': 'EDR alert: encoded PowerShell spawned by WINWORD.EXE on workstation 10.0.2.44 (user: jsmith). Command downloads and executes remote script from pastebin.com. Consistent with macro-enabled document attack.',
        'severity': 'High',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'EDR (CrowdStrike)',
        'raw_log': '23:07:22 HIGH edr: WINWORD.EXE -> powershell.exe -enc JABjAD... on 10.0.2.44 (jsmith). Conn: pastebin.com:443'
    },
    {
        'id': 'ALT-006',
        'type': 'after_hours_login',
        'title': 'Impossible Travel — Admin Account',
        'source_ip': '203.45.67.89 (Vietnam)',
        'destination': 'core-router-01 via VPN',
        'timestamp': (BASE_TIME + timedelta(minutes=89)).strftime('%H:%M:%S'),
        'mitre': 'T1078',
        'mitre_name': 'Valid Accounts',
        'description': 'Admin account "netadmin01" authenticated via VPN from Vietnam IP at 23:29. Last login was 09:14 from Auckland. Physical travel impossible in this timeframe. No change window scheduled. Session currently active.',
        'severity': 'High',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'VPN / Okta Logs',
        'raw_log': '23:29:05 WARN vpn: netadmin01 from 203.45.67.89 (VN) -> core-router-01. Prev: 09:14 210.55.x.x (NZ)'
    },
    {
        'id': 'ALT-007',
        'type': 'data_exfiltration',
        'title': 'Active Data Exfiltration — 2.1GB',
        'source_ip': '10.0.2.44 (jsmith workstation)',
        'destination': '185.199.x.x (Unknown external)',
        'timestamp': (BASE_TIME + timedelta(minutes=95)).strftime('%H:%M:%S'),
        'mitre': 'T1041',
        'mitre_name': 'Exfiltration Over C2 Channel',
        'description': 'CORRELATES WITH ALT-005: Same compromised workstation now transferring 2.1GB to unknown external IP at 8MB/s sustained. Transfer ongoing. Destination not in approved cloud services list. Process: powershell.exe.',
        'severity': 'Critical',
        'priority': None,
        'status': 'open',
        'notes': '',
        'escalated_to': '',
        'last_updated': None,
        'source': 'EDR / Network Monitor',
        'raw_log': '23:35:44 CRITICAL netmon: 10.0.2.44 -> 185.199.x.x:443. 2.1GB tx. 8MB/s sustained. Process: powershell.exe PID 4821'
    },
]


def get_alerts():
    return ALERTS


def get_alert_by_id(alert_id):
    for alert in ALERTS:
        if alert['id'] == alert_id:
            return alert
    return None