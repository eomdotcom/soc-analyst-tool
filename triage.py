from datetime import datetime

RUNBOOKS = {
    'port_scan': {
        'title': 'Port Scan Response Runbook',
        'steps': [
            'Identify source IP and check reputation via threat intel (AbuseIPDB, VirusTotal)',
            'Determine scope — how many hosts were scanned, which ports',
            'Check if source IP has previous alerts in SIEM',
            'If external: block source IP at perimeter firewall',
            'If internal: isolate host and escalate to senior analyst',
            'Document all findings and actions taken',
            'Monitor for follow-up activity from same subnet',
        ]
    },
    'brute_force': {
        'title': 'Brute Force Response Runbook',
        'steps': [
            'Confirm no successful authentication occurred',
            'Block source IP at firewall immediately',
            'Check auth logs for any successful logins in the past 24h from this IP',
            'Review targeted account for signs of compromise',
            'Enable geo-blocking if attack originates from unexpected region',
            'Notify system owner of targeted host',
            'Escalate to P2 if any successful logins found',
        ]
    },
    'phishing': {
        'title': 'Phishing Response Runbook',
        'steps': [
            'Immediately quarantine the phishing email from all mailboxes',
            'Identify all users who received and/or clicked the link',
            'Block the malicious URL at web proxy and email gateway',
            'For users who clicked: force password reset, check for credential use',
            'Preserve email headers and attachments as evidence',
            'Escalate to P1 — notify manager and security lead',
            'Check endpoint logs of users who clicked for malware activity',
            'Issue staff awareness notification',
        ]
    },
    'ddos': {
        'title': 'DDoS Response Runbook',
        'steps': [
            'Confirm attack scope — which services are affected',
            'Notify NOC and escalate to senior analyst immediately',
            'Activate DDoS mitigation service if available',
            'Apply rate limiting and geo-blocking at perimeter',
            'Redirect traffic through scrubbing centre',
            'Contact upstream ISP for null routing if needed',
            'Monitor service latency and document recovery timeline',
            'Maintain 15-minute status updates to management',
        ]
    },
    'suspicious_process': {
        'title': 'Malicious Process Response Runbook',
        'steps': [
            'Isolate the affected endpoint from the network immediately',
            'Preserve memory dump and process list before killing process',
            'Identify parent process and full command line arguments',
            'Check outbound connections made by the process',
            'Escalate to P1 — potential malware execution',
            'Notify endpoint owner and their manager',
            'Submit suspicious file/script hash to AV vendor',
            'Begin full forensic investigation of the endpoint',
        ]
    },
    'after_hours_login': {
        'title': 'Suspicious Login Response Runbook',
        'steps': [
            'Verify with account owner via phone — do not email',
            'If unverified: disable account immediately',
            'Review all actions taken during the suspicious session',
            'Check for privilege escalation or config changes',
            'Reset credentials and revoke all active sessions',
            'Escalate to P1 if network infrastructure was accessed',
            'Review MFA logs — was MFA bypassed or approved',
            'Document timeline of session activity',
        ]
    },
    'data_exfiltration': {
        'title': 'Data Exfiltration Response Runbook',
        'steps': [
            'Isolate source endpoint from network IMMEDIATELY',
            'Kill the active transfer — block destination IP at firewall',
            'Preserve network capture of transfer if possible',
            'Identify what data was transferred — file types, size, content',
            'Escalate to P1 CRITICAL — notify CISO and legal team',
            'Determine if this is a regulatory breach (Privacy Act 2020)',
            'Preserve all evidence for forensic investigation',
            'Do not power off the machine — maintain volatile memory',
        ]
    },
}


PRIORITY_DEFINITIONS = {
    'P1': 'Critical — Active threat, immediate action required. Escalate now.',
    'P2': 'High — Significant risk, investigate within 1 hour.',
    'P3': 'Medium — Monitor and investigate within 4 hours.',
    'P4': 'Low — Log and review at end of shift.',
}

SENIOR_ANALYSTS = [
    'Sarah Chen (Lead)',
    'Marcus Tuilagi',
    'On-call Manager',
]


def get_runbook(alert_type):
    return RUNBOOKS.get(alert_type, {
        'title': 'General Incident Runbook',
        'steps': [
            'Identify and document the nature of the alert',
            'Assess potential impact to systems and data',
            'Contain the threat if active',
            'Escalate if severity is High or Critical',
            'Document all findings and actions',
        ]
    })


def generate_handover_report(alerts, shift_start, analyst_name):
    now = datetime.now()
    open_alerts = [a for a in alerts if a['status'] == 'open']
    closed_alerts = [a for a in alerts if a['status'] == 'closed']
    escalated_alerts = [a for a in alerts if a['escalated_to']]
    critical = [a for a in alerts if a['severity'] == 'Critical']
    high = [a for a in alerts if a['severity'] == 'High']

    lines = []
    lines.append("=" * 60)
    lines.append("ONE NEW ZEALAND — CYBER DEFENCE CENTRE")
    lines.append("SHIFT HANDOVER REPORT")
    lines.append("=" * 60)
    lines.append(f"Shift Date:      {now.strftime('%d %B %Y')}")
    lines.append(f"Shift Period:    {shift_start} — {now.strftime('%H:%M')}")
    lines.append(f"Analyst:         {analyst_name}")
    lines.append(f"Report Generated:{now.strftime('%H:%M:%S %d/%m/%Y')}")
    lines.append("=" * 60)

    lines.append("")
    lines.append("SHIFT SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total Alerts:    {len(alerts)}")
    lines.append(f"Closed:          {len(closed_alerts)}")
    lines.append(f"Open (handover): {len(open_alerts)}")
    lines.append(f"Escalated:       {len(escalated_alerts)}")
    lines.append(f"Critical:        {len(critical)}")
    lines.append(f"High:            {len(high)}")

    if open_alerts:
        lines.append("")
        lines.append("OPEN ALERTS REQUIRING ATTENTION")
        lines.append("-" * 40)
        for a in open_alerts:
            lines.append(f"[{a['id']}] {a['title']}")
            lines.append(f"  Severity:  {a['severity']}")
            lines.append(f"  Priority:  {a['priority'] or 'Not set'}")
            lines.append(f"  Source:    {a['source_ip']}")
            lines.append(f"  Time:      {a['timestamp']}")
            if a['notes']:
                lines.append(f"  Notes:     {a['notes']}")
            lines.append("")

    if closed_alerts:
        lines.append("CLOSED ALERTS THIS SHIFT")
        lines.append("-" * 40)
        for a in closed_alerts:
            lines.append(f"[{a['id']}] {a['title']} — {a['severity']}")
            if a['notes']:
                lines.append(f"  Actions:   {a['notes']}")
        lines.append("")

    if escalated_alerts:
        lines.append("ESCALATIONS THIS SHIFT")
        lines.append("-" * 40)
        for a in escalated_alerts:
            lines.append(f"[{a['id']}] {a['title']} escalated to {a['escalated_to']}")
        lines.append("")

    lines.append("RECOMMENDATIONS FOR INCOMING SHIFT")
    lines.append("-" * 40)
    if open_alerts:
        for a in open_alerts:
            if a['severity'] in ['Critical', 'High']:
                lines.append(f"• PRIORITY: Review [{a['id']}] {a['title']}")
    lines.append("• Continue monitoring network traffic for follow-up activity")
    lines.append("• Check SIEM for any new alerts correlated with open incidents")
    lines.append("")
    lines.append("=" * 60)
    lines.append("END OF SHIFT HANDOVER REPORT")
    lines.append(f"Signed: {analyst_name} | {now.strftime('%H:%M %d/%m/%Y')}")
    lines.append("=" * 60)

    return "\n".join(lines)