from flask import Flask, render_template, request, jsonify, Response
from detector import get_alerts, get_alert_by_id
from triage import get_runbook, generate_handover_report, PRIORITY_DEFINITIONS, SENIOR_ANALYSTS
from datetime import datetime

app = Flask(__name__)

SHIFT_START = datetime.now().strftime('%H:%M')
ANALYST_NAME = "Rafael Carreon"

@app.route('/')
def dashboard():
    alerts = get_alerts()
    open_count = len([a for a in alerts if a['status'] == 'open'])
    closed_count = len([a for a in alerts if a['status'] == 'closed'])
    critical_count = len([a for a in alerts if a['severity'] == 'Critical'])
    high_count = len([a for a in alerts if a['severity'] == 'High'])
    return render_template('dashboard.html',
        alerts=alerts,
        open_count=open_count,
        closed_count=closed_count,
        critical_count=critical_count,
        high_count=high_count,
        analyst=ANALYST_NAME,
        shift_start=SHIFT_START,
        current_time=datetime.now().strftime('%H:%M:%S')
    )

@app.route('/alert/<alert_id>')
def alert_detail(alert_id):
    alert = get_alert_by_id(alert_id)
    if not alert:
        return "Alert not found", 404
    runbook = get_runbook(alert['type'])
    return render_template('alert.html',
        alert=alert,
        runbook=runbook,
        priorities=PRIORITY_DEFINITIONS,
        analysts=SENIOR_ANALYSTS
    )

@app.route('/update_alert', methods=['POST'])
def update_alert():
    data = request.json
    alert = get_alert_by_id(data['id'])
    if not alert:
        return jsonify({'success': False})
    if 'priority' in data:
        alert['priority'] = data['priority']
    if 'status' in data:
        alert['status'] = data['status']
    if 'notes' in data:
        alert['notes'] = data['notes']
    if 'escalated_to' in data:
        alert['escalated_to'] = data['escalated_to']
    alert['last_updated'] = datetime.now().strftime('%H:%M:%S')
    return jsonify({'success': True, 'alert': alert})

@app.route('/handover')
def handover():
    alerts = get_alerts()
    report = generate_handover_report(alerts, SHIFT_START, ANALYST_NAME)
    return render_template('handover.html', report=report, analyst=ANALYST_NAME)

@app.route('/handover/download')
def download_handover():
    alerts = get_alerts()
    report = generate_handover_report(alerts, SHIFT_START, ANALYST_NAME)
    return Response(
        report,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=shift_handover.txt'}
    )

if __name__ == '__main__':
    app.run(debug=True)