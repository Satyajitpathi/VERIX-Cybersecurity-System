"""
Main Flask Web Server & Cybersecurity API Gateway
Serves RESTful endpoints for dashboard, device authorization, threat calculations, attack simulation, and security analytics.
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import sqlite3
import json
import random
from datetime import datetime

from database import get_db_connection, init_db
from risk_engine import calculate_login_risk

app = Flask(__name__)
CORS(app)

# Ensure database is initialized
init_db()

# Helper function to convert DB rows to dictionaries
def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id

# -------------------------------------------------------------
# PAGE ROUTES
# -------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------------------------------------------------
# API ENDPOINTS
# -------------------------------------------------------------

# 1. Dashboard Overview API
@app.route('/api/dashboard', methods=['GET'])
def get_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()

    # User profile
    user = cur.execute("SELECT * FROM user_profile LIMIT 1").fetchone()
    user_dict = dict(user) if user else {}

    # Summary Counts
    linked_count = cur.execute("SELECT COUNT(*) FROM linked_accounts WHERE status='Connected'").fetchone()[0]
    trusted_count = cur.execute("SELECT COUNT(*) FROM devices WHERE status='Trusted'").fetchone()[0]
    pending_count = cur.execute("SELECT COUNT(*) FROM login_requests WHERE status='PENDING'").fetchone()[0]
    alerts_count = cur.execute("SELECT COUNT(*) FROM security_alerts WHERE is_read=0").fetchone()[0]

    # Recent Pending Requests
    pending_requests = [dict(r) for r in cur.execute("SELECT * FROM login_requests WHERE status='PENDING' ORDER BY id DESC LIMIT 5").fetchall()]
    for req in pending_requests:
        if req.get('factors_json'):
            req['factors'] = json.loads(req['factors_json'])

    # Recent Security Alerts
    recent_alerts = [dict(a) for a in cur.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 5").fetchall()]

    conn.close()

    return jsonify({
        'user': user_dict,
        'summary': {
            'linked_accounts': linked_count,
            'trusted_devices': trusted_count,
            'pending_requests': pending_count,
            'threat_alerts': alerts_count,
            'overall_risk_level': user_dict.get('overall_risk_level', 'Low'),
            'overall_risk_score': user_dict.get('overall_risk_score', 18),
            'protection_status': user_dict.get('protection_status', 'Active')
        },
        'pending_requests': pending_requests,
        'recent_alerts': recent_alerts
    })

# 2. Linked Accounts API
@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    accounts = [dict(a) for a in query_db("SELECT * FROM linked_accounts")]
    return jsonify({'accounts': accounts})

@app.route('/api/accounts/add', methods=['POST'])
def add_account():
    data = request.json or {}
    service_name = data.get('service_name')
    identifier = data.get('identifier', 'user@example.com')
    icon = data.get('icon_class', 'fa-solid fa-link')

    if not service_name:
        return jsonify({'error': 'Service name required'}), 400

    execute_db('''
    INSERT INTO linked_accounts (service_name, status, account_identifier, icon_class, last_synced)
    VALUES (?, 'Connected', ?, ?, 'Just now')
    ''', (service_name, identifier, icon))

    return jsonify({'message': f'{service_name} linked successfully!'})

@app.route('/api/accounts/toggle', methods=['POST'])
def toggle_account():
    data = request.json or {}
    account_id = data.get('account_id')
    current_status = data.get('status')
    new_status = 'Disconnected' if current_status == 'Connected' else 'Connected'

    execute_db("UPDATE linked_accounts SET status=? WHERE id=?", (new_status, account_id))
    return jsonify({'message': 'Account status updated', 'new_status': new_status})

# 3. Device Management API
@app.route('/api/devices', methods=['GET'])
def get_devices():
    conn = get_db_connection()
    cur = conn.cursor()

    trusted = [dict(d) for d in cur.execute("SELECT * FROM devices WHERE status='Trusted' ORDER BY id DESC").fetchall()]
    new_devices = [dict(d) for d in cur.execute("SELECT * FROM devices WHERE status='New' ORDER BY id DESC").fetchall()]
    blocked = [dict(d) for d in cur.execute("SELECT * FROM devices WHERE status='Blocked' ORDER BY id DESC").fetchall()]

    conn.close()

    return jsonify({
        'trusted': trusted,
        'new': new_devices,
        'blocked': blocked
    })

@app.route('/api/devices/action', methods=['POST'])
def device_action():
    data = request.json or {}
    device_id_code = data.get('device_id_code')
    action = data.get('action') # 'trust', 'block', 'remove', 'signout'

    if not device_id_code or not action:
        return jsonify({'error': 'Missing parameters'}), 400

    if action == 'trust':
        execute_db("UPDATE devices SET status='Trusted', last_active='Active Now' WHERE device_id_code=?", (device_id_code,))
        # Add alert
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('DEVICE_TRUSTED', '📱 Device Marked Trusted', ?, 'LOW', 'Just Now')
        ''', (f'Device {device_id_code} was marked as trusted by user.',))
    elif action == 'block':
        execute_db("UPDATE devices SET status='Blocked' WHERE device_id_code=?", (device_id_code,))
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('DEVICE_BLOCKED', '🔴 Device Blocked', ?, 'HIGH', 'Just Now')
        ''', (f'Device {device_id_code} was explicitly blocked.',))
    elif action == 'remove':
        execute_db("DELETE FROM devices WHERE device_id_code=?", (device_id_code,))
    elif action == 'signout':
        execute_db("DELETE FROM active_sessions WHERE device_id_code=?", (device_id_code,))
        execute_db("UPDATE devices SET last_active='Signed Out' WHERE device_id_code=?", (device_id_code,))

    return jsonify({'message': f'Device action {action} completed successfully.'})

# 4. Pending Login Requests API & Approval Workflows
@app.route('/api/login-requests', methods=['GET'])
def get_login_requests():
    requests_list = [dict(r) for r in query_db("SELECT * FROM login_requests WHERE status='PENDING' ORDER BY id DESC")]
    for req in requests_list:
        if req.get('factors_json'):
            req['factors'] = json.loads(req['factors_json'])
    return jsonify({'requests': requests_list})

@app.route('/api/login-requests/decision', methods=['POST'])
def handle_request_decision():
    data = request.json or {}
    request_code = data.get('request_code')
    decision = data.get('decision') # 'APPROVE' or 'DENY'

    if not request_code or not decision:
        return jsonify({'error': 'Missing parameters'}), 400

    req = query_db("SELECT * FROM login_requests WHERE request_code=?", (request_code,), one=True)
    if not req:
        return jsonify({'error': 'Request not found'}), 404

    req_dict = dict(req)
    device_code = req_dict['device_id_code']
    device_name = req_dict['device_name']
    ip_addr = req_dict['ip_address']
    location = req_dict['location']
    now_str = datetime.now().strftime("%d %b %I:%M %p")

    if decision == 'APPROVE':
        # Update request status
        execute_db("UPDATE login_requests SET status='APPROVED' WHERE request_code=?", (request_code,))
        # Update device or add to trusted
        existing_device = query_db("SELECT * FROM devices WHERE device_id_code=?", (device_code,), one=True)
        if existing_device:
            execute_db("UPDATE devices SET status='Trusted', last_active='Active Now', location=?, ip_address=? WHERE device_id_code=?",
                       (location, ip_addr, device_code))
        else:
            execute_db('''
            INSERT INTO devices (device_name, device_type, device_id_code, os_info, browser_info, ip_address, location, mac_address, status, registered_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'DEV-MAC-NEW', 'Trusted', ?, 'Active Now')
            ''', (device_name, req_dict.get('device_type', 'Unknown'), device_code, req_dict.get('os_info'), req_dict.get('browser_info'), ip_addr, location, now_str))

        # Add active session
        session_code = f"SES-{random.randint(10000, 99999)}"
        execute_db('''
        INSERT INTO active_sessions (session_code, device_name, device_id_code, location, ip_address, last_active, is_current)
        VALUES (?, ?, ?, ?, ?, 'Active Now', 0)
        ''', (session_code, device_name, device_code, location, ip_addr))

        # Audit Log
        event_id = f"LOGIN-{datetime.now().strftime('%Y%m%d')}-{random.randint(100, 999)}"
        execute_db('''
        INSERT INTO login_history (event_id, timestamp, device_name, device_id_code, location, ip_address, status, risk_score, risk_level, reasons)
        VALUES (?, ?, ?, ?, ?, ?, 'Approved', ?, ?, 'Approved by user via Security Center')
        ''', (event_id, now_str, device_name, device_code, location, ip_addr, req_dict['risk_score'], req_dict['risk_level']))

        # Alert
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('LOGIN_APPROVED', '✅ New Device Authorized', ?, 'LOW', ?)
        ''', (f'{device_name} ({location}) was approved by user.', now_str))

        msg = 'Login request approved! Device added to Trusted Devices.'

    else: # DENY
        execute_db("UPDATE login_requests SET status='DENIED' WHERE request_code=?", (request_code,))
        
        # Add to blocked devices
        existing_device = query_db("SELECT * FROM devices WHERE device_id_code=?", (device_code,), one=True)
        if existing_device:
            execute_db("UPDATE devices SET status='Blocked', last_active=? WHERE device_id_code=?", (f'Blocked {now_str}', device_code))
        else:
            execute_db('''
            INSERT INTO devices (device_name, device_type, device_id_code, os_info, browser_info, ip_address, location, mac_address, status, registered_at, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'DEV-MAC-BLOCKED', 'Blocked', ?, ?)
            ''', (device_name, req_dict.get('device_type', 'Unknown'), device_code, req_dict.get('os_info'), req_dict.get('browser_info'), ip_addr, location, now_str, f'Blocked {now_str}'))

        # Audit Log
        event_id = f"LOGIN-{datetime.now().strftime('%Y%m%d')}-{random.randint(100, 999)}"
        execute_db('''
        INSERT INTO login_history (event_id, timestamp, device_name, device_id_code, location, ip_address, status, risk_score, risk_level, reasons)
        VALUES (?, ?, ?, ?, ?, ?, 'Blocked', ?, ?, 'Denied by user; Marked unauthorized')
        ''', (event_id, now_str, device_name, device_code, location, ip_addr, req_dict['risk_score'], req_dict['risk_level']))

        # Alert
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('LOGIN_BLOCKED', '🔒 Login Access Denied & Device Blocked', ?, 'HIGH', ?)
        ''', (f'Unauthorized login attempt from {device_name} ({ip_addr}) was denied and blocked.', now_str))

        msg = 'Login request denied! Device blocked and security alert generated.'

    return jsonify({'message': msg, 'decision': decision})

# 5. Interactive Attack Simulator API
@app.route('/api/simulate-login', methods=['POST'])
def simulate_login():
    """
    Triggers a live simulated login attempt to test the Risk Engine and Security Workflow.
    Pre-configured Scenarios:
    - scenario_1: 'NORMAL' (Trusted Phone, Home Location, 0 Failures) -> Low Risk -> Allowed
    - scenario_2: 'NEW_LAPTOP' (New Device, Nearby City, 1 Failure) -> Medium Risk -> Approval Request Required
    - scenario_3: 'HACKER_ATTACK' (Unknown Device, Foreign VPN IP, Unusual Location, 5 Brute Force Failures) -> High Risk -> Blocked / MFA Required
    """
    data = request.json or {}
    scenario = data.get('scenario', 'CUSTOM')

    if scenario == 'NORMAL':
        device_name = 'OnePlus 11 Phone'
        device_type = 'Mobile'
        device_code = 'DEV-7F82A91'
        os_info = 'Android 14'
        browser_info = 'Chrome Mobile'
        ip_addr = '103.22.45.12'
        location = 'Balasore, Odisha'
        device_info = {'is_trusted': True, 'is_new': False, 'is_blocked': False, 'device_id': device_code}
        network_info = {'is_new_ip': False, 'is_suspicious_ip': False, 'ip': ip_addr}
        location_info = {'is_unusual_location': False, 'city': location}
        attempt_info = {'failed_attempts': 0, 'is_brute_force': False}
        session_info = {'is_parallel_session': False, 'unusual_time': False}

    elif scenario == 'NEW_LAPTOP':
        device_name = 'MacBook Pro M3'
        device_type = 'Laptop'
        device_code = f"DEV-MBP-{random.randint(1000, 9999)}"
        os_info = 'macOS Sonoma'
        browser_info = 'Safari 17.2'
        ip_addr = '49.37.112.40'
        location = 'Bhubaneswar, Odisha'
        device_info = {'is_trusted': False, 'is_new': True, 'is_blocked': False, 'device_id': device_code}
        network_info = {'is_new_ip': True, 'is_suspicious_ip': False, 'ip': ip_addr}
        location_info = {'is_unusual_location': True, 'city': location}
        attempt_info = {'failed_attempts': 1, 'is_brute_force': False}
        session_info = {'is_parallel_session': True, 'unusual_time': False}

    elif scenario == 'HACKER_ATTACK':
        device_name = 'Unknown Linux Exploiter'
        device_type = 'Attacker Terminal'
        device_code = f"DEV-ATTACK-{random.randint(1000, 9999)}"
        os_info = 'Kali Linux 2024'
        browser_info = 'Automated Python/Curl Script'
        ip_addr = '185.220.101.45'
        location = 'Frankfurt, Germany (TOR Proxy)'
        device_info = {'is_trusted': False, 'is_new': True, 'is_blocked': False, 'device_id': device_code}
        network_info = {'is_new_ip': True, 'is_suspicious_ip': True, 'ip': ip_addr}
        location_info = {'is_unusual_location': True, 'city': location}
        attempt_info = {'failed_attempts': 5, 'is_brute_force': True}
        session_info = {'is_parallel_session': True, 'unusual_time': True}

    else: # Custom
        device_name = data.get('device_name', 'Custom Device')
        device_type = data.get('device_type', 'Desktop')
        device_code = data.get('device_code', f"DEV-{random.randint(10000, 99999)}")
        os_info = data.get('os_info', 'Windows 11')
        browser_info = data.get('browser_info', 'Chrome')
        ip_addr = data.get('ip_address', '192.168.1.50')
        location = data.get('location', 'Balasore, Odisha')

        device_info = {
            'is_trusted': data.get('is_trusted', False),
            'is_new': data.get('is_new', True),
            'is_blocked': data.get('is_blocked', False),
            'device_id': device_code
        }
        network_info = {
            'is_new_ip': data.get('is_new_ip', True),
            'is_suspicious_ip': data.get('is_suspicious_ip', False),
            'ip': ip_addr
        }
        location_info = {
            'is_unusual_location': data.get('is_unusual_location', False),
            'city': location
        }
        attempt_info = {
            'failed_attempts': int(data.get('failed_attempts', 0)),
            'is_brute_force': data.get('is_brute_force', False)
        }
        session_info = {
            'is_parallel_session': data.get('is_parallel_session', False),
            'unusual_time': data.get('unusual_time', False)
        }

    # Evaluate Risk Score
    risk_assessment = calculate_login_risk(device_info, network_info, location_info, attempt_info, session_info)
    
    now_str = datetime.now().strftime("%d %b %I:%M %p")
    req_code = f"REQ-{datetime.now().strftime('%Y%m%d')}-{random.randint(100, 999)}"
    factors_json = json.dumps(risk_assessment['factors'])

    # Determine automated response based on risk level
    if risk_assessment['recommended_action'] == 'ALLOW':
        # Auto-approved
        event_id = f"LOGIN-{datetime.now().strftime('%Y%m%d')}-{random.randint(100, 999)}"
        reasons_str = "; ".join([f['signal'] for f in risk_assessment['factors']]) or 'Normal low-risk login'
        execute_db('''
        INSERT INTO login_history (event_id, timestamp, device_name, device_id_code, location, ip_address, status, risk_score, risk_level, reasons)
        VALUES (?, ?, ?, ?, ?, ?, 'Approved', ?, ?, ?)
        ''', (event_id, now_str, device_name, device_code, location, ip_addr, risk_assessment['risk_score'], risk_assessment['risk_level'], reasons_str))
        
        system_response = {
            'action': 'ALLOW',
            'message': '🟢 Low Risk Login detected. Access automatically granted.',
            'require_approval': False
        }

    elif risk_assessment['recommended_action'] == 'APPROVAL_REQUIRED':
        # Create Pending Request
        execute_db('''
        INSERT INTO login_requests (request_code, device_name, device_id_code, device_type, os_info, browser_info, ip_address, location, request_time, risk_score, risk_level, status, factors_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
        ''', (req_code, device_name, device_code, device_type, os_info, browser_info, ip_addr, location, now_str, risk_assessment['risk_score'], risk_assessment['risk_level'], factors_json))

        # Alert
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('PENDING_REQUEST', '⚠️ New Login Request Pending Approval', ?, 'MEDIUM', ?)
        ''', (f'{device_name} from {location} ({ip_addr}) requires user verification.', now_str))

        system_response = {
            'action': 'APPROVAL_REQUIRED',
            'message': '🟡 Medium Risk Login detected! Request sent to Dashboard for User Approval.',
            'require_approval': True,
            'request_code': req_code
        }

    else: # HIGH RISK / BLOCK
        # Create Pending Request with HIGH risk status & lock
        execute_db('''
        INSERT INTO login_requests (request_code, device_name, device_id_code, device_type, os_info, browser_info, ip_address, location, request_time, risk_score, risk_level, status, factors_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
        ''', (req_code, device_name, device_code, device_type, os_info, browser_info, ip_addr, location, now_str, risk_assessment['risk_score'], risk_assessment['risk_level'], factors_json))

        # Alert
        execute_db('''
        INSERT INTO security_alerts (alert_type, title, description, severity, timestamp)
        VALUES ('HIGH_RISK_THREAT', '🚨 HIGH RISK THREAT DETECTED', ?, 'HIGH', ?)
        ''', (f'Suspicious login blocked from {device_name} ({location}, IP: {ip_addr}). Risk Score: {risk_assessment["risk_score"]}/100.', now_str))

        system_response = {
            'action': 'BLOCK_AND_MFA',
            'message': '🔴 HIGH RISK THREAT DETECTED! Login blocked pending Multi-Factor Verification & User Approval.',
            'require_approval': True,
            'require_mfa': True,
            'request_code': req_code
        }

    return jsonify({
        'scenario': scenario,
        'device_name': device_name,
        'ip_address': ip_addr,
        'location': location,
        'risk_assessment': risk_assessment,
        'system_response': system_response
    })

# 6. Multi-Factor Authentication Verification API
@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json or {}
    otp = data.get('otp')
    request_code = data.get('request_code')

    # Demo OTP check
    if otp == '123456' or otp == '888888':
        return jsonify({
            'success': True,
            'message': '✅ Multi-Factor Authentication (MFA) Verified Successfully! Proceeding to User Final Approval step.'
        })
    else:
        return jsonify({
            'success': False,
            'message': '❌ Invalid Authentication Code! Access Denied.'
        }), 400

# 7. Login History & Security Audit Logs API
@app.route('/api/logs', methods=['GET'])
def get_logs():
    status_filter = request.args.get('status', 'ALL')
    risk_filter = request.args.get('risk', 'ALL')

    query = "SELECT * FROM login_history WHERE 1=1"
    args = []

    if status_filter != 'ALL':
        query += " AND status=?"
        args.append(status_filter)
    if risk_filter != 'ALL':
        query += " AND risk_level=?"
        args.append(risk_filter)

    query += " ORDER BY id DESC"

    logs = [dict(row) for row in query_db(query, args)]
    return jsonify({'logs': logs})

# 8. Single Security Event Detailed Inspector API
@app.route('/api/event/<event_id>', methods=['GET'])
def get_event_detail(event_id):
    event = query_db("SELECT * FROM login_history WHERE event_id=?", (event_id,), one=True)
    if not event:
        # Check login requests as fallback
        req = query_db("SELECT * FROM login_requests WHERE request_code=?", (event_id,), one=True)
        if req:
            req_dict = dict(req)
            factors = json.loads(req_dict.get('factors_json', '[]'))
            return jsonify({
                'event_id': req_dict['request_code'],
                'device_name': req_dict['device_name'],
                'device_id_code': req_dict['device_id_code'],
                'ip_address': req_dict['ip_address'],
                'location': req_dict['location'],
                'time': req_dict['request_time'],
                'risk_score': req_dict['risk_score'],
                'risk_level': req_dict['risk_level'],
                'reasons': [f['signal'] for f in factors],
                'factors': factors,
                'status': req_dict['status']
            })
        return jsonify({'error': 'Event not found'}), 404

    event_dict = dict(event)
    return jsonify({
        'event_id': event_dict['event_id'],
        'device_name': event_dict['device_name'],
        'device_id_code': event_dict['device_id_code'],
        'ip_address': event_dict['ip_address'],
        'location': event_dict['location'],
        'time': event_dict['timestamp'],
        'risk_score': event_dict['risk_score'],
        'risk_level': event_dict['risk_level'],
        'reasons': event_dict['reasons'].split('; ') if event_dict['reasons'] else [],
        'status': event_dict['status']
    })

# 9. Active Sessions API
@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    sessions = [dict(s) for s in query_db("SELECT * FROM active_sessions ORDER BY is_current DESC, id DESC")]
    return jsonify({'sessions': sessions})

@app.route('/api/sessions/signout', methods=['POST'])
def signout_session():
    data = request.json or {}
    session_id = data.get('session_id')
    signout_all_others = data.get('all_others', False)

    if signout_all_others:
        execute_db("DELETE FROM active_sessions WHERE is_current=0")
        msg = 'Signed out from all other active sessions successfully!'
    else:
        execute_db("DELETE FROM active_sessions WHERE id=?", (session_id,))
        msg = 'Session terminated successfully.'

    return jsonify({'message': msg})

# 10. Security Analytics API
@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    # Return timeline mock data for Chart.js
    labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    successful_logins = [12, 19, 15, 22, 18, 14, 25]
    failed_logins = [2, 5, 1, 8, 3, 0, 4]
    blocked_attempts = [1, 2, 0, 5, 2, 1, 3]
    risk_trend = [15, 22, 18, 82, 35, 20, 18]

    return jsonify({
        'labels': labels,
        'activity': {
            'successful': successful_logins,
            'failed': failed_logins,
            'blocked': blocked_attempts
        },
        'risk_trend': risk_trend
    })

# 11. Security Rules API
@app.route('/api/rules', methods=['GET'])
def get_rules():
    rules = [dict(r) for r in query_db("SELECT * FROM security_rules")]
    return jsonify({'rules': rules})

@app.route('/api/rules/toggle', methods=['POST'])
def toggle_rule():
    data = request.json or {}
    rule_id = data.get('rule_id')
    is_enabled = data.get('is_enabled')

    execute_db("UPDATE security_rules SET is_enabled=? WHERE id=?", (1 if is_enabled else 0, rule_id))
    return jsonify({'message': 'Security rule updated.'})

# -------------------------------------------------------------
# RUN SERVER
# -------------------------------------------------------------
if __name__ == '__main__':
    print("=================================================================")
    print("[+] VERIX - ACCOUNT PROTECTION & THREAT DETECTION SYSTEM")
    print("=================================================================")
    print("Starting VERIX Security Server on http://127.0.0.1:5000 ...")
    app.run(host='0.0.0.0', port=5000, debug=True)
