"""
Database Manager for Cybersecurity System
Handles SQLite database initialization, schema creation, query helpers, and default data seeding.
"""

import sqlite3
import json
import os
from datetime import datetime

if os.environ.get('VERCEL') or os.environ.get('NOW_REGION'):
    DB_FILE = '/tmp/security_system.db'
else:
    DB_FILE = os.path.join(os.path.dirname(__file__), 'security_system.db')

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. User Profile
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_profile (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        account_id TEXT NOT NULL,
        protection_status TEXT DEFAULT 'Active',
        overall_risk_level TEXT DEFAULT 'Low',
        overall_risk_score INTEGER DEFAULT 18
    )
    ''')

    # 2. Linked Accounts
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS linked_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        status TEXT NOT NULL,
        account_identifier TEXT,
        icon_class TEXT,
        last_synced TEXT
    )
    ''')

    # 3. Devices Management
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_name TEXT NOT NULL,
        device_type TEXT NOT NULL,
        device_id_code TEXT UNIQUE NOT NULL,
        os_info TEXT,
        browser_info TEXT,
        ip_address TEXT,
        location TEXT,
        mac_address TEXT,
        status TEXT NOT NULL, -- 'Trusted', 'New', 'Blocked'
        registered_at TEXT,
        last_active TEXT
    )
    ''')

    # 4. Pending Login Requests
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_code TEXT UNIQUE NOT NULL,
        device_name TEXT NOT NULL,
        device_id_code TEXT NOT NULL,
        device_type TEXT,
        os_info TEXT,
        browser_info TEXT,
        ip_address TEXT NOT NULL,
        location TEXT NOT NULL,
        request_time TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING', -- 'PENDING', 'APPROVED', 'DENIED', 'BLOCKED'
        factors_json TEXT
    )
    ''')

    # 5. Security Logs & Login History
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        device_name TEXT NOT NULL,
        device_id_code TEXT,
        location TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        status TEXT NOT NULL, -- 'Approved', 'Blocked', 'Denied', 'MFA Required'
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        reasons TEXT
    )
    ''')

    # 6. Security Alerts & Notifications
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL, -- 'LOW', 'MEDIUM', 'HIGH'
        timestamp TEXT NOT NULL,
        is_read INTEGER DEFAULT 0
    )
    ''')

    # 7. Active Sessions
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS active_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_code TEXT UNIQUE NOT NULL,
        device_name TEXT NOT NULL,
        device_id_code TEXT NOT NULL,
        location TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        last_active TEXT NOT NULL,
        is_current INTEGER DEFAULT 0
    )
    ''')

    # 8. Security Rules
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS security_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_key TEXT UNIQUE NOT NULL,
        rule_name TEXT NOT NULL,
        description TEXT NOT NULL,
        is_enabled INTEGER DEFAULT 1
    )
    ''')

    conn.commit()

    # Check if initial data exists, if not seed the database
    cursor.execute("SELECT COUNT(*) FROM user_profile")
    if cursor.fetchone()[0] == 0:
        seed_initial_data(conn)

    conn.close()

def seed_initial_data(conn):
    cursor = conn.cursor()

    # Seed User Profile
    cursor.execute('''
    INSERT INTO user_profile (name, email, phone, account_id, protection_status, overall_risk_level, overall_risk_score)
    VALUES ('Abhinav Pathi', 'abhinav.sec@verix.io', '+91 98765 43210', 'ACC-88421-VRX', 'Active', 'Low', 18)
    ''')

    # Seed Linked Accounts
    linked_accounts = [
        ('Facebook', 'Connected', 'abhinav.fb@meta.com', 'fa-brands fa-facebook', '2 mins ago'),
        ('Instagram', 'Connected', '@abhinav_cyber', 'fa-brands fa-instagram', '10 mins ago'),
        ('WhatsApp', 'Connected', '+91 98765 43210', 'fa-brands fa-whatsapp', 'Active now'),
        ('Email', 'Connected', 'abhinav.sec@verix.io', 'fa-solid fa-envelope', 'Active now')
    ]
    cursor.executemany('''
    INSERT INTO linked_accounts (service_name, status, account_identifier, icon_class, last_synced)
    VALUES (?, ?, ?, ?, ?)
    ''', linked_accounts)

    # Seed Devices
    devices = [
        ('OnePlus 11 Phone', 'Mobile', 'DEV-7F82A91', 'Android 14', 'Chrome Mobile 122', '103.22.45.12', 'Balasore, Odisha', '48:2C:A0:1E:44:B2', 'Trusted', '15 Jan 2026', 'Active Now'),
        ('Lenovo Legion Laptop', 'Desktop', 'DEV-3B90E44', 'Windows 11 Pro', 'Chrome 122.0', '103.22.45.88', 'Bhubaneswar, Odisha', 'B8:85:85:DF:11:A9', 'Trusted', '02 Feb 2026', '10 mins ago'),
        ('Galaxy Tab S8', 'Tablet', 'DEV-99A1C20', 'Android 13', 'Samsung Internet', '103.22.45.12', 'Bhubaneswar, Odisha', '00:1A:2B:3C:4D:5E', 'Trusted', '18 Mar 2026', '2 hours ago'),
        ('Samsung Galaxy S22', 'Mobile', 'DEV-44C9112', 'Android 13', 'Firefox Mobile', '157.44.18.90', 'Bhubaneswar, Odisha', 'A1:B2:C3:D4:E5:F6', 'New', '30 Sep 2026', 'Pending Approval'),
        ('Unknown Linux Terminal', 'Server/Bot', 'DEV-9900X99', 'Kali Linux', 'Curl / Python Request', '185.220.101.5', 'Moscow, Russia (VPN)', '12:34:56:78:90:AB', 'Blocked', '29 Sep 2026', 'Blocked 29 Sep')
    ]
    cursor.executemany('''
    INSERT INTO devices (device_name, device_type, device_id_code, os_info, browser_info, ip_address, location, mac_address, status, registered_at, last_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', devices)

    # Seed Login Request
    sample_factors = json.dumps([
        {'signal': 'New Unrecognized Device', 'points': 20, 'type': 'warning'},
        {'signal': 'New IP Address Observed', 'points': 15, 'type': 'warning'},
        {'signal': 'Unusual City Location', 'points': 20, 'type': 'warning'},
        {'signal': '1 Failed Password Attempt', 'points': 10, 'type': 'warning'}
    ])
    cursor.execute('''
    INSERT INTO login_requests (request_code, device_name, device_id_code, device_type, os_info, browser_info, ip_address, location, request_time, risk_score, risk_level, status, factors_json)
    VALUES ('REQ-20260930-001', 'Samsung Galaxy S22', 'DEV-44C9112', 'Mobile', 'Android 13', 'Firefox Mobile', '157.44.18.90', 'Bhubaneswar, Odisha', '10:42 AM Today', 65, 'MEDIUM', 'PENDING', ?)
    ''', (sample_factors,))

    # Seed Login History
    login_logs = [
        ('LOGIN-20260930-004', '30 Sep 11:42 AM', 'OnePlus 11 Phone', 'DEV-7F82A91', 'Balasore, Odisha', '103.22.45.12', 'Approved', 12, 'LOW', 'Trusted device; Recognized network'),
        ('LOGIN-20260930-003', '30 Sep 10:42 AM', 'Samsung Galaxy S22', 'DEV-44C9112', 'Bhubaneswar, Odisha', '157.44.18.90', 'Pending', 65, 'MEDIUM', 'New device; New network location'),
        ('LOGIN-20260930-002', '30 Sep 09:15 AM', 'Lenovo Legion Laptop', 'DEV-3B90E44', 'Bhubaneswar, Odisha', '103.22.45.88', 'Approved', 18, 'LOW', 'Trusted device; Normal session'),
        ('LOGIN-20260929-001', '29 Sep 11:50 PM', 'Unknown Linux Terminal', 'DEV-9900X99', 'Moscow, Russia (VPN)', '185.220.101.5', 'Blocked', 92, 'HIGH', 'Blocked device; Suspicious VPN IP; Brute force attempts')
    ]
    cursor.executemany('''
    INSERT INTO login_history (event_id, timestamp, device_name, device_id_code, location, ip_address, status, risk_score, risk_level, reasons)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', login_logs)

    # Seed Alerts
    alerts = [
        ('NEW_DEVICE', '⚠️ New Device Login Attempt', 'Samsung Galaxy S22 requested access from Bhubaneswar.', 'MEDIUM', '10:42 AM Today', 0),
        ('SUSPICIOUS_BLOCK', '🔴 High Risk Login Blocked', 'Access attempt from Unknown Linux Terminal (Moscow, Russia) was blocked automatically.', 'HIGH', '29 Sep 11:50 PM', 0),
        ('DEVICE_TRUSTED', '📱 New Device Approved', 'Lenovo Legion Laptop was confirmed as a trusted device.', 'LOW', '28 Sep 04:30 PM', 1)
    ]
    cursor.executemany('''
    INSERT INTO security_alerts (alert_type, title, description, severity, timestamp, is_read)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', alerts)

    # Seed Active Sessions
    sessions = [
        ('SES-88210-A', 'OnePlus 11 Phone', 'DEV-7F82A91', 'Balasore, Odisha', '103.22.45.12', 'Active Now', 1),
        ('SES-88210-B', 'Lenovo Legion Laptop', 'DEV-3B90E44', 'Bhubaneswar, Odisha', '103.22.45.88', 'Active 10 min ago', 0)
    ]
    cursor.executemany('''
    INSERT INTO active_sessions (session_code, device_name, device_id_code, location, ip_address, last_active, is_current)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', sessions)

    # Seed Security Rules
    rules = [
        ('REQUIRE_APPROVAL_NEW_DEVICE', 'Require User Approval for New Devices', 'Any login from an unrecognized device requires explicit manual confirmation.', 1),
        ('REQUIRE_MFA_HIGH_RISK', 'Require Multi-Factor Auth (MFA) for High Risk Logins', 'Mandate OTP verification when risk score exceeds 70.', 1),
        ('TEMP_BLOCK_FAILED_ATTEMPTS', 'Temporary Block After Repeated Failed Attempts', 'Lock account access after 5 consecutive failed password attempts.', 1),
        ('NOTIFY_SUSPICIOUS_LOGIN', 'Send Instant Notifications for Suspicious Logins', 'Push real-time security alert for any login attempt scoring MEDIUM or HIGH risk.', 1),
        ('NEVER_AUTO_TRUST_UNKNOWN', 'Never Automatically Trust Unknown Networks', 'Force location and IP validation on all new sessions.', 1)
    ]
    cursor.executemany('''
    INSERT INTO security_rules (rule_key, rule_name, description, is_enabled)
    VALUES (?, ?, ?, ?)
    ''', rules)

    conn.commit()

# Run initialization upon import
init_db()
