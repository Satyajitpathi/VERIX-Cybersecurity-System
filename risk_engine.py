"""
Threat Detection & Risk Calculation Engine
Rule-based evaluation for login requests based on security signals:
Device Identity, Network/IP, Location Anomaly, Login Attempt Patterns, Session Behavior.
"""

def calculate_login_risk(device_info, network_info, location_info, attempt_info, session_info):
    """
    Calculates numerical risk score (0 - 100) and returns breakdown details.
    
    device_info: dict { 'is_trusted': bool, 'is_new': bool, 'is_blocked': bool, 'device_id': str }
    network_info: dict { 'is_new_ip': bool, 'is_suspicious_ip': bool, 'ip': str }
    location_info: dict { 'is_unusual_location': bool, 'city': str }
    attempt_info: dict { 'failed_attempts': int, 'is_brute_force': bool }
    session_info: dict { 'is_parallel_session': bool, 'unusual_time': bool }
    """
    risk_score = 0
    factors = []

    # 1. Device Evaluation
    if device_info.get('is_blocked'):
        risk_score += 35
        factors.append({'signal': 'Previously Blocked Device', 'points': 35, 'type': 'danger'})
    elif device_info.get('is_new'):
        risk_score += 20
        factors.append({'signal': 'New Unrecognized Device', 'points': 20, 'type': 'warning'})
    elif device_info.get('is_trusted'):
        risk_score -= 10
        factors.append({'signal': 'Recognized Trusted Device', 'points': -10, 'type': 'success'})

    # 2. Network Evaluation
    if network_info.get('is_suspicious_ip'):
        risk_score += 25
        factors.append({'signal': 'Suspicious Proxy/VPN Network', 'points': 25, 'type': 'danger'})
    elif network_info.get('is_new_ip'):
        risk_score += 15
        factors.append({'signal': 'New IP Address Observed', 'points': 15, 'type': 'warning'})

    # 3. Location Evaluation
    if location_info.get('is_unusual_location'):
        risk_score += 20
        factors.append({'signal': 'Unusual / Geographic Anomaly Location', 'points': 20, 'type': 'warning'})

    # 4. Attempt History & Brute Force
    failed_count = attempt_info.get('failed_attempts', 0)
    if attempt_info.get('is_brute_force') or failed_count >= 4:
        risk_score += 30
        factors.append({'signal': f'Multiple Failed Attempts ({failed_count} failures)', 'points': 30, 'type': 'danger'})
    elif failed_count > 0:
        added_points = min(failed_count * 10, 20)
        risk_score += added_points
        factors.append({'signal': f'Prior Failed Login Attempt ({failed_count})', 'points': added_points, 'type': 'warning'})

    # 5. Session Behavior
    if session_info.get('is_parallel_session'):
        risk_score += 15
        factors.append({'signal': 'Unexpected Concurrent Active Session', 'points': 15, 'type': 'warning'})
    if session_info.get('unusual_time'):
        risk_score += 10
        factors.append({'signal': 'Unusual Login Time Pattern', 'points': 10, 'type': 'info'})

    # Clamp risk score between 0 and 100
    risk_score = max(0, min(100, risk_score))

    # Categorize Risk Level & Recommended Action
    if risk_score <= 30:
        risk_level = 'LOW'
        color = 'success'
        badge = '🟢 Low Risk'
        recommended_action = 'ALLOW'
        action_detail = 'Access granted automatically. Normal behavior pattern.'
    elif risk_score <= 70:
        risk_level = 'MEDIUM'
        color = 'warning'
        badge = '🟡 Medium Risk'
        recommended_action = 'APPROVAL_REQUIRED'
        action_detail = 'User authorization/approval required before granting access.'
    else:
        risk_level = 'HIGH'
        color = 'danger'
        badge = '🔴 High Risk'
        recommended_action = 'BLOCK_AND_MFA'
        action_detail = 'Login blocked until Multi-Factor Authentication & explicit user approval.'

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'color': color,
        'badge': badge,
        'recommended_action': recommended_action,
        'action_detail': action_detail,
        'factors': factors
    }
