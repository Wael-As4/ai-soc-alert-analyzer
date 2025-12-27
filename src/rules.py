def detect_suspicious_activity(logs):
    """
    Analyze normalized logs and return suspicious events.
    """
    alerts = []

    for log in logs:
        if _is_bruteforce(log):
            alerts.append({
                "type": "Brute Force Attempt",
                "details": log
            })

        if _is_admin_login(log):
            alerts.append({
                "type": "Admin Login Detected",
                "details": log
            })

    return alerts


def _is_bruteforce(log):
    return (
        log.get("event") == "failed_login"
        and log.get("source_ip") is not None
    )


def _is_admin_login(log):
    return (
        log.get("event") == "login"
        and log.get("username") == "admin"
    )
