# Input Validation logic
import re
import socket

def is_valid_ip(ip_str):
    """Checks if the string is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, ip_str)
        return True
    except socket.error:
        return False

def is_valid_hostname(hostname):
    """Simple hostname check."""
    if len(hostname) > 255: return False
    if hostname[-1] == ".": hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def validate_target(target):
    return is_valid_ip(target) or is_valid_hostname(target)