# Logic to remove PII before AI analysis
import re
import copy

def sanitize_scan_data(scan_data):
    """
    Removes sensitive PII (MAC addresses, specific local paths) from the JSON
    before sending it to the AI.
    """
    # Deep copy to avoid modifying the original data shown to the user
    sanitized = copy.deepcopy(scan_data)
    
    # Regex for MAC Address (e.g., 00:1A:2B:3C:4D:5E)
    mac_regex = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
    
    def recursive_clean(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    # Replace MAC addresses
                    obj[k] = mac_regex.sub("[REDACTED_MAC]", v)
                elif isinstance(v, (dict, list)):
                    recursive_clean(v)
        elif isinstance(obj, list):
            for item in obj:
                recursive_clean(item)
    
    recursive_clean(sanitized)
    return sanitized