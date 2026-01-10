import hashlib
import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def check_breach(password):
    """
    Checks if a password has been compromised using HIBP k-anonymity API.
    Returns the number of times it has been seen in breaches.
    """
    # Hash the password with SHA-1
    sha1pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pw[:5]
    suffix = sha1pw[5:]
    
    try:
        response = requests.get(HIBP_API_URL + prefix, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return 0 # Fail gracefully
        
    # Search for the suffix in the response
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
            
    return 0

def check_breach_prefix(prefix):
    """
    Alternative for ZK: Client sends prefix, Server returns raw response or parsed data.
    This ensures server never sees full hash.
    """
    try:
        response = requests.get(HIBP_API_URL + prefix, timeout=5)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return ""
