import re
from urllib.parse import urlparse
import math

def extract_features(url):
    """
    Extract 30 features from URL for phishing detection.
    Features based on phishing_dataset.csv columns.
    """
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    
    # Basic URL features
    url_length = len(url)
    hostname = parsed.netloc
    path = parsed.path
    
    # Feature 1: having_IP_Address
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    having_IP_Address = 1 if re.search(ip_pattern, hostname) else -1
    
    # Feature 2: URL_Length
    URL_Length = 1 if url_length >= 75 else (0 if url_length < 54 else -1)
    
    # Feature 3: Shortining_Service
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    Shortining_Service = 1 if any(s in url.lower() for s in shorteners) else -1
    
    # Feature 4: having_At_Symbol
    having_At_Symbol = 1 if '@' in url else -1
    
    # Feature 5: double_slash_redirecting
    double_slash_redirecting = 1 if url.count('//') > 1 else -1
    
    # Feature 6: Prefix_Suffix
    Prefix_Suffix = 1 if '-' in hostname else -1
    
    # Feature 7: having_Sub_Domain
    subdomain_count = hostname.count('.')
    having_Sub_Domain = -1 if subdomain_count <= 1 else (0 if subdomain_count == 2 else 1)
    
    # Feature 8: SSLfinal_State
    SSLfinal_State = 1 if parsed.scheme == 'https' else -1
    
    # Feature 9: Domain_registeration_length (simulated)
    domain_len = len(hostname)
    Domain_registeration_length = 1 if domain_len > 10 else -1
    
    # Feature 10: Favicon (simulated)
    Favicon = -1 if 'favicon' in path else 1
    
    # Feature 11: port
    port = 1 if ':' in hostname and not hostname.startswith('[') else -1
    
    # Feature 12: HTTPS_token
    HTTPS_token = 1 if 'https' in hostname.lower() else -1
    
    # Feature 13: Request_URL
    Request_URL = 1 if parsed.query else -1
    
    # Feature 14: URL_of_Anchor
    URL_of_Anchor = 1 if '#' in url else -1
    
    # Feature 15: Links_in_tags
    Links_in_tags = 1 if 'link' in path.lower() or 'href' in url.lower() else -1
    
    # Feature 16: SFH (Server Form Handler)
    SFH = -1 if len(path) > 20 or path == '' else 1
    
    # Feature 17: Submitting_to_email
    Submitting_to_email = 1 if 'mailto:' in url or 'email' in path.lower() else -1
    
    # Feature 18: Abnormal_URL
    Abnormal_URL = -1 if hostname == '' or not '.' in hostname else 1
    
    # Feature 19: Redirect
    Redirect = 1 if url.count('//') > 1 else -1
    
    # Feature 20: on_mouseover
    on_mouseover = -1 if 'onmouseover' in url.lower() else 1
    
    # Feature 21: RightClick
    RightClick = -1 if 'oncontextmenu' in url.lower() else 1
    
    # Feature 22: popUpWidnow
    popUpWidnow = -1 if 'alert' in url.lower() or 'prompt' in url.lower() else 1
    
    # Feature 23: Iframe
    Iframe = -1 if 'iframe' in url.lower() else 1
    
    # Feature 24: age_of_domain (simulated)
    age_of_domain = 1 if domain_len > 5 else -1
    
    # Feature 25: DNSRecord
    DNSRecord = 1 if len(hostname) > 3 else -1
    
    # Feature 26: web_traffic (simulated)
    web_traffic = 1 if len(hostname) > 5 else -1
    
    # Feature 27: Page_Rank (simulated)
    Page_Rank = -1 if len(hostname) < 5 else 1
    
    # Feature 28: Google_Index
    Google_Index = 1 if 'google' not in hostname else -1
    
    # Feature 29: Links_pointing_to_page
    Links_pointing_to_page = 1 if path != '' else -1
    
    # Feature 30: Statistical_report
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 
                       'bank', 'free', 'prize', 'win', 'password', 'credential']
    Statistical_report = -1 if any(word in url.lower() for word in suspicious_words) else 1
    
    return [
        having_IP_Address,
        URL_Length,
        Shortining_Service,
        having_At_Symbol,
        double_slash_redirecting,
        Prefix_Suffix,
        having_Sub_Domain,
        SSLfinal_State,
        Domain_registeration_length,
        Favicon,
        port,
        HTTPS_token,
        Request_URL,
        URL_of_Anchor,
        Links_in_tags,
        SFH,
        Submitting_to_email,
        Abnormal_URL,
        Redirect,
        on_mouseover,
        RightClick,
        popUpWidnow,
        Iframe,
        age_of_domain,
        DNSRecord,
        web_traffic,
        Page_Rank,
        Google_Index,
        Links_pointing_to_page,
        Statistical_report
    ]


def get_feature_names():
    """Return feature names for reference"""
    return [
        'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
        'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
        'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
        'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
        'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
        'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
        'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
        'Links_pointing_to_page', 'Statistical_report'
    ]


# Test the model
if __name__ == "__main__":
    test_urls = [
        "http://suspicious-phishing.com/login",
        "https://google.com",
        "https://secure-bank-update.com/verify"
    ]
    
    print("Testing model.py")
    print("=" * 50)
    
    for url in test_urls:
        features = extract_features(url)
        print(f"\nURL: {url}")
        print(f"Features: {len(features)} features extracted")
        print(f"First 5 features: {features[:5]}")
