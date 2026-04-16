import pickle
import re
from urllib.parse import urlparse
import sys
sys.path.insert(0, '.')
from database import get_whitelist_urls

# Load models
model = pickle.load(open("model.pkl", "rb"))
rf_model = pickle.load(open("rf_model.pkl", "rb"))
xgb_model = pickle.load(open("xgb_model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))
feature_cols = pickle.load(open("feature_cols.pkl", "rb"))

# Load whitelist from database
def load_whitelist():
    """Load whitelist from database."""
    try:
        return get_whitelist_urls()
    except Exception as e:
        print(f"Warning: Could not load whitelist from database: {e}")
        # Fallback to default whitelist
        return [
            "google.com", "youtube.com", "facebook.com", "twitter.com",
            "instagram.com", "linkedin.com", "github.com", "stackoverflow.com",
            "microsoft.com", "apple.com", "amazon.com", "netflix.com",
            "wikipedia.org", "reddit.com", "yahoo.com", "bing.com", "uptm.edu.my"
        ]

# Initialize whitelist
whitelist = load_whitelist()


def refresh_whitelist():
    """Refresh the whitelist from database."""
    global whitelist
    whitelist = load_whitelist()
    return whitelist


def is_url_valid(url):
    """Validate URL format."""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"
    
    url = url.strip()
    
    if len(url) < 3:
        return False, "URL is too short"
    
    # Add scheme if missing for validation
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc or '.' not in parsed.netloc:
            return False, "Invalid URL format - missing domain"
        return True, None
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"


def normalize_url(url):
    """Normalize URL format."""
    url = url.strip()
    
    # Add https if no scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url


# Suspicious keywords often found in phishing URLs
suspicious_keywords = [
    "login", "verify", "secure", "account", "update", "confirm",
    "bank", "free", "prize", "win", "password", "credential",
    "signin", "billing", "payment", "support", "alert", "unusual"
]

def extract_features(url):
    """
    Extract 30 features from URL matching the dataset format.
    """
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    
    # Feature 1: having_IP_Address
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    has_ip = 1 if re.search(ip_pattern, hostname) else -1
    
    # Feature 2: URL_Length
    url_length = len(url)
    url_len = 1 if url_length >= 75 else (0 if url_length < 54 else -1)
    
    # Feature 3: Shortining_Service
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    has_shortener = 1 if any(s in url.lower() for s in shorteners) else -1
    
    # Feature 4: having_At_Symbol
    has_at = 1 if '@' in url else -1
    
    # Feature 5: double_slash_redirecting
    double_slash = 1 if url.count('//') > 1 else -1
    
    # Feature 6: Prefix_Suffix
    has_prefix_suffix = 1 if '-' in hostname else -1
    
    # Feature 7: having_Sub_Domain
    subdomain_count = hostname.count('.')
    has_subdomain = -1 if subdomain_count <= 1 else (0 if subdomain_count == 2 else 1)
    
    # Feature 8: SSLfinal_State
    is_https = 1 if parsed.scheme == 'https' else -1
    
    # Feature 9: Domain_registeration_length
    domain_len = len(hostname)
    domain_reg_length = 1 if domain_len > 10 else -1
    
    # Feature 10: Favicon
    favicon = -1 if 'favicon' in path else 1
    
    # Feature 11: port
    has_port = 1 if ':' in hostname and not hostname.startswith('[') else -1
    
    # Feature 12: HTTPS_token
    https_in_domain = 1 if 'https' in hostname.lower() else -1
    
    # Feature 13: Request_URL
    has_request_url = 1 if parsed.query else -1
    
    # Feature 14: URL_of_Anchor
    has_anchor = 1 if '#' in url else -1
    
    # Feature 15: Links_in_tags
    has_links_tag = 1 if 'link' in path.lower() or 'href' in url.lower() else -1
    
    # Feature 16: SFH
    has_sfh = -1 if len(path) > 20 or path == '' else 1
    
    # Feature 17: Submitting_to_email
    has_email_submit = 1 if 'mailto:' in url or 'email' in path.lower() else -1
    
    # Feature 18: Abnormal_URL
    abnormal_url = -1 if hostname == '' or not '.' in hostname else 1
    
    # Feature 19: Redirect
    has_redirect = 1 if url.count('//') > 1 else -1
    
    # Feature 20: on_mouseover
    has_mouseover = -1 if 'onmouseover' in url.lower() else 1
    
    # Feature 21: RightClick
    has_rightclick_block = -1 if 'oncontextmenu' in url.lower() else 1
    
    # Feature 22: popUpWidnow
    has_popup = -1 if 'alert' in url.lower() or 'prompt' in url.lower() else 1
    
    # Feature 23: Iframe
    has_iframe = -1 if 'iframe' in url.lower() else 1
    
    # Feature 24: age_of_domain
    age_domain = 1 if domain_len > 5 else -1
    
    # Feature 25: DNSRecord
    dns_record = 1 if len(hostname) > 3 else -1
    
    # Feature 26: web_traffic
    web_traffic = 1 if len(hostname) > 5 else -1
    
    # Feature 27: Page_Rank
    page_rank = -1 if len(hostname) < 5 else 1
    
    # Feature 28: Google_Index
    google_index = 1 if 'google' not in hostname else -1
    
    # Feature 29: Links_pointing_to_page
    links_pointing = 1 if path != '' else -1
    
    # Feature 30: Statistical_report
    statistical_report = -1 if any(word in url.lower() for word in suspicious_keywords) else 1
    
    return [[
        has_ip, url_len, has_shortener, has_at, double_slash,
        has_prefix_suffix, has_subdomain, is_https, domain_reg_length,
        favicon, has_port, https_in_domain, has_request_url, has_anchor,
        has_links_tag, has_sfh, has_email_submit, abnormal_url, has_redirect,
        has_mouseover, has_rightclick_block, has_popup, has_iframe, age_domain,
        dns_record, web_traffic, page_rank, google_index, links_pointing, statistical_report
    ]]


def rule_based_score(url):
    """
    Calculate a rule-based suspicion score as additional verification.
    """
    score = 0
    
    # Check suspicious keywords
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        score += 2
    
    # Check for IP address in URL
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 3
    
    # Check for excessive hyphens
    if url.count('-') > 2:
        score += 1
    
    # Check URL length
    if len(url) > 75:
        score += 2
    elif len(url) > 50:
        score += 1
    
    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    if any(s in url.lower() for s in shorteners):
        score += 2
    
    # Check for @ symbol
    if '@' in url:
        score += 3
    
    # Check for multiple redirects
    if url.count('//') > 1:
        score += 1
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.click', '.gq', '.tk', '.ml', '.cf', '.ga']
    if any(url.lower().endswith(tld) for tld in suspicious_tlds):
        score += 2
    
    return score


def detect_url(url):
    """
    Main detection function using ML models.
    Returns a dictionary with detection results.
    """
    result = {
        'url': url,
        'prediction': None,
        'confidence': None,
        'risk_level': None,
        'details': {},
        'rf_prediction': None,
        'xgb_prediction': None,
        'rule_score': None
    }
    
    # Parse URL for details
    parsed = urlparse(url)
    
    # Check whitelist
    for site in whitelist:
        if site in url.lower():
            result['prediction'] = 'Legitimate'
            result['risk_level'] = 'LOW'
            result['details']['reason'] = 'Whitelisted site'
            result['confidence'] = 100.0
            result['details'] = {
                'url_length': len(url),
                'has_https': parsed.scheme == 'https',
                'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
                'has_suspicious_keywords': False,
                'rule_based_score': 0
            }
            return result
    
    # Extract features
    features = extract_features(url)
    features_scaled = scaler.transform(features)
    
    # Get predictions from both models
    rf_pred = rf_model.predict(features_scaled)[0]
    rf_proba = rf_model.predict_proba(features_scaled)[0]
    
    xgb_pred = xgb_model.predict(features_scaled)[0]
    xgb_proba = xgb_model.predict_proba(features_scaled)[0]
    
    result['rf_prediction'] = 'Phishing' if rf_pred == 0 else 'Legitimate'
    result['xgb_prediction'] = 'Phishing' if xgb_pred == 0 else 'Legitimate'
    
    # Get main model prediction (XGBoost - best model)
    prediction = 'Phishing' if xgb_pred == 0 else 'Legitimate'
    confidence = max(xgb_proba) * 100
    
    # Get rule-based score
    rule_score = rule_based_score(url)
    result['rule_score'] = rule_score
    
    # Determine risk level
    if prediction == 'Phishing':
        if confidence >= 90:
            risk_level = 'HIGH'
        elif confidence >= 70:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
    else:
        if rule_score >= 5:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
    
    # Override if rule-based score is very high
    if rule_score >= 7:
        prediction = 'Phishing'
        risk_level = 'HIGH'
        confidence = min(confidence + 10, 99.9)

    # NEW: Suspicious (Needs Verification) for uncertain links
    if ((prediction == 'Legitimate' and confidence < 60 and rule_score < 3) or
        (prediction == 'Phishing' and confidence < 40 and rule_score == 0)):
        prediction = 'Suspicious (Needs Verification)'
        risk_level = 'MEDIUM'
    
    result['prediction'] = prediction
    result['confidence'] = round(confidence, 2)
    result['risk_level'] = risk_level
    result['details'] = {
        'url_length': len(url),
        'has_https': parsed.scheme == 'https' if '://' in url else False,
        'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
        'has_suspicious_keywords': any(k in url.lower() for k in suspicious_keywords),
        'rule_based_score': rule_score
    }
    
    return result


def get_model_info():
    """
    Return information about the loaded models.
    """
    return {
        'main_model': 'XGBoost',
        'accuracy': '97.74%',
        'rf_accuracy': '96.79%',
        'xgb_accuracy': '97.74%',
        'features_count': 30,
        'training_samples': 11055
    }


if __name__ == "__main__":
    # Test the detector
    print("=" * 60)
    print("PHISHING URL DETECTOR")
    print("=" * 60)
    print("\nModel Info:", get_model_info())
    
    while True:
        url = input("\nEnter URL to scan (or 'q' to quit): ").strip()
        
        if url.lower() == 'q':
            break
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        result = detect_url(url)
        
        print("\n" + "=" * 50)
        print("DETECTION RESULT")
        print("=" * 50)
        print(f"URL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']}%")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Rule Score: {result['rule_score']}")
        print(f"XGBoost: {result['xgb_prediction']}")
        print(f"Random Forest: {result['rf_prediction']}")
        print("=" * 50)
