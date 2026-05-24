import re
import math
from urllib.parse import urlparse
import socket

# Common highly-phished brands list for brand spoofing detection
BRAND_KEYWORDS = [
    'google', 'paypal', 'amazon', 'apple', 'netflix', 'chase', 'steam', 
    'microsoft', 'facebook', 'instagram', 'twitter', 'linkedin', 'yahoo', 
    'dropbox', 'adobe', 'walmart', 'ebay', 'spotify', 'roblox', 'zoom', 
    'wellsfargo', 'bankofamerica', 'capitalone', 'citi', 'americanexpress', 
    'coinbase', 'binance', 'discord', 'telegram', 'outlook', 'office365',
    'bofa', 'wells-fargo', 'stripe', 'square'
]

# Shortener services to detect URL shortening
SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rebrand.ly', 'is.gd', 
    'buff.ly', 'adf.ly', 'bit.do', 'lnkd.in', 'db.tt', 'qr.ae', 'ow.ly', 
    'w.wiki', 'shorte.st', 'tiny.cc'
]

# Suspicious keywords in URLs indicative of credential harvesting/phishing
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'signin', 'account', 'update', 'bank', 
    'portal', 'confirm', 'billing', 'support', 'recovery', 'pass', 'reset', 
    'auth', 'card', 'wallet', 'webapps', 'admin', 'myaccount', 'client',
    'customer', 'validation', 'service', 'cancel', 'refund', 'unlock'
]

# Risky top-level domains frequently abused for phishing
RISKY_TLDS = [
    'xyz', 'top', 'club', 'work', 'icu', 'gq', 'fit', 'link', 'live', 
    'support', 'info', 'online', 'site', 'vip', 'cc', 'ru', 'cn', 'tk', 
    'ml', 'ga', 'cf', 'buzz', 'shop', 'monster', 'country', 'stream'
]

def calculate_entropy(text):
    """Calculate Shannon entropy of a string (measures randomness)."""
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    entropy = - sum([p * math.log2(p) for p in probabilities])
    return float(entropy)

def extract_domain_age(domain):
    """
    Simulates domain age in days.
    Under offline environments or API limitations, uses a fast, deterministic lookup:
    1. Known global domains (google, apple, amazon) are returned as very old (> 5000 days).
    2. Suspected phishing domains/patterns are returned as very young (< 90 days).
    """
    if not domain:
        return 0
    
    clean_domain = domain.lower().replace("www.", "")
    
    # Common trustworthy domains
    trusted_roots = ['google.com', 'apple.com', 'amazon.com', 'netflix.com', 'microsoft.com', 
                     'facebook.com', 'github.com', 'wikipedia.org', 'yahoo.com', 'linkedin.com']
    for root in trusted_roots:
        if clean_domain == root or clean_domain.endswith("." + root):
            return 8500  # ~23 years old
            
    # Check for brand spoofing combined with young patterns
    for brand in BRAND_KEYWORDS:
        if brand in clean_domain:
            # If the domain has a brand keyword but is not the official domain, it's highly likely to be a new phishing site
            is_official = False
            for root in trusted_roots:
                if brand in root and (clean_domain == root or clean_domain.endswith("." + root)):
                    is_official = True
                    break
            if not is_official:
                return 15  # 15 days old (suspiciously new)
                
    # Generic logic: if it has special characters in hostname or suspicious keywords, make it young
    if any(kw in clean_domain for kw in SUSPICIOUS_KEYWORDS) or "-" in clean_domain:
        return 45  # ~1.5 months
        
    # Check TLD
    tld = clean_domain.split('.')[-1]
    if tld in RISKY_TLDS:
        return 90  # ~3 months
        
    # Default fallback: mature but standard domain age
    return 1450  # ~4 years

def is_ip_address(hostname):
    """Check if the hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return 0
    # IPv4 regex
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, hostname):
        parts = hostname.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return 1
    # Check simple IPv6 structure
    if ':' in hostname and len(hostname) >= 3:
        return 1
    return 0

def get_longest_word_length(hostname):
    """Find the length of the longest purely alphabetical substring in the hostname."""
    if not hostname:
        return 0
    words = re.findall(r'[a-zA-Z]+', hostname)
    if not words:
        return 0
    return len(max(words, key=len))

def extract_features(url):
    """
    Extracts 33 lexical and domain-based features from a raw URL.
    Returns a dictionary of feature names and float/int values.
    """
    # 0. Parsing
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        # Fallback to parse correctly if protocol is missing
        parsed_url = urlparse('http://' + url)
        full_url = 'http://' + url
    else:
        parsed_url = urlparse(url)
        full_url = url

    hostname = parsed_url.netloc.lower() if parsed_url.netloc else parsed_url.path.split('/')[0].lower()
    path = parsed_url.path
    query = parsed_url.query
    
    # Strip port number if any
    hostname_clean = hostname.split(':')[0]
    
    # Basic lengths
    url_len = len(full_url)
    host_len = len(hostname_clean)
    path_len = len(path)
    query_len = len(query)
    
    # Subdomains & Dots
    # www.google.com -> parts: ['www', 'google', 'com'] -> subdomain count is 1 (excluding google & com)
    host_parts = hostname_clean.split('.')
    dot_count_host = hostname_clean.count('.')
    
    # If the domain is an IP address, subdomains don't apply similarly
    has_ip = is_ip_address(hostname_clean)
    
    if has_ip:
        num_subdomains = 0
        subdomain_len = 0
    else:
        # A normal hostname has format: [subdomains].[domain].[tld]
        # e.g., mail.google.com -> length of parts is 3, domain is 'google', tld is 'com', subdomain is 'mail'
        if len(host_parts) > 2:
            num_subdomains = len(host_parts) - 2
            subdomain_len = len('.'.join(host_parts[:-2]))
        else:
            num_subdomains = 0
            subdomain_len = 0
            
    # TLD details
    tld = host_parts[-1] if len(host_parts) > 1 and not has_ip else ""
    tld_len = len(tld)
    tld_is_risky = 1 if tld in RISKY_TLDS else 0
    suspicious_tld = tld_is_risky  # Duplicate representation or additional classification
    
    # Characters counts & Ratios
    num_digits = sum(c.isdigit() for c in full_url)
    digit_ratio = num_digits / url_len if url_len > 0 else 0.0
    
    num_digits_host = sum(c.isdigit() for c in hostname_clean)
    digit_ratio_host = num_digits_host / host_len if host_len > 0 else 0.0
    
    path_digits = sum(c.isdigit() for c in path)
    path_digit_ratio = path_digits / path_len if path_len > 0 else 0.0
    
    query_digits = sum(c.isdigit() for c in query)
    query_digit_ratio = query_digits / query_len if query_len > 0 else 0.0
    
    # Special character counting in the URL
    special_chars = ['-', '_', '@', '?', '=', '&', '.', '%', '+', ';']
    num_special_chars = sum(full_url.count(c) for c in special_chars)
    non_alphanumeric_ratio = sum(not c.isalnum() for c in full_url) / url_len if url_len > 0 else 0.0
    
    dash_count_host = hostname_clean.count('-')
    slash_count = full_url.count('/')
    
    # Flags & Detections
    has_at_symbol = 1 if '@' in full_url else 0
    
    # double slash in path (excluding the initial protocol double slash)
    # e.g., https://example.com/login//secure
    path_to_check = full_url.split('://', 1)[-1] if '://' in full_url else full_url
    has_double_slash = 1 if '//' in path_to_check else 0
    
    # HTTP in path (excluding the initial protocol)
    has_http_in_path = 1 if 'http' in path_to_check.lower() else 0
    
    # Shortener checking
    is_shortened = 0
    for short_dom in SHORTENER_DOMAINS:
        if hostname_clean == short_dom or hostname_clean.endswith('.' + short_dom):
            is_shortened = 1
            break
            
    # Brand Spoofing Check
    # A brand is spoofed if a popular brand keyword is present inside the hostname or path
    # but the domain is not actually the official brand domain.
    has_brand_keyword = 0
    matched_brand = None
    for brand in BRAND_KEYWORDS:
        if brand in full_url.lower():
            # Check if this is the official domain of the brand
            # e.g., if brand is 'paypal', check if host is paypal.com or ends in .paypal.com
            is_official = False
            # Simple approximation of official roots:
            official_domains = [f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.co.uk", f"{brand}.io"]
            for off_dom in official_domains:
                if hostname_clean == off_dom or hostname_clean.endswith('.' + off_dom):
                    is_official = True
                    break
            if not is_official:
                has_brand_keyword = 1
                matched_brand = brand
                break
                
    # Login Keywords Check
    has_login_keywords = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_url.lower():
            has_login_keywords = 1
            break
            
    # Hostname Vowel-Consonant Ratio
    vowels = sum(c in 'aeiou' for c in hostname_clean)
    consonants = sum(c in 'bcdfghjklmnpqrstvwxyz' for c in hostname_clean)
    vowel_consonant_ratio = vowels / consonants if consonants > 0 else (vowels if vowels > 0 else 0.0)
    
    longest_word_len = get_longest_word_length(hostname_clean)
    num_params = len(parsed_url.query.split('&')) if parsed_url.query else 0
    www_in_hostname = 1 if 'www' in host_parts else 0
    subdomain_depth = num_subdomains # Identical mapping for depth representability
    
    # Domain Age (WHOIS mock or lookup)
    domain_age_days = extract_domain_age(hostname_clean)
    
    # Assemble feature vector matching exactly the 33 expected dimensions
    features = {
        'url_len': float(url_len),
        'host_len': float(host_len),
        'path_len': float(path_len),
        'query_len': float(query_len),
        'num_subdomains': float(num_subdomains),
        'num_digits': float(num_digits),
        'digit_ratio': float(digit_ratio),
        'digit_ratio_host': float(digit_ratio_host),
        'num_special_chars': float(num_special_chars),
        'dash_count_host': float(dash_count_host),
        'dot_count_host': float(dot_count_host),
        'slash_count': float(slash_count),
        'has_ip': float(has_ip),
        'has_http_in_path': float(has_http_in_path),
        'has_at_symbol': float(has_at_symbol),
        'has_double_slash': float(has_double_slash),
        'entropy': float(calculate_entropy(full_url)),
        'has_brand_keyword': float(has_brand_keyword),
        'is_shortened': float(is_shortened),
        'tld_length': float(tld_len),
        'tld_is_risky': float(tld_is_risky),
        'subdomain_depth': float(subdomain_depth),
        'has_login_keywords': float(has_login_keywords),
        'vowel_consonant_ratio': float(vowel_consonant_ratio),
        'longest_word_len': float(longest_word_len),
        'num_params': float(num_params),
        'suspicious_tld': float(suspicious_tld),
        'domain_age_days': float(domain_age_days),
        'www_in_hostname': float(www_in_hostname),
        'subdomain_len': float(subdomain_len),
        'path_digit_ratio': float(path_digit_ratio),
        'query_digit_ratio': float(query_digit_ratio),
        'non_alphanumeric_ratio': float(non_alphanumeric_ratio)
    }
    
    # Return features dictionary, plus some raw non-numeric metadata for backend processing
    metadata = {
        'hostname': hostname_clean,
        'matched_brand': matched_brand,
        'tld': tld
    }
    
    return features, metadata

if __name__ == '__main__':
    # Test sample
    test_urls = [
        "https://www.google.com/search?q=phishing",
        "http://paypal-security-update-verification.login-accounts.xyz/index.html?token=123",
        "http://192.168.1.1/login.php",
        "bit.ly/3asDf"
    ]
    for url in test_urls:
        feats, meta = extract_features(url)
        print(f"URL: {url}")
        print(f"  Length: {feats['url_len']}, Subdomains: {feats['num_subdomains']}, Brand Spoof: {feats['has_brand_keyword']}, Risky TLD: {feats['tld_is_risky']}, Domain Age: {feats['domain_age_days']} days")
        print(f"  Metadata: {meta}")
        print("-" * 50)
