import re
from urllib.parse import urlparse

# --- Configuration ---
# Simple blacklist of known suspicious domains/keywords.
# In a real-world scenario, this would be a much larger, dynamically updated list.
BLACKLISTED_KEYWORDS = [
    "login-secure", "verify-account", "paypal-update", "bank-security",
    "free-gift", "urgent-action", "click-here-now", "discount-offer"
]

# --- Helper Functions ---

def is_ip_address(hostname: str) -> bool:
    """
    Checks if a given string is an IP address (IPv4 or IPv6).
    A common phishing tactic is to use IP addresses instead of domain names.

    Args:
        hostname (str): The hostname part of a URL.

    Returns:
        bool: True if it's an IP address, False otherwise.
    """
    # IPv4 regex
    ipv4_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    # Basic IPv6 check (more complex patterns exist for full validation)
    ipv6_pattern = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')

    if ipv4_pattern.match(hostname):
        # Additional check for valid IPv4 octets (0-255)
        parts = hostname.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    if ipv6_pattern.match(hostname):
        return True
    return False

def check_suspicious_subdomains(hostname: str) -> bool:
    """
    Checks for suspicious subdomains (e.g., 'microsoft.com.malicious.site.com').

    Args:
        hostname (str): The hostname part of a URL.

    Returns:
        bool: True if suspicious subdomain pattern is found, False otherwise.
    """
    # Look for legitimate brand names within subdomains that are not the root domain.
    # E.g., "paypal.com.evil.com" -> "evil.com" is the real domain.
    parts = hostname.split('.')
    if len(parts) > 2:
        # Check if any part before the last two (which would be the actual domain)
        # contains a common brand name like "paypal", "google", "apple".
        # This is a heuristic, not foolproof.
        for i in range(len(parts) - 2):
            if parts[i].lower() in ["paypal", "google", "apple", "microsoft", "amazon"]:
                return True
    return False

def check_typosquatting(hostname: str) -> bool:
    """
    Checks for common typosquatting patterns (e.g., 'gooogle.com', 'micros0ft.com').
    This is a very basic check and can be expanded significantly.

    Args:
        hostname (str): The hostname part of a URL.

    Returns:
        bool: True if potential typosquatting is detected, False otherwise.
    """
    # Example: Check for common misspellings of well-known domains
    known_domains = {
        "google.com": ["gooogle.com", "gogle.com"],
        "microsoft.com": ["micros0ft.com", "mircosoft.com"],
        "paypal.com": ["paypa1.com", "paypall.com"]
    }
    for real_domain, typos in known_domains.items():
        if hostname.lower() in typos:
            return True
    return False

def check_blacklisted_keywords(url_path: str) -> bool:
    """
    Checks if the URL path contains any blacklisted keywords.

    Args:
        url_path (str): The path part of the URL.

    Returns:
        bool: True if a blacklisted keyword is found, False otherwise.
    """
    for keyword in BLACKLISTED_KEYWORDS:
        if keyword.lower() in url_path.lower():
            return True
    return False

def analyze_url_for_phishing(url: str) -> dict:
    """
    Analyzes a given URL for potential phishing indicators.

    Args:
        url (str): The URL string to analyze.

    Returns:
        dict: A dictionary containing the analysis results, including a score
              and a list of detected suspicious characteristics.
    """
    results = {
        "url": url,
        "is_phishing": False,
        "score": 0, # Higher score means more suspicious
        "suspicious_indicators": []
    }

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        path = parsed_url.path

        if not hostname:
            results["suspicious_indicators"].append("URL has no valid hostname.")
            results["score"] += 5
            results["is_phishing"] = True
            return results

        # 1. Check for IP address in hostname
        if is_ip_address(hostname):
            results["suspicious_indicators"].append(f"Hostname is an IP address: {hostname}")
            results["score"] += 3

        # 2. Check for suspicious subdomains
        if check_suspicious_subdomains(hostname):
            results["suspicious_indicators"].append(f"Suspicious subdomain detected in: {hostname}")
            results["score"] += 2

        # 3. Check for typosquatting
        if check_typosquatting(hostname):
            results["suspicious_indicators"].append(f"Potential typosquatting detected: {hostname}")
            results["score"] += 4

        # 4. Check for blacklisted keywords in path
        if check_blacklisted_keywords(path):
            results["suspicious_indicators"].append(f"Blacklisted keyword found in path: {path}")
            results["score"] += 2

        # 5. Check for long URL (heuristic)
        if len(url) > 100: # Arbitrary threshold for long URLs
            results["suspicious_indicators"].append(f"URL is unusually long ({len(url)} characters).")
            results["score"] += 1

        # 6. Check for multiple subdomains (heuristic)
        if hostname.count('.') > 3: # e.g., www.login.secure.paypal.com.malicious.site.com
            results["suspicious_indicators"].append(f"Excessive subdomains: {hostname}")
            results["score"] += 1

        # Determine if it's considered phishing based on score
        if results["score"] >= 3: # Threshold can be adjusted
            results["is_phishing"] = True

    except Exception as e:
        results["suspicious_indicators"].append(f"Error parsing URL: {e}")
        results["score"] = 0 # Reset score if parsing fails
        results["is_phishing"] = False

    return results

def main():
    """
    Main function to run the URL Phishing Detector.
    Prompts the user for URLs to analyze.
    """
    print("-" * 50)
    print("Basic URL Phishing Detector")
    print("-" * 50)

    print("This tool performs basic heuristic checks and uses a small blacklist.")
    print("It is not a comprehensive phishing detection solution.")

    while True:
        url_input = input("\nEnter a URL to check (or 'q' to quit): ")
        if url_input.lower() == 'q':
            break

        if not url_input:
            print("Please enter a URL.")
            continue

        analysis_results = analyze_url_for_phishing(url_input)

        print("\n--- Analysis Results ---")
        print(f"URL: {analysis_results['url']}")
        print(f"Suspicious Score: {analysis_results['score']}")
        if analysis_results['is_phishing']:
            print("Verdict: POTENTIALLY PHISHING!")
        else:
            print("Verdict: Looks OK (based on basic checks).")

        if analysis_results['suspicious_indicators']:
            print("Indicators Found:")
            for indicator in analysis_results['suspicious_indicators']:
                print(f"- {indicator}")
        else:
            print("No suspicious indicators found.")
        print("-" * 50)

if __name__ == "__main__":
    main()
