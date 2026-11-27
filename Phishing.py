
from urllib.parse import urlparse
import ipaddress


def analyze_url(url):

    result = urlparse(url)

    hostname = result.hostname or ""
    score = 0
    findings = []

    # Check HTTPS
    if result.scheme != "https":
        score += 1
        findings.append("URL does not use HTTPS")

    # Check IP address
    try:
        ipaddress.ip_address(hostname)
        score += 3
        findings.append("IP address used instead of domain")
    except ValueError:
        pass


    if len(url) > 100:
        score += 1
        findings.append("Unusually long URL")


    keywords = [
        "login",
        "verify",
        "password",
        "account",
        "bank",
        "update"
    ]

    for word in keywords:
        if word in url.lower():
            score += 1
            findings.append(f"Suspicious keyword: {word}")

    # Final result
    print("\n========== SCAN RESULT ==========")
    print("URL:", url)
    print("Risk Score:", min(score, 10), "/10")

    if score >= 4:
        print("Status: SUSPICIOUS")
    elif score >= 2:
        print("Status: USE CAUTION")
    else:
        print("Status: NO OBVIOUS WARNING")

    print("\nFindings:")

    if findings:
        for finding in findings:
            print("-", finding)
    else:
        print("- No suspicious patterns found")


print("================================")
print("     PHISHING LINK DETECTOR")
print("================================")

url = input("\nEnter URL: ")

analyze_url(url)
