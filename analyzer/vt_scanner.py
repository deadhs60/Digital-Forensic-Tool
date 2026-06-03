import requests
import base64
from urllib.parse import urlparse

# =========================
# ADD YOUR API KEY HERE
# =========================
API_KEY = "21d8157d6c399ae90e62982da87194251c86ec646a2ce73a4c2a35428cc2a4ca"

# =========================
# Extract Domain
# =========================
def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

# =========================
# Convert URL to VT ID
# =========================
def url_to_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# =========================
# Scan Single URL
# =========================
def scan_url(url):
    try:
        url_id = url_to_id(url)

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }

        else:
            return {
                "url": url,
                "error": f"API Error {response.status_code}"
            }

    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }

# =========================
# Scan Multiple URLs
# =========================
def scan_urls_from_df(df, limit=10):
    results = []

    urls = df["url"].dropna().unique()[:limit]

    for url in urls:
        domain = get_domain(url)

        if domain:
            result = scan_url(domain)
            results.append(result)

    return results