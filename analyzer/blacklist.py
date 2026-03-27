from urllib.parse import urlparse

def load_blacklist():
    with open("blacklist.txt", "r") as f:
        return [line.strip() for line in f.readlines()]

def detect_blacklist(df):
    blacklist = load_blacklist()
    flagged = []

    for url in df["url"]:
        domain = urlparse(url).netloc

        for bad in blacklist:
            if bad in domain:
                flagged.append(domain)

    return list(set(flagged))