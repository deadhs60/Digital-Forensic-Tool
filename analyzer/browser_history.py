import sqlite3
import pandas as pd
from datetime import datetime, timedelta

# =========================
# Convert Chrome Time
# =========================
def convert_time(chrome_time):
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
    except:
        return None

# =========================
# Extract Full History
# =========================
def extract_history(db_path):
    try:
        conn = sqlite3.connect(db_path)

        query = """
        SELECT 
            urls.url, 
            urls.title, 
            urls.visit_count, 
            visits.visit_time
        FROM urls
        JOIN visits ON urls.id = visits.url
        """

        df = pd.read_sql_query(query, conn)
        conn.close()

        # Convert time
        df["visit_time"] = df["visit_time"].apply(convert_time)

        return df

    except Exception as e:
        return str(e)

# =========================
# Top Visited Sites
# =========================
def get_top_sites(df, n=10):
    top = df.groupby("url")["visit_count"].max().sort_values(ascending=False).head(n)
    return top.reset_index()

# =========================
# Search Filter
# =========================
def search_history(df, keyword):
    return df[df["url"].str.contains(keyword, case=False, na=False)]

# =========================
# Suspicious Detection
# =========================
def detect_suspicious(df):
    suspicious_keywords = ["hack", "crack", "bypass", "attack", "darkweb", "malware"]

    results = []
    for url in df["url"]:
        for word in suspicious_keywords:
            if word in str(url).lower():
                results.append(url)

    return list(set(results))

# =========================
# Timeline Data
# =========================
def timeline_data(df):
    timeline = df.copy()
    timeline["date"] = timeline["visit_time"].dt.date
    return timeline.groupby("date").size().reset_index(name="visits")