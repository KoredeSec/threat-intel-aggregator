#!/usr/bin/env python3
"""
Threat Intel Aggregator v1 
- Aggregates feeds (AlienVault, FeodoTracker, AbuseIPDB)
- Deduplicates, geolocates, saves CSV
- Produces interactive map highlighting top 10 countries
- Sends Slack and Email alerts on new indicators
- Logs runs to logs/
- Prints real-time progress in terminal while geolocating
"""

import os
import time
import logging
import requests
import pandas as pd
import folium
import schedule
import ipaddress
from datetime import datetime
from collections import Counter
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

# -------------------- Load environment --------------------
load_dotenv()
OTX_KEY = os.getenv("OTX_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")
IPINFO_KEY = os.getenv("IPINFO_KEY") 
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

# -------------------- Files & folders --------------------
CSV_FILE = "threat_feed.csv"
VISUALS_DIR = "visuals"
MAP_FILE = os.path.join(VISUALS_DIR, "threat_map_top10.html")
LOG_DIR = "logs"
os.makedirs(VISUALS_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -------------------- Logger --------------------
ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
LOG_FILE = os.path.join(LOG_DIR, f"run_{ts}.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# -------------------- Fetch feeds --------------------
def fetch_alienvault(limit_pulses=30):
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}
    results = []
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        for pulse in data.get("results", [])[:limit_pulses]:
            for ind in pulse.get("indicators", []):
                results.append({
                    "type": ind.get("type"),
                    "indicator": ind.get("indicator"),
                    "source": "AlienVault"
                })
    except Exception as e:
        logging.warning("AlienVault fetch error: %s", e)
    logging.info("AlienVault: fetched %d indicators", len(results))
    return results

def fetch_feodotracker():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    results = []
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            ip = line.strip()
            results.append({"type": "IP", "indicator": ip, "source": "FeodoTracker"})
    except Exception as e:
        logging.warning("FeodoTracker fetch error: %s", e)
    logging.info("FeodoTracker: fetched %d indicators", len(results))
    return results

def fetch_abuseipdb(limit=50):
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"} if ABUSE_KEY else {}
    results = []
    if not ABUSE_KEY:
        logging.warning("No AbuseIPDB key set; skipping AbuseIPDB fetch.")
        return results
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        for entry in data.get("data", [])[:limit]:
            results.append({"type": "IP", "indicator": entry.get("ipAddress"), "source": "AbuseIPDB"})
    except Exception as e:
        logging.warning("AbuseIPDB fetch error: %s", e)
    logging.info("AbuseIPDB: fetched %d indicators", len(results))
    return results

# -------------------- IP Validation --------------------
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# -------------------- Geolocation with ipinfo.io --------------------
def geolocate_with_ipinfo(indicators, sleep=0.2):
    indicators = [i for i in indicators if i["type"]=="IP" and valid_ip(i["indicator"])]
    total = len(indicators)
    logging.info("Starting geolocation for %d IPs...", total)
    headers = {"Authorization": f"Bearer {IPINFO_KEY}"} if IPINFO_KEY else {}
    for count, item in enumerate(indicators, start=1):
        ip = item["indicator"]
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=10)
            r.raise_for_status()
            data = r.json()
            loc = data.get("loc", "")
            if loc:
                lat, lon = map(float, loc.split(","))
            else:
                lat, lon = None, None
            country = data.get("country", "Unknown")
            item["latitude"] = lat
            item["longitude"] = lon
            item["country"] = country
        except Exception:
            item["latitude"] = None
            item["longitude"] = None
            item["country"] = "Unknown"
        print(f"Geolocated {count}/{total}: {ip} -> {item['country']}")
        time.sleep(sleep)
    logging.info("Geolocation completed.")
    return indicators

# -------------------- Save & dedupe --------------------
def save_to_csv(indicators):
    df = pd.DataFrame(indicators)
    if df.empty:
        logging.info("No indicators to save. Adding fallback test data.")
        df = pd.DataFrame([
            {"indicator": "8.8.8.8", "type": "IP", "source": "Test", "latitude": 37.386, "longitude": -122.0838, "country": "US"},
            {"indicator": "1.1.1.1", "type": "IP", "source": "Test", "latitude": -33.4940, "longitude": 143.2104, "country": "AU"},
            {"indicator": "185.199.108.153", "type": "IP", "source": "Test", "latitude": 37.7797, "longitude": -122.4192, "country": "US"}
        ])
    df.drop_duplicates(subset=["indicator"], inplace=True)
    cols = ["indicator", "type", "source", "country", "latitude", "longitude"]
    for c in cols:
        if c not in df.columns:
            df[c] = None
    df = df[cols]
    df.to_csv(CSV_FILE, index=False)
    logging.info("Saved %d unique indicators to %s", len(df), CSV_FILE)
    return df

# -------------------- Map creation --------------------
def top_countries(indicators, top_n=10):
    countries = [it.get("country", "Unknown") for it in indicators if it.get("country")]
    return Counter(countries).most_common(top_n)

def create_heatmap_top_countries(indicators):
    df = pd.DataFrame(indicators)
    if df.empty:
        logging.info("No data to map. Skipping map creation.")
        return
    top10 = [c for c,_ in top_countries(indicators)]
    m = folium.Map(location=[0,0], zoom_start=2)
    for _, row in df.iterrows():
        lat = row.get("latitude")
        lon = row.get("longitude")
        country = row.get("country")
        if pd.notnull(lat) and pd.notnull(lon):
            color = "red" if country in top10 else "blue"
            radius = 6 if country in top10 else 3
            folium.CircleMarker(
                [float(lat), float(lon)],
                radius=radius,
                color=color,
                fill=True,
                fill_opacity=0.7,
                popup=f"{row.get('indicator')} ({row.get('source')}, {country})"
            ).add_to(m)
    m.save(MAP_FILE)
    logging.info("Saved interactive map to %s", MAP_FILE)

# -------------------- Notifications --------------------
def send_slack_alert(text):
    if not SLACK_WEBHOOK:
        logging.info("No Slack webhook set; skipping Slack alert.")
        return False
    try:
        r = requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=10)
        r.raise_for_status()
        logging.info("Slack alert sent.")
        return True
    except Exception as e:
        logging.warning("Slack send error: %s", e)
        return False

def send_email_alert(subject, body):
    if not EMAIL_USER or not EMAIL_PASS:
        logging.info("No email creds set; skipping email alert.")
        return False
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=20)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        logging.info("Email alert sent.")
        return True
    except Exception as e:
        logging.warning("Email send error: %s", e)
        return False

# -------------------- Load previous indicators --------------------
def load_previous_indicators():
    if not os.path.exists(CSV_FILE):
        return set()
    try:
        df = pd.read_csv(CSV_FILE, dtype=str)
        return set(df["indicator"].dropna().tolist())
    except Exception:
        return set()

# -------------------- Main aggregator run --------------------
def run_aggregator():
    logging.info("⚡ Starting aggregator run...")
    prev = load_previous_indicators()

    indicators = []
    indicators.extend(fetch_alienvault())
    indicators.extend(fetch_feodotracker())
    indicators.extend(fetch_abuseipdb())

    indicators = geolocate_with_ipinfo(indicators)

    df = save_to_csv(indicators)

    current_set = set(df["indicator"].dropna().tolist()) if not df.empty else set()
    new_inds = current_set - prev
    new_count = len(new_inds)
    logging.info("New indicators found: %d", new_count)

    create_heatmap_top_countries(indicators)

    top10 = top_countries(indicators)
    summary = f"Threat Intel Aggregator run at {datetime.utcnow().isoformat()} UTC\nTotal unique indicators: {len(current_set)}\nNew: {new_count}\nTop countries: {top10}"
    if new_count > 0:
        sample_new = list(new_inds)[:10]
        summary += f"\nSample new indicators: {sample_new}"

    send_slack_alert(summary)
    send_email_alert("Threat Intel Aggregator Update", summary)

    logging.info("✅ Run complete.")
    return {"total": len(current_set), "new": new_count, "top10": top10}

# -------------------- Scheduler (optional) --------------------
def schedule_daily(hour_utc="09:00"):
    schedule.clear()
    schedule.every().day.at(hour_utc).do(run_aggregator)
    logging.info("Scheduled daily run at %s UTC", hour_utc)
    while True:
        schedule.run_pending()
        time.sleep(60)

# -------------------- Main --------------------
if __name__ == "__main__":
    run_aggregator()
    # Uncomment below for daily scheduling:
    # schedule_daily("09:00")
