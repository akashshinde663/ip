import os
import json
import csv
from datetime import datetime
from urllib.parse import urlencode

import requests
from flask import Flask, request, render_template, jsonify
from dotenv import load_dotenv

load_dotenv()

APIIP_KEY = os.getenv("APIIP_KEY", "")
TRUST_PROXY = os.getenv("TRUST_PROXY", "False").lower() == "true"

if not APIIP_KEY:
    raise RuntimeError("Missing APIIP_KEY in environment (.env).")

app = Flask(__name__)

LOG_FILE = "visitor_logs.csv"


def get_client_ip(req: request) -> str:
    """
    Safely derive the client IP. If you're behind a reverse proxy (Render/NGINX),
    enable TRUST_PROXY=True in .env to respect X-Forwarded-For.
    """
    if TRUST_PROXY:
        # X-Forwarded-For may contain multiple IPs: client, proxy1, proxy2...
        xff = req.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    # Fallback to remote_addr
    return req.remote_addr or ""


def geo_lookup(ip: str) -> dict:
    """
    Call apiip.net without exposing your API key to the client.
    """
    base = "https://apiip.net/api/check"
    params = {"accessKey": APIIP_KEY}
    if ip:
        params["ip"] = ip
    url = f"{base}?{urlencode(params)}"

    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def log_visit(row: dict) -> None:
    """
    Append a visit to CSV. Creates header if file doesn’t exist.
    """
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ts",
                "ip",
                "user_agent",
                "geo_json",
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


@app.route("/", methods=["GET"])
def consent():
    # Show consent page first (best practice)
    return render_template("consent.html")


@app.route("/lookup", methods=["POST"])
def do_lookup():
    # After user consents
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")

    try:
        geo = geo_lookup(ip)
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": str(e)}), 502

    # Log to CSV
    log_visit(
        {
            "ts": datetime.utcnow().isoformat() + "Z",
            "ip": ip,
            "user_agent": ua,
            "geo_json": json.dumps(geo, ensure_ascii=False),
        }
    )

    # Return a friendly JSON response
    return jsonify(
        {
            "ok": True,
            "your_ip": ip,
            "user_agent": ua,
            "geolocation": geo,
        }
    )


@app.route("/logs", methods=["GET"])
def read_logs():
    """
    Simple viewer to inspect logs during development.
    In production, protect this route (auth) or remove it.
    """
    if not os.path.isfile(LOG_FILE):
        return jsonify({"ok": True, "data": []})
    out = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["geo_json"] = json.loads(row["geo_json"]) if row.get("geo_json") else {}
            out.append(row)
    return jsonify({"ok": True, "count": len(out), "data": out})


if __name__ == "__main__":
    # For local dev only
    app.run(host="0.0.0.0", port=5000, debug=True)
