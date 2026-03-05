import feedparser
import json
import re
from datetime import datetime, timezone
import requests

FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News", "cat": "threats"},
    {"url": "https://krebsonsecurity.com/feed", "name": "Krebs on Security", "cat": "threats"},
    {"url": "http://feeds.feedburner.com/securityweek", "name": "SecurityWeek", "cat": "threats"},
    {"url": "http://feeds.feedburner.com/gbhackers", "name": "GBHackers", "cat": "threats"},
    {"url": "https://www.hackread.com/feed", "name": "HackRead", "cat": "threats"},
    {"url": "https://rss.packetstormsecurity.com/", "name": "PacketStorm", "cat": "exploits"},
    {"url": "https://www.exploit-db.com/rss.xml", "name": "Exploit-DB", "cat": "exploits"},
    {"url": "https://www.vulnhub.com/feeds/added/atom/", "name": "VulnHub", "cat": "vulns"},
    {"url": "https://www.pentestpartners.com/feed", "name": "PentestPartners", "cat": "redteam"},
    {"url": "https://news.sophos.com/en-us/category/security-operations/feed/", "name": "Sophos SecOps", "cat": "threats"},
    {"url": "https://news.sophos.com/en-us/category/threat-research/feed/", "name": "Sophos Research", "cat": "malware"},
    {"url": "https://blog.malwarebytes.com/feed/", "name": "Malwarebytes", "cat": "malware"},
    {"url": "https://isc.sans.edu/rssfeed_full.xml", "name": "SANS ISC", "cat": "vulns"},
    {"url": "https://www.schneier.com/feed/atom/", "name": "Schneier", "cat": "tools"},
    {"url": "https://feeds.feedburner.com/eset/blog", "name": "ESET Blog", "cat": "malware"},
    {"url": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches", "name": "HaveIBeenPwned", "cat": "breaches"},
    {"url": "https://www.reddit.com/r/netsec/.rss", "name": "r/netsec", "cat": "community"},
    {"url": "https://www.reddit.com/r/Pentesting/.rss", "name": "r/Pentesting", "cat": "redteam"},
    {"url": "https://www.reddit.com/r/redteamsec/.rss", "name": "r/redteamsec", "cat": "redteam"},
    {"url": "https://www.reddit.com/r/cybersecurity/.rss", "name": "r/cybersecurity", "cat": "community"},
    {"url": "https://www.reddit.com/r/blueteamsec/.rss", "name": "r/blueteamsec", "cat": "community"},
]

CRIT_KW = ["zero-day","0day","rce","remote code execution","actively exploited","critical vulnerability","ransomware attack","nation-state","supply chain attack"]
HIGH_KW  = ["vulnerability","cve-","exploit","breach","attack","malware","backdoor","trojan","phishing","privilege escalation"]

def get_severity(text):
    t = text.lower()
    if any(k in t for k in CRIT_KW): return "critical"
    if any(k in t for k in HIGH_KW):  return "high"
    return "medium"

def get_cat(text, feed_cat):
    t = text.lower()
    if any(k in t for k in ["breach","leak","pwned","data breach"]) and feed_cat == "threats": return "breaches"
    if any(k in t for k in ["malware","ransomware","trojan","wiper"]) and feed_cat == "threats": return "malware"
    if any(k in t for k in ["pentest","red team","lateral movement"]) and feed_cat in ["threats","tools"]: return "redteam"
    return feed_cat

def clean_html(raw):
    return re.sub(r'<[^>]+>', '', raw or '').strip()[:400]

def extract_cves(text):
    return list(set(re.findall(r'CVE-\d{4}-\d+', text, re.IGNORECASE)))

articles   = []
sources_ok = 0
headers    = {"User-Agent": "RedOps-Intel-Bot/3.0"}

for cfg in FEEDS:
    try:
        resp = requests.get(cfg["url"], timeout=15, headers=headers)
        feed = feedparser.parse(resp.content)
        for entry in feed.entries[:15]:
            title = entry.get("title", "Untitled").strip()
            link  = entry.get("link", "#")
            desc  = clean_html(entry.get("summary", entry.get("description", "")))
            pub   = entry.get("published", entry.get("updated", ""))
            full  = title + " " + desc
            cves  = extract_cves(full)
            articles.append({
                "id":        f"{cfg['name'][:6].replace(' ','')}-{abs(hash(title+pub)) % 999999}",
                "title":     title,
                "link":      link,
                "desc":      desc,
                "pubDate":   pub,
                "source":    cfg["name"],
                "cat":       get_cat(full, cfg["cat"]),
                "sev":       get_severity(full),
                "tags":      [{"t": c, "cls": "cve"} for c in cves[:3]],
                "iocs":      {"cves": cves, "ips": [], "hashes": []},
                "mitreTags": [],
                "cvss":      None,
                "ts":        0,
            })
        print(f"[OK]   {cfg['name']}: {len(feed.entries[:15])} articles")
        sources_ok += 1
    except Exception as e:
        print(f"[FAIL] {cfg['name']}: {e}")

output = {
    "generated_at":  datetime.now(timezone.utc).isoformat(),
    "sources_ok":    sources_ok,
    "sources_total": len(FEEDS),
    "total":         len(articles),
    "articles":      articles,
}

with open("feeds.json", "w", encoding="utf-8") as f:
    json.dump(output, f, ensure_ascii=False, indent=2)

print(f"\n✓ Done: {len(articles)} articles from {sources_ok}/{len(FEEDS)} sources")
