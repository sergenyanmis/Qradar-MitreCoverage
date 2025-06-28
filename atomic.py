#!/usr/bin/env python3
import matplotlib.pyplot as plt
from fpdf import FPDF
from collections import Counter
import requests
import time
import csv
import json
import re
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# QRadar connection settings
QRADAR_HOST = "https://QRADAR_IP"
AUTH_TOKEN = "AUTH_TOKEN"
HEADERS = {
    "Content-Type": "application/json",
    "SEC": AUTH_TOKEN
}

requests.packages.urllib3.disable_warnings()

# AQL query
query = """
select QIDNAME(qid) AS 'Event Name', QIDDESCRIPTION(qid) as "description", COUNT(*) AS 'Count'
from events
where (
    (logSourceId='63' OR logSourceId='2073' OR logSourceId='2433' OR logSourceId='17317')
    AND sourceIP='ATOMIC_SIMULATIONAGENT_IP'
    AND description ILIKE '%Mitre Tactic:%'
)
GROUP BY qid
order by "Count" desc
last 1 DAYS
"""

# 1. Send query
print("[*] Sending query...")
response = requests.post(
    f'{QRADAR_HOST}/api/ariel/searches',
    headers=HEADERS,
    params={'query_expression': query},
    verify=False
)

if response.status_code != 201:
    print("[-] Query failed:", response.status_code, response.text)
    exit(1)

search_id = response.json().get('search_id')
print(f"[+] Query started: search_id = {search_id}")

# 2. Wait until complete
while True:
    status_response = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{search_id}', headers=HEADERS, verify=False)
    status = status_response.json().get('status')
    print(f"[*] Status: {status}")
    if status == 'COMPLETED':
        break
    elif status in ['CANCELED', 'ERROR']:
        print("[-] Query failed:", status)
        exit(1)
    time.sleep(2)

# 3. Get results
print("[*] Fetching results...")
results_response = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{search_id}/results', headers=HEADERS, verify=False)
events = results_response.json().get('events', [])

# 4. Parse tactic/technique
def parse_description(description):
    tactic = None
    technique = None
    tactic_match = re.search(r"Mitre Tactic:\s*([^;,\n]+)", description, re.IGNORECASE)
    technique_match = re.search(r"Mitre Technic:\s*([^;,\n]+)", description, re.IGNORECASE)

    if tactic_match:
        tactic = tactic_match.group(1).strip()
    if technique_match:
        technique = technique_match.group(1).strip()
    return tactic, technique

def extract_technique_id(technic_field):
    match = re.search(r"(T\d{4}(?:\.\d{3})?)", technic_field)
    if match:
        return match.group(1)
    return None

technique_counts = {}

# 5. Write to CSV
with open("qradar_mitre.csv", "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Event Name", "Count", "Mitre Tactic", "Mitre Technic", "Technique ID"])

    for event in events:
        event_name = event.get("Event Name")
        description = event.get("description", "")
        count = event.get("Count")
        tactic, technic = parse_description(description)
        tech_id = extract_technique_id(technic) if technic else None

        if tech_id:
            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + count

        writer.writerow([event_name, count, tactic, technic, tech_id])

print("[+] CSV file created: mitre.csv")

# 6. Generate MITRE Navigator JSON
navigator_json = {
    "name": "QRadar Atomic MITRE Coverage",
    "description": "Coverage from QRadar + Atomic Red Team detections",
    "domain": "enterprise-attack",
    "version": "4.4",
    "techniques": []
}

for tech_id, score in technique_counts.items():
    navigator_json["techniques"].append({
        "techniqueID": tech_id,
        "score": score,
        "comment": "Detected via QRadar"
    })

with open("mitre_coverage.json", "w", encoding="utf-8") as f:
    json.dump(navigator_json, f, indent=2)

print("[+] MITRE Navigator JSON created: mitre_coverage.json")

# 7. Coverage stats
TOTAL_ATOMIC_TECHNIQUES = 325
found_technique_count = len(technique_counts)
coverage_ratio = found_technique_count / TOTAL_ATOMIC_TECHNIQUES

print(f"[+] Techniques detected: {found_technique_count}")
print(f"[+] Total Atomic techniques: {TOTAL_ATOMIC_TECHNIQUES}")
print(f"[+] Coverage: %{coverage_ratio * 100:.2f}")

# 8. Tactic distribution
tactic_counter = Counter()
for event in events:
    description = event.get("description", "")
    match = re.search(r"Mitre Tactic:\s*([^;,\n]+)", description, re.IGNORECASE)
    if match:
        tactic = match.group(1).strip()
        tactic_counter[tactic] += 1

# 9. Tactic pie chart
plt.figure(figsize=(8, 6))
plt.pie(tactic_counter.values(), labels=tactic_counter.keys(), autopct='%1.1f%%')
plt.title("MITRE Tactic Distribution")
plt.savefig("tactic_pie_chart.png")
plt.close()

# 10. Coverage bar chart
plt.figure(figsize=(6, 5))
plt.bar(["Detected", "Not Detected"],
        [found_technique_count, TOTAL_ATOMIC_TECHNIQUES - found_technique_count],
        color=["green", "red"])
plt.title("MITRE Coverage")
plt.savefig("coverage_bar_chart.png")
plt.close()

# 11. PDF Report
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", 'B', 16)
pdf.cell(0, 10, "MITRE Coverage Report", ln=True, align='C')
pdf.ln(10)

# Event List
pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "Triggered Rule List:", ln=True)
pdf.set_font("Arial", '', 11)
for event in events:
    event_name = event.get("Event Name", "Unknown")
    count = event.get("Count", 0)
    pdf.cell(0, 10, f"- {event_name} ({count} times)", ln=True)

# Charts
pdf.ln(10)
pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, "MITRE Tactic Distribution:", ln=True)
pdf.image("tactic_pie_chart.png", x=30, w=150)

pdf.ln(10)
pdf.cell(0, 10, "MITRE Coverage Chart:", ln=True)
pdf.image("coverage_bar_chart.png", x=40, w=120)

# Coverage Ratio
pdf.ln(10)
pdf.set_font("Arial", 'B', 12)
pdf.cell(0, 10, f"MITRE Coverage: %{coverage_ratio * 100:.2f}", ln=True)

# Save PDF
pdf.output("mitre_report.pdf")
print("[+] PDF report generated: mitre_report.pdf")

