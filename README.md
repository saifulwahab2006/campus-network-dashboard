# Campus Network Security Dashboard

Streamlit + Python dashboard for the **Secure Campus Network with Firewall,
VLANs and IDS** project (Group 08). The actual network is built in **Cisco
Packet Tracer** (`project of IS.pkt`); this app visualizes the real configs,
logs, and attack/defense evidence captured from that build — Phases 1–4 are
complete, so **the data here is real, not sample/synthetic**.

Everything here runs locally on your laptop — no physical hardware needed.

## 1. Install (one-time)

```bash
cd campus-network-dashboard
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Run

```bash
streamlit run app.py
```

This opens the dashboard in your browser at `http://localhost:8501`. A
custom dark theme is set in `.streamlit/config.toml` — no extra setup needed.

## 3. What's in each tab

| Tab | Shows |
|---|---|
| **Overview** | KPI cards (zones, devices, attacks mitigated, ACL rules, violations, SSH coverage), an attack-success-rate chart, and the Phase 1–6 build status |
| **Topology** | The real topology — Router0 (router-on-a-stick) → SW-Student → SW-Faculty → SW-Admin → SW-Server → SW-Guest (daisy-chain trunk) → end devices, color-coded by VLAN zone |
| **VLAN Access Matrix** | The real Allow/Deny/Limited policy enforced by STUDENT-ACL, GUEST-ACL, FACULTY-ACL |
| **Attack Scenarios** | Before / During Attack / After Control for all 4 attacks, each with real Packet Tracer screenshots, captured metrics, and relevant log lines |
| **Logs & Alerts** | Real syslog / ACL-deny / port-security log lines from the build, filterable by severity and phase |
| **CIA Mapping** | Which control (VLANs, ACLs, port security, SSH, syslog) supports Confidentiality / Integrity / Availability / Accountability |

## 4. Updating data later

Everything is driven by the files below — edit them and the dashboard
updates automatically, no code changes needed.

| File / folder | Holds |
|---|---|
| `data/vlan_matrix.csv` | The zone-to-zone Allow/Deny/Limited policy |
| `data/sample_logs.csv` | Real log lines, tagged by `attack_type` and `phase` (`setup`/`before`/`attack`/`after`) |
| `data/attack_metrics.csv` | The numbers behind each attack's metric cards and charts |
| `data/cia_mapping.csv` | Control → CIA/Accountability mapping |
| `assets/screenshots/<attack>/{before,attack,after}/*.png` | Real Packet Tracer screenshots per stage |

`<attack>` is one of `sniffing`, `unauthorized_access`, `ping_flood`,
`rogue_device`.

## 5. Project structure

```
campus-network-dashboard/
├── app.py                      # Streamlit app (6 tabs)
├── requirements.txt
├── .streamlit/config.toml      # custom dark theme
├── data/
│   ├── vlan_matrix.csv
│   ├── sample_logs.csv
│   ├── attack_metrics.csv
│   └── cia_mapping.csv
└── assets/screenshots/
    ├── sniffing/{before,attack,after}/
    ├── unauthorized_access/{before,attack,after}/
    ├── ping_flood/{before,attack,after}/
    └── rogue_device/{before,attack,after}/
```

## 6. Report & slides

Screenshot each tab directly from the browser to use as figures in the
report and the 10–12 slide deck — saves re-making the VLAN matrix, topology
diagram, or CIA mapping table by hand. The Overview tab's KPI row and
attack-success chart work well as a title/summary slide.
