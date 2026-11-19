"""
Campus Network Security Dashboard
Group 08 - Information Security - Secure Campus Network with Firewall, VLANs and IDS
Submitted to Engineer Abdul Razaque

Run with:  streamlit run app.py

This app visualizes evidence produced from the Cisco Packet Tracer
implementation (topology, VLAN access policy, attack/defense test results,
logs, and the CIA/accountability mapping). Phase 2-4 are complete; the data
in data/ and assets/screenshots/ is REAL evidence captured from the Packet
Tracer build (project of IS.pkt), not synthetic/sample data.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from PIL import Image

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
ASSETS_DIR = BASE_DIR / "assets" / "screenshots"

# ---------------------------------------------------------------------------
# Shared palette (kept in sync with .streamlit/config.toml)
# ---------------------------------------------------------------------------
BG = "#0B0F17"
PANEL = "#131A26"
GRID = "#232B3A"
TEXT = "#E6EDF3"
MUTED = "#8B98A9"
ACCENT = "#2DD4BF"
RED = "#F87171"
AMBER = "#FBBF24"
GREEN = "#4ADE80"

ZONE_COLORS = {
    "Student": "#3B82F6",
    "Faculty": "#A78BFA",
    "Admin": "#F87171",
    "Server": "#2DD4BF",
    "Guest": "#FBBF24",
}

ATTACKS = {
    "sniffing": {
        "label": "1. Passive: scanning & sniffing",
        "before_desc": "Simulation mode set to capture ARP + ICMP only. A Simple PDU (ping) is queued from PC-Student to PC-Faculty.",
        "attack_desc": "The full ARP + ICMP round trip is played through Packet Tracer's Simulation mode, hop by hop.",
        "after_desc": "Event List proof: all 10 hops stayed inside Student + Faculty + Router0. Admin, Server, and Guest zone devices recorded zero events - they saw nothing of this traffic.",
    },
    "unauthorized_access": {
        "label": "2. Active: unauthorized cross-VLAN access",
        "before_desc": "Before STUDENT-ACL/GUEST-ACL/FACULTY-ACL existed, PC-Student could reach App-Server (10.0.40.10) with 0% ping loss - fully unrestricted.",
        "attack_desc": "Student (and Guest) zones attempt direct access into the Admin and Server zones, which should be off-limits by design.",
        "after_desc": "With the ACLs applied, the same ping returns \"Destination host unreachable\" (100% loss) straight from the gateway - the router is actively enforcing least privilege.",
    },
    "ping_flood": {
        "label": "3. Active: ping flood DoS",
        "before_desc": "Baseline: PC-Faculty to App-Server, 75% success (1 ARP-timeout packet is expected), 0-1ms response time.",
        "attack_desc": "Packet Tracer's Traffic Generator floods ICMP echo requests at a 0.01s interval. The FACULTY-ACL permit counter jumps from 1030 to 1310 matches (+280) in just 10 seconds - far above the ~1/sec a normal ping would generate.",
        "after_desc": "A single ACL line inserted by sequence number (no rebuild needed) blocks ICMP echo from Faculty to App-Server specifically. It is already shown blocking 470 flood packets while the attack is still running, and a direct re-test returns 100% loss, \"Destination host unreachable\".",
    },
    "rogue_device": {
        "label": "4. Active: rogue device on access port",
        "before_desc": "SW-Guest Fa0/2 has the legitimate PC-Guest's MAC (0002.1688.3A64) sticky-locked. Violation Count: 0.",
        "attack_desc": "PC-Guest is unplugged and an unregistered PC (PC0, IP 10.0.50.20) is plugged into the same port. Port security briefly auto-learned the wrong MAC until the legitimate device was re-locked, then the rogue device was reconnected.",
        "after_desc": "Port security trips instantly: Port Status = Secure-shutdown, Violation Count: 1. Full Cisco syslog trail captured - %LINK-5-CHANGED, %PM-4-ERR_DISABLE, %PORT_SECURITY-2-PSECURE_VIOLATION.",
    },
}

ATTACK_ORDER = ["sniffing", "unauthorized_access", "ping_flood", "rogue_device"]

st.set_page_config(page_title="Campus Network Security Dashboard", layout="wide", page_icon="\U0001F6E1️")

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem;}
    [data-testid="stMetric"] {
        background-color: #131A26;
        border: 1px solid #232B3A;
        border-radius: 10px;
        padding: 14px 16px 10px 16px;
    }
    [data-testid="stMetricLabel"] {color: #8B98A9;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("\U0001F6E1️ Secure Campus Network — Firewall, VLANs & IDS")
st.caption("Group 08 · Information Security · Submitted to Engineer Abdul Razaque · Built in Cisco Packet Tracer")
st.caption(
    "Muhammad Abdullah Ansari (25F-DS-133) · Haroon Ahmed Khan (25F-DS-143) · "
    "Muhammad Daniyal Farooqui (25F-DS-147) · Saif Ul Wahab (25F-DS-155)"
)

tab_overview, tab_topology, tab_matrix, tab_attacks, tab_logs, tab_cia = st.tabs(
    ["Overview", "Topology", "VLAN Access Matrix", "Attack Scenarios", "Logs & Alerts", "CIA Mapping"]
)

# ---------------------------------------------------------------------------
# Tab 0 — Overview
# ---------------------------------------------------------------------------
with tab_overview:
    st.subheader("Project status at a glance")
    st.write(
        "A 5-zone segmented campus network built in Cisco Packet Tracer, hardened with "
        "least-privilege ACLs, port security, SSH-only management, and centralized syslog "
        "logging — then validated against 4 real attack scenarios, each with before/attack/"
        "after evidence."
    )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("VLAN zones", "5")
    c2.metric("End devices", "6")
    c3.metric("Attacks mitigated", "4 / 4")
    c4.metric("ACL deny rules", "8")
    c5.metric("Port-security violations caught", "1")
    c6.metric("SSH-secured devices", "6 / 6")

    st.markdown("#### Attack success rate — before vs. after controls")
    fig = go.Figure()
    labels = [ATTACKS[k]["label"].split(": ", 1)[-1].title() for k in ATTACK_ORDER]
    fig.add_trace(go.Bar(name="Before controls", x=labels, y=[100, 100, 100, 100], marker_color=RED))
    fig.add_trace(go.Bar(name="After controls", x=labels, y=[0, 0, 0, 0], marker_color=GREEN))
    fig.update_layout(
        barmode="group",
        plot_bgcolor=PANEL,
        paper_bgcolor="rgba(0,0,0,0)",
        font_color=TEXT,
        yaxis_title="Attack success rate (%)",
        yaxis=dict(gridcolor=GRID, range=[0, 110]),
        xaxis=dict(gridcolor=GRID),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        height=360,
        margin=dict(t=30, b=10, l=10, r=10),
    )
    st.plotly_chart(fig, width="stretch")

    with st.expander("🔑 Key terms used in this dashboard (plain-English)"):
        terms = [
            ("VLAN (Virtual LAN)", "Splits one physical network into separate logical zones (Student, Faculty, Admin, Server, Guest). Devices in different VLANs can't see each other's traffic by default, even on the same switch hardware."),
            ("ACL (Access Control List)", "A rule list on the router that explicitly allows or denies traffic between zones — the mechanism behind \"least privilege\" (only Admin/Server get full access; everyone else is restricted)."),
            ("Port security (sticky MAC)", "Locks a switch port to one specific device's hardware address. If any other device is plugged in, the port shuts itself down automatically."),
            ("SSH", "An encrypted way to remotely manage network devices, replacing Telnet (which sends passwords in plain, readable text)."),
            ("Centralized syslog", "Every switch and the router forward their security events to one logging server, so alerts can be reviewed in one place instead of checking each device individually."),
            ("CIA triad", "Confidentiality, Integrity, Availability — the three goals every security control here is designed to protect, plus Accountability (who did what, traceable via logs)."),
        ]
        for term, definition in terms:
            st.markdown(f"**{term}** — {definition}")

# ---------------------------------------------------------------------------
# Tab 1 — Topology (matches the actual Packet Tracer build)
# ---------------------------------------------------------------------------
with tab_topology:
    st.subheader("Network topology — as built in Packet Tracer")
    st.write(
        "Router0 (Cisco 2911, router-on-a-stick with 5 dot1Q sub-interfaces) connects to "
        "**SW-Student**, which daisy-chains by trunk to **SW-Faculty → SW-Admin → "
        "SW-Server → SW-Guest**. Each switch carries one VLAN's access port(s)."
    )

    def draw_box(ax, x, y, w, h, title, subtitle, face, text_color="#0B0F17", edge="none"):
        box = FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.02,rounding_size=0.1",
            linewidth=1.4, edgecolor=edge, facecolor=face, zorder=3,
        )
        ax.add_patch(box)
        if subtitle:
            ax.text(x + w / 2, y + h * 0.66, title, ha="center", va="center",
                     fontsize=9.5, fontweight="bold", color=text_color, zorder=4)
            ax.text(x + w / 2, y + h * 0.28, subtitle, ha="center", va="center",
                     fontsize=7.8, color=text_color, zorder=4)
        else:
            ax.text(x + w / 2, y + h / 2, title, ha="center", va="center",
                     fontsize=9.5, fontweight="bold", color=text_color, zorder=4)

    def draw_link(ax, start, end, dashed=False):
        arrow = FancyArrowPatch(
            start, end, arrowstyle="-", mutation_scale=10,
            color=MUTED, linewidth=1.3, zorder=1,
            linestyle="--" if dashed else "-",
        )
        ax.add_patch(arrow)

    fig, ax = plt.subplots(figsize=(12, 6.8))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 12.2)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    # Router0 at top center
    router_x, router_y, router_w, router_h = 5.1, 5.7, 2.0, 1.0
    draw_box(ax, router_x, router_y, router_w, router_h, "Router0", "2911 · router-on-a-stick", ACCENT)
    router_cx = router_x + router_w / 2

    switches = [
        ("SW-Student", "Student", "VLAN 10"),
        ("SW-Faculty", "Faculty", "VLAN 20"),
        ("SW-Admin", "Admin", "VLAN 30"),
        ("SW-Server", "Server", "VLAN 40"),
        ("SW-Guest", "Guest", "VLAN 50"),
    ]
    sw_w, sw_h, gap = 2.0, 0.95, 0.35
    total_w = len(switches) * sw_w + (len(switches) - 1) * gap
    start_x = (12.2 - total_w) / 2
    sw_y = 3.6
    sw_centers = []
    for i, (name, zone, vlan) in enumerate(switches):
        x = start_x + i * (sw_w + gap)
        color = ZONE_COLORS[zone]
        draw_box(ax, x, sw_y, sw_w, sw_h, name, vlan, color)
        sw_centers.append((x + sw_w / 2, zone, vlan, x))

    # Router -> SW-Student (single uplink)
    first_cx = sw_centers[0][0]
    draw_link(ax, (router_cx, router_y), (first_cx, sw_y + sw_h))

    # Daisy-chain trunk links between switches
    for i in range(len(sw_centers) - 1):
        x1 = sw_centers[i][3] + sw_w
        x2 = sw_centers[i + 1][3]
        y = sw_y + sw_h / 2
        draw_link(ax, (x1, y), (x2, y), dashed=True)

    # End devices under each switch
    dev_y, dev_h, dev_w = 1.2, 1.0, 1.7
    device_map = {
        "Student": [("PC-Student", "10.0.10.10")],
        "Faculty": [("PC-Faculty", "10.0.20.10")],
        "Admin": [("PC-Admin", "10.0.30.10")],
        "Server": [("App-Server", "10.0.40.10"), ("Syslog-Server", "10.0.40.11")],
        "Guest": [("PC-Guest", "10.0.50.10")],
    }
    for cx, zone, vlan, x in sw_centers:
        devices = device_map[zone]
        color = ZONE_COLORS[zone]
        if len(devices) == 1:
            dx = cx - dev_w / 2
            draw_box(ax, dx, dev_y, dev_w, dev_h, devices[0][0], devices[0][1], PANEL, text_color=TEXT, edge=color)
            draw_link(ax, (cx, sw_y), (dx + dev_w / 2, dev_y + dev_h))
        else:
            spacing = 1.9
            base = cx - spacing / 2
            for j, (dname, dip) in enumerate(devices):
                dx = base + j * spacing - dev_w / 2
                draw_box(ax, dx, dev_y, dev_w, dev_h, dname, dip, PANEL, text_color=TEXT, edge=color)
                draw_link(ax, (cx, sw_y), (dx + dev_w / 2, dev_y + dev_h))

    # Legend
    legend_y = 0.15
    lx = 0.3
    for zone, color in ZONE_COLORS.items():
        ax.add_patch(plt.Rectangle((lx, legend_y), 0.22, 0.22, facecolor=color, edgecolor="none", zorder=5))
        ax.text(lx + 0.32, legend_y + 0.11, zone, va="center", fontsize=8.5, color=TEXT, zorder=5)
        lx += 1.9

    st.pyplot(fig, width="stretch")
    st.caption(
        "Solid line = Router0's single uplink to SW-Student. Dashed lines = inter-switch "
        "trunk links (daisy-chain). Every switch's local VLAN database holds all 5 VLANs, "
        "even though it only has an access port for its own zone."
    )

# ---------------------------------------------------------------------------
# Tab 2 — VLAN Access Matrix
# ---------------------------------------------------------------------------
with tab_matrix:
    st.subheader("VLAN access matrix (least privilege)")
    st.write("Rows = source zone, columns = destination zone. Reflects the real ACLs on Router0.")

    matrix = pd.read_csv(DATA_DIR / "vlan_matrix.csv", index_col=0)

    def color_cell(val):
        colors = {
            "Allow": f"background-color: rgba(74,222,128,0.22); color: {GREEN};",
            "Deny": f"background-color: rgba(248,113,113,0.22); color: {RED};",
            "Limited": f"background-color: rgba(251,191,36,0.22); color: {AMBER};",
        }
        return colors.get(val, "")

    st.dataframe(matrix.style.map(color_cell), width="stretch")
    st.caption(
        "Allow = unrestricted · Limited = Faculty can reach App-Server only, not "
        "Syslog-Server · Deny = blocked by STUDENT-ACL / GUEST-ACL on Router0. "
        "Admin and Server have no inbound ACL, so they can reach every zone by design."
    )

# ---------------------------------------------------------------------------
# Tab 3 — Attack Scenarios
# ---------------------------------------------------------------------------
with tab_attacks:
    st.subheader("Attack scenarios — before / attack / after controls")
    attack_key = st.selectbox(
        "Choose a scenario",
        options=ATTACK_ORDER,
        format_func=lambda k: ATTACKS[k]["label"],
    )
    info = ATTACKS[attack_key]

    col_before, col_attack, col_after = st.columns(3)

    def show_evidence(col, phase_label, phase_dir, desc, badge_color):
        with col:
            st.markdown(
                f"<span style='background-color:{badge_color}22;color:{badge_color};"
                f"padding:3px 10px;border-radius:999px;font-size:0.78rem;font-weight:600;'>"
                f"{phase_label}</span>",
                unsafe_allow_html=True,
            )
            st.write(desc)
            folder = ASSETS_DIR / attack_key / phase_dir
            images = sorted(folder.glob("*.png")) + sorted(folder.glob("*.jpg"))
            if images:
                for img_path in images:
                    st.image(Image.open(img_path), width="stretch")
            else:
                st.markdown(
                    f"<div style='border:1px dashed {GRID};border-radius:8px;"
                    f"padding:18px;text-align:center;color:{MUTED};font-size:0.85rem;'>"
                    f"Evidence for this stage to be added</div>",
                    unsafe_allow_html=True,
                )

    show_evidence(col_before, "BEFORE", "before", info["before_desc"], MUTED)
    show_evidence(col_attack, "DURING ATTACK", "attack", info["attack_desc"], RED)
    show_evidence(col_after, "AFTER CONTROL", "after", info["after_desc"], GREEN)

    st.divider()

    # Attack-specific metric chart, from real captured numbers
    metrics = pd.read_csv(DATA_DIR / "attack_metrics.csv")
    m = metrics[metrics["attack_type"] == attack_key]
    if not m.empty:
        st.markdown("**Captured metrics for this scenario**")
        mc1, mc2, mc3 = st.columns(3)
        cols_cycle = [mc1, mc2, mc3]
        for i, row in enumerate(m.itertuples()):
            cols_cycle[i % 3].metric(row.label, f"{row.value} {row.unit}")

        if attack_key == "ping_flood":
            fig2 = go.Figure()
            fig2.add_trace(go.Bar(
                x=["Normal ping rate", "Flood rate (attack)", "Blocked by mitigation"],
                y=[1, 28, 470],
                marker_color=[MUTED, RED, GREEN],
                text=[1, 28, 470],
                textposition="outside",
            ))
            fig2.update_layout(
                plot_bgcolor=PANEL, paper_bgcolor="rgba(0,0,0,0)", font_color=TEXT,
                yaxis_title="matches", yaxis=dict(gridcolor=GRID), xaxis=dict(gridcolor=GRID),
                height=320, margin=dict(t=20, b=10, l=10, r=10),
            )
            st.plotly_chart(fig2, width="stretch")

    st.divider()
    st.markdown("**Relevant log entries for this scenario**")
    logs = pd.read_csv(DATA_DIR / "sample_logs.csv")
    scenario_logs = logs[logs["attack_type"] == attack_key]
    st.dataframe(scenario_logs, width="stretch", hide_index=True)

# ---------------------------------------------------------------------------
# Tab 4 — Logs & Alerts
# ---------------------------------------------------------------------------
with tab_logs:
    st.subheader("Logs & alerts")
    logs = pd.read_csv(DATA_DIR / "sample_logs.csv")

    sev_counts = logs["severity"].value_counts().reindex(["critical", "warning", "info"]).fillna(0)
    fig3 = go.Figure(go.Bar(
        x=sev_counts.index.str.title(), y=sev_counts.values,
        marker_color=[RED, AMBER, ACCENT],
    ))
    fig3.update_layout(
        plot_bgcolor=PANEL, paper_bgcolor="rgba(0,0,0,0)", font_color=TEXT,
        yaxis_title="log entries", yaxis=dict(gridcolor=GRID), xaxis=dict(gridcolor=GRID),
        height=260, margin=dict(t=10, b=10, l=10, r=10),
    )
    st.plotly_chart(fig3, width="stretch")

    severities = ["All"] + sorted(logs["severity"].unique().tolist())
    phases = ["All"] + sorted(logs["phase"].unique().tolist())

    c1, c2 = st.columns(2)
    sel_sev = c1.selectbox("Filter by severity", severities)
    sel_phase = c2.selectbox("Filter by phase", phases)

    filtered = logs.copy()
    if sel_sev != "All":
        filtered = filtered[filtered["severity"] == sel_sev]
    if sel_phase != "All":
        filtered = filtered[filtered["phase"] == sel_phase]

    def highlight_severity(row):
        color = {
            "critical": f"background-color: rgba(248,113,113,0.18);",
            "warning": f"background-color: rgba(251,191,36,0.18);",
            "info": "",
        }.get(row["severity"], "")
        return [color] * len(row)

    st.dataframe(
        filtered.style.apply(highlight_severity, axis=1),
        width="stretch",
        hide_index=True,
    )
    st.caption(
        "Real syslog / ACL-deny / port-security log lines captured from the Packet Tracer "
        "build, forwarded to the centralized Syslog-Server (10.0.40.11)."
    )

# ---------------------------------------------------------------------------
# Tab 5 — CIA Mapping
# ---------------------------------------------------------------------------
with tab_cia:
    st.subheader("Application of information security principles")
    cia = pd.read_csv(DATA_DIR / "cia_mapping.csv")

    heat_cols = ["confidentiality", "integrity", "availability", "accountability"]
    z = cia[heat_cols].map(lambda v: 1 if v == "Yes" else 0).values
    fig4 = go.Figure(data=go.Heatmap(
        z=z,
        x=["Confidentiality", "Integrity", "Availability", "Accountability"],
        y=cia["control"],
        colorscale=[[0, PANEL], [1, ACCENT]],
        showscale=False,
        xgap=4, ygap=4,
        text=[["✅" if v else "" for v in row] for row in z],
        texttemplate="%{text}",
        textfont=dict(size=18),
    ))
    fig4.update_layout(
        plot_bgcolor=PANEL, paper_bgcolor="rgba(0,0,0,0)", font_color=TEXT,
        height=320, margin=dict(t=10, b=10, l=10, r=10),
        yaxis=dict(autorange="reversed"),
    )
    st.plotly_chart(fig4, width="stretch")

    cia_display = cia.rename(columns={
        "control": "Control",
        "description": "How it contributes",
    })[["Control", "How it contributes"]]

    rows_html = "".join(
        f"<tr><td class='cia-control'>{r['Control']}</td>"
        f"<td class='cia-desc'>{r['How it contributes']}</td></tr>"
        for _, r in cia_display.iterrows()
    )
    st.markdown(
        f"""
        <style>
        .cia-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
        .cia-table th {{
            text-align: left; padding: 10px 14px; color: {MUTED};
            border-bottom: 1px solid {GRID}; font-weight: 600; font-size: 0.85rem;
        }}
        .cia-table td {{
            padding: 12px 14px; border-bottom: 1px solid {GRID};
            color: {TEXT}; vertical-align: top; white-space: normal;
        }}
        .cia-table .cia-control {{ width: 24%; font-weight: 600; color: {ACCENT}; }}
        .cia-table .cia-desc {{ line-height: 1.5; }}
        </style>
        <table class="cia-table">
            <tr><th>Control</th><th>How it contributes</th></tr>
            {rows_html}
        </table>
        """,
        unsafe_allow_html=True,
    )
