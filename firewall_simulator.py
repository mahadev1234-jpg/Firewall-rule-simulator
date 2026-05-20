"""
Firewall Simulator — Python / Tkinter
Based on: "Firewall Simulator", American Journal of AI Cyber Computing Management, Vol.4, No.1 (2024)
Modules: Dashboard · Learning Center · Simulator · Manual/Docs
Stack  : Python 3 · Tkinter (GUI) · ttk · sqlite3 (persistent storage)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sqlite3
import datetime
import ipaddress
import json
import os
import sys

# ─── THEME ────────────────────────────────────────────────────────────────────
BG        = "#060d14"
PANEL     = "#0b1622"
BORDER    = "#1a3050"
ACCENT    = "#00d4ff"
ACCENT2   = "#ff6b35"
GREEN     = "#00ff88"
RED       = "#ff3355"
YELLOW    = "#ffcc00"
TEXT      = "#c8dce8"
DIM       = "#4a6a80"
MONO      = ("Courier New", 10)
MONO_SM   = ("Courier New", 9)
SANS      = ("Segoe UI", 10)
SANS_B    = ("Segoe UI", 10, "bold")
SANS_LG   = ("Segoe UI", 13, "bold")
SANS_XL   = ("Segoe UI", 18, "bold")

# ─── DATABASE ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_sim.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT DEFAULT 'any',
        dst_ip TEXT DEFAULT 'any',
        port   TEXT DEFAULT 'any',
        protocol TEXT DEFAULT 'TCP',
        action TEXT DEFAULT 'ALLOW',
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, type TEXT, message TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS progress (
        lesson_id INTEGER PRIMARY KEY,
        completed INTEGER DEFAULT 0,
        completed_at TEXT
    )""")
    # Seed default rules if empty
    c.execute("SELECT COUNT(*) FROM rules")
    if c.fetchone()[0] == 0:
        now = _ts()
        defaults = [
            ("any", "any", "80",  "TCP",  "ALLOW", now),
            ("any", "any", "443", "TCP",  "ALLOW", now),
            ("any", "any", "22",  "TCP",  "DENY",  now),
        ]
        c.executemany("INSERT INTO rules (src_ip,dst_ip,port,protocol,action,created_at) VALUES (?,?,?,?,?,?)", defaults)
    conn.commit()
    conn.close()

def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")

def db_get_rules():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id,src_ip,dst_ip,port,protocol,action FROM rules ORDER BY id").fetchall()
    conn.close()
    return rows

def db_add_rule(src, dst, port, proto, action):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO rules (src_ip,dst_ip,port,protocol,action,created_at) VALUES (?,?,?,?,?,?)",
                 (src or "any", dst or "any", port or "any", proto, action, _ts()))
    conn.commit()
    conn.close()

def db_delete_rule(rid):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM rules WHERE id=?", (rid,))
    conn.commit()
    conn.close()

def db_clear_rules():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM rules")
    conn.commit()
    conn.close()

def db_add_log(ltype, msg):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO logs (ts,type,message) VALUES (?,?,?)", (_ts(), ltype, msg))
    conn.commit()
    conn.close()

def db_get_logs(limit=200):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT ts,type,message FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

def db_clear_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

def db_get_progress():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT lesson_id FROM progress WHERE completed=1").fetchall()
    conn.close()
    return [r[0] for r in rows]

def db_complete_lesson(lid):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO progress (lesson_id,completed,completed_at) VALUES (?,1,?)", (lid, _ts()))
    conn.commit()
    conn.close()

def db_log_counts():
    conn = sqlite3.connect(DB_PATH)
    allow = conn.execute("SELECT COUNT(*) FROM logs WHERE type='allow'").fetchone()[0]
    deny  = conn.execute("SELECT COUNT(*) FROM logs WHERE type='deny'").fetchone()[0]
    conn.close()
    return allow, deny

# ─── LESSON DATA ──────────────────────────────────────────────────────────────
LESSONS = [
    {
        "id": 1, "title": "What is a Firewall?", "category": "BASICS",
        "desc": "Introduction to firewalls and their role in network security.",
        "content": (
            "OVERVIEW\n"
            "A firewall is a network security device (hardware or software) that monitors and "
            "controls incoming/outgoing network traffic based on predetermined security rules.\n\n"
            "HOW FIREWALLS WORK\n"
            "Firewalls act as a barrier between a trusted internal network and untrusted external "
            "networks. They inspect packets and decide whether to ALLOW or DENY based on a ruleset.\n\n"
            "TYPES OF FIREWALLS\n"
            "• Packet Filtering  — Inspects packets at the network layer using header info (IP, port, protocol).\n"
            "• Stateful Inspection — Tracks connection states; decisions based on context.\n"
            "• Application Layer — Operates at Layer 7; inspects content, not just headers.\n"
            "• Next-Generation (NGFW) — Combines stateful inspection, DPI, application awareness, and IDS/IPS.\n\n"
            "KEY CONCEPTS\n"
            "• Ruleset / ACL    — Ordered list of rules defining allowed/denied traffic.\n"
            "• Default Policy   — Action when no rule matches (typically DENY all).\n"
            "• Ingress/Egress   — Filtering of inbound vs outbound traffic."
        ),
        "quiz": {
            "q": "Which firewall type tracks connection states?",
            "opts": ["Packet Filter", "Stateful Inspection", "Proxy", "NAT"],
            "ans": 1
        }
    },
    {
        "id": 2, "title": "Firewall Rules & ACLs", "category": "RULES",
        "desc": "Learn how to define and manage Access Control Lists.",
        "content": (
            "RULE STRUCTURE (5-TUPLE)\n"
            "Every ACL rule is based on five attributes:\n"
            "• Source IP      — Origin of the packet (e.g., 192.168.1.0/24)\n"
            "• Destination IP — Target of the packet\n"
            "• Protocol       — TCP, UDP, ICMP\n"
            "• Port           — Source or destination port (1–65535)\n"
            "• Action         — ALLOW or DENY\n\n"
            "RULE EVALUATION\n"
            "Rules are processed sequentially — the FIRST MATCH WINS. "
            "If no rule matches, the default policy applies (usually DENY ALL).\n\n"
            "BEST PRACTICES\n"
            "• Place more specific rules before general ones.\n"
            "• Use a default-deny policy at the end of the chain.\n"
            "• Log denied traffic for forensic analysis.\n"
            "• Review and audit rules regularly.\n\n"
            "EXAMPLES\n"
            "• Allow HTTP  : TCP, any → port 80,  ALLOW\n"
            "• Block SSH   : TCP, 0.0.0.0/0 → port 22, DENY\n"
            "• Allow ICMP  : ICMP, 192.168.0.0/16 → any, ALLOW"
        ),
        "quiz": {
            "q": "What does 'first match wins' mean in firewall rules?",
            "opts": ["Last rule takes priority", "First matching rule determines outcome",
                     "All rules are checked", "Newest rule wins"],
            "ans": 1
        }
    },
    {
        "id": 3, "title": "NAT & DMZ", "category": "ADVANCED",
        "desc": "Network Address Translation and Demilitarized Zones.",
        "content": (
            "NETWORK ADDRESS TRANSLATION (NAT)\n"
            "NAT modifies IP address information in packet headers as they pass through a router/firewall. "
            "It allows multiple devices to share a single public IP.\n\n"
            "Types of NAT:\n"
            "• SNAT (Source NAT)      — Changes source IP (outbound masquerading)\n"
            "• DNAT (Destination NAT) — Changes destination IP (port forwarding)\n"
            "• PAT / Masquerade       — Many-to-one NAT using port numbers\n\n"
            "DEMILITARIZED ZONE (DMZ)\n"
            "A DMZ is a subnet that separates an internal network from untrusted external networks. "
            "Servers that need public access (web, email) are placed here.\n\n"
            "DMZ ARCHITECTURE\n"
            "• External Firewall : Between Internet and DMZ\n"
            "• Internal Firewall : Between DMZ and internal LAN\n"
            "• DMZ servers can receive Internet traffic but cannot directly access the LAN.\n\n"
            "BENEFITS\n"
            "• Protects internal network even if a DMZ server is compromised.\n"
            "• Provides an additional layer of segmentation.\n"
            "• Allows public services without exposing the internal network."
        ),
        "quiz": {
            "q": "What is the primary purpose of a DMZ?",
            "opts": ["Speed up traffic", "Isolate public-facing servers from internal network",
                     "Block all external traffic", "Replace NAT"],
            "ans": 1
        }
    },
    {
        "id": 4, "title": "IDS / IPS", "category": "DETECTION",
        "desc": "Intrusion Detection and Prevention Systems overview.",
        "content": (
            "INTRUSION DETECTION SYSTEM (IDS)\n"
            "An IDS monitors network traffic for suspicious activity and issues alerts. "
            "It is PASSIVE — it does not block traffic.\n\n"
            "Detection Methods:\n"
            "• Signature-Based — Matches traffic against known attack patterns.\n"
            "• Anomaly-Based   — Baselines normal behavior and flags deviations.\n"
            "• Hybrid          — Combines both approaches.\n\n"
            "Popular IDS Tools: Snort, Suricata, Zeek\n\n"
            "INTRUSION PREVENTION SYSTEM (IPS)\n"
            "An IPS is ACTIVE — it can block or drop malicious traffic in real-time, "
            "sitting inline in the network path.\n\n"
            "KEY METRICS\n"
            "• False Positive — Legitimate traffic flagged as malicious\n"
            "• False Negative — Malicious traffic not detected\n"
            "• True Positive  — Correctly identified attack\n\n"
            "COMMON ATTACKS DETECTED\n"
            "• TCP SYN Flood (DDoS)\n"
            "• Port Scanning\n"
            "• SQL Injection\n"
            "• Brute-force logins"
        ),
        "quiz": {
            "q": "An IPS differs from an IDS because it can:",
            "opts": ["Only detect threats", "Block traffic in real-time",
                     "Generate reports only", "Scan ports"],
            "ans": 1
        }
    },
    {
        "id": 5, "title": "Common Attack Types", "category": "THREATS",
        "desc": "DDoS, port scans, spoofing and how to defend against them.",
        "content": (
            "TCP SYN FLOOD (DDoS)\n"
            "Attacker sends many TCP SYN packets, exhausting server resources without completing "
            "the handshake.\n"
            "Defense: SYN cookies, rate limiting, firewall SYN-rate rules.\n\n"
            "PORT SCANNING\n"
            "Attackers probe a host to discover open ports and services (e.g., Nmap).\n"
            "Defense: Block/limit ICMP, use stateful inspection, enable port-scan detection.\n\n"
            "IP SPOOFING\n"
            "Attacker forges source IP addresses to disguise identity or bypass filtering.\n"
            "Defense: Ingress filtering (RFC 2827), anti-spoofing rules.\n\n"
            "MAN-IN-THE-MIDDLE (MITM)\n"
            "Attacker intercepts and possibly alters communication between two parties.\n"
            "Defense: TLS/HTTPS, certificate pinning, mutual authentication.\n\n"
            "ZERO-DAY EXPLOITS\n"
            "Attacks targeting unknown vulnerabilities.\n"
            "Defense: Behavior-based detection, network segmentation, least privilege.\n\n"
            "FIREWALL DEFENCE RULES\n"
            "• Block RFC 1918 private addresses on external interfaces\n"
            "• Default DENY ALL, allow explicitly\n"
            "• Rate-limit new connections per source IP\n"
            "• Log and alert on repeated denied attempts"
        ),
        "quiz": {
            "q": "TCP SYN Flood exploits which part of TCP?",
            "opts": ["Data transfer phase", "Three-way handshake",
                     "FIN termination", "ACK response"],
            "ans": 1
        }
    },
    {
        "id": 6, "title": "iptables & pfSense", "category": "TOOLS",
        "desc": "Hands-on firewall tools: iptables syntax and pfSense overview.",
        "content": (
            "IPTABLES (Linux)\n"
            "iptables is the primary Linux firewall tool, manipulating Netfilter kernel hooks.\n\n"
            "Basic Syntax:\n"
            "  iptables [-t table] -A CHAIN rule -j TARGET\n\n"
            "Tables : filter (default), nat, mangle, raw\n"
            "Chains : INPUT, OUTPUT, FORWARD (filter table)\n\n"
            "COMMON COMMANDS\n"
            "  iptables -A INPUT  -p tcp --dport 22  -j ACCEPT   # Allow SSH\n"
            "  iptables -A INPUT  -p tcp --dport 80  -j ACCEPT   # Allow HTTP\n"
            "  iptables -P INPUT DROP                            # Default deny\n"
            "  iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
            "  iptables -L -v -n                                 # List all rules\n\n"
            "PFSENSE\n"
            "pfSense is an open-source firewall/router based on FreeBSD with a web UI.\n"
            "Supports: Stateful filtering, NAT, VPN, traffic shaping, IDS/IPS via Snort/Suricata.\n\n"
            "NFTABLES\n"
            "Modern replacement for iptables in newer Linux kernels. "
            "More expressive syntax and better performance."
        ),
        "quiz": {
            "q": "Which iptables chain handles packets destined for the local system?",
            "opts": ["FORWARD", "OUTPUT", "INPUT", "PREROUTING"],
            "ans": 2
        }
    }
]

MANUAL_CMDS = [
    ("Allow HTTP Traffic",        "Permit inbound TCP on port 80",
     "iptables -A INPUT -p tcp --dport 80 -j ACCEPT"),
    ("Allow HTTPS Traffic",       "Permit inbound TCP on port 443",
     "iptables -A INPUT -p tcp --dport 443 -j ACCEPT"),
    ("Allow SSH (restricted)",    "Allow SSH only from a subnet",
     "iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 22 -j ACCEPT"),
    ("Block IP Address",          "Drop all traffic from a source IP",
     "iptables -A INPUT -s 10.0.0.5 -j DROP"),
    ("Allow ICMP (Ping)",         "Permit ICMP echo requests",
     "iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT"),
    ("Default Deny Policy",       "Set default policy to DROP",
     "iptables -P INPUT DROP\niptables -P FORWARD DROP"),
    ("Allow Established",         "Allow return traffic for existing sessions",
     "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"),
    ("Rate Limit Connections",    "Limit new TCP connections (SYN flood defence)",
     "iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/min --limit-burst 100 -j ACCEPT"),
    ("Log Dropped Packets",       "Log all dropped packets before DROP rule",
     "iptables -A INPUT -j LOG --log-prefix 'DROPPED: ' --log-level 4\niptables -A INPUT -j DROP"),
    ("Save Rules",                "Persist iptables rules across reboots",
     "iptables-save > /etc/iptables/rules.v4"),
    ("Allow DNS",                 "Permit outbound DNS queries",
     "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT\niptables -A INPUT -p udp --sport 53 -j ACCEPT"),
    ("Block Port Range",          "Block a range of ports",
     "iptables -A INPUT -p tcp --dport 6881:6889 -j DROP"),
]

QUICK_TESTS = [
    ("HTTP",  "TCP",  "203.0.113.10",  "10.0.0.1", "80"),
    ("HTTPS", "TCP",  "198.51.100.5",  "10.0.0.1", "443"),
    ("SSH",   "TCP",  "192.168.1.50",  "10.0.0.2", "22"),
    ("Ping",  "ICMP", "192.168.1.1",   "10.0.0.1", "0"),
    ("DNS",   "UDP",  "10.0.0.5",      "8.8.8.8",  "53"),
    ("RDP",   "TCP",  "45.33.32.156",  "10.0.0.3", "3389"),
]

# ─── TRAFFIC MATCHING ─────────────────────────────────────────────────────────
def match_ip(rule_ip, pkt_ip):
    if not rule_ip or rule_ip.lower() in ("any", "0.0.0.0/0", "0.0.0.0"):
        return True
    try:
        net = ipaddress.ip_network(rule_ip, strict=False)
        return ipaddress.ip_address(pkt_ip) in net
    except ValueError:
        return rule_ip == pkt_ip

def test_traffic(rules, src_ip, dst_ip, port, proto):
    """Returns (action, rule_index_or_None)"""
    for i, r in enumerate(rules):
        rid, r_src, r_dst, r_port, r_proto, r_action = r
        src_ok   = match_ip(r_src, src_ip)
        dst_ok   = match_ip(r_dst, dst_ip)
        port_ok  = (not r_port or r_port == "any" or r_port == str(port))
        proto_ok = (not r_proto or r_proto == "ANY" or r_proto.upper() == proto.upper())
        if src_ok and dst_ok and port_ok and proto_ok:
            return r_action, i + 1
    return "DENY", None  # default policy

def compute_skill(completed, rule_count):
    if len(completed) >= 5 and rule_count >= 5:
        return "Advanced"
    if len(completed) >= 3 or rule_count >= 3:
        return "Intermediate"
    return "Beginner"

# ─── STYLED WIDGETS ───────────────────────────────────────────────────────────
def styled_frame(parent, **kw):
    kw.setdefault("bg", PANEL)
    return tk.Frame(parent, **kw)

def styled_label(parent, text, font=SANS, fg=TEXT, bg=PANEL, **kw):
    return tk.Label(parent, text=text, font=font, fg=fg, bg=bg, **kw)

def styled_button(parent, text, command, bg=ACCENT, fg="#000000", font=SANS_B, **kw):
    btn = tk.Button(parent, text=text, command=command,
                    bg=bg, fg=fg, font=font,
                    relief="flat", cursor="hand2",
                    activebackground=bg, activeforeground=fg,
                    padx=10, pady=4, **kw)
    return btn

def styled_entry(parent, width=18, **kw):
    e = tk.Entry(parent, bg="#0a1520", fg=TEXT, insertbackground=ACCENT,
                 font=MONO, relief="flat", bd=0,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT, width=width, **kw)
    return e

def styled_combo(parent, values, width=12):
    cb = ttk.Combobox(parent, values=values, width=width, state="readonly", font=MONO)
    cb.set(values[0])
    return cb

def styled_text(parent, height=10, **kw):
    t = scrolledtext.ScrolledText(
        parent, bg="#040b12", fg=TEXT, insertbackground=ACCENT,
        font=MONO_SM, relief="flat", bd=0,
        highlightthickness=1, highlightbackground=BORDER,
        height=height, wrap="word", **kw
    )
    return t

def section_label(parent, text):
    f = tk.Frame(parent, bg=PANEL, pady=6)
    f.pack(fill="x")
    tk.Label(f, text=text, font=("Courier New", 9, "bold"),
             fg=ACCENT, bg=PANEL, anchor="w").pack(side="left", padx=4)
    tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x", expand=True, padx=8)
    return f

# ─── LESSON DIALOG ────────────────────────────────────────────────────────────
class LessonDialog(tk.Toplevel):
    def __init__(self, parent, lesson, already_done, on_complete):
        super().__init__(parent)
        self.title(f"Lesson {lesson['id']} — {lesson['title']}")
        self.configure(bg=BG)
        self.resizable(True, True)
        w, h = 760, 580
        sx = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        sy = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{sx}+{sy}")
        self.grab_set()

        self._lesson = lesson
        self._on_complete = on_complete
        self._quiz_answered = False

        # Header
        hdr = tk.Frame(self, bg=PANEL, pady=12)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"  LESSON {lesson['id']:02d}  ·  {lesson['category']}",
                 font=MONO_SM, fg=ACCENT, bg=PANEL).pack(side="left", padx=12)
        tk.Label(hdr, text=lesson['title'],
                 font=SANS_LG, fg=TEXT, bg=PANEL).pack(side="left", padx=4)
        tk.Button(hdr, text="✕ CLOSE", command=self.destroy,
                  bg=PANEL, fg=DIM, font=MONO_SM, relief="flat", cursor="hand2").pack(side="right", padx=12)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Scrollable body
        canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        body = tk.Frame(canvas, bg=BG, padx=24, pady=16)
        win_id = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win_id, width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        # Content
        txt = styled_text(body, height=16)
        txt.pack(fill="both", expand=True, pady=(0, 16))
        txt.insert("end", lesson["content"])
        txt.configure(state="disabled")

        # Quiz
        q = lesson["quiz"]
        qf = tk.Frame(body, bg=PANEL, relief="flat", bd=1, padx=16, pady=14)
        qf.pack(fill="x", pady=(0, 12))
        tk.Label(qf, text="KNOWLEDGE CHECK", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).pack(anchor="w", pady=(0, 6))
        tk.Label(qf, text=q["q"], font=SANS_B, fg=TEXT, bg=PANEL,
                 wraplength=680, justify="left").pack(anchor="w", pady=(0, 8))

        self._opt_btns = []
        for i, opt in enumerate(q["opts"]):
            btn = tk.Button(qf, text=f"  {chr(65+i)}.  {opt}",
                            font=SANS, bg="#0a1520", fg=TEXT,
                            relief="flat", cursor="hand2", anchor="w", padx=6, pady=4,
                            highlightthickness=1, highlightbackground=BORDER,
                            command=lambda idx=i: self._answer(idx))
            btn.pack(fill="x", pady=2)
            self._opt_btns.append(btn)

        self._result_lbl = tk.Label(qf, text="", font=MONO_SM, bg=PANEL)
        self._result_lbl.pack(anchor="w", pady=(6, 0))

        # Complete button
        if not already_done:
            styled_button(body, "  MARK AS COMPLETED  ✓",
                          command=self._complete, bg=GREEN).pack(anchor="e", pady=4)
        else:
            tk.Label(body, text="✓  Lesson already completed",
                     font=MONO_SM, fg=GREEN, bg=BG).pack(anchor="e", pady=4)

    def _answer(self, idx):
        if self._quiz_answered:
            return
        self._quiz_answered = True
        correct = self._lesson["quiz"]["ans"]
        for i, btn in enumerate(self._opt_btns):
            if i == correct:
                btn.configure(bg="#0d2e1a", fg=GREEN, highlightbackground=GREEN)
            elif i == idx:
                btn.configure(bg="#2e0d15", fg=RED, highlightbackground=RED)
        if idx == correct:
            self._result_lbl.configure(text="✓  CORRECT! Well done.", fg=GREEN)
        else:
            self._result_lbl.configure(text="✗  INCORRECT. Review the material above.", fg=RED)

    def _complete(self):
        self._on_complete(self._lesson["id"])
        self.destroy()

# ─── MAIN APPLICATION ─────────────────────────────────────────────────────────
class FirewallSimulator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Simulator")
        self.configure(bg=BG)
        self.geometry("1280x800")
        self.minsize(900, 600)

        init_db()

        # ttk style
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview",
                        background="#0a1520", foreground=TEXT,
                        fieldbackground="#0a1520", rowheight=26,
                        font=MONO_SM, borderwidth=0)
        style.configure("Treeview.Heading",
                        background=PANEL, foreground=ACCENT,
                        font=("Courier New", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", BORDER)])
        style.configure("TCombobox", fieldbackground="#0a1520",
                        background="#0a1520", foreground=TEXT,
                        selectbackground=BORDER, selectforeground=TEXT)
        style.configure("Vertical.TScrollbar",
                        background=BORDER, troughcolor=BG, arrowcolor=DIM)

        self._build_ui()
        self._refresh_all()

    # ── BUILD ──────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡  FIREWALL SIMULATOR",
                 font=("Courier New", 14, "bold"), fg=ACCENT, bg=PANEL).pack(side="left", padx=20)

        self._clock_var = tk.StringVar()
        self._skill_var = tk.StringVar(value="Beginner")
        self._lesson_var = tk.StringVar(value="0/6")
        self._rules_var  = tk.StringVar(value="0")

        for (label, var) in [("TIME:", self._clock_var), ("LEVEL:", self._skill_var),
                               ("LESSONS:", self._lesson_var), ("RULES:", self._rules_var)]:
            f = tk.Frame(hdr, bg=PANEL)
            f.pack(side="right", padx=14)
            tk.Label(f, text=label, font=MONO_SM, fg=DIM, bg=PANEL).pack(side="left")
            tk.Label(f, textvariable=var, font=("Courier New", 10, "bold"), fg=ACCENT, bg=PANEL).pack(side="left", padx=2)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Nav tabs
        nav = tk.Frame(self, bg=PANEL)
        nav.pack(fill="x")
        self._tabs = {}
        self._active_tab = tk.StringVar(value="dashboard")
        for tid, label in [("dashboard", "📊 Dashboard"), ("learning", "📚 Learning Center"),
                            ("simulator", "⚙  Simulator"), ("manual", "📖 Manual / Docs")]:
            btn = tk.Button(nav, text=label, font=("Segoe UI", 10, "bold"),
                            fg=DIM, bg=PANEL, relief="flat", cursor="hand2",
                            padx=18, pady=10, bd=0,
                            command=lambda t=tid: self._switch_tab(t))
            btn.pack(side="left")
            self._tabs[tid] = btn
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Content area
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(fill="both", expand=True)

        self._pages = {}
        for pid in ("dashboard", "learning", "simulator", "manual"):
            p = tk.Frame(self._content, bg=BG)
            self._pages[pid] = p

        self._build_dashboard(self._pages["dashboard"])
        self._build_learning(self._pages["learning"])
        self._build_simulator(self._pages["simulator"])
        self._build_manual(self._pages["manual"])

        self._switch_tab("dashboard")
        self._tick_clock()

    def _switch_tab(self, tid):
        for pid, p in self._pages.items():
            p.pack_forget()
        self._pages[tid].pack(fill="both", expand=True)
        for bid, btn in self._tabs.items():
            btn.configure(fg=ACCENT if bid == tid else DIM,
                          bg="#0d1c2e" if bid == tid else PANEL)
        self._active_tab.set(tid)
        if tid == "dashboard":
            self._refresh_dashboard()

    def _tick_clock(self):
        self._clock_var.set(datetime.datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    # ── DASHBOARD ──────────────────────────────────────────────────────────────
    def _build_dashboard(self, parent):
        pad = tk.Frame(parent, bg=BG)
        pad.pack(fill="both", expand=True, padx=20, pady=16)

        # Stat cards row
        cards_frame = tk.Frame(pad, bg=BG)
        cards_frame.pack(fill="x", pady=(0, 16))

        self._stat_labels = {}
        card_defs = [
            ("skill",    "Security Level",    "Beginner",  "#7b2fff"),
            ("lessons",  "Lessons Completed", "0 / 6",     ACCENT),
            ("rules",    "Rules Created",      "0",         ACCENT2),
            ("tested",   "Packets Tested",     "0",         ACCENT),
            ("blocked",  "Blocked",            "0",         RED),
            ("allowed",  "Allowed",            "0",         GREEN),
        ]
        for (key, lbl, val, color) in card_defs:
            cf = tk.Frame(cards_frame, bg=PANEL, relief="flat", bd=1,
                          highlightbackground=BORDER, highlightthickness=1)
            cf.pack(side="left", fill="both", expand=True, padx=4)
            tk.Frame(cf, bg=color, height=3).pack(fill="x")
            v_lbl = tk.Label(cf, text=val,
                             font=("Courier New", 18, "bold"), fg=color, bg=PANEL, pady=8)
            v_lbl.pack()
            tk.Label(cf, text=lbl.upper(), font=("Courier New", 8),
                     fg=DIM, bg=PANEL, pady=4).pack()
            self._stat_labels[key] = v_lbl

        # Middle row: detection + bar chart
        mid = tk.Frame(pad, bg=BG)
        mid.pack(fill="both", expand=True, pady=(0, 16))

        # Detection panel
        det = tk.Frame(mid, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        det.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(det, text="  DETECTION ACCURACY", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL, anchor="w").pack(fill="x", pady=(8, 2), padx=4)
        tk.Frame(det, bg=BORDER, height=1).pack(fill="x")

        self._det_frame = tk.Frame(det, bg=PANEL)
        self._det_frame.pack(fill="both", expand=True, padx=12, pady=10)

        # Bar chart panel
        bc = tk.Frame(mid, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, width=320)
        bc.pack(side="left", fill="both", padx=(8, 0))
        bc.pack_propagate(False)
        tk.Label(bc, text="  MODULE USAGE STATISTICS", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL, anchor="w").pack(fill="x", pady=(8, 2), padx=4)
        tk.Frame(bc, bg=BORDER, height=1).pack(fill="x")
        self._draw_bar_chart(bc)

        # Log panel
        lp = tk.Frame(pad, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        lp.pack(fill="both", expand=True)
        lh = tk.Frame(lp, bg=PANEL)
        lh.pack(fill="x")
        tk.Label(lh, text="  RECENT ACTIVITY LOG", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL, anchor="w").pack(side="left", pady=6, padx=4)
        styled_button(lh, "CLEAR LOG", self._clear_log,
                      bg=RED, fg="white", font=("Segoe UI", 8, "bold")).pack(side="right", padx=8, pady=4)
        tk.Frame(lp, bg=BORDER, height=1).pack(fill="x")
        self._dash_log = styled_text(lp, height=7, state="disabled")
        self._dash_log.pack(fill="both", expand=True, padx=2, pady=2)
        self._dash_log.tag_configure("allow", foreground=GREEN)
        self._dash_log.tag_configure("deny",  foreground=RED)
        self._dash_log.tag_configure("info",  foreground=ACCENT)
        self._dash_log.tag_configure("warn",  foreground=YELLOW)
        self._dash_log.tag_configure("dim",   foreground=DIM)

    def _draw_bar_chart(self, parent):
        data = [("Login\nAuth", 22, ACCENT), ("Learning\nCenter", 45, GREEN),
                ("Simulator", 28, ACCENT2), ("Manual\nDocs", 5, YELLOW)]
        chart = tk.Canvas(parent, bg=PANEL, highlightthickness=0, height=160)
        chart.pack(fill="x", padx=16, pady=16)
        chart.update_idletasks()
        W = 288; H = 140; mx = max(d[1] for d in data)
        bar_w = W // (len(data) * 2)
        for i, (lbl, val, col) in enumerate(data):
            x = 20 + i * (W // len(data))
            bh = int((val / mx) * 90)
            chart.create_rectangle(x, H - bh, x + bar_w, H, fill=col, outline="")
            chart.create_text(x + bar_w // 2, H + 8, text=f"{val}%",
                              font=("Courier New", 7), fill=DIM, anchor="n")
            for j, part in enumerate(lbl.split("\n")):
                chart.create_text(x + bar_w // 2, H + 20 + j * 11, text=part,
                                  font=("Courier New", 7), fill=DIM, anchor="n")

    def _refresh_dashboard(self):
        completed = db_get_progress()
        rules = db_get_rules()
        allow, deny = db_log_counts()
        total = allow + deny
        skill = compute_skill(completed, len(rules))

        self._stat_labels["skill"].configure(text=skill)
        self._stat_labels["lessons"].configure(text=f"{len(completed)} / {len(LESSONS)}")
        self._stat_labels["rules"].configure(text=str(len(rules)))
        self._stat_labels["tested"].configure(text=str(total))
        self._stat_labels["blocked"].configure(text=str(deny))
        self._stat_labels["allowed"].configure(text=str(allow))

        # Detection panel
        for w in self._det_frame.winfo_children():
            w.destroy()

        if total == 0:
            tk.Label(self._det_frame, text="No traffic tested yet.\nUse the Simulator tab.",
                     font=MONO_SM, fg=DIM, bg=PANEL, justify="center").pack(expand=True)
        else:
            pct = int((deny / total) * 100)
            tk.Label(self._det_frame, text=f"{pct}%",
                     font=("Courier New", 32, "bold"), fg=RED, bg=PANEL).pack(pady=(8, 0))
            tk.Label(self._det_frame, text="BLOCK RATE",
                     font=("Courier New", 8), fg=DIM, bg=PANEL).pack()
            for label, count, color in [("DENIED", deny, RED), ("ALLOWED", allow, GREEN)]:
                row = tk.Frame(self._det_frame, bg=PANEL)
                row.pack(fill="x", padx=8, pady=4)
                tk.Label(row, text=label, font=MONO_SM, fg=color, bg=PANEL, width=8).pack(side="left")
                bar_bg = tk.Frame(row, bg=BORDER, height=8)
                bar_bg.pack(side="left", fill="x", expand=True, padx=4)
                bar_bg.update_idletasks()
                fill_pct = (count / total) if total > 0 else 0
                tk.Frame(bar_bg, bg=color, height=8,
                         width=max(1, int(bar_bg.winfo_width() * fill_pct))).place(x=0, y=0, relwidth=fill_pct, relheight=1)
                tk.Label(row, text=str(count), font=MONO_SM, fg=TEXT, bg=PANEL, width=4).pack(side="left")

            status_color = GREEN if pct > 70 else (YELLOW if pct > 30 else RED)
            status_text = "HIGH SECURITY ✓" if pct > 70 else ("MODERATE SECURITY ⚠" if pct > 30 else "LOW SECURITY ✗")
            tk.Label(self._det_frame, text=f"STATUS: {status_text}",
                     font=("Courier New", 9, "bold"), fg=status_color, bg=PANEL).pack(pady=8)

        # Log
        logs = db_get_logs(40)
        self._dash_log.configure(state="normal")
        self._dash_log.delete("1.0", "end")
        if not logs:
            self._dash_log.insert("end", "No activity yet.\n", "dim")
        for (ts, ltype, msg) in logs:
            self._dash_log.insert("end", f"{ts}  ", "dim")
            self._dash_log.insert("end", msg + "\n", ltype if ltype in ("allow","deny","info","warn") else "info")
        self._dash_log.configure(state="disabled")

    def _clear_log(self):
        db_clear_logs()
        self._refresh_dashboard()

    # ── LEARNING ───────────────────────────────────────────────────────────────
    def _build_learning(self, parent):
        top = tk.Frame(parent, bg=BG, padx=20, pady=12)
        top.pack(fill="x")

        # Progress bar
        tk.Label(top, text="OVERALL PROGRESS", font=("Courier New", 9, "bold"),
                 fg=DIM, bg=BG).pack(anchor="w")
        pbar_bg = tk.Frame(top, bg=BORDER, height=8)
        pbar_bg.pack(fill="x", pady=(4, 2))
        self._learn_pbar = tk.Frame(pbar_bg, bg=ACCENT, height=8)
        self._learn_pbar.place(x=0, y=0, relheight=1, relwidth=0)
        self._learn_pct_lbl = tk.Label(top, text="0%", font=MONO_SM, fg=ACCENT, bg=BG)
        self._learn_pct_lbl.pack(anchor="e")

        # Scrollable grid
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self._learn_grid = tk.Frame(canvas, bg=BG, padx=20, pady=8)
        wid = canvas.create_window((0, 0), window=self._learn_grid, anchor="nw")
        self._learn_grid.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        self._lesson_btns = {}
        # Grid: 2 columns
        for i, lesson in enumerate(LESSONS):
            row, col = divmod(i, 2)
            self._build_lesson_card(self._learn_grid, lesson, row, col)

    def _build_lesson_card(self, parent, lesson, row, col):
        card = tk.Frame(parent, bg=PANEL,
                        highlightbackground=BORDER, highlightthickness=1,
                        cursor="hand2", padx=16, pady=14)
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        parent.columnconfigure(col, weight=1)

        tk.Label(card, text=f"LESSON {lesson['id']:02d}  ·  {lesson['category']}",
                 font=("Courier New", 8, "bold"), fg=ACCENT, bg=PANEL, anchor="w").pack(anchor="w")
        tk.Label(card, text=lesson["title"], font=SANS_LG, fg=TEXT, bg=PANEL,
                 anchor="w").pack(anchor="w", pady=(4, 2))
        tk.Label(card, text=lesson["desc"], font=("Segoe UI", 9), fg=DIM, bg=PANEL,
                 anchor="w", wraplength=350, justify="left").pack(anchor="w", pady=(0, 10))

        status_lbl = tk.Label(card, text="▶  CLICK TO START",
                              font=("Courier New", 8, "bold"), fg=DIM, bg=PANEL)
        status_lbl.pack(anchor="w")
        self._lesson_btns[lesson["id"]] = {"card": card, "status": status_lbl}

        def open_lesson(l=lesson):
            comp = db_get_progress()
            LessonDialog(self, l, l["id"] in comp, self._on_lesson_complete)

        card.bind("<Button-1>", lambda e, f=open_lesson: f())
        for w in card.winfo_children():
            w.bind("<Button-1>", lambda e, f=open_lesson: f())

    def _on_lesson_complete(self, lid):
        db_complete_lesson(lid)
        db_add_log("info", f"Lesson {lid} completed: {LESSONS[lid-1]['title']}")
        self._refresh_learning()
        self._refresh_header()

    def _refresh_learning(self):
        completed = db_get_progress()
        pct = len(completed) / len(LESSONS)
        self._learn_pbar.place(relwidth=pct)
        self._learn_pct_lbl.configure(text=f"{int(pct*100)}%  ({len(completed)}/{len(LESSONS)} lessons)")
        for lesson in LESSONS:
            info = self._lesson_btns.get(lesson["id"])
            if info:
                done = lesson["id"] in completed
                info["card"].configure(highlightbackground=GREEN if done else BORDER)
                info["status"].configure(
                    text="✓  COMPLETED" if done else "▶  CLICK TO START",
                    fg=GREEN if done else DIM
                )

    # ── SIMULATOR ──────────────────────────────────────────────────────────────
    def _build_simulator(self, parent):
        pad = tk.Frame(parent, bg=BG, padx=20, pady=12)
        pad.pack(fill="both", expand=True)

        top = tk.Frame(pad, bg=BG)
        top.pack(fill="x", pady=(0, 12))

        # Rule creator
        rc = tk.Frame(top, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        rc.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(rc, text="  RULE CONFIGURATION", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL, anchor="w").pack(fill="x", pady=(8, 2), padx=4)
        tk.Frame(rc, bg=BORDER, height=1).pack(fill="x")
        rf = tk.Frame(rc, bg=PANEL, padx=12, pady=10)
        rf.pack(fill="x")

        self._r_src  = styled_entry(rf, width=16)
        self._r_dst  = styled_entry(rf, width=16)
        self._r_port = styled_entry(rf, width=8)
        self._r_proto  = styled_combo(rf, ["TCP", "UDP", "ICMP", "ANY"], width=7)
        self._r_action = styled_combo(rf, ["ALLOW", "DENY"], width=7)

        for (lbl, w) in [("Src IP (or CIDR)", self._r_src), ("Dst IP (or CIDR)", self._r_dst),
                          ("Port", self._r_port), ("Protocol", self._r_proto), ("Action", self._r_action)]:
            f = tk.Frame(rf, bg=PANEL)
            f.pack(side="left", padx=6)
            tk.Label(f, text=lbl.upper(), font=("Courier New", 7), fg=DIM, bg=PANEL).pack(anchor="w")
            w.pack(anchor="w", pady=2)

        for entry, placeholder in [(self._r_src, "any"), (self._r_dst, "any"), (self._r_port, "any")]:
            entry.insert(0, placeholder)
            entry.configure(fg=DIM)
            entry.bind("<FocusIn>",  lambda e, en=entry: (en.delete(0, "end"), en.configure(fg=TEXT)) if en.get() in ("any",) else None)
            entry.bind("<FocusOut>", lambda e, en=entry: (en.insert(0, "any"), en.configure(fg=DIM)) if en.get() == "" else None)

        styled_button(rf, " + ADD RULE ", self._add_rule, bg=ACCENT).pack(side="left", padx=12, pady=(14, 0))

        # Traffic tester
        tt = tk.Frame(top, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        tt.pack(side="left", fill="both", expand=True, padx=(8, 0))
        tk.Label(tt, text="  TRAFFIC TESTING MODULE", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL, anchor="w").pack(fill="x", pady=(8, 2), padx=4)
        tk.Frame(tt, bg=BORDER, height=1).pack(fill="x")
        tpad = tk.Frame(tt, bg=PANEL, padx=12, pady=10)
        tpad.pack(fill="x")

        # Quick tests
        tk.Label(tpad, text="QUICK TESTS", font=("Courier New", 7, "bold"),
                 fg=DIM, bg=PANEL).pack(anchor="w", pady=(0, 4))
        qrow = tk.Frame(tpad, bg=PANEL)
        qrow.pack(anchor="w")
        for (name, proto, src, dst, port) in QUICK_TESTS:
            styled_button(qrow, name, lambda n=name,p=proto,s=src,d=dst,po=port: self._quick_test(n,p,s,d,po),
                          bg=BORDER, fg=TEXT, font=("Segoe UI", 8, "bold")).pack(side="left", padx=2)

        # Manual fields
        tf = tk.Frame(tpad, bg=PANEL)
        tf.pack(fill="x", pady=(10, 0))
        self._t_src  = styled_entry(tf, width=14)
        self._t_dst  = styled_entry(tf, width=14)
        self._t_port = styled_entry(tf, width=7)
        self._t_proto = styled_combo(tf, ["TCP", "UDP", "ICMP"], width=7)

        for (lbl, w) in [("Src IP", self._t_src), ("Dst IP", self._t_dst),
                          ("Port", self._t_port), ("Proto", self._t_proto)]:
            f = tk.Frame(tf, bg=PANEL)
            f.pack(side="left", padx=6)
            tk.Label(f, text=lbl.upper(), font=("Courier New", 7), fg=DIM, bg=PANEL).pack(anchor="w")
            w.pack(anchor="w", pady=2)

        test_row = tk.Frame(tpad, bg=PANEL)
        test_row.pack(anchor="w", pady=(8, 0))
        styled_button(test_row, " TEST PACKET ▶ ", self._test_packet, bg=ACCENT).pack(side="left")
        self._test_result_lbl = tk.Label(test_row, text="", font=("Courier New", 10, "bold"), bg=PANEL)
        self._test_result_lbl.pack(side="left", padx=12)

        # Rule table
        rule_frame = tk.Frame(pad, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        rule_frame.pack(fill="both", expand=True, pady=(0, 12))
        rh = tk.Frame(rule_frame, bg=PANEL)
        rh.pack(fill="x")
        tk.Label(rh, text="  ACTIVE FIREWALL RULES", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", pady=6, padx=4)
        styled_button(rh, "DELETE SELECTED", self._delete_selected_rule,
                      bg=RED, fg="white", font=("Segoe UI", 8, "bold")).pack(side="right", padx=4, pady=4)
        styled_button(rh, "CLEAR ALL", self._clear_rules,
                      bg=RED, fg="white", font=("Segoe UI", 8, "bold")).pack(side="right", padx=4, pady=4)
        tk.Frame(rule_frame, bg=BORDER, height=1).pack(fill="x")

        cols = ("#", "Src IP", "Dst IP", "Port", "Protocol", "Action")
        self._rule_tree = ttk.Treeview(rule_frame, columns=cols, show="headings", height=8)
        for col in cols:
            w = 50 if col == "#" else (120 if col in ("Src IP", "Dst IP") else 90)
            self._rule_tree.heading(col, text=col)
            self._rule_tree.column(col, width=w, anchor="w")
        sb2 = ttk.Scrollbar(rule_frame, orient="vertical", command=self._rule_tree.yview)
        self._rule_tree.configure(yscrollcommand=sb2.set)
        sb2.pack(side="right", fill="y")
        self._rule_tree.pack(fill="both", expand=True)
        self._rule_tree.tag_configure("allow", foreground=GREEN)
        self._rule_tree.tag_configure("deny",  foreground=RED)

        # IDS Log
        log_frame = tk.Frame(pad, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        log_frame.pack(fill="both")
        lh2 = tk.Frame(log_frame, bg=PANEL)
        lh2.pack(fill="x")
        tk.Label(lh2, text="  INTRUSION DETECTION LOG", font=("Courier New", 9, "bold"),
                 fg=ACCENT, bg=PANEL).pack(side="left", pady=6, padx=4)
        styled_button(lh2, "CLEAR", lambda: (db_clear_logs(), self._refresh_sim_log()),
                      bg=RED, fg="white", font=("Segoe UI", 8, "bold")).pack(side="right", padx=4, pady=4)
        tk.Frame(log_frame, bg=BORDER, height=1).pack(fill="x")
        self._sim_log = styled_text(log_frame, height=6, state="disabled")
        self._sim_log.pack(fill="both", padx=2, pady=2)
        self._sim_log.tag_configure("allow", foreground=GREEN)
        self._sim_log.tag_configure("deny",  foreground=RED)
        self._sim_log.tag_configure("info",  foreground=ACCENT)
        self._sim_log.tag_configure("dim",   foreground=DIM)

    def _add_rule(self):
        src   = self._r_src.get().strip()
        dst   = self._r_dst.get().strip()
        port  = self._r_port.get().strip()
        proto = self._r_proto.get()
        action= self._r_action.get()
        src  = "" if src  == "any" else src
        dst  = "" if dst  == "any" else dst
        port = "" if port == "any" else port
        db_add_rule(src, dst, port, proto, action)
        db_add_log("info", f"Rule added: {action} {proto} {src or 'any'} → {dst or 'any'}:{port or 'any'}")
        self._refresh_rules()
        self._refresh_header()

    def _delete_selected_rule(self):
        sel = self._rule_tree.selection()
        if not sel:
            return
        for item in sel:
            rid = self._rule_tree.item(item)["values"][0]
            # rid is the display row number; get actual db id
            rid_real = self._rule_id_map.get(int(rid))
            if rid_real:
                db_delete_rule(rid_real)
        self._refresh_rules()
        self._refresh_header()

    def _clear_rules(self):
        if messagebox.askyesno("Clear All Rules", "Delete all firewall rules?", parent=self):
            db_clear_rules()
            self._refresh_rules()
            self._refresh_header()

    def _test_packet(self):
        src   = self._t_src.get().strip()
        dst   = self._t_dst.get().strip()
        port  = self._t_port.get().strip()
        proto = self._t_proto.get()
        if not src or not dst:
            messagebox.showwarning("Missing Fields", "Enter Src IP and Dst IP.", parent=self)
            return
        rules = db_get_rules()
        action, rule_idx = test_traffic(rules, src, dst, port, proto)
        tag = "allow" if action == "ALLOW" else "deny"
        rule_note = f"(Rule #{rule_idx})" if rule_idx else "(Default Policy)"
        self._test_result_lbl.configure(
            text=f"{'✓ ALLOWED' if action == 'ALLOW' else '✗ BLOCKED'}  {rule_note}",
            fg=GREEN if action == "ALLOW" else RED
        )
        db_add_log(tag, f"TRAFFIC TEST: {proto} {src} → {dst}:{port or 'any'} — {action} {rule_note}")
        self._refresh_sim_log()

    def _quick_test(self, name, proto, src, dst, port):
        self._t_src.delete(0, "end");  self._t_src.insert(0, src)
        self._t_dst.delete(0, "end");  self._t_dst.insert(0, dst)
        self._t_port.delete(0, "end"); self._t_port.insert(0, port)
        self._t_proto.set(proto)
        rules = db_get_rules()
        action, rule_idx = test_traffic(rules, src, dst, port, proto)
        tag = "allow" if action == "ALLOW" else "deny"
        rule_note = f"(Rule #{rule_idx})" if rule_idx else "(Default Policy)"
        self._test_result_lbl.configure(
            text=f"{'✓ ALLOWED' if action == 'ALLOW' else '✗ BLOCKED'}  {rule_note}",
            fg=GREEN if action == "ALLOW" else RED
        )
        db_add_log(tag, f"QUICK TEST [{name}]: {proto} {src}:{port} → {dst} — {action} {rule_note}")
        self._refresh_sim_log()

    def _refresh_rules(self):
        for row in self._rule_tree.get_children():
            self._rule_tree.delete(row)
        self._rule_id_map = {}
        for i, (rid, src, dst, port, proto, action) in enumerate(db_get_rules(), 1):
            tag = "allow" if action == "ALLOW" else "deny"
            self._rule_tree.insert("", "end",
                values=(i, src or "any", dst or "any", port or "any", proto, action),
                tags=(tag,))
            self._rule_id_map[i] = rid

    def _refresh_sim_log(self):
        logs = db_get_logs(80)
        self._sim_log.configure(state="normal")
        self._sim_log.delete("1.0", "end")
        if not logs:
            self._sim_log.insert("end", "System ready. Waiting for traffic...\n", "info")
        for (ts, ltype, msg) in logs:
            self._sim_log.insert("end", f"{ts}  ", "dim")
            self._sim_log.insert("end", msg + "\n", ltype if ltype in ("allow","deny","info","warn") else "info")
        self._sim_log.configure(state="disabled")

    # ── MANUAL ─────────────────────────────────────────────────────────────────
    def _build_manual(self, parent):
        top = tk.Frame(parent, bg=BG, padx=20, pady=12)
        top.pack(fill="x")
        tk.Label(top, text="SEARCH COMMANDS", font=("Courier New", 9, "bold"),
                 fg=DIM, bg=BG).pack(anchor="w", pady=(0, 4))
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *a: self._filter_manual())
        se = styled_entry(top, width=60)
        se.pack(anchor="w")
        se.configure(textvariable=self._search_var)
        se.insert(0, "Search commands... (e.g. 'block port 80')")
        se.configure(fg=DIM)
        se.bind("<FocusIn>",  lambda e: (se.delete(0, "end"), se.configure(fg=TEXT)) if se.get().startswith("Search") else None)

        # Scrollable list
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        self._manual_body = tk.Frame(canvas, bg=BG, padx=20, pady=8)
        wid = canvas.create_window((0, 0), window=self._manual_body, anchor="nw")
        self._manual_body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))

        self._manual_cards = []
        for cmd in MANUAL_CMDS:
            card = self._build_cmd_card(self._manual_body, cmd)
            self._manual_cards.append((cmd, card))

    def _build_cmd_card(self, parent, cmd):
        title, desc, code = cmd
        card = tk.Frame(parent, bg="#040b12",
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=4)

        header = tk.Frame(card, bg="#040b12")
        header.pack(fill="x", padx=12, pady=(10, 2))
        tk.Label(header, text=title, font=SANS_B, fg=ACCENT, bg="#040b12").pack(side="left")

        def copy_cmd(c=code):
            self.clipboard_clear()
            self.clipboard_append(c)
            copy_lbl.configure(text="✓ COPIED", fg=GREEN)
            self.after(1500, lambda: copy_lbl.configure(text="COPY", fg=DIM))

        copy_lbl = tk.Label(header, text="COPY", font=MONO_SM, fg=DIM, bg="#040b12", cursor="hand2")
        copy_lbl.pack(side="right")
        copy_lbl.bind("<Button-1>", lambda e, c=code: copy_cmd(c))

        tk.Label(card, text=desc, font=("Segoe UI", 9), fg=DIM, bg="#040b12",
                 anchor="w").pack(anchor="w", padx=12, pady=2)
        tk.Label(card, text=code, font=("Courier New", 9), fg=ACCENT2, bg="#040b12",
                 anchor="w", justify="left").pack(anchor="w", padx=12, pady=(2, 10))
        return card

    def _filter_manual(self):
        q = self._search_var.get().lower()
        if q.startswith("search"):
            q = ""
        for (cmd, card) in self._manual_cards:
            title, desc, code = cmd
            visible = (not q or q in title.lower() or q in desc.lower() or q in code.lower())
            if visible:
                card.pack(fill="x", pady=4)
            else:
                card.pack_forget()

    # ── GLOBAL REFRESH ─────────────────────────────────────────────────────────
    def _refresh_header(self):
        completed = db_get_progress()
        rules = db_get_rules()
        skill = compute_skill(completed, len(rules))
        self._skill_var.set(skill)
        self._lesson_var.set(f"{len(completed)}/{len(LESSONS)}")
        self._rules_var.set(str(len(rules)))

    def _refresh_all(self):
        self._refresh_rules()
        self._refresh_learning()
        self._refresh_sim_log()
        self._refresh_header()
        self._refresh_dashboard()
        db_add_log("info", "Firewall Simulator initialized. Python · Tkinter · SQLite3 stack active.")
        db_add_log("info", f"Default rules loaded. Default policy: DENY ALL.")
        self._refresh_sim_log()
        self._refresh_dashboard()

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = FirewallSimulator()
    app.mainloop()
