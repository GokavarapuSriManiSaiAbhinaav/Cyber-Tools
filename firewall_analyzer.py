import os
import re
import threading
import queue
import csv
import ipaddress
from datetime import datetime
from collections import Counter
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

class FirewallParser:
    """Uses Regex and structural rules to identify and extract metrics from firewall strings."""
    def __init__(self):
        # Universal patterns covering standard logging formats (WinDefender, pfSense CSVs, iptables, asa)
        self.ts_pattern = re.compile(r'(\d{4}[-/]\d{2}[-/]\d{2}[\sT]\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.port_pattern = re.compile(r'(?:SPT|DPT|sport|dport|port|:)\s*=?\s*(\d{1,5})\b', re.IGNORECASE)
        self.proto_pattern = re.compile(r'\b(TCP|UDP|ICMP|IGMP|GRE)\b', re.IGNORECASE)
        self.action_pattern = re.compile(r'\b(ALLOW|ACCEPT|PERMIT|DENY|DROP|BLOCK|REJECT)\b', re.IGNORECASE)

    def parse_line(self, line):
        line = line.strip()
        if not line: return None
        
        timestamp = "-"
        src_ip = "-"
        dst_ip = "-"
        src_port = "-"
        dst_port = "-"
        proto = "UNKNOWN"
        action = "-"

        # Action Explicit Matching
        act_match = self.action_pattern.search(line)
        if act_match:
            action = act_match.group(1).upper()
            if action in ["ACCEPT", "PERMIT"]: action = "ALLOW"
            if action in ["DROP", "REJECT", "BLOCK"]: action = "DENY"
            
        # Timestamp Regex Mapping
        ts_match = self.ts_pattern.search(line)
        if ts_match:
            timestamp = ts_match.group(1)
            
        # Proto Explicit Matching
        pro_match = self.proto_pattern.search(line)
        if pro_match:
            proto = pro_match.group(1).upper()
            
        # IP Processing via iterative indexing to distinguish SRC vs DST predictably
        ips = self.ip_pattern.findall(line)
        if len(ips) >= 1:
            # Common pattern heuristics explicitly checking keys
            if "DST=" in line and "SRC=" in line:
                src_match = re.search(r'SRC=([0-9.]+)', line)
                dst_match = re.search(r'DST=([0-9.]+)', line)
                src_ip = src_match.group(1) if src_match else ips[0]
                dst_ip = dst_match.group(1) if dst_match else (ips[1] if len(ips)>1 else "-")
            else:
                src_ip = ips[0]
                if len(ips) >= 2: dst_ip = ips[1]
                
        # Port Processing heuristics finding common DPT / SPT / generic trailing port tuples
        ports = self.port_pattern.findall(line)
        if len(ports) >= 1:
             if "DPT=" in line and "SPT=" in line:
                 s_match = re.search(r'SPT=(\d+)', line)
                 d_match = re.search(r'DPT=(\d+)', line)
                 src_port = s_match.group(1) if s_match else ports[0]
                 dst_port = d_match.group(1) if d_match else (ports[1] if len(ports)>1 else "-")
             else:
                 dst_port = ports[-1]
                 if len(ports) >= 2: src_port = ports[-2]

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "action": action,
            "raw": line[:600]
        }


class ThreatDetector:
    """Categorizes logs into specific traffic segments isolating suspicious patterns implicitly."""
    def __init__(self):
        self.risky_ports = ["4444", "1337", "8080", "22", "23", "3389", "445", "135", "139"]
        self.port_scan_threshold = 10
        self.deny_threshold = 10

    def is_private_ip(self, ip_str):
        if not ip_str or ip_str == "-": return False
        try:
             ip = ipaddress.ip_address(ip_str)
             return ip.is_private
        except Exception:
             return False

    def categorize_and_detect(self, parsed):
        categories = ["All Traffic"]
        action = parsed["action"]
        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        dst_port = parsed["dst_port"]
        
        tags = []
        is_suspicious = False
        
        # Categorize by Action explicitly
        if action == "ALLOW":
            categories.append("Allowed Traffic")
            tags.append("ALLOW")
        elif action == "DENY":
            categories.append("Blocked Traffic")
            tags.append("DENY")
        
        # Evaluate Intranet vs Internet mappings
        src_priv = self.is_private_ip(src_ip)
        dst_priv = self.is_private_ip(dst_ip)
        if src_priv and dst_priv:
            tags.append("INTERNAL")
        elif src_priv and not dst_priv and action == "ALLOW":
            tags.append("OUTBOUND")
            
        # Immediate Suspicious Triggers mapping explicit risk logic boundaries
        sus_reason = ""
        if dst_port in self.risky_ports:
             is_suspicious = True
             sus_reason = f"Accessed known risky port {dst_port}"
             
        if not src_priv and dst_priv and action == "ALLOW":
             # Extremely rare for an external internet IP to actively hit a private IP block legitimately unless DMZ/NATed weirdly
             pass # Educational heuristic tracker
             
        if is_suspicious:
            categories.append("Suspicious Activity")
            tags.append("SUSPICIOUS")
            
        return categories, tags, is_suspicious, sus_reason


class LogLoader:
    """Reads large payload logs asynchronously mapping records through detection pipelines explicitly."""
    def __init__(self, parser, detector, update_queue):
        self.parser = parser
        self.detector = detector
        self.update_queue = update_queue
        self.is_running = False

    def load_file(self, path):
        self.is_running = True
        try:
            total_size = os.path.getsize(path)
            read_size = 0
            count = 0
            
            # Stateful IP tracking objects mapping logic explicitly isolating advanced threats (Scan / Brute Force)
            ip_tracking = {}
            ip_denies = Counter()
            
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                batch = []
                for line in f:
                    if not self.is_running: break
                    
                    read_size += len(line.encode('utf-8'))
                    parsed = self.parser.parse_line(line)
                    
                    if parsed:
                        count += 1
                        cats, tags, is_sus, reason = self.detector.categorize_and_detect(parsed)
                        
                        src_ip = parsed["src_ip"]
                        dst_port = str(parsed["dst_port"])
                        
                        # Stateful Analysis -> Port Scan + Repeated Denial Detection Mapping explicitly
                        if src_ip != "-" and not self.detector.is_private_ip(src_ip):
                            # Count unique ports contacted for mapping
                            if src_ip not in ip_tracking:
                                ip_tracking[src_ip] = set()
                            ip_tracking[src_ip].add(dst_port)
                            
                            # Tally denials dynamically
                            if parsed["action"] == "DENY":
                                ip_denies[src_ip] += 1
                                
                            # Check Thresholds Dynamically mapping real-time triggers cleanly
                            if len(ip_tracking[src_ip]) > self.detector.port_scan_threshold or ip_denies[src_ip] > self.detector.deny_threshold:
                                if "Suspicious Activity" not in cats:
                                     cats.append("Suspicious Activity")
                                if "SUSPICIOUS" not in tags:
                                     tags.append("SUSPICIOUS")
                                if ip_denies[src_ip] > self.detector.deny_threshold:
                                     reason = f"Repeated Denial Attempt Brute Force Triggers ({ip_denies[src_ip]}+)"
                                else:
                                     reason = f"Port Scan Indicator Detected (Hit {len(ip_tracking[src_ip])} distinct ports)"
                                     
                        batch.append((parsed, cats, tags, reason))
                        
                        # Yield back logic mapping smoothly natively inside Tkinter limitations dynamically
                        if count % 300 == 0:
                            self.update_queue.put(('BATCH_DATA', batch))
                            batch = []
                            progress = (read_size / total_size) * 100 if total_size > 0 else 0
                            self.update_queue.put(('PROGRESS', progress))
                            
                # Flush batch buffer cleanly to pipeline natively
                if batch:
                    self.update_queue.put(('BATCH_DATA', batch))
                    
            self.update_queue.put(('PROGRESS', 100))
            self.update_queue.put(('LOG', f"\n[✓] Extracted & mapped {count} distinct structured log payloads."))
            self.update_queue.put(('DONE', count))
            
        except Exception as e:
            self.update_queue.put(('ERROR', str(e)))
        finally:
            self.is_running = False

    def stop(self):
        self.is_running = False


class DashboardGenerator:
    """Parses extracted objects natively accumulating stats logic maps smoothly rendering metrics."""
    def __init__(self):
        self.total = 0
        self.allowed = 0
        self.blocked = 0
        self.suspicious = 0
        self.src_ips = Counter()
        self.dst_ports = Counter()
        self.protocols = Counter()
        self.time_series = Counter()

    def clear(self):
        self.total = 0
        self.allowed = 0
        self.blocked = 0
        self.suspicious = 0
        self.src_ips.clear()
        self.dst_ports.clear()
        self.protocols.clear()
        self.time_series.clear()

    def process_log(self, parsed, categories):
        self.total += 1
        
        if parsed["action"] == "ALLOW": self.allowed += 1
        if parsed["action"] == "DENY": self.blocked += 1
        if "Suspicious Activity" in categories: self.suspicious += 1
        
        if parsed["src_ip"] != "-": self.src_ips[parsed["src_ip"]] += 1
        if parsed["dst_port"] != "-": self.dst_ports[parsed["dst_port"]] += 1
        if parsed["proto"] != "UNKNOWN": self.protocols[parsed["proto"]] += 1
        
        if parsed["timestamp"] != "-":
             try:
                 ts = parsed["timestamp"].split(":")[0] # Top-level Group by hour implicitly 
                 self.time_series[ts] += 1
             except Exception:
                 pass

    def get_metrics(self):
        top_ip = self.src_ips.most_common(1)[0][0] if self.src_ips else "N/A"
        top_port = self.dst_ports.most_common(1)[0][0] if self.dst_ports else "N/A"
        top_proto = self.protocols.most_common(1)[0][0] if self.protocols else "N/A"
             
        return {
            "total": self.total,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "suspicious": self.suspicious,
            "top_ip": top_ip,
            "top_port": top_port,
            "top_proto": top_proto,
            "top_10_ips": self.src_ips.most_common(10)
        }


# ==========================================
# 2️⃣ GUI CONTROLLER (Tkinter Application)
# ==========================================

class GUIController:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Activity Log Analyzer")
        self.root.geometry("1450x850")
        
        # SOC Dashboard Colors
        self.c_bg = "#0d1117"                  # Deep Charcoal/Github Dark
        self.c_panel = "#161b22"               # Panel Layer
        self.c_fg = "#c9d1d9"                  # Fore Text
        self.c_neon_green = "#2ea043"          # Allow/Green
        self.c_neon_red = "#f85149"            # Deny/Block
        self.c_neon_cyan = "#58a6ff"           # Internal/Cyan
        self.c_warning = "#d29922"             # Orange Warnings
        self.c_dark_border = "#30363d"
        
        self.root.configure(bg=self.c_bg)
        
        # Backend properties
        self.parser = FirewallParser()
        self.detector = ThreatDetector()
        self.dashboard = DashboardGenerator()
        self.update_queue = queue.Queue()
        self.loader = None
        self.cached_logs = [] 
        
        self.setup_styles()
        self.setup_ui()
        self.check_queue()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Treeview styling matching cybersecurity layout context
        style.configure("Treeview", background=self.c_panel, foreground=self.c_fg, fieldbackground=self.c_panel, rowheight=25, borderwidth=0)
        style.map('Treeview', background=[('selected', '#21262d')], foreground=[('selected', '#ffffff')])
        style.configure("Treeview.Heading", background="#21262d", foreground=self.c_fg, font=('Helvetica', 10, 'bold'), borderwidth=1, bordercolor=self.c_dark_border)

        # Notebook tabs styling visually explicitly cleanly mapped
        style.configure("TNotebook", background=self.c_bg, borderwidth=0)
        style.configure("TNotebook.Tab", background="#21262d", foreground="#8b949e", padding=[20, 5], font=('Helvetica', 10, 'bold'))
        style.map("TNotebook.Tab", background=[("selected", self.c_neon_cyan)], foreground=[("selected", "#000000")])

    def setup_ui(self):
        # ------------------------------------------------
        # Top Header
        # ------------------------------------------------
        header_frame = tk.Frame(self.root, bg=self.c_bg, pady=10)
        header_frame.pack(fill=tk.X)
        
        tk.Label(header_frame, text="🛡️ NETWORK SECURITY INTELLIGENCE", font=("Courier", 12, "bold"), bg=self.c_bg, fg=self.c_neon_cyan).pack()
        tk.Label(header_frame, text="FIREWALL ACTIVITY LOG ANALYZER", font=("Helvetica", 18, "bold"), bg=self.c_bg, fg="#ffffff").pack()
        
        self.lbl_file = tk.Label(header_frame, text="[ NO LOG FILE MOUNTED ]", font=("Consolas", 10), bg=self.c_bg, fg=self.c_warning)
        self.lbl_file.pack(pady=(5,0))

        # Main Layout Splitting Array boundaries
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.c_dark_border, bd=0)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10,0))
        
        # ------------------------------------------------
        # Left Sidebar (Operations)
        # ------------------------------------------------
        self.sidebar_frame = tk.Frame(main_paned, bg=self.c_panel, width=220)
        main_paned.add(self.sidebar_frame, minsize=220)
        
        tk.Label(self.sidebar_frame, text="OPERATIONS", bg="#21262d", fg=self.c_fg, font=("Helvetica", 12, "bold"), pady=15).pack(fill=tk.X)
        
        btn_font = ("Helvetica", 10, "bold")
        ops = [
            ("📁 Load Firewall Log", self.load_log, self.c_neon_cyan, "#000000"),
            ("▶ Analyze Logs", self.analyze_trigger, "#21262d", self.c_fg),
            ("📥 Export Report CSV", self.export_csv, "#21262d", self.c_fg),
            ("🗑 Clear Results", self.clear_all, "#8b0000", self.c_fg),
        ]
        self.btns = {}
        for text, cmd, bg_c, fg_c in ops:
            btn = tk.Button(self.sidebar_frame, text=text, command=cmd, bg=bg_c, fg=fg_c, activebackground="#ffffff", activeforeground="#000000", relief=tk.FLAT, font=btn_font, pady=10, cursor="hand2")
            btn.pack(fill=tk.X, padx=15, pady=8)
            self.btns[text] = btn

        # ------------------------------------------------
        # Main Content Area Layout Parameters Dynamically Scaled
        # ------------------------------------------------
        content_frame = tk.Frame(main_paned, bg=self.c_bg)
        main_paned.add(content_frame, minsize=800)

        # Filters Toolbar Explicit Mapping Bounds Constraints Nativley
        tools_frame = tk.Frame(content_frame, bg=self.c_bg)
        tools_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(tools_frame, text="🔍 Search:", bg=self.c_bg, fg=self.c_fg, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(tools_frame, textvariable=self.search_var, bg="#21262d", fg=self.c_fg, insertbackground="#ffffff", bd=1, relief=tk.SOLID, width=25, font=("Consolas", 10))
        search_entry.pack(side=tk.LEFT, padx=10)
        search_entry.bind("<KeyRelease>", self.apply_filters)

        tk.Label(tools_frame, text="Protocol:", bg=self.c_bg, fg=self.c_fg, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT, padx=(10,5))
        self.proto_var = tk.StringVar(value="ALL")
        proto_menu = ttk.Combobox(tools_frame, textvariable=self.proto_var, values=["ALL", "TCP", "UDP", "ICMP"], state="readonly", width=8)
        proto_menu.pack(side=tk.LEFT)
        proto_menu.bind("<<ComboboxSelected>>", self.apply_filters)

        tk.Label(tools_frame, text="Port:", bg=self.c_bg, fg=self.c_fg, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT, padx=(20,5))
        self.port_var = tk.StringVar()
        port_entry = tk.Entry(tools_frame, textvariable=self.port_var, bg="#21262d", fg=self.c_fg, insertbackground="#ffffff", bd=1, relief=tk.SOLID, width=10, font=("Consolas", 10))
        port_entry.pack(side=tk.LEFT)
        port_entry.bind("<KeyRelease>", self.apply_filters)

        self.lbl_count = tk.Label(tools_frame, text="Analyzed Events: 0", bg=self.c_bg, fg="#8b949e", font=("Helvetica", 10, "bold"))
        self.lbl_count.pack(side=tk.RIGHT, padx=10)

        # Notebook Tabs Explicit Context Definitions Scaled UI Grid Layout Structures
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self.apply_filters)

        self.tabs = {}
        tab_names = ["All Traffic", "Allowed Traffic", "Blocked Traffic", "Suspicious Activity", "IP Analysis"]
        
        main_columns = [("timestamp", "Timestamp", 150), ("src_ip", "Source IP", 130), ("dst_ip", "Destination IP", 130), 
                        ("src_port", "Src Port", 80), ("dst_port", "Dst Port", 80), ("proto", "Protocol", 70), 
                        ("action", "Action", 80), ("info", "Context/Reason", 350)]
                        
        ip_columns = [("ip", "Tracked Source IP Address", 250), ("count", "Total Connection Attempts Logged", 150)]
        
        for tab_name in tab_names:
            frame = tk.Frame(self.notebook, bg=self.c_bg)
            self.notebook.add(frame, text=f" {tab_name} ")
            
            cols = ip_columns if tab_name == "IP Analysis" else main_columns
            tree = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings")
            for col_id, title, width in cols:
                tree.heading(col_id, text=title)
                tree.column(col_id, width=width, anchor=tk.W)
            
            # Setup Tags Matching Spec Color Rules Systematically
            tree.tag_configure("ALLOW", foreground=self.c_neon_green)
            tree.tag_configure("DENY", foreground=self.c_neon_red)
            tree.tag_configure("INTERNAL", foreground=self.c_neon_cyan)
            tree.tag_configure("SUSPICIOUS", foreground="#ff0000", font=('Helvetica', 10, 'bold')) # Bright structural red
            tree.tag_configure("OUTBOUND", foreground=self.c_warning)
            
            y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscroll=y_scroll.set)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.tabs[tab_name] = tree

        # Summary Dashboard Layout Definitions Clean
        self.summary_frame = tk.Frame(self.notebook, bg=self.c_panel)
        self.notebook.add(self.summary_frame, text=" Summary Dashboard ")
        self.summary_labels = {}
        self.chart_frame_1 = tk.Frame(self.summary_frame, bg=self.c_panel)
        self.chart_frame_2 = tk.Frame(self.summary_frame, bg=self.c_panel)
        self.setup_summary_dashboard()

        # ------------------------------------------------
        # Footer
        # ------------------------------------------------
        footer_frame = tk.Frame(self.root, bg="#000000", height=40)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tk.Label(footer_frame, text="This application performs firewall log analysis for cybersecurity monitoring and educational purposes.", bg="#000000", fg="#444444", font=("Helvetica", 8, "italic")).pack(pady=(5,0), side=tk.TOP)
        
        bottom_strip = tk.Frame(footer_frame, bg="#000000")
        bottom_strip.pack(fill=tk.X, expand=True)
        
        self.status_var = tk.StringVar(value="Status: Ready.")
        tk.Label(bottom_strip, textvariable=self.status_var, bg="#000000", fg=self.c_warning, font=("Consolas", 9, "bold")).pack(side=tk.LEFT, padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(bottom_strip, maximum=100, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=20, pady=5)

    def setup_summary_dashboard(self):
        self.summary_frame.columnconfigure(0, weight=1)
        self.summary_frame.columnconfigure(1, weight=1)
        self.summary_frame.columnconfigure(2, weight=1)
        self.summary_frame.rowconfigure(1, weight=1)
        
        details_frame = tk.Frame(self.summary_frame, bg=self.c_panel)
        details_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=20, pady=(20,0))
        
        fields = [
            ("Total Action Events", "0"),
            ("Allowed Connections", "0"),
            ("Blocked / Denied", "0"),
            ("Suspicious Anomalies", "0"),
            ("Top Host Source IP", "N/A"),
            ("Targeted Destination Port", "N/A"),
            ("Used Network Protocol", "N/A")
        ]
        
        for i, (label, default) in enumerate(fields):
             frame = tk.Frame(details_frame, bg=self.c_dark_border, bd=1, relief=tk.SOLID)
             frame.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
             tk.Label(frame, text=label, bg=self.c_dark_border, fg="#8b949e", font=("Helvetica", 9, "bold")).pack(pady=(5,0))
             val_var = tk.StringVar(value=default)
             self.summary_labels[label] = val_var
             tk.Label(frame, textvariable=val_var, bg=self.c_dark_border, fg="#ffffff", font=("Helvetica", 14, "bold")).pack(pady=(0,5))

        self.chart_frame_1.grid(row=1, column=0, columnspan=1, sticky="nsew", padx=20, pady=20)
        self.chart_frame_2.grid(row=1, column=1, columnspan=2, sticky="nsew", padx=(0,20), pady=20)

    def update_dashboard_ui(self):
        metrics = self.dashboard.get_metrics()
        
        self.summary_labels["Total Action Events"].set(str(metrics["total"]))
        self.summary_labels["Allowed Connections"].set(str(metrics["allowed"]))
        self.summary_labels["Blocked / Denied"].set(str(metrics["blocked"]))
        self.summary_labels["Suspicious Anomalies"].set(str(metrics["suspicious"]))
        self.summary_labels["Top Host Source IP"].set(metrics["top_ip"])
        self.summary_labels["Targeted Destination Port"].set(metrics["top_port"])
        self.summary_labels["Used Network Protocol"].set(metrics["top_proto"])

        # Populate Top 10 IP Table explicitly mapping layout properties implicitly
        tree_ip = self.tabs["IP Analysis"]
        tree_ip.delete(*tree_ip.get_children())
        for ip, count in metrics["top_10_ips"]:
             tree_ip.insert("", tk.END, values=(ip, count))

        # Handle Chart Bindings dynamically safely wrapping matplotlib figures
        if MATPLOTLIB_AVAILABLE:
            for widget in self.chart_frame_1.winfo_children(): widget.destroy()
            for widget in self.chart_frame_2.winfo_children(): widget.destroy()
                
            # Chart 1: Actions Pie Chart natively
            fig1 = Figure(figsize=(4, 3), dpi=90, facecolor=self.c_panel)
            ax1 = fig1.add_subplot(111)
            labels1 = ['Allowed', 'Blocked', 'Suspicious']
            sizes1 = [metrics["allowed"], metrics["blocked"] - metrics["suspicious"], metrics["suspicious"]]
            colors1 = [self.c_neon_green, self.c_neon_red, "#ff0000"]
            
            # Prevent crashes safely if zero datasets natively array constraints handled
            if sum(sizes1) > 0:
                ax1.pie(sizes1, labels=labels1, colors=colors1, startangle=90, textprops={'color': "white", 'weight': 'bold'})
                ax1.set_title("Traffic Action Distribution", color=self.c_fg, fontweight='bold')
                FigureCanvasTkAgg(fig1, master=self.chart_frame_1).get_tk_widget().pack(fill=tk.BOTH, expand=True)

            # Chart 2: Protocol Line/Bar dynamically tracked safely arrays mapped explicitly cleanly
            fig2 = Figure(figsize=(5, 3), dpi=90, facecolor=self.c_panel)
            ax2 = fig2.add_subplot(111)
            ax2.set_facecolor(self.c_panel)
            
            p_keys = list(self.dashboard.protocols.keys())
            p_vals = list(self.dashboard.protocols.values())
            
            if p_keys:
                ax2.bar(p_keys, p_vals, color=self.c_neon_cyan)
                ax2.spines['bottom'].set_color(self.c_dark_border)
                ax2.spines['left'].set_color(self.c_dark_border)
                ax2.spines['top'].set_visible(False)
                ax2.spines['right'].set_visible(False)
                ax2.tick_params(axis='x', colors=self.c_fg)
                ax2.tick_params(axis='y', colors=self.c_fg)
                ax2.set_title("Distribution Protocol Matrix", color=self.c_fg, fontweight='bold')
                FigureCanvasTkAgg(fig2, master=self.chart_frame_2).get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------
    # State Processing Handlers Natively Handled Securely Scaling Framework Loops
    # ------------------------------------------------

    def clear_all(self):
        self.cached_logs.clear()
        self.dashboard.clear()
        self.lbl_file.config(text="[ NO LOG FILE MOUNTED ]")
        self.lbl_count.config(text="Analyzed Events: 0")
        for tree in self.tabs.values(): tree.delete(*tree.get_children())
        self.update_dashboard_ui()
        self.progress_bar["value"] = 0
        self.status_var.set("Status: All properties cleared systematically.")

    def load_log(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log *.txt *.csv"), ("All Files", "*.*")])
        if not file_path: return
        
        self.clear_all()
        self.current_file = file_path
        self.lbl_file.config(text=f"Mounted Target: {os.path.basename(file_path)}")
        self.status_var.set("Status: File mounted successfully. Click 'Analyze Logs' natively.")

    def analyze_trigger(self):
        if not hasattr(self, 'current_file') or not self.current_file:
            messagebox.showwarning("Warning", "Mount a file via 'Load Firewall Log' strictly beforehand.")
            return
            
        self.btns["▶ Analyze Logs"].config(state=tk.DISABLED)
        self.status_var.set("Status: Extracting network telemetry dynamically array streams natively...")
        self.progress_bar["value"] = 0
        
        self.loader = LogLoader(self.parser, self.detector, self.update_queue)
        threading.Thread(target=self.loader.load_file, args=(self.current_file,), daemon=True).start()

    def check_queue(self):
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == 'BATCH_DATA':
                    self.cached_logs.extend(data)
                    for parsed, categories, tags, reason in data:
                        self.dashboard.process_log(parsed, categories)
                        
                elif msg_type == 'PROGRESS':
                    self.progress_bar["value"] = data
                    
                elif msg_type == 'DONE':
                    self.update_dashboard_ui()
                    self.apply_filters()
                    self.status_var.set(f"Status: Safe parsing finalized -> {data} unique events mapped internally.")
                    self.btns["▶ Analyze Logs"].config(state=tk.NORMAL)
                    
                elif msg_type == 'ERROR':
                    self.status_var.set(f"Status: Halt triggers thrown -> {data}")
                    self.btns["▶ Analyze Logs"].config(state=tk.NORMAL)
                    
        except queue.Empty:
            pass
            
        self.root.after(100, self.check_queue)

    def apply_filters(self, event=None):
        if not self.cached_logs: return
        
        query = self.search_var.get().lower()
        pr_filter = self.proto_var.get()
        port_filter = self.port_var.get().strip()
        
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        
        if active_tab_id < len(tab_names) and tab_names[active_tab_id] != "IP Analysis":
            current_category = tab_names[active_tab_id]
            tree = self.tabs[current_category]
            
            tree.delete(*tree.get_children())
            
            display_count = 0
            limit = 5000 
            
            for parsed, categories, tags, reason in self.cached_logs:
                if current_category not in categories: continue
                if pr_filter != "ALL" and parsed["proto"] != pr_filter: continue
                if port_filter and parsed["dst_port"] != port_filter and parsed["src_port"] != port_filter: continue
                
                # Query explicit logic strings gracefully filtering natively
                if query:
                    searchable = f"{parsed['src_ip']} {parsed['dst_ip']} {parsed['action']} {reason}".lower()
                    if query not in searchable: continue
                
                if display_count < limit:
                    tree.insert("", tk.END, values=(parsed["timestamp"], parsed["src_ip"], parsed["dst_ip"], parsed["src_port"], parsed["dst_port"], parsed["proto"], parsed["action"], reason), tags=tags)
                display_count += 1
                
            limit_str = f" (Render limit capped structurally safely 5k implicitly)" if display_count > limit else ""
            self.lbl_count.config(text=f"Events Listed: {display_count}{limit_str}")

    def export_csv(self):
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        if active_tab_id >= len(tab_names): return
        
        current_tab_name = tab_names[active_tab_id]
        tree = self.tabs[current_tab_name]
        
        children = tree.get_children()
        if not children:
            messagebox.showinfo("Export", "No properties inside active tab currently to extract natively.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"Firewall_Audit_{current_tab_name.replace(' ', '_')}.csv", title="Export Network Report Matrix")
        if not file_path: return
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                headers = [tree.heading(col)["text"] for col in tree["columns"]]
                writer.writerow(headers)
                
                for item in children:
                    row_data = tree.item(item)["values"]
                    writer.writerow(row_data)
            self.status_var.set(f"Status: Safe output array extracted explicitly bound locally targeting '{file_path}'.")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


if __name__ == "__main__":
    app_root = tk.Tk()
    app = GUIController(app_root)
    app_root.mainloop()
