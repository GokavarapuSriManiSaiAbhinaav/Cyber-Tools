import os
import re
import threading
import queue
import csv
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


# ==========================================
# 1️⃣ LOG ANALYSIS CLASSES (BACKEND)
# ==========================================

class LogParser:
    """Uses Regex to parse generic log formats and extract key metadata."""
    def __init__(self):
        # Basic patterns parsing most common log formats
        self.ts_pattern = re.compile(r'(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)')
        self.lvl_pattern = re.compile(r'\b(ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL|FATAL|SUCCESS|EXCEPTION|FAILED)\b', re.IGNORECASE)
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

    def parse_line(self, line):
        line = line.strip()
        if not line:
            return None
            
        timestamp = "-"
        level = "INFO" # Default fallback
        source = "-"
        
        # Extract Timestamp
        ts_match = self.ts_pattern.search(line)
        if ts_match:
            timestamp = ts_match.group(1)
            
        # Extract Level
        lvl_match = self.lvl_pattern.search(line)
        if lvl_match:
            level = lvl_match.group(1).upper()
            if level in ["WARN"]: level = "WARNING"
            if level in ["EXCEPTION", "FAILED"]: level = "ERROR"
            if level in ["FATAL"]: level = "CRITICAL"
        else:
            # Fallback level detection
            if "error" in line.lower() or "exception" in line.lower() or "failed" in line.lower():
                level = "ERROR"
            elif "warn" in line.lower():
                level = "WARNING"
            elif "debug" in line.lower():
                level = "DEBUG"
                
        # Extract IP (used as source proxy if available)
        ip_match = self.ip_pattern.search(line)
        if ip_match:
            source = ip_match.group(0)

        return {
            "timestamp": timestamp,
            "level": level,
            "source": source,
            "message": line[:500] # Truncate extremely long lines for display
        }

class LogCategorizer:
    """Categorizes logs into groups based on keywords and levels."""
    def __init__(self):
        self.security_keywords = ["unauthorized", "login failed", "attack", "malware", "denied", "intrusion", "brute force", "exploit"]
        
    def categorize(self, parsed_log):
        categories = ["All Logs"]
        
        lvl = parsed_log["level"]
        msg = parsed_log["message"].lower()

        # By Level
        if lvl in ["ERROR", "CRITICAL"]: categories.append("Errors")
        elif lvl == "WARNING": categories.append("Warnings")
        elif lvl == "INFO": categories.append("Info")
        
        # By Security Keywords
        is_security_alert = any(k in msg for k in self.security_keywords)
        if is_security_alert:
            categories.append("Security Alerts")
            
        return categories

class LogLoader:
    """Line-by-line file reader designed to handle large log payloads securely without crashing."""
    def __init__(self, parser, categorizer, update_queue):
        self.parser = parser
        self.categorizer = categorizer
        self.update_queue = update_queue
        self.is_running = False

    def load_file(self, path):
        self.is_running = True
        try:
            total_size = os.path.getsize(path)
            read_size = 0
            count = 0
            
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                batch = []
                for line in f:
                    if not self.is_running: break
                    
                    read_size += len(line.encode('utf-8'))
                    parsed = self.parser.parse_line(line)
                    
                    if parsed:
                        cats = self.categorizer.categorize(parsed)
                        batch.append((parsed, cats))
                        count += 1
                        
                        # Emit batches of 200 logs to prevent queue bottlenecks
                        if count % 200 == 0:
                            self.update_queue.put(('BATCH_DATA', batch))
                            batch = []
                            # Stream progress size
                            progress = (read_size / total_size) * 100 if total_size > 0 else 0
                            self.update_queue.put(('PROGRESS', progress))
                            
                # Emit remainder
                if batch:
                    self.update_queue.put(('BATCH_DATA', batch))
                    
            self.update_queue.put(('PROGRESS', 100))
            self.update_queue.put(('LOG', f"\n[✓] Finished loading {count} log entries."))
            self.update_queue.put(('DONE', count))
            
        except Exception as e:
            self.update_queue.put(('ERROR', str(e)))
        finally:
            self.is_running = False

    def stop(self):
        self.is_running = False


class DashboardGenerator:
    """Handles parsing metrics and preparing plotting data."""
    def __init__(self):
        self.total = 0
        self.counts = {"ERROR": 0, "WARNING": 0, "INFO": 0, "DEBUG": 0, "CRITICAL": 0, "SUCCESS": 0, "Security Alerts": 0}
        self.errors_list = []
        self.times_list = []

    def clear(self):
        self.total = 0
        for k in self.counts: self.counts[k] = 0
        self.errors_list.clear()
        self.times_list.clear()

    def process_log(self, parsed, categories):
        self.total += 1
        lvl = parsed["level"]
        
        if lvl in self.counts:
             self.counts[lvl] += 1
             
        if "Security Alerts" in categories:
            self.counts["Security Alerts"] += 1
            
        if lvl in ["ERROR", "CRITICAL"]:
            # Quick hash of error message to find most frequent
            self.errors_list.append(parsed["message"][:80])
            
        if parsed["timestamp"] != "-":
             # Group by hour for peak time mapping
             try:
                 ts = parsed["timestamp"].split(":")[0] # Gives YYYY-MM-DD HH
                 self.times_list.append(ts)
             except Exception:
                 pass

    def get_metrics(self):
        most_freq_error = "None"
        if self.errors_list:
            most_freq_error = Counter(self.errors_list).most_common(1)[0][0] + "..."
            
        peak_time = "None"
        if self.times_list:
             peak_time = Counter(self.times_list).most_common(1)[0][0] + ":00"
             
        return {
            "total": self.total,
            "counts": self.counts,
            "most_frequent_error": most_freq_error,
            "peak_time": peak_time
        }


# ==========================================
# 2️⃣ GUI CONTROLLER (Tkinter Application)
# ==========================================

class GUIController:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Log Analyzer & Categorization Tool")
        self.root.geometry("1400x850")
        
        # Modern SOC Dark Theme Colors
        self.c_bg = "#121212"                  # Deep Charcoal/Black
        self.c_panel = "#1e1e1e"               # Dark Panel
        self.c_fg = "#ffffff"                  # Crisp White
        self.c_neon_blue = "#00e5ff"           # Neon Blue Highlights
        self.c_neon_green = "#00e676"          # Neon Green Highlights
        self.c_dark_border = "#333333"         # Panel borders
        
        # Status Colors
        self.cl_error = "#ff3d00"              # Red
        self.cl_warning = "#ff9100"            # Orange
        self.cl_info = "#00e676"               # Green
        self.cl_debug = "#9e9e9e"              # Gray
        self.cl_critical = "#d50000"           # Bright Red
        self.cl_success = "#00b0ff"            # Cyan

        self.root.configure(bg=self.c_bg)
        
        # Backend properties
        self.parser = LogParser()
        self.categorizer = LogCategorizer()
        self.dashboard = DashboardGenerator()
        self.update_queue = queue.Queue()
        self.loader = None
        self.cached_logs = [] # Needed for local filtering and exporting
        
        self.setup_styles()
        self.setup_ui()
        self.check_queue()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Treeview styling matching terminal look
        style.configure("Treeview", background=self.c_panel, foreground=self.c_fg, fieldbackground=self.c_panel, rowheight=28, borderwidth=0)
        style.map('Treeview', background=[('selected', '#333333')], foreground=[('selected', self.c_neon_blue)])
        style.configure("Treeview.Heading", background="#1a1a1a", foreground=self.c_neon_blue, font=('Helvetica', 10, 'bold'), borderwidth=1, bordercolor=self.c_dark_border)

        # Notebook tabs
        style.configure("TNotebook", background=self.c_bg, borderwidth=0)
        style.configure("TNotebook.Tab", background="#1a1a1a", foreground="#aaaaaa", padding=[20, 5], font=('Helvetica', 10, 'bold'))
        style.map("TNotebook.Tab", background=[("selected", self.c_neon_blue)], foreground=[("selected", "#000000")])

    def setup_ui(self):
        # ------------------------------------------------
        # Top Header
        # ------------------------------------------------
        header_frame = tk.Frame(self.root, bg=self.c_bg, pady=10)
        header_frame.pack(fill=tk.X)
        
        # Logo Context
        tk.Label(header_frame, text="⚡ SMART SOC ANALYTICS", font=("Courier", 12, "bold"), bg=self.c_bg, fg=self.c_neon_green).pack()
        tk.Label(header_frame, text="LOG ANALYZER & CATEGORIZATION TOOL", font=("Helvetica", 18, "bold"), bg=self.c_bg, fg=self.c_fg).pack()
        
        self.lbl_file = tk.Label(header_frame, text="[ NO LOG FILE LOADED ]", font=("Consolas", 10), bg=self.c_bg, fg=self.c_neon_blue)
        self.lbl_file.pack(pady=(5,0))

        # Main Layout splitting: Sidebar (Left) / Main Content (Right)
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.c_dark_border, bd=0)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10,0))
        
        # ------------------------------------------------
        # Left Sidebar (Operations)
        # ------------------------------------------------
        self.sidebar_frame = tk.Frame(main_paned, bg=self.c_panel, width=220)
        main_paned.add(self.sidebar_frame, minsize=220)
        
        tk.Label(self.sidebar_frame, text="OPERATIONS", bg="#1a1a1a", fg=self.c_neon_blue, font=("Helvetica", 12, "bold"), pady=15).pack(fill=tk.X)
        
        btn_font = ("Helvetica", 10, "bold")
        ops = [
            ("📁 Load Log File", self.load_log, self.c_neon_green, "#000000"),
            ("▶ Analyze Logs", self.analyze_trigger, "#333333", self.c_fg),
            ("📥 Export Report CSV", self.export_csv, "#333333", self.c_fg),
            ("🗑 Clear Results", self.clear_all, "#550000", self.c_fg),
        ]
        self.btns = {}
        for text, cmd, bg_c, fg_c in ops:
            btn = tk.Button(self.sidebar_frame, text=text, command=cmd, bg=bg_c, fg=fg_c, activebackground=self.c_neon_blue, activeforeground="#000000", relief=tk.FLAT, font=btn_font, pady=10, cursor="hand2")
            btn.pack(fill=tk.X, padx=15, pady=8)
            self.btns[text] = btn

        # ------------------------------------------------
        # Main Content Area
        # ------------------------------------------------
        content_frame = tk.Frame(main_paned, bg=self.c_bg)
        main_paned.add(content_frame, minsize=800)

        # Utility Toolbar Mapping (Search & Filters)
        tools_frame = tk.Frame(content_frame, bg=self.c_bg)
        tools_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(tools_frame, text="🔍 Search:", bg=self.c_bg, fg=self.c_fg, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(tools_frame, textvariable=self.search_var, bg="#1a1a1a", fg=self.c_neon_blue, insertbackground=self.c_neon_blue, bd=1, relief=tk.SOLID, width=35, font=("Consolas", 10))
        search_entry.pack(side=tk.LEFT, padx=10)
        search_entry.bind("<KeyRelease>", self.apply_filters)

        tk.Label(tools_frame, text="Filter Level:", bg=self.c_bg, fg=self.c_fg, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT, padx=(20,5))
        self.level_var = tk.StringVar(value="ANY")
        level_menu = ttk.Combobox(tools_frame, textvariable=self.level_var, values=["ANY", "ERROR", "WARNING", "INFO", "CRITICAL", "DEBUG", "SUCCESS"], state="readonly", width=15)
        level_menu.pack(side=tk.LEFT)
        level_menu.bind("<<ComboboxSelected>>", self.apply_filters)

        self.lbl_count = tk.Label(tools_frame, text="Showing: 0 logs", bg=self.c_bg, fg="#94a3b8", font=("Helvetica", 10, "bold"))
        self.lbl_count.pack(side=tk.RIGHT, padx=10)

        # Notebook Tabs
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self.apply_filters)

        self.tabs = {}
        tab_names = ["All Logs", "Errors", "Warnings", "Info", "Security Alerts"]
        columns = [("timestamp", "Timestamp", 180), ("level", "Level", 100), ("source", "Source (IP/Module)", 150), ("message", "Log Message", 700)]
        
        for tab_name in tab_names:
            frame = tk.Frame(self.notebook, bg=self.c_bg)
            self.notebook.add(frame, text=f" {tab_name} ")
            
            tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings")
            for col_id, title, width in columns:
                tree.heading(col_id, text=title)
                tree.column(col_id, width=width, anchor=tk.W)
            
            # Setup Tags Matching Application Security Context Colors
            tree.tag_configure("ERROR", foreground=self.cl_error)
            tree.tag_configure("WARNING", foreground=self.cl_warning)
            tree.tag_configure("INFO", foreground=self.cl_info)
            tree.tag_configure("DEBUG", foreground=self.cl_debug)
            tree.tag_configure("CRITICAL", foreground=self.cl_critical, font=('Helvetica', 10, 'bold'))
            tree.tag_configure("SUCCESS", foreground=self.cl_success)
            
            y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscroll=y_scroll.set)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.tabs[tab_name] = tree

        # Summary Dashboard Layout
        self.summary_frame = tk.Frame(self.notebook, bg=self.c_panel)
        self.notebook.add(self.summary_frame, text=" Summary Dashboard ")
        self.summary_labels = {}
        self.chart_frame = tk.Frame(self.summary_frame, bg=self.c_panel)
        self.setup_summary_dashboard()

        # ------------------------------------------------
        # Footer & Terminal Format
        # ------------------------------------------------
        footer_frame = tk.Frame(self.root, bg="#050505", height=40)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tk.Label(footer_frame, text="This application performs log analysis and categorization for cybersecurity monitoring and educational purposes.", bg="#050505", fg="#666666", font=("Helvetica", 8, "italic")).pack(pady=(5,0), side=tk.TOP)
        
        bottom_strip = tk.Frame(footer_frame, bg="#050505")
        bottom_strip.pack(fill=tk.X, expand=True)
        
        self.status_var = tk.StringVar(value="Status: Ready.")
        tk.Label(bottom_strip, textvariable=self.status_var, bg="#050505", fg=self.c_neon_green, font=("Consolas", 9, "bold")).pack(side=tk.LEFT, padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(bottom_strip, maximum=100, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=20, pady=5)

    def setup_summary_dashboard(self):
        # Master Grid Left side details, Right side chart
        self.summary_frame.columnconfigure(0, weight=1)
        self.summary_frame.columnconfigure(1, weight=1)
        
        details_frame = tk.Frame(self.summary_frame, bg=self.c_panel)
        details_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        fields = [
            ("Total Logs Processed", "0"),
            ("Total Errors", "0"),
            ("Total Warnings", "0"),
            ("Total Info", "0"),
            ("Security Alerts", "0"),
            ("Most Frequent Error", "None"),
            ("Peak Log Activity Time", "None")
        ]
        
        tk.Label(details_frame, text="[ LOG METADATA INTELLIGENCE ]", bg=self.c_panel, fg=self.c_neon_blue, font=("Helvetica", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=15, sticky="w")
        
        for i, (label, default) in enumerate(fields):
            tk.Label(details_frame, text=f"{label}:", bg=self.c_panel, fg="#94a3b8", font=("Helvetica", 12)).grid(row=i+1, column=0, sticky="e", padx=10, pady=10)
            val_var = tk.StringVar(value=default)
            self.summary_labels[label] = val_var
            tk.Label(details_frame, textvariable=val_var, bg=self.c_panel, fg="#ffffff", font=("Helvetica", 12, "bold")).grid(row=i+1, column=1, sticky="w", pady=10)

        # Matplotlib Chart Integration Area
        self.chart_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    def update_dashboard_ui(self):
        metrics = self.dashboard.get_metrics()
        
        self.summary_labels["Total Logs Processed"].set(str(metrics["total"]))
        self.summary_labels["Total Errors"].set(str(metrics["counts"]["ERROR"] + metrics["counts"]["CRITICAL"]))
        self.summary_labels["Total Warnings"].set(str(metrics["counts"]["WARNING"]))
        self.summary_labels["Total Info"].set(str(metrics["counts"]["INFO"]))
        self.summary_labels["Security Alerts"].set(str(metrics["counts"]["Security Alerts"]))
        self.summary_labels["Most Frequent Error"].set(metrics["most_frequent_error"])
        self.summary_labels["Peak Log Activity Time"].set(metrics["peak_time"])

        # Create interactive Chart dynamically mapped avoiding memory leaks
        if MATPLOTLIB_AVAILABLE:
            for widget in self.chart_frame.winfo_children():
                widget.destroy()
                
            fig = Figure(figsize=(5, 4), dpi=100, facecolor=self.c_panel)
            ax = fig.add_subplot(111)
            ax.set_facecolor(self.c_panel)
            
            labels = ['ERROR', 'WARN', 'INFO', 'ALERT']
            values = [
                metrics["counts"]["ERROR"] + metrics["counts"]["CRITICAL"],
                metrics["counts"]["WARNING"],
                metrics["counts"]["INFO"],
                metrics["counts"]["Security Alerts"]
            ]
            colors = [self.cl_error, self.cl_warning, self.cl_info, self.c_neon_blue]
            
            bars = ax.bar(labels, values, color=colors)
            ax.spines['bottom'].set_color(self.c_dark_border)
            ax.spines['left'].set_color(self.c_dark_border)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.tick_params(axis='x', colors=self.c_fg)
            ax.tick_params(axis='y', colors=self.c_fg)
            ax.set_title("Log Severity Distribution", color=self.c_neon_blue, fontsize=12, fontweight='bold')
            
            canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------
    # State Processing Handlers
    # ------------------------------------------------

    def clear_all(self):
        self.cached_logs.clear()
        self.dashboard.clear()
        self.lbl_file.config(text="[ NO LOG FILE LOADED ]")
        self.lbl_count.config(text="Showing: 0 logs")
        for tree in self.tabs.values():
            tree.delete(*tree.get_children())
        self.update_dashboard_ui()
        self.progress_bar["value"] = 0
        self.status_var.set("Status: All properties cleared systematically.")

    def load_log(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log *.txt *.csv"), ("All Files", "*.*")])
        if not file_path: return
        
        self.clear_all()
        self.current_file = file_path
        self.lbl_file.config(text=f"Loaded Target: {os.path.basename(file_path)}")
        self.status_var.set("Status: Target staged. Click 'Analyze Logs' to safely execute.")

    def analyze_trigger(self):
        if not hasattr(self, 'current_file') or not self.current_file:
            messagebox.showwarning("Warning", "Stage a file via 'Load Log File' strictly beforehand.")
            return
            
        self.btns["▶ Analyze Logs"].config(state=tk.DISABLED)
        self.status_var.set("Status: Extracting log telemetry & analyzing structures...")
        self.progress_bar["value"] = 0
        
        self.loader = LogLoader(self.parser, self.categorizer, self.update_queue)
        threading.Thread(target=self.loader.load_file, args=(self.current_file,), daemon=True).start()

    def check_queue(self):
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == 'BATCH_DATA':
                    # data = [(parsed, categories), ...]
                    self.cached_logs.extend(data)
                    for parsed, categories in data:
                        self.dashboard.process_log(parsed, categories)
                        # We only incrementally insert into the active mapped tab UI to keep memory low currently
                        
                elif msg_type == 'PROGRESS':
                    self.progress_bar["value"] = data
                    
                elif msg_type == 'LOG':
                    print(data) # Minimal console tracking natively
                    
                elif msg_type == 'DONE':
                    self.update_dashboard_ui()
                    self.apply_filters()
                    self.status_var.set(f"Status: Safely mapped and processed {data} telemetry blocks.")
                    self.btns["▶ Analyze Logs"].config(state=tk.NORMAL)
                    
                elif msg_type == 'ERROR':
                    self.status_var.set(f"Status: Exception handled natively -> {data}")
                    self.btns["▶ Analyze Logs"].config(state=tk.NORMAL)
                    
        except queue.Empty:
            pass
            
        self.root.after(100, self.check_queue)

    def apply_filters(self, event=None):
        if not self.cached_logs: return
        
        query = self.search_var.get().lower()
        level_filter = self.level_var.get()
        
        # Determine target category tab based on active notebook interface index
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        
        if active_tab_id < len(tab_names):
            current_category = tab_names[active_tab_id]
            tree = self.tabs[current_category]
            
            # Wipe tab clean
            tree.delete(*tree.get_children())
            
            display_count = 0
            # Remap matching parameters dynamically 
            # Note: For massive files (1M+ lines) standard Treeview inserts freeze Tkinter, 
            # we limit the visual interface mappings softly purely for educational bounds if immense.
            limit = 5000 
            
            for parsed, categories in self.cached_logs:
                if current_category not in categories: continue
                if level_filter != "ANY" and parsed["level"] != level_filter: continue
                if query and query not in parsed["message"].lower() and query not in parsed["source"].lower(): continue
                
                if display_count < limit:
                    tree.insert("", tk.END, values=(parsed["timestamp"], parsed["level"], parsed["source"], parsed["message"]), tags=(parsed["level"],))
                display_count += 1
                
            limit_str = f" (Display truncated tracking top 5k dynamically)" if display_count > limit else ""
            self.lbl_count.config(text=f"Showing: {display_count} logs{limit_str}")

    def export_csv(self):
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        if active_tab_id >= len(tab_names): return
        
        current_tab_name = tab_names[active_tab_id]
        tree = self.tabs[current_tab_name]
        
        children = tree.get_children()
        if not children:
            messagebox.showinfo("Export", "No logs present inside this tab currently to map and export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"SOC_Export_{current_tab_name.replace(' ', '_')}.csv", title="Export Log Metadata")
        if not file_path: return
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                headers = [tree.heading(col)["text"] for col in tree["columns"]]
                writer.writerow(headers)
                
                for item in children:
                    row_data = tree.item(item)["values"]
                    writer.writerow(row_data)
            self.status_var.set(f"Status: Safe output extraction succeeded targeting '{file_path}'.")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


if __name__ == "__main__":
    app_root = tk.Tk()
    app = GUIController(app_root)
    app_root.mainloop()
