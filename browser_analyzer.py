import os
import shutil
import sqlite3
import json
import threading
import time
import csv
import tempfile
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Temporary directory for copied DBs to bypass locks safely
TEMP_DIR = tempfile.gettempdir()

def copy_db_temp(db_path):
    """Copies a locked database to a temporary file to bypass locks safely."""
    try:
        if not os.path.exists(db_path):
            return None
        temp_path = os.path.join(TEMP_DIR, f"temp_{os.path.basename(db_path)}_{int(time.time()*1000)}")
        shutil.copy2(db_path, temp_path)
        return temp_path
    except Exception:
        return None

def chrome_time_to_datetime(webkit_timestamp):
    if not webkit_timestamp or webkit_timestamp == 0:
        return "-"
    try:
        epoch_start = datetime(1601, 1, 1)
        delta = timedelta(microseconds=int(webkit_timestamp))
        return (epoch_start + delta).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(webkit_timestamp)

def gecko_time_to_datetime(gecko_time):
    if not gecko_time or gecko_time == 0:
        return "-"
    try:
        return datetime.fromtimestamp(int(gecko_time)/1000000.0).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(gecko_time)

# ==========================================
# 2️⃣ BROWSER DETECTION & ARTIFACT EXTRACTION
# ==========================================

class ChromiumAnalyzer:
    def __init__(self, profile_path):
        self.profile_path = profile_path
        
    def get_history(self):
        history_path = os.path.join(self.profile_path, "History")
        temp_db = copy_db_temp(history_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 800")
            for row in cursor.fetchall():
                results.append({
                    "url": row[0],
                    "title": row[1] if row[1] else "No Title",
                    "visit_count": row[2],
                    "last_visit_time": chrome_time_to_datetime(row[3])
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_downloads(self):
        history_path = os.path.join(self.profile_path, "History")
        temp_db = copy_db_temp(history_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT target_path, start_time, total_bytes FROM downloads ORDER BY start_time DESC LIMIT 400")
            for row in cursor.fetchall():
                path = row[0]
                results.append({
                    "file_name": os.path.basename(path) if path else "Unknown",
                    "path": path,
                    "date": chrome_time_to_datetime(row[1]),
                    "size": f"{row[2] / (1024*1024):.2f} MB" if row[2] else "Unknown"
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_extensions(self):
        # Look in the parent dir of Default profile for 'Extensions' directory
        parent_dir = os.path.dirname(self.profile_path)
        extensions_path = os.path.join(parent_dir, "Extensions")
        if not os.path.exists(extensions_path):
            extensions_path = os.path.join(self.profile_path, "Extensions") # fallback
            
        results = []
        if not os.path.exists(extensions_path):
            return results
        
        try:
            for ext_id in os.listdir(extensions_path):
                ext_dir = os.path.join(extensions_path, ext_id)
                if os.path.isdir(ext_dir):
                    versions = os.listdir(ext_dir)
                    if versions:
                        version_dir = os.path.join(ext_dir, versions[-1])
                        manifest_path = os.path.join(version_dir, "manifest.json")
                        if os.path.exists(manifest_path):
                            with open(manifest_path, "r", encoding="utf-8") as f:
                                manifest = json.load(f)
                                name = manifest.get("name", ext_id)
                                if name.startswith("__MSG_"): name = f"Localized Extension ({ext_id})"
                                results.append({
                                    "name": name,
                                    "version": manifest.get("version", "Unknown"),
                                    "status": "Installed"
                                })
        except Exception:
            pass
        return results

    def get_cookies(self):
        cookies_path = os.path.join(self.profile_path, "Network", "Cookies")
        if not os.path.exists(cookies_path):
            cookies_path = os.path.join(self.profile_path, "Cookies")
            
        temp_db = copy_db_temp(cookies_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, creation_utc, expires_utc FROM cookies LIMIT 800")
            for row in cursor.fetchall():
                results.append({
                    "domain": row[0],
                    "creation_date": chrome_time_to_datetime(row[1]),
                    "expiry_date": chrome_time_to_datetime(row[2])
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_cache(self):
        cache_paths = [
            os.path.join(self.profile_path, "Cache", "Cache_Data"),
            os.path.join(self.profile_path, "Cache"),
            os.path.join(self.profile_path, "Code Cache")
        ]
        results = []
        total_size = 0
        for cp in cache_paths:
            if os.path.exists(cp):
                try:
                    for f in os.listdir(cp)[:300]:
                        full_path = os.path.join(cp, f)
                        if os.path.isfile(full_path):
                            size = os.path.getsize(full_path)
                            mtime = os.path.getmtime(full_path)
                            total_size += size
                            results.append({
                                "file_name": f,
                                "size": f"{size / 1024:.2f} KB",
                                "raw_size": size,
                                "modified": datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                            })
                except Exception:
                    pass
        return results, f"{total_size / (1024 * 1024):.2f} MB"


class GeckoAnalyzer:
    def __init__(self, profile_path):
        self.profile_path = profile_path

    def get_history(self):
        places_path = os.path.join(self.profile_path, "places.sqlite")
        temp_db = copy_db_temp(places_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.url, p.title, p.visit_count, h.visit_date 
                FROM moz_places p 
                JOIN moz_historyvisits h ON p.id = h.place_id 
                ORDER BY h.visit_date DESC LIMIT 800
            """)
            for row in cursor.fetchall():
                results.append({
                    "url": row[0],
                    "title": row[1] if row[1] else "No Title",
                    "visit_count": row[2],
                    "last_visit_time": gecko_time_to_datetime(row[3])
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_downloads(self):
        places_path = os.path.join(self.profile_path, "places.sqlite")
        temp_db = copy_db_temp(places_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT a.content, p.url, a.dateAdded 
                FROM moz_annos a 
                JOIN moz_places p ON a.place_id = p.id 
                WHERE a.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name = 'downloads/destinationFileURI')
                ORDER BY a.dateAdded DESC LIMIT 300
            """)
            for row in cursor.fetchall():
                path = row[0].replace('file:///', '').replace('%20', ' ')
                results.append({
                    "file_name": os.path.basename(path),
                    "path": path,
                    "date": gecko_time_to_datetime(row[2]),
                    "size": "Check File"
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_extensions(self):
        ext_json = os.path.join(self.profile_path, "extensions.json")
        results = []
        if os.path.exists(ext_json):
            try:
                with open(ext_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for ext in data.get("addons", []):
                        results.append({
                            "name": ext.get("defaultLocale", {}).get("name", ext.get("id")),
                            "version": ext.get("version", "Unknown"),
                            "status": "Enabled" if ext.get("active") else "Disabled"
                        })
            except Exception:
                pass
        return results

    def get_cookies(self):
        cookies_path = os.path.join(self.profile_path, "cookies.sqlite")
        temp_db = copy_db_temp(cookies_path)
        if not temp_db: return []
        
        results = []
        try:
            conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT host, creationTime, expiry FROM moz_cookies LIMIT 800")
            for row in cursor.fetchall():
                results.append({
                    "domain": row[0],
                    "creation_date": gecko_time_to_datetime(row[1]),
                    "expiry_date": datetime.fromtimestamp(row[2]).strftime('%Y-%m-%d %H:%M:%S') if row[2] else "-"
                })
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        return results

    def get_cache(self):
        cache_path = os.path.join(self.profile_path, "cache2", "entries")
        results = []
        total_size = 0
        if os.path.exists(cache_path):
            try:
                for f in os.listdir(cache_path)[:300]:
                    full_path = os.path.join(cache_path, f)
                    if os.path.isfile(full_path):
                        size = os.path.getsize(full_path)
                        mtime = os.path.getmtime(full_path)
                        total_size += size
                        results.append({
                            "file_name": f,
                            "size": f"{size / 1024:.2f} KB",
                            "raw_size": size,
                            "modified": datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })
            except Exception:
                pass
        return results, f"{total_size / (1024 * 1024):.2f} MB"

class BrowserDetector:
    def __init__(self):
        self.browsers_found = []

    def detect_browsers(self):
        self.browsers_found = []
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        roaming_appdata = os.environ.get("APPDATA", "")

        search_paths = [
            (local_appdata, "Google\\Chrome", "Chromium", "Google Chrome"),
            (local_appdata, "Microsoft\\Edge", "Chromium", "Microsoft Edge"),
            (local_appdata, "BraveSoftware\\Brave-Browser", "Chromium", "Brave"),
            (roaming_appdata, "Opera Software\\Opera Stable", "Chromium", "Opera"),
            (local_appdata, "Vivaldi", "Chromium", "Vivaldi"),
            (local_appdata, "Chromium", "Chromium", "Chromium"),
            (roaming_appdata, "Mozilla\\Firefox", "Gecko", "Mozilla Firefox"),
            (roaming_appdata, "Waterfox", "Gecko", "Waterfox")
        ]

        for base_dir, rel_path, b_type, name in search_paths:
            if not base_dir: continue
            
            if name == "Opera":
                full_path = os.path.join(base_dir, rel_path)
            else:
                full_path = os.path.join(base_dir, rel_path, "User Data", "Default") if b_type == "Chromium" else os.path.join(base_dir, rel_path, "Profiles")

            if b_type == "Gecko" and os.path.exists(full_path):
                # Target the default release profile folder
                for d in os.listdir(full_path):
                    if os.path.isdir(os.path.join(full_path, d)) and "default" in d:
                        self.browsers_found.append({"name": name, "type": b_type, "profile_path": os.path.join(full_path, d)})
                        break
            elif b_type == "Chromium" and os.path.exists(full_path):
                self.browsers_found.append({"name": name, "type": b_type, "profile_path": full_path})
                
        return self.browsers_found


# ==========================================
# 1️⃣ GUI DESIGN & CONTROLLER
# ==========================================

class GUIController:
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Browser Artifact & History Analyzer")
        self.root.geometry("1200x800")
        
        # Dark Cyber Theme Colors
        self.bg_color = "#0a0a0a"         # Deep Black
        self.panel_bg = "#111111"         # Slightly lighter for panels
        self.fg_color = "#e0e0e0"         # Light Gray Text
        self.cyan = "#00ffff"             # Neon Cyan (Active/Accents)
        self.red = "#ff2a2a"              # Suspicious Red
        self.blue = "#0088ff"             # Downloads Blue
        self.purple = "#b000ff"           # Extensions Purple
        self.orange = "#ff8800"           # Cache Orange
        self.dark_border = "#222222"
        
        self.root.configure(bg=self.bg_color)
        
        # State Arrays
        self.current_browser = None
        self.active_data = {} # Caches standard data mappings
        
        self.setup_styles()
        self.setup_ui()
        
        # Initialization
        self.detector = BrowserDetector()
        self.refresh_browsers()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Treeview styling
        style.configure("Treeview", background=self.panel_bg, foreground=self.fg_color, fieldbackground=self.panel_bg, rowheight=25, borderwidth=0)
        style.map('Treeview', background=[('selected', '#333333')], foreground=[('selected', self.cyan)])
        style.configure("Treeview.Heading", background="#1a1a1a", foreground=self.cyan, font=('Helvetica', 10, 'bold'), borderwidth=1, bordercolor=self.dark_border)

        # Notebook tabs
        style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        style.configure("TNotebook.Tab", background="#1a1a1a", foreground=self.fg_color, padding=[15, 5], font=('Helvetica', 10, 'bold'))
        style.map("TNotebook.Tab", background=[("selected", self.cyan)], foreground=[("selected", "#000000")])

    def setup_ui(self):
        # Top Header
        header_frame = tk.Frame(self.root, bg=self.bg_color, pady=10)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        
        tk.Label(header_frame, text="🌐 DIGITAL FORENSICS", font=("Courier", 12, "bold"), bg=self.bg_color, fg=self.cyan).pack()
        tk.Label(header_frame, text="UNIVERSAL BROWSER ARTIFACT ANALYZER", font=("Helvetica", 16, "bold"), bg=self.bg_color, fg="#ffffff").pack()
        
        # Layout splitting: Sidebar (Left) / Main Content (Right)
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.dark_border, bd=0)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # -- Sidebar (Browser List)
        self.sidebar_frame = tk.Frame(main_paned, bg=self.panel_bg, width=250)
        main_paned.add(self.sidebar_frame, minsize=200)
        
        tk.Label(self.sidebar_frame, text="DETECTED BROWSERS", bg="#1a1a1a", fg=self.cyan, font=("Helvetica", 11, "bold"), pady=10).pack(fill=tk.X)
        
        self.browser_listbox = tk.Listbox(self.sidebar_frame, bg=self.panel_bg, fg=self.fg_color, selectbackground=self.cyan, selectforeground="#000000", font=("Helvetica", 11), bd=0, highlightthickness=0)
        self.browser_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.browser_listbox.bind("<<ListboxSelect>>", self.on_browser_select)
        
        self.btn_rescan = tk.Button(self.sidebar_frame, text="🔄 Auto-Detect", command=self.refresh_browsers, bg="#1a1a1a", fg=self.fg_color, activebackground=self.cyan, relief=tk.FLAT, font=("Helvetica", 10, "bold"), pady=5)
        self.btn_rescan.pack(fill=tk.X, padx=5, pady=5)

        # -- Main Content Area
        self.content_frame = tk.Frame(main_paned, bg=self.bg_color)
        main_paned.add(self.content_frame, minsize=600)
        
        # Tools Bar (Search, Export, Scan)
        tools_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        tools_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(tools_frame, text="Search:", bg=self.bg_color, fg=self.fg_color, font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(tools_frame, textvariable=self.search_var, bg="#1a1a1a", fg=self.cyan, insertbackground=self.cyan, bd=1, relief=tk.SOLID, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=10)
        self.search_entry.bind("<KeyRelease>", self.apply_search_filter)

        self.btn_scan_active = tk.Button(tools_frame, text="▶ Extract Artifacts", command=self.scan_active_browser, bg=self.cyan, fg="#000000", activebackground="#00cccc", relief=tk.FLAT, font=("Helvetica", 10, "bold"))
        self.btn_scan_active.pack(side=tk.RIGHT, padx=5)

        self.btn_export = tk.Button(tools_frame, text="📥 Export CSV", command=self.export_csv, bg="#333333", fg=self.fg_color, activebackground="#555555", relief=tk.FLAT, font=("Helvetica", 10, "bold"))
        self.btn_export.pack(side=tk.RIGHT, padx=5)

        # Notebook Tabs
        self.notebook = ttk.Notebook(self.content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create Treeviews inside Tabs mapping logic securely mapped arrays implicitly
        self.tabs = {}
        tab_configs = {
            "History": [("url", "URL", 300), ("title", "Page Title", 250), ("visits", "Visits", 80), ("date", "Last Visit Time", 150)],
            "Downloads": [("file", "File Name", 250), ("path", "Download Path", 350), ("date", "Date", 150), ("size", "Size", 80)],
            "Extensions": [("name", "Extension Name", 300), ("version", "Version", 100), ("status", "Status", 100)],
            "Cache": [("file", "File Name", 250), ("size", "Size", 100), ("modified", "Last Modified", 150)],
            "Cookies": [("domain", "Domain (Metadata Only)", 250), ("creation", "Creation Date", 150), ("expiry", "Expiry Date", 150)],
        }
        
        for tab_name, columns in tab_configs.items():
            frame = tk.Frame(self.notebook, bg=self.bg_color)
            self.notebook.add(frame, text=f" {tab_name} ")
            
            tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings")
            for col_id, title, width in columns:
                tree.heading(col_id, text=title)
                tree.column(col_id, width=width, anchor=tk.W)
            
            # Setup Tags
            tree.tag_configure("suspicious", foreground=self.red)
            tree.tag_configure("downloads", foreground=self.blue)
            tree.tag_configure("extensions", foreground=self.purple)
            tree.tag_configure("cache", foreground=self.orange)
            
            y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscroll=y_scroll.set)
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.tabs[tab_name] = tree

        # Summary Tab
        self.summary_frame = tk.Frame(self.notebook, bg=self.panel_bg)
        self.notebook.add(self.summary_frame, text=" Summary Dashboard ")
        self.summary_labels = {}
        self.setup_summary_dashboard()

        # Footer Status Bar
        footer_frame = tk.Frame(self.root, bg="#000000", height=40)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        tk.Label(footer_frame, text="This tool performs logical browser artifact analysis for educational digital forensic purposes only.", bg="#000000", fg="#666666", font=("Helvetica", 8, "italic")).pack(pady=2, side=tk.TOP)
        
        self.status_var = tk.StringVar(value="Status: Ready.")
        tk.Label(footer_frame, textvariable=self.status_var, bg="#000000", fg=self.cyan, font=("Helvetica", 9, "bold")).pack(side=tk.LEFT, padx=10)
        
        self.progress_bar = ttk.Progressbar(footer_frame, maximum=100, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=20, pady=5)

    def setup_summary_dashboard(self):
        fields = [
            ("Total Browsers Found", "0"),
            ("Total URLs Visited", "0"),
            ("Most Visited Domain", "N/A"),
            ("Total Downloads", "0"),
            ("Total Extensions", "0"),
            ("Total Cache Size", "0 MB")
        ]
        
        title_font = ("Helvetica", 14, "bold")
        value_font = ("Helvetica", 12)
        
        tk.Label(self.summary_frame, text="ARTIFACT METRICS", bg=self.panel_bg, fg=self.cyan, font=("Helvetica", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=20, sticky="w", padx=20)
        
        for i, (label, default) in enumerate(fields):
            tk.Label(self.summary_frame, text=f"{label}:", bg=self.panel_bg, fg=self.fg_color, font=title_font).grid(row=i+1, column=0, sticky="e", padx=20, pady=10)
            
            val_var = tk.StringVar(value=default)
            self.summary_labels[label] = val_var
            
            tk.Label(self.summary_frame, textvariable=val_var, bg=self.panel_bg, fg="#ffffff", font=value_font).grid(row=i+1, column=1, sticky="w", pady=10)

    def refresh_browsers(self):
        self.status_var.set("Status: Detecting local browsers...")
        self.browser_listbox.delete(0, tk.END)
        detected = self.detector.detect_browsers()
        
        for b in detected:
            self.browser_listbox.insert(tk.END, f"{b['name']} ({b['type']})")
        
        self.summary_labels["Total Browsers Found"].set(str(len(detected)))
        self.status_var.set("Status: Browser detection complete.")

    def on_browser_select(self, event):
        selection = self.browser_listbox.curselection()
        if selection:
            idx = selection[0]
            self.current_browser = self.detector.browsers_found[idx]
            self.status_var.set(f"Selected: {self.current_browser['name']}")

    def apply_search_filter(self, event=None):
        query = self.search_var.get().lower()
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        
        if active_tab_id < len(tab_names):
            current_tab = tab_names[active_tab_id]
            tree = self.tabs[current_tab]
            
            for item in tree.get_children():
                tree.delete(item)
                
            if current_tab in self.active_data:
                for row_data, tags in self.active_data[current_tab]:
                    row_str = " ".join([str(x) for x in row_data]).lower()
                    if query in row_str:
                        tree.insert("", tk.END, values=row_data, tags=tags)

    def scan_active_browser(self):
        if not self.current_browser:
            messagebox.showwarning("Warning", "Select a browser from the list first.")
            return

        self.btn_scan_active.config(state=tk.DISABLED)
        self.status_var.set(f"Status: Extracting artifacts from {self.current_browser['name']}...")
        self.progress_bar.start(15)
        
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        analyzer = None
        if self.current_browser["type"] == "Chromium":
            analyzer = ChromiumAnalyzer(self.current_browser["profile_path"])
        else:
            analyzer = GeckoAnalyzer(self.current_browser["profile_path"])

        history = analyzer.get_history()
        downloads = analyzer.get_downloads()
        extensions = analyzer.get_extensions()
        cookies = analyzer.get_cookies()
        cache, cache_size = analyzer.get_cache()

        # Update via root.after securely mapping constraints
        self.root.after(0, self.update_gui_results, history, downloads, extensions, cookies, cache, cache_size)

    def update_gui_results(self, history, downloads, extensions, cookies, cache, cache_size):
        # Clear existing tree mappings securely tracking constraints
        for tree in self.tabs.values():
            for item in tree.get_children():
                tree.delete(item)
                
        self.active_data = {
            "History": [], "Downloads": [], "Extensions": [], "Cache": [], "Cookies": []
        }

        # DOMAINS Mapping to flag Suspicious activity patterns (Educational purposes)
        suspicious_keywords = ["darknet", "onion", "hack", "torrent", "exploit", "leak", "bypass"]

        # Populate History
        domains_count = {}
        for h in history:
            tags = ()
            for k in suspicious_keywords:
                if k in h['url'].lower():
                    tags = ("suspicious",)
                    break
            
            # Domain extraction calculation
            domain = h['url'].split('/')[2] if len(h['url'].split('/')) > 2 else "Unknown"
            domains_count[domain] = domains_count.get(domain, 0) + 1
            
            row = (h['url'], h['title'], h['visit_count'], h['last_visit_time'])
            self.tabs["History"].insert("", tk.END, values=row, tags=tags)
            self.active_data["History"].append((row, tags))

        # Populate Downloads
        for d in downloads:
            row = (d['file_name'], d['path'], d['date'], d['size'])
            self.tabs["Downloads"].insert("", tk.END, values=row, tags=("downloads",))
            self.active_data["Downloads"].append((row, ("downloads",)))

        # Populate Extensions
        for e in extensions:
            row = (e['name'], e['version'], e['status'])
            self.tabs["Extensions"].insert("", tk.END, values=row, tags=("extensions",))
            self.active_data["Extensions"].append((row, ("extensions",)))

        # Populate Cache
        for c in cache:
            row = (c['file_name'], c['size'], c['modified'])
            self.tabs["Cache"].insert("", tk.END, values=row, tags=("cache",))
            self.active_data["Cache"].append((row, ("cache",)))

        # Populate Cookies Metadata
        for c in cookies:
            row = (c['domain'], c['creation_date'], c['expiry_date'])
            self.tabs["Cookies"].insert("", tk.END, values=row, tags=())
            self.active_data["Cookies"].append((row, ()))

        # Update Dashboard Summary Strings
        most_visited = max(domains_count, key=domains_count.get) if domains_count else "N/A"
        self.summary_labels["Total URLs Visited"].set(str(len(history)))
        self.summary_labels["Most Visited Domain"].set(most_visited)
        self.summary_labels["Total Downloads"].set(str(len(downloads)))
        self.summary_labels["Total Extensions"].set(str(len(extensions)))
        self.summary_labels["Total Cache Size"].set(cache_size)

        self.progress_bar.stop()
        self.status_var.set("Status: Artifact extraction completed successfully.")
        self.btn_scan_active.config(state=tk.NORMAL)

    def export_csv(self):
        active_tab_id = self.notebook.index(self.notebook.select())
        tab_names = list(self.tabs.keys())
        if active_tab_id >= len(tab_names): return
        
        current_tab = tab_names[active_tab_id]
        data_to_export = self.active_data.get(current_tab, [])
        
        if not data_to_export:
            messagebox.showinfo("Export CSV", "No data to export on this tab.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"{current_tab}_Artifacts.csv", title="Export Data")
        if not file_path: return
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Write headers from tree columns implicitly mapped
                tree = self.tabs[current_tab]
                headers = [tree.heading(col)["text"] for col in tree["columns"]]
                writer.writerow(headers)
                
                for row_data, tags in data_to_export:
                    writer.writerow(row_data)
            self.status_var.set(f"Status: Successfully exported {current_tab} data to CSV.")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


if __name__ == "__main__":
    app_root = tk.Tk()
    app = GUIController(app_root)
    app_root.mainloop()
