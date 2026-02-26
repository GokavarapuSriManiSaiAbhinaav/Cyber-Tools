import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import subprocess
import ipaddress
import queue
from concurrent.futures import ThreadPoolExecutor

class ScannerLogic:
    """
    Handles the scanning logic including pinging hosts and scanning ports.
    Communicates results back to the GUI using a thread-safe Queue.
    """
    def __init__(self, start_ip, end_ip, ports, update_queue):
        self.start_ip = start_ip
        self.end_ip = end_ip
        self.ports = ports
        self.update_queue = update_queue
        self.is_scanning = False
        self.executor = None

    def get_ip_list(self):
        """Generates a list of IPs from start_ip to end_ip."""
        try:
            start = ipaddress.IPv4Address(self.start_ip)
            end = ipaddress.IPv4Address(self.end_ip)
            if int(start) > int(end):
                return []
            return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
        except Exception as e:
            return []

    def ping_host(self, ip):
        """Pings a host to check if it's alive."""
        cmd = ['ping', '-n', '1', '-w', '500', ip]
        creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
        try:
            output = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                creationflags=creationflags
            )
            return output.returncode == 0
        except Exception:
            return False

    def scan_ports(self, ip):
        """Scans specified ports for a given IP."""
        open_ports = []
        for port in self.ports:
            if not self.is_scanning:
                break
            try:
                # Use TCP connection to check if port is open
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.5)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        return open_ports

    def get_hostname(self, ip):
        """Attempts to resolve the hostname of an IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def scan_ip(self, ip):
        """Main method to scan a single IP."""
        if not self.is_scanning:
            return None
        
        # 1. Check if alive via ping
        is_alive = self.ping_host(ip)
        
        # 2. Get hostname (only if alive, to save time)
        hostname = self.get_hostname(ip) if is_alive else "N/A"
        
        # 3. Check ports (only if alive)
        open_ports = self.scan_ports(ip) if is_alive else []
        
        result = {
            'ip': ip,
            'hostname': hostname,
            'is_alive': is_alive,
            'open_ports': open_ports
        }
        
        self.update_queue.put(('RESULT', result))
        return result

    def start_scan(self):
        """Starts the multi-threaded scanning process."""
        self.is_scanning = True
        ips = self.get_ip_list()
        
        if not ips:
            self.update_queue.put(('ERROR', "Invalid IP range or Start IP is greater than End IP."))
            return

        self.update_queue.put(('START', len(ips)))
        
        # Use ThreadPoolExecutor for concurrent scanning to make it fast
        self.executor = ThreadPoolExecutor(max_workers=50)
        
        def run_all():
            list(self.executor.map(self.scan_ip, ips))
            self.is_scanning = False
            self.update_queue.put(('DONE', None))

        # Start a daemon thread to wait for all scans to complete
        threading.Thread(target=run_all, daemon=True).start()

    def stop_scan(self):
        """Stops the ongoing scan."""
        self.is_scanning = False
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)


class IPScannerApp:
    """
    The main GUI class for the IP and Port Scanner application.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("IP and Port Scanner")
        self.root.geometry("850x600")
        self.root.minsize(700, 500)
        
        self.scanner = None
        self.update_queue = queue.Queue()
        
        self.live_hosts_count = 0
        self.total_hosts = 0
        self.scanned_hosts = 0
        
        self.setup_ui()
        self.check_queue()

    def setup_ui(self):
        """Initialize and layout all GUI components."""
        # --- Top Frame: Inputs ---
        top_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding=10)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Start IP input
        ttk.Label(top_frame, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.start_ip_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(top_frame, textvariable=self.start_ip_var, width=15).grid(row=0, column=1, padx=5, pady=5)
        
        # End IP input
        ttk.Label(top_frame, text="End IP:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.end_ip_var = tk.StringVar(value="192.168.1.254")
        ttk.Entry(top_frame, textvariable=self.end_ip_var, width=15).grid(row=0, column=3, padx=5, pady=5)
        
        # Ports input
        ttk.Label(top_frame, text="Ports:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.ports_var = tk.StringVar(value="80,443")
        ttk.Entry(top_frame, textvariable=self.ports_var, width=15).grid(row=0, column=5, padx=5, pady=5)
        
        # Scan Button
        self.scan_btn = ttk.Button(top_frame, text="Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=6, padx=15, pady=5)
        
        # --- Middle Frame: Results Table ---
        mid_frame = ttk.Frame(self.root, padding=10)
        mid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Treeview setup
        columns = ("ip", "hostname", "status", "ports")
        self.tree = ttk.Treeview(mid_frame, columns=columns, show="headings")
        
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("status", text="Status (Live/Dead)")
        self.tree.heading("ports", text="Open Ports")
        
        self.tree.column("ip", width=120, anchor=tk.CENTER)
        self.tree.column("hostname", width=200, anchor=tk.W)
        self.tree.column("status", width=100, anchor=tk.CENTER)
        self.tree.column("ports", width=300, anchor=tk.W)
        
        # Setup background color rules for Live and Dead hosts
        self.tree.tag_configure("live", background="#d4edda") # Light green
        self.tree.tag_configure("dead", background="#f8d7da") # Light red
        
        # Scrollbars
        y_scrollbar = ttk.Scrollbar(mid_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=y_scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # --- Bottom Frame: Status & Progress ---
        bottom_frame = ttk.Frame(self.root, padding=10)
        bottom_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        # Status Label
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bottom_frame, textvariable=self.status_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(bottom_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        
        # Total Live Hosts Label
        self.live_count_var = tk.StringVar(value="Live Hosts: 0")
        ttk.Label(bottom_frame, textvariable=self.live_count_var, font=("", 10, "bold")).pack(side=tk.RIGHT, padx=5)

    def parse_ports(self, port_string):
        """Parses a port string (e.g. '80, 443, 8000-8010') into a list of integers."""
        ports = []
        if not port_string:
            return ports
            
        for part in port_string.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def start_scan(self):
        """Initiates the scanning process and updates GUI state."""
        start_ip = self.start_ip_var.get().strip()
        end_ip = self.end_ip_var.get().strip()
        ports_str = self.ports_var.get().strip()
        
        # Validation checks for IP addresses
        try:
            ipaddress.IPv4Address(start_ip)
            ipaddress.IPv4Address(end_ip)
        except ipaddress.AddressValueError:
            messagebox.showerror("Error", "Please enter valid IPv4 addresses for Start and End IP.")
            return

        # Validation check for ports
        try:
            ports = self.parse_ports(ports_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid ports format. Use comma separated values or ranges (e.g. '80, 443, 100-200').")
            return
            
        # Clear previous results from Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Reset tracking variables
        self.live_hosts_count = 0
        self.scanned_hosts = 0
        self.total_hosts = 0
        
        self.live_count_var.set("Live Hosts: 0")
        self.progress_var.set(0)
        
        # Disable the scan button during the scan process
        self.scan_btn.config(text="Scanning...", state=tk.DISABLED)
        
        # Initialize and start scanner logic independently from GUI logic
        self.scanner = ScannerLogic(start_ip, end_ip, ports, self.update_queue)
        self.scanner.start_scan()

    def check_queue(self):
        """Periodically checks the thread-safe queue for UI updates from the backend scanner."""
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == 'START':
                    self.total_hosts = data
                    self.status_var.set(f"Scanning 0/{self.total_hosts} hosts...")
                    
                elif msg_type == 'RESULT':
                    self.scanned_hosts += 1
                    status_text = "Live" if data['is_alive'] else "Dead"
                    ports_text = ", ".join(map(str, data['open_ports'])) if data['open_ports'] else ""
                    tag = "live" if data['is_alive'] else "dead"
                    
                    # Insert result into treeview with appropriate color tag
                    self.tree.insert("", tk.END, values=(
                        data['ip'],
                        data['hostname'],
                        status_text,
                        ports_text
                    ), tags=(tag,))
                    
                    # Scroll to bottom
                    self.tree.yview_moveto(1)
                    
                    # Update live host count
                    if data['is_alive']:
                        self.live_hosts_count += 1
                        self.live_count_var.set(f"Live Hosts: {self.live_hosts_count}")
                        
                    # Update progress and status bar
                    if self.total_hosts > 0:
                        progress = (self.scanned_hosts / self.total_hosts) * 100
                        self.progress_var.set(progress)
                        self.status_var.set(f"Scanning {self.scanned_hosts}/{self.total_hosts} hosts...")
                    
                elif msg_type == 'DONE':
                    # Enable the properties and show completion message when scanning finishes
                    self.scan_btn.config(text="Scan", state=tk.NORMAL)
                    self.status_var.set("Scan complete.")
                    self.progress_var.set(100)
                    messagebox.showinfo("Scan Complete", f"Scanning process finished.\nTotal Live Hosts Found: {self.live_hosts_count}")
                    
                elif msg_type == 'ERROR':
                    self.scan_btn.config(text="Scan", state=tk.NORMAL)
                    self.status_var.set("Error occurred.")
                    messagebox.showerror("Error", data)
                    
        except queue.Empty:
            pass
            
        # Schedule the next queue check (running on the main loop periodically)
        self.root.after(100, self.check_queue)


if __name__ == "__main__":
    root = tk.Tk()
    app = IPScannerApp(root)
    root.mainloop()
