import tkinter as tk
from tkinter import scrolledtext, messagebox, font
import hashlib
import threading
import time
import queue
import itertools
import string

class MD5Logic:
    """Class to handle all hashing, wordlists, brute force, and rainbow table operations."""
    def __init__(self):
        # Small predefined wordlist (Dictionary attack)
        self.wordlist = [
            "password", "123456", "12345678", "qwerty", "admin", 
            "welcome", "letmein", "123123", "password123", "football",
            "iloveyou", "dragon", "sunshine", "monkey", "qwertyuiop",
            "abc", "test", "hello"
        ]
        # Pre-generate rainbow table structure (Hash Dictionary)
        self.rainbow_table = self._generate_rainbow_table()

    def _generate_rainbow_table(self):
        """Converts the wordlist into a dictionary mapping: MD5_Hash -> Plaintext."""
        table = {}
        for word in self.wordlist:
            md5_hash = hashlib.md5(word.encode()).hexdigest()
            table[md5_hash] = word
        return table

    def check_wordlist(self, target_hash):
        """Iterates through the wordlist sequentially (Dictionary Attack)."""
        for word in self.wordlist:
            word_hash = hashlib.md5(word.encode()).hexdigest()
            if word_hash.lower() == target_hash.lower():
                return word
        return None

    def brute_force_attack(self, target_hash, max_length=5, update_queue=None):
        """
        True Brute Force Attack:
        Mathematically generates every possible sequential character permutation.
        Tests up to `max_length` using lowercase letters and digits.
        """
        char_set = string.ascii_lowercase + string.digits
        
        for length in range(1, max_length + 1):
            if update_queue:
                update_queue.put(('LOG', f"[*] Sweeping all permutations of length {length}..."))
            
            # itertools.product generates all possible character permutations
            for guess in itertools.product(char_set, repeat=length):
                word = "".join(guess)
                word_hash = hashlib.md5(word.encode()).hexdigest()
                
                if word_hash == target_hash.lower():
                    return word
        return None

    def lookup_rainbow_table(self, target_hash):
        """Looks up the hash in O(1) time using dictionary traversal (Rainbow Table)."""
        return self.rainbow_table.get(target_hash.lower())


class MD5App:
    def __init__(self, root):
        self.root = root
        self.root.title("MD5 Decrypter Ultra")
        self.root.geometry("750x650")
        
        # Premium Dark Theme Colors
        self.bg_color = "#0f172a"          # Slate 900
        self.card_color = "#1e293b"        # Slate 800
        self.text_color = "#f8fafc"        # Slate 50
        self.accent_color = "#38bdf8"      # Light Blue 400
        self.success_color = "#4ade80"     # Green 400
        self.danger_color = "#ef4444"      # Red 500
        self.input_bg = "#0f172a"          # Slate 900
        self.outline_color = "#334155"     # Slate 700

        self.root.configure(bg=self.bg_color)
        
        # Initialize Backend Logic & Thread-safe message Queue
        self.logic = MD5Logic()
        self.update_queue = queue.Queue()
        
        self.setup_ui()
        self.check_queue()

    def setup_ui(self):
        """Setup all Tkinter GUI Frames and Widgets."""
        # Custom Fonts
        title_font = font.Font(family="Helvetica", size=22, weight="bold")
        label_font = font.Font(family="Helvetica", size=11, weight="bold")
        input_font = font.Font(family="Consolas", size=13)
        btn_font = font.Font(family="Helvetica", size=11, weight="bold")
        
        # 1. Header Frame
        header_frame = tk.Frame(self.root, bg=self.bg_color)
        header_frame.pack(fill=tk.X, pady=(20, 10))
        
        tk.Label(
            header_frame, 
            text="🔒 MD5 Decrypter Ultra", 
            font=title_font, 
            bg=self.bg_color, 
            fg=self.accent_color
        ).pack()
        
        tk.Label(
            header_frame, 
            text="Advanced Hash Cracking utility via Brute Force & Dictionary analysis.", 
            font=("Helvetica", 10), 
            bg=self.bg_color, 
            fg="#94a3b8"
        ).pack(pady=(5, 0))

        # 2. Main Card Frame (Input Area)
        card_frame = tk.Frame(self.root, bg=self.card_color, highlightbackground=self.outline_color, highlightthickness=1)
        card_frame.pack(fill=tk.X, padx=30, pady=15)
        
        # Padding inside the card
        inner_frame = tk.Frame(card_frame, bg=self.card_color)
        inner_frame.pack(padx=20, pady=20, fill=tk.X)

        tk.Label(
            inner_frame, 
            text="TARGET MD5 HASH:", 
            bg=self.card_color, 
            fg=self.accent_color, 
            font=label_font
        ).pack(anchor="w", pady=(0, 5))
        
        self.md5_hash_var = tk.StringVar()
        self.md5_entry = tk.Entry(
            inner_frame, 
            textvariable=self.md5_hash_var, 
            bg=self.input_bg, 
            fg=self.accent_color, 
            insertbackground=self.accent_color, 
            font=input_font,
            bd=1,
            relief=tk.SOLID,
            highlightbackground=self.outline_color,
            highlightcolor=self.accent_color,
            highlightthickness=1
        )
        self.md5_entry.pack(fill=tk.X, ipady=8)

        # 3. Operations Buttons Layout
        btn_frame = tk.Frame(inner_frame, bg=self.card_color)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        
        # We will use grid for symmetrical buttons
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        self.btn_dict = tk.Button(
            btn_frame, text="📖 Dictionary Attack", command=self.start_check_wordlist, 
            bg="#475569", fg=self.text_color, activebackground="#334155", activeforeground=self.text_color, 
            relief=tk.FLAT, font=btn_font, cursor="hand2"
        )
        self.btn_dict.grid(row=0, column=0, padx=(0, 5), sticky="ew", ipady=5)

        self.btn_brute = tk.Button(
            btn_frame, text="💣 Brute Force Attack", command=self.start_brute_force, 
            bg=self.danger_color, fg=self.text_color, activebackground="#b91c1c", activeforeground=self.text_color, 
            relief=tk.FLAT, font=btn_font, cursor="hand2"
        )
        self.btn_brute.grid(row=0, column=1, padx=5, sticky="ew", ipady=5)

        self.btn_demo = tk.Button(
            btn_frame, text="⚡ Rainbow Lookup", command=self.start_demo_rainbow_table, 
            bg="#2563eb", fg=self.text_color, activebackground="#1d4ed8", activeforeground=self.text_color, 
            relief=tk.FLAT, font=btn_font, cursor="hand2"
        )
        self.btn_demo.grid(row=0, column=2, padx=(5, 0), sticky="ew", ipady=5)

        # 4. Multiline Output Console
        output_container = tk.Frame(self.root, bg=self.bg_color)
        output_container.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 20))

        tk.Label(
            output_container, text="TERMINAL OUTPUT", 
            bg=self.bg_color, fg="#94a3b8", font=("Helvetica", 9, "bold")
        ).pack(anchor="w", pady=(0, 5))
        
        self.output_txt = scrolledtext.ScrolledText(
            output_container, 
            bg="#020617",         # Deep Black/Blue
            fg=self.success_color, 
            insertbackground=self.text_color, 
            font=("Consolas", 11),
            bd=0,
            padx=10,
            pady=10
        )
        self.output_txt.pack(fill=tk.BOTH, expand=True)

        # 5. Status Footer
        status_frame = tk.Frame(self.root, bg="#1e293b", height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value="SYSTEM STATUS: IDLE")
        self.status_label = tk.Label(
            status_frame, 
            textvariable=self.status_var, 
            bg="#1e293b", 
            fg=self.accent_color, 
            font=("Consolas", 9, "bold")
        )
        self.status_label.pack(side=tk.LEFT, padx=30, pady=5)

    def log(self, message):
        """Helper to append text securely to the Output Text Area."""
        self.output_txt.insert(tk.END, message + "\n")
        self.output_txt.see(tk.END)

    def set_buttons_state(self, state):
        """Enables or disables operations depending on processing."""
        self.btn_dict.config(state=state)
        self.btn_brute.config(state=state)
        self.btn_demo.config(state=state)

    def start_check_wordlist(self):
        """Starts dictionary attack thread."""
        target_hash = self.md5_hash_var.get().strip()
        if not target_hash:
            messagebox.showwarning("Input Error", "Please provide a target MD5 hash first.")
            return

        self.set_buttons_state(tk.DISABLED)
        self.status_var.set("SYSTEM STATUS: RUNNING DICTIONARY ATTACK...")
        self.log(f"\n[+] Initialization: Dictionary Attack Module")
        self.log(f"[*] Target Hash: {target_hash}")
        
        threading.Thread(target=self._thread_check_wordlist, args=(target_hash,), daemon=True).start()

    def _thread_check_wordlist(self, target_hash):
        time.sleep(1.0) # Simulated lag
        result = self.logic.check_wordlist(target_hash)
        self.update_queue.put(('DICT', result))

    def start_brute_force(self):
        """Starts true brute force thread."""
        target_hash = self.md5_hash_var.get().strip()
        if not target_hash:
            messagebox.showwarning("Input Error", "Please provide a target MD5 hash to crack.")
            return
            
        self.set_buttons_state(tk.DISABLED)
        self.status_var.set("SYSTEM STATUS: RUNNING BRUTE FORCE ALGORITHMS...")
        
        self.log(f"\n[+] Initialization: Brute Force Engine")
        self.log(f"[*] Target Hash: {target_hash}")
        self.log(f"[*] Calculating character space limits (a-z, 0-9)...")
        self.log(f"[*] Max Depth: 5 characters")
        
        threading.Thread(target=self._thread_brute_force, args=(target_hash,), daemon=True).start()

    def _thread_brute_force(self, target_hash):
        start_time = time.time()
        # Generates combinations and computes md5 until solved or hits length boundary
        result = self.logic.brute_force_attack(target_hash, max_length=5, update_queue=self.update_queue)
        end_time = time.time()
        
        duration = end_time - start_time
        self.update_queue.put(('BRUTE', (result, duration)))

    def start_demo_rainbow_table(self):
        """Starts rainbow table demo comparison."""
        target_hash = self.md5_hash_var.get().strip()
        if not target_hash:
            messagebox.showwarning("Input Error", "Please provide a target MD5 hash for demo.")
            return

        self.set_buttons_state(tk.DISABLED)
        self.status_var.set("SYSTEM STATUS: RUNNING RAINBOW TABLE MATRIX...")
        self.log(f"\n[+] Initialization: Rainbow Lookup Matrix")
        self.log(f"[*] Target Hash: {target_hash}")
        
        threading.Thread(target=self._thread_demo_rainbow_table, args=(target_hash,), daemon=True).start()

    def _thread_demo_rainbow_table(self, target_hash):
        # 1. Simulate Brute Force Loop Wait Time
        start_bf = time.time()
        time.sleep(1.2) 
        bf_result = self.logic.check_wordlist(target_hash)
        end_bf = time.time()
        time_bf = end_bf - start_bf

        # 2. Instant Rainbow Table Dictionary Lookup
        start_rt = time.time()
        rt_result = self.logic.lookup_rainbow_table(target_hash)
        end_rt = time.time()
        time_rt = end_rt - start_rt

        self.update_queue.put(('DEMO', (bf_result, rt_result, time_bf, time_rt)))

    def check_queue(self):
        """Continuously monitors thread queue for responses to update the GUI."""
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                # General Purpose Logs
                if msg_type == 'LOG':
                    self.log(data)

                # Dictionary Attack Response
                elif msg_type == 'DICT':
                    if data:
                        self.log(f"[✓] SUCCESS! Password Cracked: '{data}'")
                    else:
                        self.log("[-] Sequence not found in wordlist.")
                    self.set_buttons_state(tk.NORMAL)
                    self.status_var.set("SYSTEM STATUS: IDLE")
                    
                # Brute Force Attack Response
                elif msg_type == 'BRUTE':
                    result, duration = data
                    self.log(f"[*] Brute-Force Execution Time: {duration:.4f} seconds.")
                    if result:
                        self.log(f"[✓] SUCCESS! PASSWORD CRACKED: '{result}'")
                    else:
                        self.log("[-] Exhausted all combinations up to 5 chars length. No match found.")
                    self.set_buttons_state(tk.NORMAL)
                    self.status_var.set("SYSTEM STATUS: IDLE")

                # Rainbow Table Response
                elif msg_type == 'DEMO':
                    bf_res, rt_res, t_bf, t_rt = data
                    self.log(f"[*] Dictionary Attack Time (Simulated): {t_bf:.4f} seconds")
                    self.log(f"[*] Rainbow Matrix Lookup Time: {t_rt:.6f} seconds")
                    
                    if rt_res:
                        self.log(f"[✓] SUCCESS! Match Found via Lookup: '{rt_res}'")
                    else:
                        self.log("[-] Hash Match Not Found in structured matrix.")
                    
                    self.set_buttons_state(tk.NORMAL)
                    self.status_var.set("SYSTEM STATUS: IDLE")

        except queue.Empty:
            pass
            
        # Recursive loop interval check
        self.root.after(100, self.check_queue)


if __name__ == "__main__":
    app_root = tk.Tk()
    app = MD5App(app_root)
    app_root.mainloop()
