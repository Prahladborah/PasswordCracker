#!/usr/bin/env python3
import os
import re
import zipfile
import rarfile
import py7zr
import logging
import itertools
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from threading import Thread, Lock, Event
from time import time, sleep
import sv_ttk
from pikepdf import Pdf
from collections import defaultdict

# Set the path to your UnRAR executable (adjust as needed)
rarfile.UNRAR_TOOL = r"E:\\UNRAR\\unrar.exe"

def expand_charset(charset):
    """
    Expand simple range expressions in the given charset.
    For example, "0-9" becomes "0123456789" and "a-z" becomes "abcdefghijklmnopqrstuvwxyz".
    """
    pattern = re.compile(r'([a-zA-Z0-9])\-([a-zA-Z0-9])')
    def repl(match):
        start = match.group(1)
        end = match.group(2)
        return ''.join(chr(c) for c in range(ord(start), ord(end)+1))
    return pattern.sub(repl, charset)

def generate_passwords(charset, max_length, thread_index=None, total_threads=1):
    """
    Generator that yields all possible combinations of the given character set,
    from length 1 up to max_length.
    When total_threads > 1 and length>=3, only yield candidates that belong
    to the partition for the given thread_index.
    """
    for length in range(1, max_length + 1):
        for pwd_tuple in itertools.product(charset, repeat=length):
            candidate = ''.join(pwd_tuple)
            if length >= 3 and total_threads > 1 and thread_index is not None:
                idx = charset.index(candidate[0])
                if idx % total_threads != thread_index:
                    continue
            yield candidate

def try_password(file_path, ext, password):
    """Try the given password on the file (based on its extension)."""
    if ext == '.zip':
        try:
            with zipfile.ZipFile(file_path, 'r') as zfile:
                zfile.extractall(pwd=password.encode('utf-8'))
            return True
        except Exception:
            return False
    elif ext == '.rar':
        try:
            with rarfile.RarFile(file_path) as rf:
                rf.setpassword(password)
                members = rf.infolist()
                if not members:
                    return False
                with rf.open(members[0]) as f:
                    f.read(1)
            return True
        except Exception:
            return False
    elif ext == '.7z':
        try:
            with py7zr.SevenZipFile(file_path, mode='r', password=password) as archive:
                archive.test()
            return True
        except Exception:
            return False
    elif ext == '.pdf':
        try:
            with Pdf.open(file_path, password=password):
                return True
        except Exception:
            return False
    return False

def crack_zip_password(zip_file, candidate_iter):
    logging.info("Starting password cracking for ZIP file...")
    try:
        with zipfile.ZipFile(zip_file, 'r') as zfile:
            for password in candidate_iter:
                try:
                    zfile.extractall(pwd=password.encode('utf-8'))
                    logging.info(f"Found ZIP password: {password}")
                    return password
                except Exception:
                    continue
    except Exception as e:
        logging.error(f"Error opening ZIP file: {e}")
    return None

def crack_rar_password(rar_file, candidate_iter):
    logging.info("Starting password cracking for RAR file...")
    for password in candidate_iter:
        try:
            with rarfile.RarFile(rar_file) as rf:
                rf.setpassword(password)
                try:
                    members = rf.infolist()
                    if not members:
                        raise Exception("Wrong password")
                    with rf.open(members[0]) as f:
                        f.read(1)
                except Exception:
                    continue
            logging.info(f"Found RAR password: {password}")
            return password
        except Exception:
            continue
    return None

def crack_7z_password(sevenz_file, candidate_iter):
    logging.info("Starting password cracking for 7-Zip file...")
    for password in candidate_iter:
        try:
            with py7zr.SevenZipFile(sevenz_file, mode='r', password=password) as archive:
                archive.test()
            logging.info(f"Found 7z password: {password}")
            return password
        except Exception:
            continue
    return None

def crack_pdf_password(pdf_file, candidate_iter):
    logging.info("Starting password cracking for PDF file...")
    for password in candidate_iter:
        try:
            with Pdf.open(pdf_file, password=password):
                logging.info(f"Found PDF password: {password}")
                return password
        except Exception:
            continue
    return None

def check_password_strength(password):
    """Evaluate password strength based on various criteria"""
    if not password:
        return 0, "Found Nothing"
    
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    strength = 0
    if length >= 8: strength += 1
    if length >= 12: strength += 1
    if length >= 16: strength += 2
    
    char_types = sum([has_lower, has_upper, has_digit, has_special])
    if char_types >= 3: strength += 2
    if char_types == 4: strength += 1
    
    if length < 4: strength = 0
    if password.isnumeric(): strength = min(strength, 2)
    
    strength = min(strength, 6)
    
    if strength <= 2: label = "Easy"
    elif strength <= 3: label = "Easy"
    elif strength <= 4: label = "It was moderate"
    elif strength <= 5: label = "It took a while"
    else: label = "Strong"
    
    return strength, label

def analyze_common_patterns(password):
    """Check for common weak patterns"""
    patterns = {
        'sequential': (r'(?:123|abc|qwe|asd|zxcv|password)', 3),
        'repeating': (r'(.)\1{3,}', 2),
        'year': (r'19\d{2}|20[01]\d', 2),
        'short': (r'^.{1,5}$', 4)
    }
    
    penalty = 0
    for name, (pattern, score) in patterns.items():
        if re.search(pattern, password, re.IGNORECASE):
            penalty += score
    return penalty

# --- Optimized brute force worker with periodic update of attempts ---
def brute_force_worker_partitioned(thread_index, total_threads, file_path, ext, full_charset, max_length,
                                   shared_found, shared_attempts, shared_current, stop_event, update_lock):
    """
    Each worker generates only candidates whose first character is in its partition.
    To update attempts in realtime, we update the shared_attempts counter every 100 tries.
    """
    local_attempts = 0
    update_interval = 100  # update shared counter every 100 attempts
    # Partition the charset: each thread gets characters where (index mod total_threads) equals thread_index.
    partition = [c for i, c in enumerate(full_charset) if i % total_threads == thread_index]
    
    for L in range(1, max_length+1):
        if stop_event.is_set():
            break
        if L == 1:
            for char in partition:
                if stop_event.is_set():
                    break
                candidate = char
                local_attempts += 1
                if local_attempts % update_interval == 0:
                    with update_lock:
                        shared_attempts[0] += update_interval
                shared_current[thread_index] = candidate
                if try_password(file_path, ext, candidate):
                    shared_found[0] = candidate
                    stop_event.set()
                    break
        else:
            for first in partition:
                if stop_event.is_set():
                    break
                for tail in itertools.product(full_charset, repeat=L-1):
                    if stop_event.is_set():
                        break
                    candidate = first + ''.join(tail)
                    local_attempts += 1
                    if local_attempts % update_interval == 0:
                        with update_lock:
                            shared_attempts[0] += update_interval
                    shared_current[thread_index] = candidate
                    if try_password(file_path, ext, candidate):
                        shared_found[0] = candidate
                        stop_event.set()
                        break
                if stop_event.is_set():
                    break
    # Add any remaining attempts not yet added
    remainder = local_attempts % update_interval
    if remainder:
        with update_lock:
            shared_attempts[0] += remainder

class PasswordCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BruteForge Password Cracker")
        self.geometry("1200x800")
        self.minsize(800, 600)
        # Launch maximized
        self.state('zoomed')
        
        # Setup dark theme and custom styles
        sv_ttk.set_theme("dark")
        self.current_theme = "dark"
        self.setup_styles()
        
        # Main container split into top and bottom frames
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.top_frame = ttk.Frame(self.main_frame)
        self.top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.bottom_frame = ttk.Frame(self.main_frame)
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        # Initialize variables
        self.file_path = tk.StringVar()
        self.attack_type = tk.StringVar(value="dict")
        self.max_length = tk.IntVar(value=4)
        self.batch_size = tk.IntVar(value=os.cpu_count() if os.cpu_count() is not None else 4)
        self.running = False
        self.start_time = None
        self.attempts = 0
        
        self.charset_options = [
            "a-z", "A-Z", "0-9",
            "a-z & A-Z", "a-z & 0-9", "A-Z & 0-9",
            "a-z & A-Z & 0-9 & special"
        ]
        self.charset_mapping = {
            "a-z": "abcdefghijklmnopqrstuvwxyz",
            "A-Z": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0-9": "0123456789",
            "a-z & A-Z": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "a-z & 0-9": "abcdefghijklmnopqrstuvwxyz0123456789",
            "A-Z & 0-9": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "a-z & A-Z & 0-9 & special": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+{}:\"<>?|[]\\;',./~"
        }
        self.difficulty_mapping = {
            "a-z": "Easy",
            "A-Z": "Easy",
            "0-9": "Easy",
            "a-z & A-Z": "Intermediate",
            "a-z & 0-9": "Hard",
            "A-Z & 0-9": "Hard",
            "a-z & A-Z & 0-9 & special": "Extreme"
        }
        
        self.sort_dict = tk.BooleanVar(value=False)
        self.thread_labels = []
        
        self.create_top_widgets()
        self.create_bottom_widgets()

    def setup_styles(self):
        style = ttk.Style()
        style.configure('TButton', padding=6, relief="flat", background="#444")
        style.map('TButton',
                  background=[('active', '#666'), ('disabled', '#333')],
                  foreground=[('active', 'white'), ('disabled', '#999')])
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        style.configure('Status.TLabel', background="#333", padding=5, foreground="white")
        style.configure('Thread.TLabel', font=('Helvetica', 10), foreground="cyan", background="#333")

    def create_top_widgets(self):
        # Top Frame: Settings
        
        # File Selection
        file_heading = ttk.Label(self.top_frame, text="File Selection", style='Header.TLabel')
        file_heading.pack(anchor="w", pady=(5,0))
        file_frame = ttk.Frame(self.top_frame)
        file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(file_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT, padx=5, pady=5)
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=60)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        # Attack Type Selection
        attack_frame = ttk.Frame(self.top_frame)
        attack_frame.pack(fill=tk.X, pady=5)
        ttk.Radiobutton(attack_frame, text="Dictionary Attack", variable=self.attack_type, 
                        value="dict", command=self.toggle_attack_type).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Radiobutton(attack_frame, text="Brute Force Attack", variable=self.attack_type, 
                        value="brute", command=self.toggle_attack_type).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Dictionary Options
        self.dict_frame = ttk.Frame(self.top_frame)
        self.dict_frame.pack(fill=tk.X, pady=5)
        ttk.Button(self.dict_frame, text="Select Dictionary", command=self.browse_dict).pack(side=tk.LEFT, padx=5, pady=5)
        self.dict_entry = ttk.Entry(self.dict_frame, width=60)
        self.dict_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        ttk.Button(self.dict_frame, text="Analyze", command=self.analyze_dictionary).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Checkbutton(self.dict_frame, text="Sort Strong First", variable=self.sort_dict).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Brute Force Options
        self.brute_frame = ttk.Frame(self.top_frame)
        self.brute_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.brute_frame, text="Character Set:").pack(side=tk.LEFT, padx=5, pady=5)
        self.charset_combo = ttk.Combobox(self.brute_frame, values=self.charset_options, state="readonly", width=30)
        self.charset_combo.current(0)
        self.charset_combo.pack(side=tk.LEFT, padx=5, pady=5)
        self.charset_combo.bind("<<ComboboxSelected>>", self.update_difficulty)
        self.difficulty_label = ttk.Label(self.brute_frame, text=f"Difficulty: {self.difficulty_mapping[self.charset_options[0]]}")
        self.difficulty_label.pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Label(self.brute_frame, text="Max Length:").pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Spinbox(self.brute_frame, from_=1, to=10, textvariable=self.max_length, width=5).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Label(self.brute_frame, text="Batch Size (Worker Threads):").pack(side=tk.LEFT, padx=5, pady=5)
        self.batch_spinbox = ttk.Spinbox(self.brute_frame, from_=1, to=100, textvariable=self.batch_size, width=5, command=self.check_batch_warning)
        self.batch_spinbox.pack(side=tk.LEFT, padx=5, pady=5)
        self.batch_warning_label = ttk.Label(self.brute_frame, text="", foreground="red")
        self.batch_warning_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Active Threads Section – only visible for brute force
        self.threads_frame = ttk.LabelFrame(self.top_frame, text="", style='Header.TLabel')
        self.threads_frame.pack(fill=tk.X, pady=5)
        self.thread_labels = []
        
        self.toggle_attack_type()

    def create_bottom_widgets(self):
        # Bottom Frame: Progress and Controls
        progress_frame = ttk.Frame(self.bottom_frame)
        progress_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        self.stats_text = ScrolledText(progress_frame, height=8, state='disabled')
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        control_frame = ttk.Frame(self.bottom_frame)
        control_frame.pack(fill=tk.X, pady=5)
        self.start_btn = ttk.Button(control_frame, text="Start", command=self.start_cracking, style='TButton')
        self.start_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.theme_btn = ttk.Button(control_frame, text="Light", command=self.toggle_theme, style='TButton')
        self.theme_btn.pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="About Us", command=self.show_about, style='TButton').pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Exit", command=self.destroy, style='TButton').pack(side=tk.RIGHT, padx=5, pady=5)

    def check_batch_warning(self):
        if self.batch_size.get() > 20:
            self.batch_warning_label.config(text="Warning: High batch size may cause system lag!")
        else:
            self.batch_warning_label.config(text="Keep this around 10-20 for optimal perfomance.")

    def update_difficulty(self, event):
        selected = self.charset_combo.get()
        difficulty = self.difficulty_mapping.get(selected, "Unknown")
        self.difficulty_label.config(text=f"Difficulty: {difficulty}")

    def toggle_attack_type(self):
        if self.attack_type.get() == "dict":
            self.dict_frame.pack(fill=tk.X, pady=5)
            self.brute_frame.pack_forget()
            self.threads_frame.pack_forget()
        else:
            self.dict_frame.pack_forget()
            self.brute_frame.pack(fill=tk.X, pady=5)
            self.threads_frame.pack(fill=tk.X, pady=5)

    def toggle_theme(self):
        if self.current_theme == "dark":
            sv_ttk.set_theme("light")
            self.current_theme = "light"
            self.theme_btn.config(text="Dark")
        else:
            sv_ttk.set_theme("dark")
            self.current_theme = "dark"
            self.theme_btn.config(text="Light")

    def browse_file(self):
        filetypes = [("Supported files", "*.zip;*.rar;*.7z;*.pdf"), ("All Files", "*.*")]
        filename = filedialog.askopenfilename(title="Select file to crack", filetypes=filetypes)
        if filename:
            self.file_path.set(filename)

    def browse_dict(self):
        filetypes = [("Text files", "*.txt"), ("All Files", "*.*")]
        filename = filedialog.askopenfilename(title="Select dictionary file", filetypes=filetypes)
        if filename:
            self.dict_entry.delete(0, tk.END)
            self.dict_entry.insert(0, filename)

    def analyze_dictionary(self):
        dict_path = self.dict_entry.get()
        if not dict_path:
            messagebox.showerror("Error", "No dictionary selected!")
            return
        try:
            with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read dictionary: {e}")
            return
        if not passwords:
            messagebox.showinfo("Info", "Dictionary is empty!")
            return

        strength_counts = defaultdict(int)
        length_buckets = defaultdict(int)
        pattern_counts = defaultdict(int)
        total = len(passwords)
        
        for pwd in passwords:
            strength, label = check_password_strength(pwd)
            strength_counts[label] += 1
            length_buckets[len(pwd)] += 1
            penalty = analyze_common_patterns(pwd)
            if penalty >= 3:
                pattern_counts['weak'] += 1
            elif penalty >= 1:
                pattern_counts['moderate'] += 1
            else:
                pattern_counts['strong'] += 1

        report = [
            "Dictionary Analysis Report:",
            f"Total Passwords: {total}",
            f"Average Length: {sum(l * n for l, n in length_buckets.items()) / total:.1f}",
            f"Most Common Lengths: {sorted(length_buckets.items(), key=lambda x: -x[1])[:3]}",
            "\nStrength Distribution:"
        ]
        
        for strength in ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]:
            if strength in strength_counts:
                count = strength_counts[strength]
                report.append(f"- {strength}: {count} ({count/total:.1%})")
        
        report.extend([
            "\nPattern Analysis:",
            f"- Weak Patterns: {pattern_counts['weak']} ({pattern_counts['weak']/total:.1%})",
            f"- Moderate Patterns: {pattern_counts['moderate']} ({pattern_counts['moderate']/total:.1%})",
            f"- Strong Patterns: {pattern_counts['strong']} ({pattern_counts['strong']/total:.1%})"
        ])
        
        analysis_win = tk.Toplevel(self)
        analysis_win.title("Advanced Dictionary Analysis")
        text = ScrolledText(analysis_win, wrap=tk.WORD, width=80, height=20)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, "\n".join(report))
        text.configure(state='disabled')

    def update_stats(self, attempts, elapsed_time):
        self.stats_text.configure(state='normal')
        self.stats_text.delete(1.0, tk.END)
        if self.attack_type.get() == "brute":
            found_password = ""
            if hasattr(self, "shared_found") and self.shared_found[0]:
                strength, label = check_password_strength(self.shared_found[0])
                found_password = f"{self.shared_found[0]} ({label})"
            stats = [
                f"Elapsed Time: {elapsed_time:.2f}s",
                f"Attempts: {attempts}",
                f"Found Password: {found_password}"
            ]
        else:
            stats = [
                f"Elapsed Time: {elapsed_time:.2f}s",
                f"Attempts: {attempts}"
            ]
        self.stats_text.insert(tk.END, "\n".join(stats))
        self.stats_text.configure(state='disabled')

    def update_thread_status(self, num_threads):
        for widget in self.threads_frame.winfo_children():
            widget.destroy()
        self.thread_labels = []
        cols = 10
        for i in range(num_threads):
            lbl = ttk.Label(self.threads_frame, text=f"Thread {i+1}: Idle", style='Thread.TLabel')
            row = (i // cols)
            col = i % cols
            lbl.grid(row=row, column=col, padx=5, pady=5, sticky="w")
            self.thread_labels.append(lbl)

    def monitor_progress(self):
        if self.running:
            if hasattr(self, "lock") and hasattr(self, "shared_current"):
                with self.lock:
                    self.attempts = self.shared_attempts[0]
                    for i, label in enumerate(self.thread_labels):
                        pwd = self.shared_current[i] if i < len(self.shared_current) else ""
                        display_pwd = (pwd[:15] + "...") if pwd and len(pwd) > 15 else (pwd if pwd else "Idle")
                        label.config(text=f"Thread {i+1}: {display_pwd}")
            elapsed_time = time() - self.start_time
            self.update_stats(self.attempts, elapsed_time)
            self.after(100, self.monitor_progress)

    def start_cracking(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file to crack!")
            return
        if self.attack_type.get() == "dict" and not self.dict_entry.get():
            messagebox.showerror("Error", "Please select a dictionary file!")
            return
        
        self.running = True
        self.start_btn.config(text="Stop", command=self.stop_cracking)
        self.progress_bar.start()
        self.start_time = time()
        Thread(target=self.run_cracking, daemon=True).start()
        self.monitor_progress()

    def stop_cracking(self):
        self.running = False
        if hasattr(self, "stop_event"):
            self.stop_event.set()
        self.progress_bar.stop()
        final_elapsed = time() - self.start_time
        self.update_stats(self.attempts, final_elapsed)
        self.start_btn.config(text="Start", command=self.start_cracking)

    def run_cracking(self):
        file_path = self.file_path.get()
        ext = os.path.splitext(file_path)[1].lower()
        crack_functions = {
            '.zip': crack_zip_password,
            '.rar': crack_rar_password,
            '.7z': crack_7z_password,
            '.pdf': crack_pdf_password
        }
        
        if self.attack_type.get() == "dict":
            try:
                with open(self.dict_entry.get(), 'r') as f:
                    candidates = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open dictionary: {e}")
                self.stop_cracking()
                return
            if self.sort_dict.get():
                candidates.sort(key=lambda p: check_password_strength(p)[0], reverse=True)
            candidate_iter = iter(candidates)
            password = crack_functions[ext](file_path, candidate_iter)
        else:
            selected_charset = self.charset_combo.get()
            raw_charset = self.charset_mapping.get(selected_charset, "abcdefghijklmnopqrstuvwxyz")
            max_len = self.max_length.get()
            num_threads = self.batch_size.get()
            
            if num_threads > 1:
                shared_found = [None]
                shared_attempts = [0]
                shared_current = ["" for _ in range(num_threads)]
                update_lock = Lock()
                stop_event = Event()
                self.stop_event = stop_event
                self.shared_found = shared_found
                self.shared_current = shared_current
                self.shared_attempts = shared_attempts
                self.lock = update_lock
                self.attempts = 0
                self.update_thread_status(num_threads)
                threads = []
                for i in range(num_threads):
                    t = Thread(target=brute_force_worker_partitioned, args=(
                        i, num_threads, file_path, ext, raw_charset, max_len,
                        shared_found, shared_attempts, shared_current, stop_event, update_lock
                    ))
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join()
                password = shared_found[0]
                self.attempts = shared_attempts[0]
            else:
                candidate_iter = generate_passwords(raw_charset, max_len)
                password = crack_functions[ext](file_path, candidate_iter)
        
        if password:
            strength, label = check_password_strength(password)
            msg = f"Password found: {password}\nStrength: {label}\nLength: {len(password)}"
            messagebox.showinfo("Success", msg)
        else:
            if self.attack_type.get() == "brute":
                messagebox.showinfo("Failure", "No possible password has been found after checking a large number of combinations.")
            else:
                messagebox.showinfo("Failure", "Password not found")
        self.stop_cracking()

    def show_about(self):
        about_win = tk.Toplevel(self)
        about_win.title("Help")
        about_win.geometry("800x600")
        
        about_message = (
            "PasswordCracker Tool\n"
            "Developed by Prahlad\n\n"
            "This application currently supports only ZIP, 7ZIP, RAR, and PDF files.\n\n"
            "Contact me at discord: prahlad9741\n\n"
            "Usage Tips:\n"
            "- To test common passwords, consider using a dictionary attack.\n"
            "- You will need a .txt file that contains a list of potential passwords\n"
            "- with each password listed on a separate line.\n\n"
            "- Use brute force with the appropriate character set for more complex cases.\n"
            "- Begin with simple attack combinations to increase the chances of obtaining the password.\n"
            "- The more complex you choose, the longer it will take to get the right combination.\n\n"
            "About Batch Size:\n"
            "- Specifies the number of combinations processed in parallel during brute force.\n"
            "- Choose a number between 1 and 100; higher numbers are more resource-intensive.\n"
            "- For low-end systems, keep within 1-20; mid-end: 20-50; high-end: 50-100.\n"
            "- Match the batch count with your processor cores for stability.\n\n"
            "- Always use this tool responsibly.\n"
            "- Don't blame me for any misuse.\n\n"
            "Coming soon: Additional file support and more brute-force attack patterns.\n"
            "A new feature, Intruder Injection, will bypass smartphone security (screen locks via USB) using brute force."
        )
        
        label = ttk.Label(about_win, text=about_message, justify="left")
        label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Button(about_win, text="Close", command=about_win.destroy).pack(pady=10)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    app = PasswordCrackerApp()
    app.mainloop()
