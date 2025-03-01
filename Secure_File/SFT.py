import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext
import socket
import threading
import os
import struct
import time
import hashlib
import mysql.connector
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =======================
# Database Configuration
# =======================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "file_transfer_db"
}

def setup_database():
    """Ensure that the database and user table exist."""
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        cursor = conn.cursor()
        cursor.execute("CREATE DATABASE IF NOT EXISTS file_transfer_db")
        conn.database = DB_CONFIG["database"]
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(255) NOT NULL
            )
        """)
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals() and conn.is_connected():
            conn.close()

setup_database()

# =======================
# Authentication Helpers
# =======================
def hash_password(password, salt=None):
    """Hash the password with an optional salt (creates one if not provided)."""
    if salt is None:
        salt = os.urandom(16).hex()
    salted_password = salt.encode() + password.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt

def register_user(username, password):
    """Register a new user in the database."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        hashed_password, salt = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
            (username, hashed_password, salt)
        )
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

def authenticate_user(username, password):
    """Authenticate a user by comparing with stored hash."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()
    if result:
        stored_hash, salt = result
        attempted_hash, _ = hash_password(password, salt)
        return stored_hash == attempted_hash
    return False

# =======================
# Cryptography Helpers
# =======================
def derive_key(password):
    """Derive a symmetric key from the password using PBKDF2."""
    salt = b'sal_t'  
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def pad_data(data):
    """Pad the data to match AES block size."""
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(data):
    """Remove padding from the data."""
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def decrypt_data(key, data):
    """Decrypt AES-CBC encrypted data."""
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return unpad_data(decrypted)

# =======================
# Helper: Center a Tk window on screen
# =======================
def center_window(root, width, height):
    """Center the Tkinter window on the screen and ensure correct size."""
    root.geometry(f"{width}x{height}") 
    root.update_idletasks() 
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    root.geometry(f"{width}x{height}+{x}+{y}")  
    root.update()  # Force update

# =======================
# Authentication Window
# =======================
class AuthWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Login or Register")
        self.resizable(False, False)
        center_window(self, 300, 200)
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(expand=True, fill="both")

        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky="e", pady=5)
        self.username_entry = ttk.Entry(frm)
        self.username_entry.grid(row=0, column=1, pady=5)

        ttk.Label(frm, text="Password:").grid(row=1, column=0, sticky="e", pady=5)
        self.password_entry = ttk.Entry(frm, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frm, text="Login", command=self.login).pack(side="left", padx=5)
        ttk.Button(btn_frm, text="Register", command=self.register).pack(side="left", padx=5)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if authenticate_user(username, password):
            self.destroy()
            app = FileTransferApp(password)
            app.run()
        else:
            messagebox.showerror("Error", "Invalid Credentials")

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if register_user(username, password):
            messagebox.showinfo("Success", "Registration Successful")
        else:
            messagebox.showerror("Error", "Username already exists or registration error.")

# =======================
# File Transfer Application
# =======================
class FileTransferApp(tk.Tk):
    def __init__(self, login_password):
        super().__init__()
        self.login_password = login_password
        self.running = False
        self.title("Secure File Transfer Tool")
        center_window(self, 600, 800)
        self.create_style()
        self.create_menu()
        self.create_widgets()
        self.create_status_bar()

    def create_style(self):
        """Configure a modern but neutral style for the application."""
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background="#f0f0f0", foreground="black", font=("Helvetica", 11))

        style.configure("TLabel", background="#f0f0f0", foreground="black", font=("Helvetica", 11))

        style.configure("TFrame", background="#f0f0f0")

        style.configure("TNotebook", background="#f0f0f0", tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background="#d9d9d9", foreground="black", padding=[5, 2])
        style.map("TNotebook.Tab", background=[("selected", "#ffffff")])

        style.configure("Horizontal.TProgressbar", troughcolor="#d9d9d9", background="#4caf50")

    def create_menu(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Clear Log", command=self.clear_log)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=filemenu)
        self.config(menu=menubar)

    def create_widgets(self):

        header = ttk.Label(self, text="Secure File Transfer Tool", anchor="center",
                           font=("Helvetica", 16, "bold"))
        header.pack(fill="x", pady=5, padx=5)

        self.notebook = ttk.Notebook(self)
        self.send_tab = ttk.Frame(self.notebook)
        self.recv_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.send_tab, text="Send File")
        self.notebook.add(self.recv_tab, text="Receive File")
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Build individual tabs
        self.build_send_tab()
        self.build_recv_tab()

        # Log Area
        log_frame = ttk.LabelFrame(self, text="Log", padding=5)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap="word", height=8, font=("Helvetica", 10))
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_status_bar(self):
        """Create a bottom status bar for persistent messages."""
        self.status_bar = ttk.Label(self, text="Ready", relief="sunken", anchor="w", font=("Helvetica", 10))
        self.status_bar.pack(side="bottom", fill="x")

    def set_status(self, message):
        """Update the bottom status bar."""
        self.status_bar.config(text=message)

    def build_send_tab(self):
        frm = ttk.Frame(self.send_tab, padding=10)
        frm.pack(fill="both", expand=True)

        # Local IP display
        ttk.Label(frm, text=f"Your IP: {self.get_ip()}").grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

        # Host and Port entries
        ttk.Label(frm, text="Host:").grid(row=1, column=0, sticky="e", pady=5)
        self.host_entry = ttk.Entry(frm)
        self.host_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(frm, text="Port:").grid(row=2, column=0, sticky="e", pady=5)
        self.port_entry_send = ttk.Entry(frm)
        self.port_entry_send.grid(row=2, column=1, sticky="ew", pady=5)

        # File selection
        ttk.Label(frm, text="File:").grid(row=3, column=0, sticky="e", pady=5)
        self.file_path_var = tk.StringVar(value="No file chosen")
        self.file_label = ttk.Label(frm, textvariable=self.file_path_var)
        self.file_label.grid(row=3, column=1, sticky="ew", pady=5)
        ttk.Button(frm, text="Choose File", command=self.choose_file).grid(row=4, column=1, sticky="e", pady=5)

        # Password/Key entry with toggle
        ttk.Label(frm, text="Password/Key:").grid(row=5, column=0, sticky="e", pady=5)
        pwd_frm = ttk.Frame(frm)
        pwd_frm.grid(row=5, column=1, sticky="ew", pady=5)
        self.password_entry_send = ttk.Entry(pwd_frm, show="*")
        self.password_entry_send.pack(side="left", fill="x", expand=True)
        self.password_entry_send.insert(0, self.login_password)
        self.toggle_btn_send = ttk.Button(
            pwd_frm, text="Show", width=6,
            command=lambda: self.toggle_password(self.password_entry_send, self.toggle_btn_send)
        )
        self.toggle_btn_send.pack(side="left", padx=5)

        # Execute Button, Progress, and Status
        self.send_btn = ttk.Button(frm, text="Send File", command=self.start_sending)
        self.send_btn.grid(row=6, column=0, columnspan=2, pady=10)

        self.progress_bar_send = ttk.Progressbar(frm, orient="horizontal", mode="determinate", length=300)
        self.progress_bar_send.grid(row=7, column=0, columnspan=2, pady=5)
        self.progress_label_send = ttk.Label(frm, text="Progress: 0%")
        self.progress_label_send.grid(row=8, column=0, columnspan=2, pady=5)
        self.status_label_send = ttk.Label(frm, text="")
        self.status_label_send.grid(row=9, column=0, columnspan=2, pady=5)

        frm.columnconfigure(1, weight=1)

    def build_recv_tab(self):
        frm = ttk.Frame(self.recv_tab, padding=10)
        frm.pack(fill="both", expand=True)

        # Local IP display
        ttk.Label(frm, text=f"Your IP: {self.get_ip()}").grid(row=0, column=0, columnspan=2, sticky="w", pady=5)

        # Port entry for receiving
        ttk.Label(frm, text="Port:").grid(row=1, column=0, sticky="e", pady=5)
        self.port_entry_recv = ttk.Entry(frm)
        self.port_entry_recv.grid(row=1, column=1, sticky="ew", pady=5)

        # Password/Key entry with toggle
        ttk.Label(frm, text="Password/Key:").grid(row=2, column=0, sticky="e", pady=5)
        pwd_frm = ttk.Frame(frm)
        pwd_frm.grid(row=2, column=1, sticky="ew", pady=5)
        self.password_entry_recv = ttk.Entry(pwd_frm, show="*")
        self.password_entry_recv.pack(side="left", fill="x", expand=True)
        self.password_entry_recv.insert(0, self.login_password)
        self.toggle_btn_recv = ttk.Button(
            pwd_frm, text="Show", width=6,
            command=lambda: self.toggle_password(self.password_entry_recv, self.toggle_btn_recv)
        )
        self.toggle_btn_recv.pack(side="left", padx=5)

        # Execute Button, Progress, and Status
        self.recv_btn = ttk.Button(frm, text="Start Listening", command=self.start_receiving)
        self.recv_btn.grid(row=3, column=0, columnspan=2, pady=10)

        self.progress_bar_recv = ttk.Progressbar(frm, orient="horizontal", mode="determinate", length=300)
        self.progress_bar_recv.grid(row=4, column=0, columnspan=2, pady=5)
        self.progress_label_recv = ttk.Label(frm, text="Progress: 0%")
        self.progress_label_recv.grid(row=5, column=0, columnspan=2, pady=5)
        self.status_label_recv = ttk.Label(frm, text="")
        self.status_label_recv.grid(row=6, column=0, columnspan=2, pady=5)

        frm.columnconfigure(1, weight=1)

    def get_ip(self):
        """Retrieve the local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()

    def toggle_password(self, entry_widget, btn_widget):
        """Toggle password visibility."""
        if entry_widget.cget("show") == "*":
            entry_widget.config(show="")
            btn_widget.config(text="Hide")
        else:
            entry_widget.config(show="*")
            btn_widget.config(text="Show")

    def choose_file(self):
        """Prompt the user to choose a file."""
        filename = filedialog.askopenfilename()
        self.file_path_var.set(filename if filename else "No file chosen")
        self.log(f"File chosen: {self.file_path_var.get()}")

    def log(self, message):
        """Append a timestamped message to the log area."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"{timestamp} - {message}\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        """Clear the log area."""
        self.log_text.delete("1.0", tk.END)

    # =======================
    # File Transfer Methods
    # =======================
    def start_sending(self):
        threading.Thread(target=self.send_file_gui, daemon=True).start()

    def send_file_gui(self):
        file_path = self.file_path_var.get()
        password = self.password_entry_send.get()
        host = self.host_entry.get().strip()

        # Basic validation
        if not file_path or file_path == "No file chosen":
            self.status_label_send.config(text="No file selected!")
            self.set_status("No file selected. Please choose a file first.")
            self.log("Attempted to send without selecting a file.")
            return

        try:
            port = int(self.port_entry_send.get().strip())
            if not (password and host and port):
                raise ValueError("Please fill in all fields!")
        except ValueError as e:
            self.status_label_send.config(text=str(e))
            self.set_status("Send failed: Invalid input.")
            self.log(f"Send error: {e}")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            self.status_label_send.config(text="Connecting...")
            self.set_status("Connecting...")
            self.log(f"Connecting to {host}:{port}")
            self.update_idletasks()
            sock.connect((host, port))

            self.status_label_send.config(text="Sending file...")
            self.set_status("Sending file...")
            self.log("Connected. Starting file transfer.")

            speed = self.send_file(sock, file_path, password)
            if speed:
                self.status_label_send.config(text=f"File sent at {speed:.2f} Mb/s")
                self.set_status("File sent successfully.")
                self.log(f"Transfer complete at {speed:.2f} Mb/s.")
            else:
                self.status_label_send.config(text="File transfer failed.")
                self.set_status("File transfer failed.")
                self.log("File transfer failed.")
        except Exception as e:
            self.status_label_send.config(text=f"Error: {e}")
            self.set_status("Error during send.")
            self.log(f"Error during send: {e}")
        finally:
            sock.close()
            # Reset the progress bar to 0
            self.progress_bar_send['value'] = 0
            self.progress_label_send.config(text="Progress: 0%")

    def send_file(self, sock, filename, password):
        start_time = time.time()
        key = derive_key(password)
        try:
            with open(filename, 'rb') as f:
                file_data = f.read()
            total_size = os.path.getsize(filename)

            padded_data = pad_data(file_data)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            fn_bytes = os.path.basename(filename).encode()
            sock.sendall(struct.pack('I', len(fn_bytes)) + fn_bytes)
            sock.sendall(struct.pack('Q', len(encrypted_data)))
            sock.sendall(iv)

            sent = 0
            chunk_size = 8192
            for i in range(0, len(encrypted_data), chunk_size):
                chunk = encrypted_data[i:i+chunk_size]
                sock.sendall(chunk)
                sent += len(chunk)
                progress = (sent / len(encrypted_data)) * 100
                self.progress_bar_send['value'] = progress
                self.progress_label_send.config(text=f"Progress: {int(progress)}%")
                self.update_idletasks()

            elapsed = time.time() - start_time
            return (total_size / elapsed) * 8 / (1024 * 1024) 
        except Exception as e:
            self.status_label_send.config(text=f"Send error: {e}")
            self.log(f"Send file error: {e}")
            return None

    def start_receiving(self):
        # Start listening in a separate thread
        threading.Thread(target=self.listen_for_connections, daemon=True).start()

    def listen_for_connections(self):
        try:
            port = int(self.port_entry_recv.get().strip())
            if not port:
                raise ValueError("Port is required!")
        except ValueError as e:
            self.status_label_recv.config(text=str(e))
            self.set_status("Receive failed: Invalid port.")
            self.log(f"Receive error: {e}")
            return

        self.running = True
        receiver_socket = None
        try:
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            receiver_socket.bind(('0.0.0.0', port))
            receiver_socket.listen(1)

            self.status_label_recv.config(text="Listening...")
            self.set_status("Listening for incoming connections...")
            self.log(f"Listening on port {port}.")

            while self.running:
                receiver_socket.settimeout(1)
                try:
                    client_sock, addr = receiver_socket.accept()
                except socket.timeout:
                    continue

                self.status_label_recv.config(text=f"Connected: {addr}")
                self.log(f"Connection established with {addr}")

                speed = self.receive_file(client_sock, derive_key(self.password_entry_recv.get()))
                client_sock.close()
                if speed:
                    self.status_label_recv.config(text=f"File received at {speed:.2f} Mb/s")
                    self.set_status("File received successfully.")
                    self.log(f"File received at {speed:.2f} Mb/s")
                else:
                    self.status_label_recv.config(text="File reception failed!")
                    self.set_status("Reception error.")
                    self.log("File reception failed.")

        except Exception as e:
            self.status_label_recv.config(text=f"Error: {e}")
            self.set_status("Error during receive.")
            self.log(f"Error during receiving: {e}")
        finally:
            if receiver_socket:
                receiver_socket.close()
            self.log("Receiver socket closed.")
            # Reset the progress bar to 0
            self.progress_bar_recv['value'] = 0
            self.progress_label_recv.config(text="Progress: 0%")

    def receive_file(self, client_sock, key):
        start_time = time.time()
        try:
            fn_len_data = client_sock.recv(4)
            if len(fn_len_data) < 4:
                raise ConnectionError("Connection lost before receiving filename length.")
            fn_len = struct.unpack('I', fn_len_data)[0]

            filename_data = client_sock.recv(fn_len)
            if len(filename_data) < fn_len:
                raise ConnectionError("Connection lost before receiving filename.")
            filename = filename_data.decode()

            total_size_data = client_sock.recv(8)
            if len(total_size_data) < 8:
                raise ConnectionError("Connection lost before receiving file size.")
            total_size = struct.unpack('Q', total_size_data)[0]

            iv = client_sock.recv(16)
            if len(iv) < 16:
                raise ConnectionError("Connection lost before receiving IV.")

            encrypted_data = b""
            received = 0
            while received < total_size:
                chunk = client_sock.recv(8192)
                if not chunk:
                    raise ConnectionError("Connection lost during transfer.")
                encrypted_data += chunk
                received += len(chunk)
                progress = (received / total_size) * 100
                self.progress_bar_recv['value'] = progress
                self.progress_label_recv.config(text=f"Progress: {int(progress)}%")
                self.update_idletasks()

            try:
                decrypted = decrypt_data(key, iv + encrypted_data)
                with open(filename, 'wb') as f:
                    f.write(decrypted)
                elapsed = time.time() - start_time
                return (total_size / elapsed) * 8 / (1024 * 1024)
            except Exception as de:
                self.status_label_recv.config(text="Decryption failed!")
                self.log(f"Decryption error: {de}")
                return None
        except Exception as e:
            self.status_label_recv.config(text=f"Receive error: {e}")
            self.log(f"Error in receive_file: {e}")
            return None

    def on_closing(self):
        self.running = False
        self.destroy()

    def run(self):
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.mainloop()

# =======================
# Main Execution
# =======================
if __name__ == "__main__":
    auth_app = AuthWindow()
    auth_app.mainloop()