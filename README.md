Secure File Transfer Tool

Welcome to the Secure File Transfer Tool! This interactive guide will help you set up, use, and understand the security aspects of this application.

🚀 Features
✅ Secure User Authentication – MySQL-backed user registration and login with hashed passwords.
✅ AES Encryption – AES-CBC encryption with PBKDF2-HMAC-derived keys for secure file transfers.
✅ Reliable Network Communication – TCP sockets for stable and efficient file transfer.
✅ Intuitive GUI – Tkinter-based interface with progress indicators and real-time logging.
✅ Automatic IP Retrieval – Detects and displays the local IP address for easier configuration.
✅ Password Visibility Toggle – Allows users to toggle password visibility during login.
✅ Comprehensive Logging – Tracks file selections, connection status, and transfer speeds.

🛠️ Prerequisites
Before you begin, ensure you have the following installed:
Python 
MySQL Server
Required Python Libraries:
pip install mysql-connector-python cryptography

📥 Installation
1️⃣ Set Up MySQL Database
Ensure MySQL is running.
Create a database named file_transfer_db or modify DB_CONFIG accordingly.
The script will automatically create a users table if it doesn’t exist.

2️⃣ Run the Application
python your_script_name.py

🎮 How to Use

🔑 Authentication
On launching, log in or register an account.
Passwords are securely stored using SHA-256 with a salt.

📤 Sending Files
1️⃣ Enter recipient's IP and port.
2️⃣ Choose a file for transfer.
3️⃣ Provide a password/key (default is your login password).
4️⃣ Click "Send File."

📥 Receiving Files
1️⃣ Enter the listening port.
2️⃣ Provide the password/key.
3️⃣ Click "Start Listening" to accept incoming files.
4️⃣ Files are saved in the application directory.

📜 Logging & Monitoring
📌 A real-time log tracks authentication, transfers, and errors.
📌 Use "File > Clear Log" to reset logs.

🔚 Exiting the Application
Close the window or select "File > Exit."

🔐 Security Considerations
🔒 Password Protection: Securely hashed using SHA-256 with PBKDF2 key derivation.
🔒 File Encryption: AES-CBC ensures confidentiality during transit.
🔒 Network Security: Uses TCP sockets with optional encryption layers.
🔒 Mitigating Attacks: Prevents MITM, replay attacks, and unauthorized access.

🚀 Future Improvements
🔹 Two-Factor Authentication (2FA) for enhanced security.
🔹 Modernized GUI with enhanced user experience.
🔹 Custom Save Directory for received files.
🔹 Advanced Error Handling for improved stability.
🔹 End-to-End Encryption to further secure transfers.

👨‍💻 Author
Sara Singh Dangol

📜 License
This project is licensed under the MIT License.
