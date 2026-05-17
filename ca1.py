import socket
import threading
import json
import time
import tkinter as tk
from tkinter import scrolledtext
import ECDSA

# Dedicated CA Keypair
CA_PRIVATE_KEY = 49806086994081315768535503621314805076665862072723885913589355959401176605073
CA_PUBLIC_KEY = (
    32167098971702862536868029676832383352378452658998998980548421460672022530668,
    45303739504553886989148950397054188194730681477689363086709449507248545053226
)

REGISTERED_KEYS = {} 

class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Laptop C: Root Cryptographic Matrix")
        self.root.geometry("800x600")
        self.root.configure(bg="#090D16") 

        # --- TOP STATUS HUB BANNER ---
        top_banner = tk.Frame(root, bg="#111827", height=80, bd=0, highlightthickness=0)
        top_banner.pack(fill=tk.X)
        
        tk.Label(
            top_banner, 
            text="🔒 CORE SECURITY CONTROLLER (LAPTOP C)", 
            font=("Segoe UI", 13, "bold"), 
            fg="#06B6D4", 
            bg="#111827"
        ).pack(side=tk.LEFT, padx=30, pady=22)
        
        self.status_indicator = tk.Label(
            top_banner, 
            text="● NETWORK MONITOR ACTIVE", 
            font=("Consolas", 9, "bold"), 
            fg="#34D399", 
            bg="#064E3B",
            padx=12,
            pady=5
        )
        self.status_indicator.pack(side=tk.RIGHT, padx=30, pady=22)

        # --- CENTRAL LOGGING INTERFACE ---
        main_frame = tk.Frame(root, bg="#090D16")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Identity Authority Engine
        log_panel = tk.LabelFrame(
            main_frame, 
            text=" [ IDENTITY AUTHORITY & CERTIFICATE ENGINE ] ", 
            font=("Consolas", 10, "bold"), 
            fg="#38BDF8", 
            bg="#1E293B", 
            bd=1, 
            relief=tk.SOLID
        )
        log_panel.pack(fill=tk.BOTH, expand=True)
        
        self.ca_log = scrolledtext.ScrolledText(
            log_panel, 
            bg="#030712", 
            fg="#E2E8F0", 
            insertbackground="#FFFFFF",
            relief=tk.FLAT, 
            font=("Consolas", 10),
            padx=8, pady=8
        )
        self.ca_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.ca_log.tag_config("info", foreground="#38BDF8")
        self.ca_log.tag_config("success", foreground="#34D399")

        self.log_ca("CA Core Kernel active. Cryptographic anchors secured.", "success")
        

        # --- NETWORKING PIPELINE ---
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("", 5000))
        self.server_socket.listen(10)

        threading.Thread(target=self.accept_connections, daemon=True).start()

    def log_ca(self, msg, tag="info"):
        self.root.after(0, self._safe_log_ca, msg, tag)

    def _safe_log_ca(self, msg, tag):
        self.ca_log.config(state='normal')
        self.ca_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)
        self.ca_log.config(state='disabled')
        self.ca_log.see(tk.END)

    def accept_connections(self):
        while True:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except:
                break

    def handle_client(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data: return
            
            request = json.loads(data)
            req_type = request.get("type")

            if req_type == "issue_cert":
                user_id = request["user_id"]
                elgammal_pub = request["elgammal_pub"]
                ecdsa_pub = request["ecdsa_pub"]  

                expiration = time.time() + 3600
    
                cert_body = f"{user_id}:{int(elgammal_pub[0])}:{int(elgammal_pub[1])}:{int(elgammal_pub[2])}:{int(ecdsa_pub[0])}:{int(ecdsa_pub[1])}:{expiration}"
                print("CERT_BODY_CA:", cert_body)
                signature = ECDSA.sign(CA_PRIVATE_KEY, cert_body)
                print("SIGNATURE:", signature)

                certificate = {
                    "user_id": user_id,
                    "elgammal_pub": elgammal_pub,
                    "ecdsa_pub": ecdsa_pub,       
                    "expiration": expiration,
                    "signature": [signature[0], signature[1]]
                }

                REGISTERED_KEYS[user_id] = elgammal_pub
                self.log_ca(f"Certificate issued for '{user_id}'. Identity verified.", "success")
                conn.sendall(json.dumps(certificate).encode('utf-8'))

        except Exception as e:
            print(f"Server parsing anomaly: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()