import socket
import threading
import json
import time
import os
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import chacha20
import elgammal
import ECDSA
import blowfish

SERVER_IP = "127.0.0.1"      
SERVER_PORT = 5000           
PEER_PORT = 6001             
PEER_IP = "127.0.0.1"        

CA_PUBLIC_KEY = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

class UserYApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Comms Link: Client Y")
        self.root.geometry("560x720")
        self.root.configure(bg="#0F172A") 

        self.my_id = "UserY"
        self.elg_pub, self.elg_priv = elgammal.generate_keys(bits=256)
        self.ecdsa_priv, self.ecdsa_pub = ECDSA.generate_keypair()
        self.my_cert = None
        self.session_key = None

        self.bf_vault = blowfish.Blowfish("local_vault_key_y")
        if not os.path.exists("chat_history_y.bin"):
            open("chat_history_y.bin", "wb").close()

        header_banner = tk.Frame(root, bg="#1E293B", height=65)
        header_banner.pack(fill=tk.X)
        
        tk.Label(
            header_banner, 
            text="🛰️ SECURE COMMS LINK TERMINAL", 
            font=("Segoe UI", 12, "bold"), 
            fg="#38BDF8", 
            bg="#1E293B"
        ).pack(side=tk.LEFT, padx=20, pady=18)
        
        self.badge = tk.Label(
            header_banner, 
            text="DISCONNECTED", 
            font=("Segoe UI", 8, "bold"), 
            fg="#FCA5A5", 
            bg="#7F1D1D",
            padx=10, pady=4
        )
        self.badge.pack(side=tk.RIGHT, padx=20, pady=18)

        action_bar = tk.Frame(root, bg="#1E293B", pady=10)
        action_bar.pack(fill=tk.X)
        
        self.connect_btn = tk.Button(
            action_bar, 
            text="🔌 CONNECT TO HOST CLIENT ENDPOINT", 
            font=("Segoe UI", 9, "bold"), 
            bg="#10B981", fg="#FFFFFF", 
            activebackground="#059669", activeforeground="#FFFFFF",
            relief=tk.FLAT, padx=15, pady=6,
            command=self.connect_to_peer
        )
        self.connect_btn.pack(fill=tk.X, padx=20)

        chat_wrapper = tk.Frame(root, bg="#0F172A", padx=20, pady=15)
        chat_wrapper.pack(fill=tk.BOTH, expand=True)

        self.chat_area = scrolledtext.ScrolledText(
            chat_wrapper, 
            state='disabled', 
            bg="#030712", 
            fg="#F8FAFC", 
            insertbackground="#FFFFFF",
            relief=tk.SOLID, 
            bd=1, 
            font=("Consolas", 10),
            padx=12, pady=12
        )
        self.chat_area.pack(fill=tk.BOTH, expand=True)
        
        self.chat_area.tag_config("me", foreground="#38BDF8", font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("peer", foreground="#F59E0B", font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("system", foreground="#64748B", font=("Consolas", 10, "italic")) 
        self.chat_area.tag_config("error", foreground="#DC2626", font=("Consolas", 10, "bold"))
        self.chat_area.tag_config("text", foreground="#F8FAFC", font=("Consolas", 10))

        input_panel = tk.Frame(root, bg="#1E293B", padx=12, pady=12)
        input_panel.pack(fill=tk.X)

        self.attach_btn = tk.Button(
            input_panel, 
            text="📎", 
            font=("Segoe UI", 11), 
            bg="#334155", fg="#F8FAFC", 
            activebackground="#475569", activeforeground="#F8FAFC",
            relief=tk.FLAT, width=3, 
            command=self.attach_document
        )
        self.attach_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.msg_entry = tk.Entry(
            input_panel, 
            font=("Consolas", 11), 
            bg="#030712", fg="#FFFFFF", 
            insertbackground="#FFFFFF",
            relief=tk.SOLID, bd=1
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.msg_entry.bind("<Return>", lambda event: self.send_text_message())

        self.send_btn = tk.Button(
            input_panel, 
            text="SEND", 
            font=("Consolas", 9, "bold"), 
            bg="#10B981", fg="#FFFFFF", 
            activebackground="#059669", activeforeground="#FFFFFF",
            relief=tk.FLAT, width=9, 
            command=self.send_text_message
        )
        self.send_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.get_certificate()

    def update_badge(self, text, color, bg):
        self.root.after(0, lambda: self.badge.config(text=text, fg=color, bg=bg))

    def display_message(self, sender, text):
        self.root.after(0, self._safe_display_message, sender, text)

    def _safe_display_message(self, sender, text):
        self.chat_area.config(state='normal')
        ts = time.strftime('%H:%M:%S')
        if sender == "Me":
            self.chat_area.insert(tk.END, f"[{ts}] Me: ", "me")
            self.chat_area.insert(tk.END, f"{text}\n", "text")
        elif sender in ["User X", "UserX"]:
            self.chat_area.insert(tk.END, f"[{ts}] User X: ", "peer")
            self.chat_area.insert(tk.END, f"{text}\n", "text")
        elif sender in ["SECURITY ERROR", "Error", "System Error"]:
            self.chat_area.insert(tk.END, f"[{ts}] [{sender}]: {text}\n", "error")
        else:
            self.chat_area.insert(tk.END, f"[{ts}] • {text}\n", "system")
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def write_to_rest(self, sender, message):
        record = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {sender}: {message}"
        encrypted_block = self.bf_vault.encrypt(record)
        with open("chat_history_y.bin", "ab") as f:
            f.write(struct.pack(">I", len(encrypted_block)) + encrypted_block)

    def get_certificate(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            req = {"type": "issue_cert", "user_id": self.my_id, "elgammal_pub": self.elg_pub}
            s.sendall(json.dumps(req).encode('utf-8'))
            self.my_cert = json.loads(s.recv(4096).decode('utf-8'))
            s.close()
            self.display_message("System", "Identity matrix parameters signed by CA Node.")
        except Exception as e:
            messagebox.showerror("Network Error", f"Cannot connect to CA Server: {e}")

    def connect_to_peer(self):
        threading.Thread(target=self._bg_connect, daemon=True).start()

    def _bg_connect(self):
        try:
            self.peer_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.peer_conn.connect((PEER_IP, PEER_PORT))
            self.run_handshake()
            threading.Thread(target=self.receive_messages_loop, daemon=True).start()
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"P2P Link setup failed: {e}"))

    def recv_all(self, length):
        data = b""
        while len(data) < length:
            packet = self.peer_conn.recv(length - len(data))
            if not packet: return None
            data += packet
        return data

    def run_handshake(self):
        size_header = self.recv_all(4)
        if not size_header: return
        cert_size = struct.unpack(">I", size_header)[0]
        x_cert_data = self.recv_all(cert_size).decode('utf-8')
        x_cert = json.loads(x_cert_data)

        bytes_to_send = json.dumps(self.my_cert).encode('utf-8')
        self.peer_conn.sendall(struct.pack(">I", len(bytes_to_send)) + bytes_to_send)

        cert_body = f"{x_cert['user_id']}:{x_cert['elgammal_pub'][0]}:{x_cert['elgammal_pub'][1]}:{x_cert['elgammal_pub'][2]}:{x_cert['expiration']}"
        sig = (x_cert['signature'][0], x_cert['signature'][1])

        if not ECDSA.verify(CA_PUBLIC_KEY, cert_body, sig) or time.time() > x_cert['expiration']:
            raise ValueError("Verification failed: Security anchor check signature rejected.")

        size_header = self.recv_all(4)
        if not size_header: return
        packet_size = struct.unpack(">I", size_header)[0]
        key_packet_data = self.recv_all(packet_size).decode('utf-8')
        packet = json.loads(key_packet_data)
        
        decrypted_key_int = elgammal.decrypt(self.elg_priv, (packet["c1"], packet["c2"]))
        self.session_key = decrypted_key_int.to_bytes(32, "big")

        self.update_badge("TUNNEL LINKED", "#10B981", "#064E3B")
        self.display_message("System", f"Channel secured. Key received from Host.")

    def send_text_message(self):
        text = self.msg_entry.get().strip()
        if not text or not self.session_key: return
        self.msg_entry.delete(0, tk.END)
        self.transmit_payload("text", text)

    def attach_document(self):
        if not self.session_key: return
        path = filedialog.askopenfilename()
        if path:
            with open(path, "rb") as f:
                content = f.read().decode('utf-8', errors='ignore')
            self.transmit_payload("file", json.dumps({"filename": os.path.basename(path), "body": content}))

    def transmit_payload(self, data_type, payload):
        msg_id = f"Y_{time.time()}"
        raw_package = json.dumps({"type": data_type, "content": payload, "msg_id": msg_id, "timestamp": time.time()})
        
        nonce = chacha20.generate_nonce()
        encrypted_payload = chacha20.encrypt(raw_package, self.session_key, nonce)
        signature = ECDSA.sign(self.ecdsa_priv, raw_package)

        wire_format = {
            "nonce": nonce.hex(), "payload": encrypted_payload.hex(),
            "sender_ecdsa_pub": [self.ecdsa_pub[0], self.ecdsa_pub[1]], "signature": [signature[0], signature[1]]
        }
        
        try:
            wire_bytes = json.dumps(wire_format).encode('utf-8')
            self.peer_conn.sendall(struct.pack(">I", len(wire_bytes)) + wire_bytes)
            
            if data_type == "text":
                self.display_message("Me", payload)
                self.write_to_rest("Me", payload)
            else:
                self.display_message("Me", f"📄 Attached Document: {json.loads(payload)['filename']}")
        except Exception as e:
            self.display_message("System Error", f"Transmission failure: {e}")

    def receive_messages_loop(self):
        while True:
            try:
                size_header = self.recv_all(4)
                if not size_header: break
                total_size = struct.unpack(">I", size_header)[0]
                
                raw_data = self.recv_all(total_size).decode('utf-8')
                packet = json.loads(raw_data)
                
                nonce = bytes.fromhex(packet["nonce"])
                encrypted_payload = bytes.fromhex(packet["payload"])
                sender_pub = tuple(packet["sender_ecdsa_pub"])
                sig = tuple(packet["signature"])

                decrypted_json = chacha20.decrypt(encrypted_payload, self.session_key, nonce).decode('utf-8')
                
                if not ECDSA.verify(sender_pub, decrypted_json, sig):
                    self.display_message("SECURITY ERROR", "Dropped signature verification anomaly.")
                    continue

                frame = json.loads(decrypted_json)
                if frame["type"] == "key_rotation":
                    control_info = json.loads(frame["content"])
                    decrypted_key_int = elgammal.decrypt(self.elg_priv, (control_info["c1"], control_info["c2"]))
                    self.session_key = decrypted_key_int.to_bytes(32, "big")
                    self.display_message("System", f"In-band session key shift executed.")
                    continue

                if frame["type"] == "text":
                    self.display_message("User X", frame["content"])
                    self.write_to_rest("User X", frame["content"])
                elif frame["type"] == "file":
                    file_info = json.loads(frame["content"])
                    self.display_message("User X", f"📄 Attached Document: {file_info['filename']}")
                    self.write_to_rest("User X", f"[Attached File: {file_info['filename']}]")
            except:
                break
        self.update_badge("OFFLINE", "#EF4444", "#7F1D1D")
        self.display_message("System", "Connection lost.")

if __name__ == "__main__":
    root = tk.Tk()
    app = UserYApp(root)
    root.mainloop()