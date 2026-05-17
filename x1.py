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
import hashlib

SERVER_IP = ""      
SERVER_PORT = 5000           
PEER_PORT = 6001             

CA_PUBLIC_KEY = (
    32167098971702862536868029676832383352378452658998998980548421460672022530668,
    45303739504553886989148950397054188194730681477689363086709449507248545053226
)

class UserXApp:
    def __init__(self, root, vault_key):
        self.root = root
        self.root.title("Secure Comms Link: Host X")
        self.root.geometry("560x720")
        self.root.configure(bg="#0F172A") 

        self.my_id = "UserX"
        self.elg_pub, self.elg_priv = elgammal.generate_keys(bits=256)
        self.ecdsa_priv, self.ecdsa_pub = ECDSA.generate_keypair()
        self.my_cert = None
        self.session_key = None
        self.peer_elg_pub = None
        self.peer_ecdsa_pub = None
        
        self.rotation_interval_ms = 60000
        self.timer_handle = None

        self.bf_vault = blowfish.Blowfish(vault_key)
        if not os.path.exists("chat_history_x.bin"):
            open("chat_history_x.bin", "wb").close()

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
        
        self.status_lbl = tk.Label(
            action_bar, 
            text="🛰️ P2P HOST LISTENING LAYER ACTIVE", 
            font=("Segoe UI", 9, "bold"), 
            bg="#334155", fg="#F8FAFC",
            pady=6
        )
        self.status_lbl.pack(fill=tk.X, padx=20)

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

        
        self.display_message("System", "Ready. Standing by for User Y...")
        threading.Thread(target=self.start_peer_listener, daemon=True).start()
        self.get_certificate()

    def update_status(self, text, color, bg):
        self.root.after(0, lambda: self.badge.config(text=text, fg=color, bg=bg))

    def display_message(self, sender, text):
        self.root.after(0, self._safe_display_message, sender, text)

    def _safe_display_message(self, sender, text):
        self.chat_area.config(state='normal')
        ts = time.strftime('%H:%M:%S')
        if sender == "Me":
            self.chat_area.insert(tk.END, f"[{ts}] Me: ", "me")
            self.chat_area.insert(tk.END, f"{text}\n", "text")
        elif sender in ["User Y", "UserY"]:
            self.chat_area.insert(tk.END, f"[{ts}] User Y: ", "peer")
            self.chat_area.insert(tk.END, f"{text}\n", "text")
        elif sender in ["SECURITY ERROR", "Error", "System Error"]:
            self.chat_area.insert(tk.END, f"[{ts}] [CRITICAL FAULT]: {text}\n", "error")
        else:
            self.chat_area.insert(tk.END, f"[{ts}] • {text}\n", "system")
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def write_to_rest(self, sender, message):
        record = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {sender}: {message}"
        encrypted_block = self.bf_vault.encrypt(record)
        with open("chat_history_x.bin", "ab") as f:
            f.write(struct.pack(">I", len(encrypted_block)) + encrypted_block)

    def get_certificate(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            req = {"type": "issue_cert", "user_id": self.my_id, "elgammal_pub": self.elg_pub, "ecdsa_pub": [self.ecdsa_pub[0], self.ecdsa_pub[1]]}
            s.sendall(json.dumps(req).encode('utf-8'))
            self.my_cert = json.loads(s.recv(4096).decode('utf-8'))
            s.close()
        except Exception as e:
            messagebox.showerror("Network Error", f"Cannot connect to CA Server: {e}")

    def start_peer_listener(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("", PEER_PORT))
        server_sock.listen(1)
        while True:
            try:
                self.peer_conn, addr = server_sock.accept()
                self.run_handshake()
                threading.Thread(target=self.receive_messages_loop, daemon=True).start()
            except:
                break

    def run_handshake(self):
        try:
            cert_bytes = json.dumps(self.my_cert).encode('utf-8')
            self.peer_conn.sendall(struct.pack(">I", len(cert_bytes)) + cert_bytes)

            size_header = self.recv_all(4)
            if not size_header: return
            cert_size = struct.unpack(">I", size_header)[0]
            peer_cert_data = self.recv_all(cert_size).decode('utf-8')
            y_cert = json.loads(peer_cert_data)

            cert_body = f"{y_cert['user_id']}:{y_cert['elgammal_pub'][0]}:{y_cert['elgammal_pub'][1]}:{y_cert['elgammal_pub'][2]}:{y_cert['ecdsa_pub'][0]}:{y_cert['ecdsa_pub'][1]}:{y_cert['expiration']}"
            sig = (y_cert['signature'][0], y_cert['signature'][1])

            if not ECDSA.verify(CA_PUBLIC_KEY, cert_body, sig) or time.time() > y_cert['expiration']:
                raise ValueError("Verification failed: Compromised cert parameters.")

            self.peer_elg_pub = tuple(y_cert['elgammal_pub'])
            self.peer_ecdsa_pub = tuple(y_cert['ecdsa_pub']) 
            self.session_key = chacha20.generate_key()
            
            key_int = int.from_bytes(self.session_key, "big")
            c1, c2 = elgammal.encrypt(self.peer_elg_pub, key_int)
            
            token_id = int(time.time())
            key_packet = {"c1": c1, "c2": c2, "session_id": token_id}
            packet_bytes = json.dumps(key_packet).encode('utf-8')
            self.peer_conn.sendall(struct.pack(">I", len(packet_bytes)) + packet_bytes)

           
            
            self.update_status("TUNNEL LINKED", "#10B981", "#064E3B")
            self.display_message("System", f"Handshake Secured. Tunnel active ")
            
            self.schedule_next_rotation()
        except Exception as e:
            self.display_message("System Error", f"Handshake failure: {e}")

    def recv_all(self, length):
        data = b""
        while len(data) < length:
            packet = self.peer_conn.recv(length - len(data))
            if not packet: return None
            data += packet
        return data

    def schedule_next_rotation(self):
        if self.timer_handle:
            self.root.after_cancel(self.timer_handle)
        self.timer_handle = self.root.after(self.rotation_interval_ms, self.trigger_periodic_rotation)

    def trigger_periodic_rotation(self):
        if self.session_key:
            self.display_message("System", "Temporal window achieved. Initiating key rotation...")
            self.initiate_key_rotation()
            self.schedule_next_rotation()

    def initiate_key_rotation(self):
        try:
            new_key = chacha20.generate_key()
            key_int = int.from_bytes(new_key, "big")
            c1, c2 = elgammal.encrypt(self.peer_elg_pub, key_int)
            token_id = int(time.time())
            
            control_content = json.dumps({"c1": c1, "c2": c2, "session_id": token_id})
            raw_package = json.dumps({"type": "key_rotation", "content": control_content, "msg_id": f"ROT_{time.time()}"})
            
            nonce = chacha20.generate_nonce()
            encrypted_payload = chacha20.encrypt(raw_package, self.session_key, nonce)
            signature = ECDSA.sign(self.ecdsa_priv, raw_package)

            wire_format = {
                "nonce": nonce.hex(), "payload": encrypted_payload.hex(),
                "signature": [signature[0], signature[1]]
            }
            wire_bytes = json.dumps(wire_format).encode('utf-8')
            self.peer_conn.sendall(struct.pack(">I", len(wire_bytes)) + wire_bytes)
            
            

            self.session_key = new_key
            self.display_message("System", "Dynamic key cycle complete. Local tunnel updated.")
        except Exception as e:
            self.display_message("System Error", f"Rotation fault: {e}")

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
        msg_id = f"X_{time.time()}"
        raw_package = json.dumps({"type": data_type, "content": payload, "msg_id": msg_id, "timestamp": time.time()})
        
        nonce = chacha20.generate_nonce()
        encrypted_payload = chacha20.encrypt(raw_package, self.session_key, nonce)
        signature = ECDSA.sign(self.ecdsa_priv, raw_package)

        wire_format = {
            "nonce": nonce.hex(), "payload": encrypted_payload.hex(),
            "signature": [signature[0], signature[1]]
        }   
        
        try:
            wire_bytes = json.dumps(wire_format).encode('utf-8')
            self.peer_conn.sendall(struct.pack(">I", len(wire_bytes)) + wire_bytes)
            
            if data_type == "text":
                self.display_message("Me", payload)
                self.write_to_rest("Me", payload)
            else:
                self.display_message("Me", f"📄 FILE: {json.loads(payload)['filename']}")
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
                sig = tuple(packet["signature"])            

                decrypted_json = chacha20.decrypt(encrypted_payload, self.session_key, nonce).decode('utf-8')


                if not ECDSA.verify(self.peer_ecdsa_pub, decrypted_json, sig):
                    self.display_message("SECURITY ERROR", "Corrupt frames discarded.")
                    continue

                frame = json.loads(decrypted_json)
                if frame["type"] == "key_rotation":
                    control_info = json.loads(frame["content"])
                    decrypted_key_int = elgammal.decrypt(self.elg_priv, (control_info["c1"], control_info["c2"]))
                    self.session_key = decrypted_key_int.to_bytes(32, "big")
                    self.display_message("System", f"In-band rotation active. New session key applied.")
                    continue

                if frame["type"] == "text":
                    self.display_message("User Y", frame["content"])
                    self.write_to_rest("User Y", frame["content"])
                elif frame["type"] == "file":
                    file_info = json.loads(frame["content"])
                    self.display_message("User Y", f"📄 FILE: {file_info['filename']}")
                    self.write_to_rest("User Y", f"[Attached File: {file_info['filename']}]")
            except Exception as e:
                print(f"Receive loop error: {e}")
                break
        
        if self.timer_handle:
            self.root.after_cancel(self.timer_handle)
            self.timer_handle = None
        self.update_status("OFFLINE", "#EF4444", "#7F1D1D")
        self.display_message("System", "Tunnel drop.")

if __name__ == "__main__":
    import hashlib
    _vault_pass = input("Enter vault password for User X: ")
    _vault_key = hashlib.sha256(_vault_pass.encode()).hexdigest()
    root = tk.Tk()
    app = UserXApp(root, _vault_key)
    root.mainloop()