import socket
import sys
import time

PORT = 5005
MAGIC = "VARB"
SESSION_ID = "01234567-89ab-cdef-0123-456789abcdef"
BOOTSTRAP_NONCE = "deadbeef" * 4

def main():
    print(f"[mock-runtime] Listening on TCP 127.0.0.1:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print(f"[mock-runtime] Agent connected from {addr}")
            
            # 1. Send Bundle Header
            header = f"BUNDLE_HEADER:magic={MAGIC}:version=01:session={SESSION_ID}:nonce={BOOTSTRAP_NONCE}:QUOTE=MOCK_QUOTE_BYTES"
            conn.sendall((header + "\n").encode())
            print(f"[mock-runtime] Sent header: {header}")
            
            # 2. Send READY
            conn.sendall(b"READY\n")
            print("[mock-runtime] Sent READY")
            
            # 3. Protocol loop
            while True:
                buf = bytearray()
                while True:
                    chunk = conn.recv(1)
                    if not chunk: break
                    if chunk == b"\n": break
                    buf += chunk
                
                if not buf and not chunk: break
                msg = buf.decode("utf-8", errors="replace").strip()
                if not msg: continue
                
                print(f"[mock-runtime] Received: {msg}")
                
                if msg.startswith("SECRET:"):
                    print(f"[mock-runtime] -> Secret stored.")
                elif msg.startswith("LOG:"):
                    print(f"[mock-runtime] -> Logged.")
                elif msg == "GET_EVIDENCE":
                    evidence = "EVIDENCE:stream=s123:state=v456:sig=canonical_v1_1"
                    conn.sendall((evidence + "\n").encode())
                    print(f"[mock-runtime] Sent evidence: {evidence}")
                    time.sleep(1) # Give agent time to read
                    break
            
            print("[mock-runtime] Session complete.")

if __name__ == "__main__":
    main()
