import socket
import sys
import threading

# Configuration for AWS Nitro VSOCK
# VMADDR_CID_HOST = 2
# PORT = 5005

class HostEnclaveProxy:
    def __init__(self, use_vsock=False, cid=2, port=5005):
        self.use_vsock = use_vsock
        self.cid = cid
        self.port = port
        self.server_socket = None

    def start(self):
        if self.use_vsock:
            try:
                self.server_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                self.server_socket.bind((self.cid, self.port))
            except AttributeError:
                print("Error: AF_VSOCK not supported on this OS. Falling back to TCP simulation.")
                self.use_vsock = False
        
        if not self.use_vsock:
            # Simulation Mode: Standard TCP
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('127.0.0.1', self.port))
        
        self.server_socket.listen(1)
        print(f"[*] VAR Proxy listening on {'vsock:' + str(self.cid) if self.use_vsock else 'tcp:127.0.0.1'}:{self.port}...")
        
        while True:
            conn, addr = self.server_socket.accept()
            print(f"[+] Enclave connection established from {addr}")
            # Start threads to bridge stdin/stdout to the enclave
            threading.Thread(target=self.bridge_io, args=(conn,), daemon=True).start()

    def bridge_io(self, conn):
        # Read from enclave, write to stdout
        def read_from_enclave():
            while True:
                try:
                    data = conn.recv(4096)
                    if not data: break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except Exception as e:
                    print(f"\n[-] Enclave read error: {e}")
                    break

        # Read from stdin, write to enclave
        def write_to_enclave():
            while True:
                try:
                    data = sys.stdin.buffer.read(1) # Read byte by byte for PTY feel
                    if not data: break
                    conn.sendall(data)
                except Exception as e:
                    print(f"\n[-] Enclave write error: {e}")
                    break

        t1 = threading.Thread(target=read_from_enclave)
        t2 = threading.Thread(target=write_to_enclave)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print("[*] Enclave connection closed.")

if __name__ == "__main__":
    proxy = HostEnclaveProxy(use_vsock=False) # Simulation by default for Mac
    proxy.start()
