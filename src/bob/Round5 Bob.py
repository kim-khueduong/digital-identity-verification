import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
import pki_lib as pki

print(" BOB: RECIPIENT (Round 5)")

NONCE_FILE = os.path.join(HERE, "seen_nonces.txt")

# Bob's ONLY trust anchor is the CA certificate. He does not trust any key that arrives in the packet.
ca_cert = pki.load_cert(pki.CA_CERT)
seen = set()
if os.path.exists(NONCE_FILE):
    with open(NONCE_FILE) as f:
        seen = {line.strip() for line in f if line.strip()}

packet = pki.read_packet()

print()
print("Bob received:")
print(packet["message"])
print()
print("Nonce:", packet["nonce"])
print("Timestamp:", packet["timestamp"])
print()

ok, reason = pki.verify_packet(packet, ca_cert, seen, revoked=pki.load_revoked())

if ok:
    with open(NONCE_FILE, "a") as f:
        f.write(packet["nonce"] + "\n")
    print("RESULT: PASSED - message accepted as authentic from Alice")
else:
    print(f"RESULT: FAILED - message REJECTED ({reason})")
