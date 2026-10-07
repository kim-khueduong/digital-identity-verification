import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
import pki_lib as pki

print(" ALICE: LEGITIMATE SENDER - Round 5")

if not os.path.exists(pki.ALICE_CERT):
    sys.exit("No certificate found. Run: python src/ca/ca.py init   then   python src/ca/ca.py issue")

private_key, _ = pki.ensure_alice_keys()
cert = pki.load_cert(pki.ALICE_CERT)

message = input("Enter a message to send to Bob: ")

# The signature covers message + nonce + timestamp. Alice attaches her CA-issued certificate.
packet = pki.build_packet(message, private_key, cert)
pki.write_packet(packet)

print()
print("Alice's sent:")
print(message)
print()
print("Nonce:", packet["nonce"])
print("Timestamp:", packet["timestamp"])
print("Signature (hex, truncated):", packet["signature"][:64] + "...")
print("Certificate serial:", cert.serial_number)
