import os
import sys
import json
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "shared"))
import pki_lib as pki

print(" MALLORY: ATTACKER / RELAY (Round 5)")

CAPTURE = os.path.join(HERE, "captured_packet.json")

print()
print("Choose attack type:")
print("  0 - Passive: capture Alice's packet and forward it unchanged")
print("  1 - Public-key substitution: own key + self-signed certificate claiming to be Alice")
print("  2 - Rogue CA: certificate from Mallory's own CA that reuses the real CA's name")
print("  3 - Tamper with the message but reuse Alice's signature and certificate")
print("  4 - Replay a previously captured packet unchanged")
print("  5 - Controlled key-compromise (Mallory has Alice's private key and certificate)")
choice = input("Enter 0-5: ").strip()

if choice == "4":
    if not os.path.exists(CAPTURE):
        sys.exit("Nothing captured yet. Run option 0 first.")
    with open(CAPTURE) as f:
        pki.write_packet(json.load(f))
    print("\n[Mallory replayed the captured packet unchanged]")

else:
    original = pki.read_packet()
    print("\nMallory intercepted:", original["message"])

    if choice == "0":
        shutil.copy(pki.PACKET_PATH, CAPTURE)
        print("\n[Mallory saved a copy and forwarded the packet unchanged]")

    else:
        fake = input("Enter the fake message Mallory wants Bob to receive: ")

        if choice == "1":
            key = pki.gen_key()
            packet = pki.build_packet(fake, key, pki.self_signed_cert(key, "Alice"))
            print("\n[Mallory used her own key and a self-signed certificate claiming to be Alice]")

        elif choice == "2":
            rogue_key, rogue_ca = pki.make_ca(pki.CA_NAME)  # same name as the real CA, different key
            key = pki.gen_key()
            cert = pki.issue_cert(rogue_key, rogue_ca, "Alice", key.public_key())
            packet = pki.build_packet(fake, key, cert)
            print("\n[Mallory made a rogue CA with the real CA's name and certified herself as 'Alice']")

        elif choice == "3":
            packet = dict(original)
            packet["message"] = fake
            print("\n[Mallory changed the message but kept Alice's signature and certificate]")

        elif choice == "5":
            key = pki.load_private_key(pki.ALICE_PRIV)
            cert = pki.load_cert(pki.ALICE_CERT)
            packet = pki.build_packet(fake, key, cert)
            print("\n[Mallory signed a fresh message with Alice's REAL (compromised) private key]")

        else:
            sys.exit("Invalid choice.")

        pki.write_packet(packet)

print()
print("Mallory forwarded message:")
print(pki.read_packet()["message"])
