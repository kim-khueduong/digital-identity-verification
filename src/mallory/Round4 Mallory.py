
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
 
print(" MALLORY: ATTACKER / RELAY (Round 4)")
 
KEY_DIR = "src/shared/keys"
 
with open("src/shared/message.txt", "r") as f:
    original_message = f.read()
 
with open("src/shared/signature.bin", "rb") as f:
    original_signature = f.read()
 
print()
print("Mallory intercepted:")
print(original_message)
print()
print("Original signature (hex, truncated):")
print(original_signature.hex()[:64] + "...")
 
print()
print("Choose attack type:")
print("  1 - Forge with Mallory's OWN keypair (no access to Alice's private key)")
print("  2 - Tamper with the message but reuse Alice's original signature")
print("  3 - Controlled key-compromise (Mallory has been given Alice's real private key)")
choice = input("Enter 1, 2 or 3: ").strip()
 
modified_message = input("Enter the fake message Mallory wants Bob to receive: ")
 
if choice == "1":
    # Mallory has no access to Alice's private key, so she generates
    # her own keypair and signs with that instead. Bob will still
    # verify against ALICE's public key, which will not match.
    mallory_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_signature = mallory_key.sign(
        modified_message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("\n[Mallory signed with HER OWN keypair, not Alice's]")
 
elif choice == "2":
    # Mallory changes the message but keeps Alice's original signature,
    # betting Bob won't notice. The signature is bound to the original
    # message content, so this should fail verification.
    forged_signature = original_signature
    print("\n[Mallory reused Alice's ORIGINAL signature on a CHANGED message]")
 
elif choice == "3":
    # Controlled key-compromise scenario: Mallory has been deliberately
    # given Alice's real private key (e.g. leaked/stolen) for testing.
    with open(f"{KEY_DIR}/alice_private.pem", "rb") as f:
        alice_private_key = serialization.load_pem_private_key(f.read(), password=None)
    forged_signature = alice_private_key.sign(
        modified_message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("\n[Mallory signed using ALICE'S REAL (compromised) private key]")
 
else:
    print("Invalid choice.")
    raise SystemExit(1)
 
with open("src/shared/message.txt", "w") as f:
    f.write(modified_message)
 
with open("src/shared/signature.bin", "wb") as f:
    f.write(forged_signature)
 
print()
print("Mallory forwarded message:")
print(modified_message)
print()
print("Mallory forwarded signature (hex, truncated):")
print(forged_signature.hex()[:64] + "...")
 