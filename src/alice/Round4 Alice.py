from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os
 
print(" ALICE: LEGITIMATE SENDER - Round 4")
 
KEY_DIR = "src/shared/keys"
os.makedirs(KEY_DIR, exist_ok=True)
 
private_key_path = f"{KEY_DIR}/alice_private.pem"
public_key_path = f"{KEY_DIR}/alice_public.pem"
 
# Generate Alice's keypair once, reuse it on later runs so Bob keeps
# using the same public key across the whole round.
if not os.path.exists(private_key_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
 
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
 
    with open(public_key_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print("[New keypair generated for Alice]")
else:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    print("[Reusing Alice's existing keypair]")
 
message = input("Enter a message to send to Bob: ")
 
# Sign the message with Alice's PRIVATE key using RSA-PSS + SHA-256.
# Only someone holding this private key can produce a valid signature.
signature = private_key.sign(
    message.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
 
with open("src/shared/message.txt", "w") as f:
    f.write(message)
 
with open("src/shared/signature.bin", "wb") as f:
    f.write(signature)
 
print()
print("Alice's sent:")
print(message)
print()
print("Signature (hex, truncated):")
print(signature.hex()[:64] + "...")
print()
print(f"Alice's public key saved at: {public_key_path}")
print("(Bob uses this to verify. Mallory should NOT have alice_private.pem")
print("unless this is the controlled key-compromise test.)")