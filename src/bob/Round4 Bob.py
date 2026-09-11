from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
 
print(" BOB: RECIPIENT (Round 4)")
 
KEY_DIR = "src/shared/keys"
public_key_path = f"{KEY_DIR}/alice_public.pem"
 
# Bob only ever needs Alice's PUBLIC key. He never holds anything
# capable of producing a valid signature himself.
with open(public_key_path, "rb") as f:
    alice_public_key = serialization.load_pem_public_key(f.read())
 
with open("src/shared/message.txt", "r") as f:
    message = f.read()
 
with open("src/shared/signature.bin", "rb") as f:
    signature = f.read()
 
print()
print("Bob received:")
print(message)
print()
print("Signature (hex, truncated):")
print(signature.hex()[:64] + "...")
print()
 
try:
    alice_public_key.verify(
        signature,
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("RESULT: Signature verification PASSED - message accepted as authentic")
except InvalidSignature:
    print("RESULT: Signature verification FAILED - message REJECTED")