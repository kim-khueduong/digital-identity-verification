import hmac
import hashlib
 
print("MALLORY: ATTACKER")
 
# Read Alice's original message
with open("src/shared/message.txt", "r") as file:
    original_message = file.read()
 
# Read Alice's original HMAC
with open("src/shared/hmac.txt", "r") as file:
    original_hmac = file.read()
 
print()
print("Mallory intercepted:")
print(original_message)
 
print()
print("Original HMAC:")
print(original_hmac)
 

# key-compromise scenario (Mallory has been given the key)
has_key = input("\nDoes Mallory have the shared key for this test? (y/n): ").strip().lower()
 
modified_message = input("Enter the fake message Mallory wants Bob to receive: ")
 
if has_key == "y":
    # Controlled key-compromise scenario: Mallory has obtained the
    # same shared key Alice and Bob use, e.g. leaked or poorly stored.
    SHARED_KEY = b"round3-shared-secret-key"
    modified_hmac = hmac.new(SHARED_KEY, modified_message.encode(), hashlib.sha256).hexdigest()
    print("\n[Mallory is using the COMPROMISED shared key]")
else:
    # Normal attack: Mallory does not know the real shared key, so she
    # can only guess/fabricate one. This should fail Bob's verification.
    FAKE_KEY = b"mallorys-guessed-key"
    modified_hmac = hmac.new(FAKE_KEY, modified_message.encode(), hashlib.sha256).hexdigest()
    print("\n[Mallory does NOT have the real key - using a guessed key]")
 
# Replace Alice's message
with open("src/shared/message.txt", "w") as file:
    file.write(modified_message)
 
# Replace Alice's HMAC
with open("src/shared/hmac.txt", "w") as file:
    file.write(modified_hmac)
 
print()
print("Mallory forwarded message:")
print(modified_message)
 
print()
print("Mallory forwarded HMAC:")
print(modified_hmac)
