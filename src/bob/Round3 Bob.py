import hmac
import hashlib

print("BOB: RECIPIENT")

SHARED_KEY = b"round3-shared-secret-key"
 
# Read the received message
with open("src/shared/message.txt", "r") as file:
    message = file.read()
 
# Read the HMAC sent with the message
with open("src/shared/hmac.txt", "r") as file:
    received_hmac = file.read()
 
# Bob recalculates the HMAC using the message and the shared key
calculated_hmac = hmac.new(SHARED_KEY, message.encode(), hashlib.sha256).hexdigest()
 
print()
print("Bob received:")
print(message)
 
print()
print("Received HMAC:")
print(received_hmac)
 
print()
print("Calculated HMAC:")
print(calculated_hmac)
 
print()
 
# Use constant-time comparison to avoid leaking info via timing
if hmac.compare_digest(received_hmac, calculated_hmac):
    print("RESULT: HMAC verification PASSED - message accepted as authentic")
else:
    print("RESULT: HMAC verification FAILED - message REJECTED")
 
