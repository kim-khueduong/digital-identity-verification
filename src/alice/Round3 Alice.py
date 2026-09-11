import hmac
import hashlib

print ("ALICE: LEGITIMATE SENDER (Round 3)")
message = input("Enter a message to send to Bob:")

#Alice and Bob uses the same key
SHARED_KEY = b"shared-secret-key"

#Generate HMAC-SHA256 of the message using the shared key
message_hmac = hmac.new(SHARED_KEY, message.encode(), hashlib.sha256).hexdigest()

#save the message 
with open("src/shared/message.txt", "w") as file:
   file.write(message_hmac)

print()
print("Alice's sent:")
print(message)

print()
print("HAMC-SHA256 (using shared key):")
print(message_hmac)

