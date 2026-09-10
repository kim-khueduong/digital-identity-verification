import hashlib

print("=== BOB: RECIPIENT ===")

#Read the received message
with open ("src/shared/message.txt", "r") as file:
    message = file.read()

#Read the hash sent with the message
with open("src/shared/hash.txt", "r") as file:
    received_hash = file.read()

#Bob calculates his own hash from the received message
calculated_hash = hashlib.sha256(message.encode()).hexdigest()

print()
print("Bob received:")
print(message)  

print()
print("Received hash:")
print(received_hash)

print()
print("Calculated hash:")
print(calculated_hash)

print()

if received_hash == calculated_hash:
    print("RESULT: Message integrity check PASSED")
else:
    print("RESULT: Message integrity check FAILED")