import hashlib

print("=== ALICE: LEGITIMATE SENDER ===")

message = input("Enter a message to send to Bob: ")

#Generate SHA-256 hash of Alilce's message
message_hash = hashlib.sha256(message.encode()).hexdigest()

#Save the message
with open ("src/shared/message.txt", "w") as file:
    file.write(message)

#Save the hasmeetinh
with open("src/shared/hash.txt","w") as file:
    file.write(message_hash)    

print()
print("Alice's sent:")
print(message)

print()
print("SHA-256 hash:")
print(message_hash)