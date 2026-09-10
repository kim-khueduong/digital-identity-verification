import hashlib

print("=== MALLORY: ATTACKER / RELAY ===")

#Read Alice's original message
with open("src/shared/message.txt", "r") as file:
    original_message = file.read()

#Read Alice's original hash
with open("src/shared/hash.txt", "r") as file:
    original_hash = file.read()

print()
print("Mallory intercepted:")
print(original_message)

print()
print("Original SHA-256 hash:")
print(original_hash)

#Mallory creates fake message
modified_message = input("\nEnter the fake message Mallory wants Bob to receive: ")

#Mallory generates a NEW hash for the fake message
modified_hash = hashlib.sha256(modified_message.encode()).hexdigest()

#Replace Alice's message
with open("src/shared/message.txt", "w") as file:
    file.write(modified_message)

#Replace ALice's hash
with open("src/shared/hash.txt", "w") as file:
    file.write(modified_hash)    

print()
print("Mallory forwarded:")
print(modified_message)

print()
print("Mallory forwarded:")
print(modified_hash)