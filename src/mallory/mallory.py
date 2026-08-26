print("=== MALLORY: ATTACKER / RELAY ===")

with open("src/shared/message.txt", "r") as file:
    original_message = file.read()

print()
print("Mallory intercepted:")
print(original_message)

modified_message = input("\nEnter the fake message Mallory wants Bob to receive: ")

with open("src/shared/message.txt", "w") as file:
    file.write(modified_message)

print()
print("Mallory forwarded:")
print(modified_message)