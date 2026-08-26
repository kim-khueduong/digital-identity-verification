print("=== ALICE: LEGITIMATE SENDER ===")

message = input("Enter a message to send to Bob: ")

with open ("src/shared/message.txt", "w") as file:
    file.write(message)

print()
print("Alice's message:")
print(message)