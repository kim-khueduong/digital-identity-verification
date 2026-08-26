print("=== BOB: RECIPIENT ===")

with open ("src/shared/message.txt", "r") as file:
    message = file.read()

print()
print("Bob received:")
print(message)  