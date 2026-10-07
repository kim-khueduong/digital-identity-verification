import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
import voice_common as vc

print("=== ALICE: LEGITIMATE SENDER (Voice) ===")

print("\nProtection mode for this round:")
print("  1 - No protection")
print("  2 - SHA-256 hash")
print("  3 - HMAC shared secret")
print("  4 - RSA digital signature")
mode = vc.MODES.get(input("Enter 1, 2, 3 or 4: ").strip())
if mode is None:
    raise SystemExit("Invalid mode.")

text = input("\nWhat does Alice say in her voice message? ")

audio_path, engine = vc.generate_voice(text)
audio = vc.read_bytes(audio_path)
audio_hash = vc.sha256_hex(audio)

auth = {
    "mode": mode,
    "sender": "Alice",
    "recipient": "Bob",
    "message_id": str(uuid.uuid4()),
    "transcript_for_testing": text,
}

if mode == "sha256":
    auth["audio_sha256"] = audio_hash
elif mode == "hmac":
    auth["hmac"] = vc.hmac_hex(vc.SHARED_KEY, audio)
elif mode == "signature":
    private_key = vc.load_or_create_alice_keys()
    auth["audio_sha256"] = audio_hash
    auth["signature"] = vc.sign(private_key, vc.signed_fields(auth, audio_hash))

vc.write_auth(auth)

print(f"\nVoice engine used: {engine}")
print(f"Audio file: {audio_path} ({len(audio)} bytes)")
print(f"Mode: {mode}")
print(f"Message ID: {auth['message_id']}")
print(f"Audio SHA-256: {audio_hash[:32]}...")
if mode == "hmac":
    print(f"HMAC: {auth['hmac'][:32]}...")
if mode == "signature":
    print(f"Signature: {auth['signature'][:32]}...")
print("\nAlice sent the voice message to Bob.")
