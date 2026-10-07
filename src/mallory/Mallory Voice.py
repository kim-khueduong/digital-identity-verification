import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
import voice_common as vc

print("=== MALLORY: ATTACKER (Voice) ===")

audio_path = vc.find_audio()
if audio_path is None or not os.path.exists(vc.AUTH_PATH):
    raise SystemExit("No voice message to intercept. Run Alice first.")

original_audio = vc.read_bytes(audio_path)
auth = vc.read_auth()
mode = auth["mode"]

print(f"\nMallory intercepted Alice's voice message ({len(original_audio)} bytes).")
print(f"Protection mode in use: {mode}")


def forge_voice():
    text = input("\nWhat should the fake message say? ")
    # Same synthetic voice engine as Alice, which models the assumption
    # that Mallory can imitate Alice's voice convincingly.
    path, engine = vc.generate_voice(text)
    audio = vc.read_bytes(path)
    print(f"Fake audio generated with the same voice ({engine}), {len(audio)} bytes.")
    return audio, text


if mode == "none":
    audio, text = forge_voice()
    auth["transcript_for_testing"] = text
    print("No protection to bypass. Mallory simply replaces the audio.")

elif mode == "sha256":
    audio, text = forge_voice()
    auth["audio_sha256"] = vc.sha256_hex(audio)
    auth["transcript_for_testing"] = text
    print("Mallory recalculated a matching SHA-256 hash for her fake audio.")

elif mode == "hmac":
    has_key = input("\nDoes Mallory have the shared key (controlled compromise)? (y/n): ").strip().lower()
    audio, text = forge_voice()
    key = vc.SHARED_KEY if has_key == "y" else b"mallorys-guessed-key"
    auth["hmac"] = vc.hmac_hex(key, audio)
    auth["transcript_for_testing"] = text
    print("Mallory used the COMPROMISED key." if has_key == "y" else "Mallory used a guessed key.")

elif mode == "signature":
    print("\nChoose an attack:")
    print("  1 - Sign with Mallory's own keypair")
    print("  2 - Replace the audio but reuse Alice's original signature")
    print("  3 - Controlled key compromise (Mallory holds Alice's private key)")
    print("  4 - Replay Alice's original message unchanged")
    print("  5 - Public key substitution (Mallory replaces Alice's public key)")
    choice = input("Enter 1 to 5: ").strip()

    if choice == "1":
        from cryptography.hazmat.primitives.asymmetric import rsa
        audio, text = forge_voice()
        mallory_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        auth["message_id"] = str(uuid.uuid4())
        auth["audio_sha256"] = vc.sha256_hex(audio)
        auth["signature"] = vc.sign(mallory_key, vc.signed_fields(auth, auth["audio_sha256"]))
        auth["transcript_for_testing"] = text

    elif choice == "2":
        audio, text = forge_voice()
        auth["transcript_for_testing"] = text
        print("Alice's original signature and metadata are kept unchanged.")

    elif choice == "3":
        audio, text = forge_voice()
        alice_private = vc.load_private_key(f"{vc.KEY_DIR}/alice_private.pem")
        auth["message_id"] = str(uuid.uuid4())
        auth["audio_sha256"] = vc.sha256_hex(audio)
        auth["signature"] = vc.sign(alice_private, vc.signed_fields(auth, auth["audio_sha256"]))
        auth["transcript_for_testing"] = text
        print("Mallory signed with Alice's COMPROMISED private key.")

    elif choice == "4":
        audio = original_audio
        print("Mallory resends Alice's original audio, signature and message ID unchanged.")

    elif choice == "5":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        audio, text = forge_voice()
        mallory_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        auth["message_id"] = str(uuid.uuid4())
        auth["audio_sha256"] = vc.sha256_hex(audio)
        auth["signature"] = vc.sign(mallory_key, vc.signed_fields(auth, auth["audio_sha256"]))
        auth["transcript_for_testing"] = text
        with open(f"{vc.KEY_DIR}/alice_public.pem", "wb") as f:
            f.write(mallory_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        print("Mallory overwrote Alice's public key with her own.")
        print("(Run Alice again to restore the genuine public key.)")

    else:
        raise SystemExit("Invalid choice.")

# Write the (possibly forged) message back onto the shared channel.
if mode == "signature" and choice == "4":
    pass  # nothing changes on the channel for a pure replay
else:
    for old in vc.glob.glob(f"{vc.VOICE_DIR}/message_audio.*"):
        os.remove(old)
    ext = os.path.splitext(audio_path)[1]
    with open(f"{vc.VOICE_DIR}/message_audio{ext}", "wb") as f:
        f.write(audio)
    vc.write_auth(auth)

print("\nMallory forwarded the message to Bob.")
