import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
import voice_common as vc

print("=== BOB: RECIPIENT (Voice) ===")

audio_path = vc.find_audio()
if audio_path is None or not os.path.exists(vc.AUTH_PATH):
    raise SystemExit("No voice message found. Run Alice first.")

audio = vc.read_bytes(audio_path)
auth = vc.read_auth()
mode = auth["mode"]
actual_hash = vc.sha256_hex(audio)

print(f"\nBob received an audio file: {audio_path} ({len(audio)} bytes)")
print(f"Claimed sender: {auth['sender']}")
print(f"Protection mode: {mode}")
print(f"SHA-256 of received audio: {actual_hash[:32]}...")

accepted = False
reason = ""

if mode == "none":
    accepted = True
    reason = "No verification is performed. Bob trusts the voice."

elif mode == "sha256":
    accepted = actual_hash == auth.get("audio_sha256")
    reason = "Hash matches the audio." if accepted else "Hash does not match the audio."

elif mode == "hmac":
    expected = vc.hmac_hex(vc.SHARED_KEY, audio)
    import hmac as _hmac
    accepted = _hmac.compare_digest(expected, auth.get("hmac", ""))
    reason = "HMAC valid under the shared key." if accepted else "HMAC invalid under the shared key."

elif mode == "signature":
    public_key = vc.load_public_key(f"{vc.KEY_DIR}/alice_public.pem")
    signed = vc.signed_fields(auth, actual_hash)
    if auth.get("sender") != "Alice" or auth.get("recipient") != "Bob":
        reason = "Sender or recipient field is wrong."
    elif not vc.verify(public_key, signed, auth.get("signature", "")):
        reason = "Signature invalid for this audio, sender, recipient and message ID."
    elif vc.already_seen(auth["message_id"]):
        reason = "Valid signature, but this message ID was already used (replay)."
    else:
        accepted = True
        vc.record_seen(auth["message_id"])
        reason = "Signature valid and message ID is new."

print()
if accepted:
    print("RESULT: ACCEPTED as authentic")
else:
    print("RESULT: REJECTED")
print(f"Reason: {reason}")
print(f"(Test label, not seen by Bob in a real system: {auth.get('transcript_for_testing')})")
