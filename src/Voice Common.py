"""
voice_common.py
Shared helpers for the voice verification rounds.
Place this file in src/shared/ and run all scripts from the repository root.
"""

import glob
import hashlib
import hmac
import json
import math
import os
import struct
import wave

SHARED_DIR = "src/shared"
VOICE_DIR = f"{SHARED_DIR}/voice"
KEY_DIR = f"{SHARED_DIR}/keys"
AUTH_PATH = f"{VOICE_DIR}/auth.json"
SEEN_IDS_PATH = f"{VOICE_DIR}/seen_ids.txt"

# Pre-shared secret used only for the HMAC mode.
SHARED_KEY = b"voice-round-shared-secret"

MODES = {"1": "none", "2": "sha256", "3": "hmac", "4": "signature"}


# ---------------------------------------------------------------
# Voice generation
# ---------------------------------------------------------------
def clear_audio():
    os.makedirs(VOICE_DIR, exist_ok=True)
    for old in glob.glob(f"{VOICE_DIR}/message_audio.*"):
        os.remove(old)


def generate_voice(text):
    """
    Generate a generic synthetic voice for the given text.
    The same engine is used by Alice and Mallory, so the attacker's audio
    is indistinguishable in voice from the sender's. This represents the
    project assumption that Mallory can imitate Alice convincingly.

    Order of preference:
      1. gTTS (needs internet, produces .mp3)
      2. pyttsx3 (offline, needs espeak-ng, produces .wav)
      3. Placeholder tone (.wav), so the cryptography can still be tested
    """
    clear_audio()

    try:
        from gtts import gTTS
        path = f"{VOICE_DIR}/message_audio.mp3"
        gTTS(text=text, lang="en").save(path)
        return path, "gTTS"
    except Exception:
        pass

    try:
        import pyttsx3
        path = f"{VOICE_DIR}/message_audio.wav"
        engine = pyttsx3.init()
        engine.save_to_file(text, path)
        engine.runAndWait()
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return path, "pyttsx3"
    except Exception:
        pass

    # Placeholder: tone length depends on the text so different messages
    # produce different audio bytes.
    path = f"{VOICE_DIR}/message_audio.wav"
    rate = 16000
    seconds = max(1, min(len(text) // 10, 8))
    freq = 200 + (sum(text.encode()) % 400)
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        for i in range(rate * seconds):
            w.writeframes(struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / rate))))
    return path, "placeholder-tone"


def find_audio():
    files = glob.glob(f"{VOICE_DIR}/message_audio.*")
    return files[0] if files else None


# ---------------------------------------------------------------
# Hashing and HMAC
# ---------------------------------------------------------------
def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key, data):
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------
# Auth package (metadata + tag) stored beside the audio
# ---------------------------------------------------------------
def write_auth(auth):
    with open(AUTH_PATH, "w") as f:
        json.dump(auth, f, indent=2)


def read_auth():
    with open(AUTH_PATH, "r") as f:
        return json.load(f)


def signed_fields(auth, audio_hash):
    """The fields covered by the digital signature."""
    return json.dumps(
        {
            "sender": auth["sender"],
            "recipient": auth["recipient"],
            "message_id": auth["message_id"],
            "audio_sha256": audio_hash,
        },
        sort_keys=True,
    ).encode()


# ---------------------------------------------------------------
# RSA digital signatures (cryptography library)
# ---------------------------------------------------------------
def _pss():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()


def load_or_create_alice_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(KEY_DIR, exist_ok=True)
    priv_path = f"{KEY_DIR}/alice_private.pem"
    pub_path = f"{KEY_DIR}/alice_public.pem"

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(priv_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))

    # Always republish Alice's genuine public key, so a substituted key
    # from the key substitution test is reset whenever Alice runs again.
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return key


def load_private_key(path):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign(private_key, data):
    padding_scheme, algo = _pss()
    return private_key.sign(data, padding_scheme, algo).hex()


def verify(public_key, data, signature_hex):
    from cryptography.exceptions import InvalidSignature
    padding_scheme, algo = _pss()
    try:
        public_key.verify(bytes.fromhex(signature_hex), data, padding_scheme, algo)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------
# Replay tracking (used by Bob in signature mode)
# ---------------------------------------------------------------
def already_seen(message_id):
    if not os.path.exists(SEEN_IDS_PATH):
        return False
    with open(SEEN_IDS_PATH) as f:
        return message_id in {line.strip() for line in f}


def record_seen(message_id):
    with open(SEEN_IDS_PATH, "a") as f:
        f.write(message_id + "\n")
