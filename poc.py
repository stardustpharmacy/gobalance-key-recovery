#!/usr/bin/env python3
import base64
import hashlib
import hmac
import queue
import sys
import time

from nacl.bindings import crypto_scalarmult_ed25519_base_noclamp
from stem.control import Controller, EventType
from stem.descriptor.hidden_service import HiddenServiceDescriptorV3


ORDER = 2**252 + 27742317777372353535851937790883648493
BASEPOINT = (
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
    b"46316835694926478169428394003475163141307993866256225615783033603165251855960)"
)

def onion_key(address):
    raw = base64.b32decode(address.removesuffix(".onion").upper())
    if len(raw) != 35 or raw[34] != 3:
        raise ValueError("expected a v3 onion address")
    public = raw[:32]
    check = hashlib.sha3_256(b".onion checksum" + public + raw[34:35]).digest()[:2]
    if not hmac.compare_digest(check, raw[32:34]):
        raise ValueError("invalid onion address checksum")
    return public

def fetch_descriptor(address):
    address = address.removesuffix(".onion").lower()
    result = queue.Queue()

    def on_content(event):
        if event.address and event.address.lower().removesuffix(".onion") == address and event.descriptor:
            result.put(HiddenServiceDescriptorV3(event.descriptor.get_bytes(), validate=False))

    with Controller.from_port(address="127.0.0.1", port=9051) as tor:
        tor.authenticate()
        tor.add_event_listener(on_content, EventType.HS_DESC_CONTENT)
        reply = tor.msg("HSFETCH " + address)
        if not reply.is_ok():
            raise RuntimeError(str(reply))
        return result.get(timeout=180)

def blinding_param(identity_key, period):
    data = (b"Derive temporary signing key\x00" + identity_key + BASEPOINT + b"key-blind" + period.to_bytes(8, "big") + (1440).to_bytes(8, "big"))
    return hashlib.sha3_256(data).digest()

def hint(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")

def recover_scalar(cert, nonce):
    signature = cert.signature
    blinded_key = cert.signing_key()
    message = cert.pack()[:-64]
    prefix = hashlib.sha512(b"Derive temporary signing key hash input").digest()[:32]
    r = hint(prefix + message) % ORDER
    challenge = hint(signature[:32] + blinded_key + message) % ORDER
    blinded_scalar = ((int.from_bytes(signature[32:], "little") - r) * pow(challenge, -1, ORDER)) % ORDER

    multiplier = 1 << 254
    for bit in range(3, 254):
        if nonce[bit // 8] >> (bit % 8) & 1:
            multiplier += 1 << bit
    return blinded_scalar * pow(multiplier % ORDER, -1, ORDER) % ORDER


def main():
    address = sys.argv[1].lower()

    try:
        identity_key = onion_key(address)
        print(f"fetching {address}")
        descriptor = fetch_descriptor(address)
        #print(descriptor)
    except Exception as exc:
        raise SystemExit(f"fetch failed: {exc}") from exc

    cert = descriptor.signing_cert
    now = int(time.time()) // 60
    current_period = (now - 720) // 1440

    for period in range(current_period - 2, current_period + 3):
        scalar = recover_scalar(cert, blinding_param(identity_key, period))
        public = crypto_scalarmult_ed25519_base_noclamp(scalar.to_bytes(32, "little"))

        if hmac.compare_digest(public, identity_key):
            print(scalar.to_bytes(32, "little").hex())
            return 0

    print("nuhuh")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
