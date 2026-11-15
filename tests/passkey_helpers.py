"""A software passkey and a stand-in for the approval page, for the approval tests.

`Authenticator` produces the responses a browser's WebAuthn API would hand to
the page (a real P-256 key, real signatures over real authenticator data), and
`Page` posts them the way `approve.js` does. The server side that checks them
is the production code and the `fido2` library, unmodified.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

import httpx2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData
from helpers import base_config, hash_token

ORIGIN = "http://localhost"
TOKEN_A2 = "agw_test-token-for-person-a-second-client-3333333"


def approval_config(**approvals: Any) -> dict[str, Any]:
    """The base config plus an approval page, a second client for person_a, and a household write tool."""
    raw = base_config()
    raw["approvals"] = {"origin": ORIGIN, "store": "approvals.sqlite", **approvals}
    raw["clients"].append({"id": "agent-a2", "principal": "person_a", "token_sha256": hash_token(TOKEN_A2)})
    house = next(c for c in raw["connections"] if c["id"] == "notes-house")
    house["tools"].append({"upstream": "add_note", "name": "house_add_note"})
    raw["policy"].append(
        {
            "principals": ["person_a", "person_b", "household"],
            "connection": "notes-house",
            "tools": ["house_add_note"],
            "effect": "approval_required",
        }
    )
    return raw


def request_id_in(message: str) -> str:
    found = re.search(r"/approvals/r/([A-Za-z0-9_-]+)", message)
    assert found, message
    return found.group(1)


class Authenticator:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.id = secrets.token_bytes(16)
        self.counter = 0
        self.user_handle: bytes | None = None

    def response(self, ceremony: dict[str, Any], *, origin: str = ORIGIN, verified: bool = True) -> dict[str, Any]:
        options = ceremony["options"]["publicKey"]
        register = "user" in options
        rp_id = options["rp"]["id"] if register else options["rpId"]
        client = CollectedClientData.create(
            "webauthn.create" if register else "webauthn.get", options["challenge"], origin
        )
        self.counter += 1
        flags = AuthenticatorData.FLAG.UP
        if verified:
            flags |= AuthenticatorData.FLAG.UV
        attested = b""
        if register:
            flags |= AuthenticatorData.FLAG.AT
            self.user_handle = bytes(websafe_decode(options["user"]["id"]))
            attested = AttestedCredentialData.create(b"\0" * 16, self.id, ES256.from_cryptography_key(self.key.public_key()))
        auth = AuthenticatorData.create(hashlib.sha256(rp_id.encode()).digest(), flags, self.counter, attested)
        response: dict[str, Any] = {"clientDataJSON": websafe_encode(client)}
        if register:
            response["attestationObject"] = websafe_encode(cbor.encode({"fmt": "none", "authData": bytes(auth), "attStmt": {}}))
        else:
            response["authenticatorData"] = websafe_encode(auth)
            response["signature"] = websafe_encode(self.key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256())))
            if self.user_handle is not None:
                response["userHandle"] = websafe_encode(self.user_handle)
        return {"id": websafe_encode(self.id), "rawId": websafe_encode(self.id), "type": "public-key", "response": response}


class Page:
    """What `approve.js` does, without a browser."""

    def __init__(self, base: str, origin: str = ORIGIN) -> None:
        self.base = base
        self.origin = origin

    async def _post(self, path: str, body: Any) -> tuple[int, Any]:
        async with httpx2.AsyncClient(base_url=self.base) as http:
            reply = await http.post(f"/approvals/api/{path}", json=body, headers={"Origin": self.origin})
            return reply.status_code, reply.json()

    async def view(self, request_id: str) -> tuple[int, Any]:
        async with httpx2.AsyncClient(base_url=self.base) as http:
            reply = await http.get(f"/approvals/api/request/{request_id}")
            return reply.status_code, reply.json()

    async def begin(self, action: str, target: str) -> tuple[int, Any]:
        return await self._post("begin", {"action": action, "target": target})

    async def finish(self, ceremony: dict[str, Any], response: Any) -> tuple[int, Any]:
        return await self._post("finish", {"ceremony_id": ceremony["ceremony_id"], "response": response})

    async def decide(self, action: str, target: str, authenticator: Authenticator, **how: Any) -> tuple[int, Any]:
        status, ceremony = await self.begin(action, target)
        if status != 200:
            return status, ceremony
        return await self.finish(ceremony, authenticator.response(ceremony, **how))

    async def enroll(self, gateway: Any, principal: str) -> Authenticator:
        link = gateway.approver.new_enrollment(principal)
        authenticator = Authenticator()
        status, result = await self.decide("enroll", link.split("#", 1)[1], authenticator)
        assert status == 200, result
        return authenticator



async def wait_for_approval(client, request_id, seconds=10):
    return await client.call_tool("gateway_call_tool", {"request_id": request_id, "wait_seconds": seconds})
