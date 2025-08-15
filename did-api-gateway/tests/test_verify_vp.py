import base64
import json
import asyncio
import importlib.util
import hashlib
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location(
    "did_vc_api", Path(__file__).resolve().parents[1] / "did_vc_api.py"
)
did_vc_api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(did_vc_api)

class DummyRequest:
    def __init__(self, data):
        self._data = data
    async def json(self):
        return self._data

def _setup_did(tmp_path):
    did_dir = Path(did_vc_api.DID_DIR_TEMPLATE.format(name="test"))
    did_dir.mkdir(parents=True, exist_ok=True)
    did_doc = {"verificationMethod": [{"publicKeyPem": "pem"}]}
    with open(did_dir / "did.json", "w") as f:
        json.dump(did_doc, f)

class StubKey:
    def verify(self, *args, **kwargs):
        return None

def test_verify_vp_bad_firmware_hash(tmp_path, monkeypatch):
    _setup_did(tmp_path)
    monkeypatch.setattr(did_vc_api.serialization, "load_pem_public_key", lambda *_: StubKey())
    monkeypatch.setattr(did_vc_api, "contract", None)

    fw_data = b"realfirmware"
    class Resp:
        status_code = 200
        content = fw_data
        def raise_for_status(self):
            pass
    class Client:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
        async def get(self, url):
            return Resp()
    monkeypatch.setattr(did_vc_api.httpx, "AsyncClient", Client)

    claims = {"firmwareHash": "bad", "firmwareVersion": "1", "deviceModel": "x"}
    salts = {k: f"salt{i}" for i, k in enumerate(sorted(claims.keys()))}

    def leaf(k):
        return hashlib.sha256(f"{k}:{claims[k]}:{salts[k]}".encode()).hexdigest()

    keys = sorted(claims.keys())
    leaves = [leaf(k) for k in keys]

    def merkle(leaves):
        lvl = leaves[:]
        while len(lvl) > 1:
            if len(lvl) % 2 == 1:
                lvl.append(lvl[-1])
            nxt = []
            for i in range(0, len(lvl), 2):
                a, b = sorted([lvl[i], lvl[i + 1]])
                nxt.append(hashlib.sha256((a + b).encode()).hexdigest())
            lvl = nxt
        return lvl[0]

    def proof_for(leaves, idx):
        proof = []
        lvl = leaves[:]
        index = idx
        while len(lvl) > 1:
            if len(lvl) % 2 == 1:
                lvl.append(lvl[-1])
            nxt = []
            for i in range(0, len(lvl), 2):
                pair = [lvl[i], lvl[i + 1]]
                if i == index or i + 1 == index:
                    sibling = pair[0] if i + 1 == index else pair[1]
                    proof.append(sibling)
                    index = len(nxt)
                nxt.append(hashlib.sha256(''.join(sorted(pair)).encode()).hexdigest())
            lvl = nxt
        return proof

    root = merkle(leaves)
    idx = keys.index("firmwareHash")
    proof = proof_for(leaves, idx)

    vc = {
        "id": "vc:test:1",
        "issuer": "did:local:test",
        "firmwareCid": "cid",
        "commitmentRoot": root,
        "proof": {"jws": base64.urlsafe_b64encode(b"sig").decode(), "verificationMethod": {"publicKeyPem": "pem"}},
    }
    disclosures = [{"claim": {"firmwareHash": "bad"}, "salt": salts["firmwareHash"], "merkleProof": proof}]
    vp = {"verifiableCredential": [vc], "disclosures": disclosures}
    req = DummyRequest(vp)
    result = asyncio.run(did_vc_api.verify_vp(req))
    assert result["firmware_hash_match"] is False


def test_verify_vp_requires_secure_element(tmp_path, monkeypatch):
    _setup_did(tmp_path)
    monkeypatch.setattr(did_vc_api.serialization, "load_pem_public_key", lambda *_: StubKey())
    monkeypatch.setattr(did_vc_api, "contract", None)

    vc = {
        "id": "vc:test:1",
        "issuer": "did:local:test",
        "credentialSubject": {},
        "proof": {"jws": base64.urlsafe_b64encode(b"sig").decode(), "verificationMethod": {"publicKeyPem": "pem"}},
    }
    vp = {"verifiableCredential": [vc]}
    req = DummyRequest(vp)
    with pytest.raises(did_vc_api.HTTPException):
        asyncio.run(did_vc_api.verify_vp(req, require_secure_element=True))
