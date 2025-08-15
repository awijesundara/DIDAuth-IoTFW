import os, json, base64, hashlib, re, binascii
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import requests
from dotenv import load_dotenv
from web3 import Web3
from cryptography.fernet import Fernet
from fastapi import HTTPException

                  
load_dotenv()
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
FERNET_SECRET = os.getenv("FERNET_SECRET")
if not FERNET_SECRET:
    raise RuntimeError("FERNET_SECRET environment variable is required")
FERNET_SECRET = FERNET_SECRET.encode()

DATA_DIR = "data"
VC_DIR_TEMPLATE = os.path.join(DATA_DIR, "vendors", "{did_name}", "vcs", "{version}")
KEY_DIR_TEMPLATE = os.path.join(DATA_DIR, "vendors", "{did_name}", "keys")
APIKEY_DIR = os.path.join(DATA_DIR, "vendors", "{did_name}", "apikey.key")
                                                      
IPFS_API_URL = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001/api/v0")

fernet = Fernet(FERNET_SECRET)


def enforce_permissions():
    """Restrict sensitive files to user-only access on startup."""
    for root, _, files in os.walk(DATA_DIR):
        for name in files:
            if name in {"private_key.pem", "public_key.pem", "apikey.key"}:
                try:
                    os.chmod(os.path.join(root, name), 0o600)
                except OSError:
                    pass


enforce_permissions()

def sanitize_name(name: str) -> str:
    if not re.match(r"^[A-Za-z0-9_-]+$", name):
        raise HTTPException(status_code=400, detail="Invalid name")
    return name

def load_or_create_keys(did_name: str):
    did_name = sanitize_name(did_name)
    key_dir = KEY_DIR_TEMPLATE.format(did_name=did_name)
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, "private_key.pem")
    pub_path = os.path.join(key_dir, "public_key.pem")

    if not os.path.exists(priv_path):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    else:
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    # enforce owner-only permissions (0o600) for key files
    for path in (priv_path, pub_path):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    with open(pub_path, "r") as f:
        pubkey_pem = f.read()

    return private_key, pubkey_pem

def save_api_key(did_name: str):
    did_name = sanitize_name(did_name)
    api_key = Fernet.generate_key().decode()
    encrypted = fernet.encrypt(api_key.encode()).decode()

    apikey_path = APIKEY_DIR.format(did_name=did_name)
    os.makedirs(os.path.dirname(apikey_path), exist_ok=True)
    with open(apikey_path, "w") as f:
        f.write(encrypted)

    try:
        os.chmod(apikey_path, 0o600)
    except OSError:
        pass  # best effort to lock down API key file

    return api_key

def verify_api_key(did_name: str, api_key: str):
    did_name = sanitize_name(did_name)
    apikey_path = APIKEY_DIR.format(did_name=did_name)
    if not os.path.exists(apikey_path):
        return False
    with open(apikey_path, "r") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted.encode()).decode()
        return api_key == decrypted
    except Exception:
        return False

def ipfs_upload(json_obj):
    json_str = json.dumps(json_obj)
    files = {'file': ('vc.json', json_str)}
    try:
        res = requests.post(f"{IPFS_API_URL}/add", files=files, timeout=10)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"IPFS upload failed: {e}")
    return res.json().get("Hash")


def ipfs_upload_bytes(data: bytes) -> str:
    files = {"file": ("firmware.bin", data)}
    try:
        res = requests.post(f"{IPFS_API_URL}/add", files=files, timeout=10)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"IPFS upload failed: {e}")
    return res.json().get("Hash")

def ipfs_download(cid: str):
    try:
        res = requests.post(f"{IPFS_API_URL}/cat?arg={cid}", timeout=10)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=f"IPFS download failed: {e}")
    return json.loads(res.content)

def issue_vc(did_name: str, firmware_version: str, device_model: str, firmware_b64: str):
    did_name = sanitize_name(did_name)
    try:
        firmware_bytes = base64.b64decode(firmware_b64)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid base64 data")
    firmware_hash = hashlib.sha256(firmware_bytes).hexdigest()

    firmware_cid = ipfs_upload_bytes(firmware_bytes)

    private_key, pubkey_pem = load_or_create_keys(did_name)

    # Build salts and leaf hashes for each claim
    claims = {
        "firmwareVersion": firmware_version,
        "firmwareHash": firmware_hash,
        "deviceModel": device_model,
    }
    salts = {}
    leaf_hashes = []
    for k in sorted(claims.keys()):
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()
        salts[k] = salt
        leaf = hashlib.sha256(f"{k}:{claims[k]}:{salt}".encode()).hexdigest()
        leaf_hashes.append(leaf)

    # Compute Merkle root
    def merkle_root(leaves):
        if not leaves:
            return ""
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

    root = merkle_root(leaf_hashes)

    vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "FirmwareCredential"],
        "id": f"vc:{did_name}:{firmware_version}",
        "issuer": f"did:local:{did_name}",
        "issuanceDate": datetime.utcnow().isoformat() + "Z",
        "credentialSubject": {},
        "commitmentRoot": root,
        "firmwareCid": firmware_cid,
        "contractAddress": CONTRACT_ADDRESS,
    }

    message = json.dumps(vc, separators=(",", ":"), sort_keys=True).encode()
    signature = private_key.sign(message)

    vc["proof"] = {
        "type": "Ed25519Signature2020",
        "verificationMethod": {
            "id": f"did:local:{did_name}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": f"did:local:{did_name}",
            "publicKeyPem": pubkey_pem
        },
        "jws": base64.urlsafe_b64encode(signature).decode()
    }

    vc_dir = VC_DIR_TEMPLATE.format(did_name=did_name, version=firmware_version)
    os.makedirs(vc_dir, exist_ok=True)
    with open(os.path.join(vc_dir, "firmware_vc.json"), "w") as f:
        json.dump(vc, f, indent=2)
    # Persist salts and claims for proof generation
    proof_data = {"claims": claims, "salts": salts}
    with open(os.path.join(vc_dir, "salts.json"), "w") as f:
        json.dump(proof_data, f, indent=2)

    try:
        cid = ipfs_upload(vc)
    except HTTPException as e:
        return {"status": e.detail, "vc": vc, "ipfs_cid": None}

    return {
        "status": "✅ VC issued",
        "vc": vc,
        "ipfs_cid": cid,
        "firmware_cid": firmware_cid,
        "proof_data": proof_data,
    }

def verify_vc(vc: dict, contract):
    vc_data = vc.copy()
    proof = vc_data.pop("proof")
    vc_id = vc_data.get("id")
    issuer = vc_data.get("issuer")
    vc_contract_address = vc_data.get("contractAddress")

    if not vc_contract_address:
        return {
            "valid": False,
            "status": "contractAddress missing",
        }

    if Web3.to_checksum_address(vc_contract_address) != contract.address:
        return {
            "valid": False,
            "status": "❌ VC was not issued by current smart contract",
            "issuer": issuer,
            "revoked": None
        }

    message = json.dumps(vc_data, separators=(",", ":"), sort_keys=True).encode()
    signature = base64.urlsafe_b64decode(proof["jws"] + "==")

    pubkey_pem = proof["verificationMethod"]["publicKeyPem"]
    public_key = serialization.load_pem_public_key(pubkey_pem.encode())

    try:
        public_key.verify(signature, message)
        is_revoked = contract.functions.isVCRevoked(vc_id).call()
        return {
            "valid": not is_revoked,
            "issuer": issuer,
            "revoked": is_revoked,
            "status": "✅ Signature valid" if not is_revoked else "❌ Revoked"
        }
    except InvalidSignature:
        return {
            "valid": False,
            "issuer": issuer,
            "revoked": False,
            "status": "❌ Invalid signature"
        }


def revoke_vc(vc_id: str, w3: Web3, contract, account, eth_private_key):
    nonce = w3.eth.get_transaction_count(account.address)
    txn = contract.functions.revokeVC(vc_id).build_transaction({
        "from": account.address,
        "nonce": nonce,
        "gas": 1000000,
        "maxFeePerGas": w3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
    })
    signed = w3.eth.account.sign_transaction(txn, eth_private_key)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise HTTPException(status_code=500, detail="Blockchain transaction failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain error: {e}")

    return w3.to_hex(tx_hash)

