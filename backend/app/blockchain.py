"""Minimal Web3.py adapter for the local CampusTrust EVM demo."""
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from web3 import Web3

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

ABI: list[dict[str, Any]] = [
    {"type": "function", "name": "owner", "stateMutability": "view", "inputs": [], "outputs": [{"name": "", "type": "address"}]},
    {"type": "function", "name": "anchorCertificate", "stateMutability": "nonpayable", "inputs": [{"name": "fingerprint", "type": "bytes32"}], "outputs": []},
    {"type": "function", "name": "revokeCertificate", "stateMutability": "nonpayable", "inputs": [{"name": "fingerprint", "type": "bytes32"}], "outputs": []},
    {"type": "function", "name": "getCertificate", "stateMutability": "view", "inputs": [{"name": "fingerprint", "type": "bytes32"}], "outputs": [{"name": "issuer", "type": "address"}, {"name": "issuedAt", "type": "uint64"}, {"name": "revokedAt", "type": "uint64"}, {"name": "exists", "type": "bool"}]},
    {"type": "function", "name": "anchorSignedAction", "stateMutability": "nonpayable", "inputs": [{"name": "fingerprint", "type": "bytes32"}, {"name": "actionHash", "type": "bytes32"}, {"name": "contentHash", "type": "bytes32"}], "outputs": []},
]


class BlockchainNotConfigured(Exception):
    pass


def _client() -> tuple[Web3, Any, str]:
    rpc_url = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
    contract_address = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", "")
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 2}))
    if not w3.is_connected():
        raise BlockchainNotConfigured("Local EVM node is offline")
    if not contract_address:
        raise BlockchainNotConfigured("Deploy CampusTrustRegistry and set BLOCKCHAIN_CONTRACT_ADDRESS")
    address = Web3.to_checksum_address(contract_address)
    return w3, w3.eth.contract(address=address, abi=ABI), address


def _fingerprint(value: str) -> bytes:
    clean = value.lower().removeprefix("0x")
    if len(clean) != 64 or any(c not in "0123456789abcdef" for c in clean):
        raise ValueError("Fingerprint must be a 32-byte SHA-256 hex value")
    return bytes.fromhex(clean)


def _send(w3: Web3, contract: Any, method: str, *args: Any) -> str:
    # The local Hardhat node provides unlocked development accounts. Do not expose
    # this transaction pattern as a production key-management solution.
    sender = os.getenv("BLOCKCHAIN_ACCOUNT_ADDRESS", "")
    if not sender:
        raise BlockchainNotConfigured("Set BLOCKCHAIN_ACCOUNT_ADDRESS to the local Hardhat deployer")
    tx_hash = getattr(contract.functions, method)(*args).transact({"from": Web3.to_checksum_address(sender)})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status != 1:
        raise RuntimeError("Blockchain transaction reverted")
    return tx_hash.hex()


def status() -> dict[str, Any]:
    try:
        w3, contract, address = _client()
        return {"connected": True, "chain_id": w3.eth.chain_id, "block_number": w3.eth.block_number, "contract_address": address}
    except Exception as exc:
        return {"connected": False, "chain_id": None, "block_number": None, "contract_address": None, "detail": str(exc)}


def anchor(fingerprint: str) -> dict[str, str]:
    w3, contract, _ = _client()
    tx_hash = _send(w3, contract, "anchorCertificate", _fingerprint(fingerprint))
    return {"transaction_hash": tx_hash, "fingerprint": fingerprint.removeprefix("0x").lower()}


def revoke(fingerprint: str) -> dict[str, str]:
    w3, contract, _ = _client()
    tx_hash = _send(w3, contract, "revokeCertificate", _fingerprint(fingerprint))
    return {"transaction_hash": tx_hash, "fingerprint": fingerprint.removeprefix("0x").lower()}


def lookup(fingerprint: str) -> dict[str, Any]:
    _, contract, _ = _client()
    issuer, issued_at, revoked_at, exists = contract.functions.getCertificate(_fingerprint(fingerprint)).call()
    return {"fingerprint": fingerprint.removeprefix("0x").lower(), "exists": exists, "issuer": issuer, "issued_at": issued_at, "revoked_at": revoked_at, "revoked": revoked_at != 0}


def anchor_signed_action(fingerprint: str, action_hash: str, content_hash: str) -> dict[str, str]:
    w3, contract, _ = _client()
    tx_hash = _send(w3, contract, "anchorSignedAction", _fingerprint(fingerprint), _fingerprint(action_hash), _fingerprint(content_hash))
    return {"transaction_hash": tx_hash, "fingerprint": fingerprint.removeprefix("0x").lower(), "action_hash": action_hash, "content_hash": content_hash}

