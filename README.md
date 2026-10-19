# CampusTrust

CampusTrust is a classroom PKI and blockchain demo for a university. It supports RA-reviewed enrollment, two-tier X.509 certificate issuance, local browser signatures, certificate lookup and revocation, an audit log, and blockchain anchoring for certificates and signed academic actions.

Personal identity fields and certificate files stay in the local SQLite database. The EVM contract stores certificate fingerprints, revocation timestamps, and hashes of signed actions. It never stores the signed message or private keys.

## Stack

- Python 3.11+, FastAPI, SQLAlchemy/SQLite, `cryptography`, Web3.py
- React + TypeScript + Vite
- Solidity 0.8.24, Hardhat 2, local development EVM

## Start the blockchain

Open a terminal in `blockchain`:

```powershell
npm install
npm run chain
```

Leave the local chain running. In another terminal:

```powershell
cd blockchain
npm run compile
npm run deploy:local
```

Set the address printed by deploy and the first unlocked account printed by Hardhat in the project root `.env`:

```dotenv
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_CONTRACT_ADDRESS=0x...deployed-address
BLOCKCHAIN_ACCOUNT_ADDRESS=0x...first-hardhat-account
```

Copy `.env.example` first if needed. A local Hardhat node resets its chain when restarted, so redeploy the contract after a reset. These unlocked development accounts are public demo keys; never use them with real funds or a public network.

## Start the API

In another terminal:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

On first start, the API creates a demo Root CA, Intermediate CA, and SQLite database under `backend/data/`. API docs are at `http://localhost:8000/docs`.

## Start the dashboard

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Demo flow

1. Use **New enrollment** to submit a student, faculty, or staff identity.
2. In **Enrollment Requests**, approve it. The API issues an X.509 client certificate signed by the Intermediate CA, stores the certificate, anchors its fingerprint, and shows the private key once for download.
3. In **Certificate Registry**, inspect the certificate and view its fingerprint, serial number, trust status, and transaction.
4. In **Sign & Verify**, choose the active certificate, paste its downloaded private key, and sign an academic action. The browser signs locally. The API validates the X.509 chain and RSA signature, then the contract emits an event with hashes of the action and signature.
5. Revoke the certificate from the registry or **Revocation & OCSP**. The local record and smart contract show its revoked state. If the chain is unavailable, local revocation is retained and **Sync chain** publishes it when the EVM is back online.
6. In **Revocation & OCSP**, check status by fingerprint or download the Intermediate CA-signed CRL.
7. Use **Audit Log** to review lifecycle actions.

The API also exposes `GET /api/blockchain/status`, `GET /api/authorities`, `GET /api/enrollments`, `GET /api/certificates`, `GET /api/audit`, `GET /api/ocsp/{fingerprint}`, and `GET /api/crl.pem`. The status endpoint is an OCSP-style demo query, not a network OCSP protocol responder.

> This project is an educational prototype. The demo API has no administrator login or production key custody. Do not use its CA files or local unlocked accounts for real identities or a live blockchain.
