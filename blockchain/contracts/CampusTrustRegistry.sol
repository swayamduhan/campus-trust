// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CampusTrustRegistry
/// @notice Anchors certificate fingerprints and revocation state on an EVM chain.
/// @dev Never put names, student IDs, certificate contents, or private keys on-chain.
contract CampusTrustRegistry {
    struct CertificateRecord {
        address issuer;
        uint64 issuedAt;
        uint64 revokedAt;
        bool exists;
    }

    address public immutable owner;
    mapping(bytes32 => CertificateRecord) private records;

    event CertificateAnchored(bytes32 indexed fingerprint, address indexed issuer, uint64 issuedAt);
    event CertificateRevoked(bytes32 indexed fingerprint, address indexed revokedBy, uint64 revokedAt);
    event SignedActionAnchored(bytes32 indexed fingerprint, bytes32 indexed actionHash, bytes32 contentHash, uint64 timestamp);

    error Unauthorized();
    error AlreadyAnchored();
    error UnknownCertificate();
    error AlreadyRevoked();
    error RevokedCredential();

    constructor() { owner = msg.sender; }

    function anchorCertificate(bytes32 fingerprint) external {
        if (msg.sender != owner) revert Unauthorized();
        if (records[fingerprint].exists) revert AlreadyAnchored();
        uint64 nowTime = uint64(block.timestamp);
        records[fingerprint] = CertificateRecord(msg.sender, nowTime, 0, true);
        emit CertificateAnchored(fingerprint, msg.sender, nowTime);
    }

    function revokeCertificate(bytes32 fingerprint) external {
        if (msg.sender != owner) revert Unauthorized();
        CertificateRecord storage record = records[fingerprint];
        if (!record.exists) revert UnknownCertificate();
        if (record.revokedAt != 0) revert AlreadyRevoked();
        record.revokedAt = uint64(block.timestamp);
        emit CertificateRevoked(fingerprint, msg.sender, record.revokedAt);
    }

    function anchorSignedAction(bytes32 fingerprint, bytes32 actionHash, bytes32 contentHash) external {
        if (msg.sender != owner) revert Unauthorized();
        CertificateRecord memory record = records[fingerprint];
        if (!record.exists) revert UnknownCertificate();
        if (record.revokedAt != 0) revert RevokedCredential();
        emit SignedActionAnchored(fingerprint, actionHash, contentHash, uint64(block.timestamp));
    }

    function getCertificate(bytes32 fingerprint)
        external view returns (address issuer, uint64 issuedAt, uint64 revokedAt, bool exists)
    {
        CertificateRecord memory record = records[fingerprint];
        return (record.issuer, record.issuedAt, record.revokedAt, record.exists);
    }
}
