// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract PKIRegistry {
    /**
     * @dev The owner of the contract.
     */
    address private immutable owner;

    /**
     * @dev The role of a certificate.
     */
    enum CertificateRole {
        RootCA,
        IntermediateCA,
        EndEntity
    }

    /**
     * @dev The status of a certificate.
     */
    struct Certificate {
        address owner;
        bytes32 issuerCertificateHash;
        uint256 issuedAt;
        uint256 expiresAt;
        uint256 revokedAt;
        CertificateRole role;
    }

    /**
     * @dev The certificates by certificate hash.
     */
    mapping(bytes32 certificateHash => Certificate certificate)
        private certificates;

    /**
     * @dev The certificates by owner.
     */
    mapping(address owner => bytes32[] certificateHashes)
        private certificatesByOwner;

    /**
     * @notice Event emitted when a certificate is issued.
     * @param owner The owner of the certificate.
     * @param certificateHash The hash of the certificate.
     * @param expiresAt The expiration date of the certificate.
     */
    event CertificateIssued(
        address indexed owner,
        bytes32 indexed certificateHash,
        bytes32 indexed issuerCertificateHash,
        uint256 expiresAt
    );

    /**
     * @notice Event emitted when a certificate is revoked.
     * @param certificateHash The hash of the certificate.
     * @param revokedAt The date the certificate was revoked.
     */
    event CertificateRevoked(
        address indexed revoker,
        bytes32 indexed certificateHash,
        uint256 revokedAt
    );

    /**
     * @notice Error emitted when the caller is not the owner of the contract.
     * @param caller The address that called the function.
     */
    error CallerNotOwner(address caller);

    /**
     * @notice Error emitted when the caller is not the issuer of the certificate.
     * @param caller The address that called the function.
     * @param issuerCertificateHash The hash of the issuer certificate.
     */
    error CallerNotIssuer(address caller, bytes32 issuerCertificateHash);

    /**
     * @notice Error emitted when the caller is not the issuer or the owner of the certificate.
     * @param caller The address that called the function.
     * @param certificateHash The hash of the certificate.
     */
    error CallerNotIssuerNorOwner(address caller, bytes32 certificateHash);

    /**
     * @notice Error emitted when the issuance is not allowed.
     * @param issuerRole The role of the issuer certificate.
     * @param newCertificateRole The role of the new certificate.
     */
    error IssuanceNotAllowed(
        CertificateRole issuerRole,
        CertificateRole newCertificateRole
    );

    /**
     * @notice Error emitted when the caller is not the owner or the issuer of the certificate.
     * @param caller The address that called the function.
     * @param certificateHash The hash of the certificate.
     */
    error CallerNotCertificateOwnerOrIssuer(
        address caller,
        bytes32 certificateHash
    );

    /**
     * @notice Error emitted when the certificate is not registered.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateNotRegistered(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate is already registered.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyRegistered(bytes32 certificateHash);

    /**
     * @notice Error emitted when the issuer certificate is not trusted.
     * @param issuerCertificateHash The hash of the issuer certificate.
     */
    error IssuerNotTrusted(bytes32 issuerCertificateHash);

    /**
     * @notice Error emitted when the issuance timestamp is in the future.
     * @param issuedAt The timestamp of the certificate issuance.
     * @param blockTimestamp The timestamp of the block.
     */
    error IssuanceTimestampInFuture(uint256 issuedAt, uint256 blockTimestamp);

    /**
     * @notice Error emitted when the certificate is already expired.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyExpired(bytes32 certificateHash);

    /**
     * @notice Error emitted when the owner is invalid.
     * @param owner The owner of the certificate.
     */
    error InvalidOwnerAddress(address owner);

    /**
     * @notice Error emitted when the certificate hash is invalid.
     * @param certificateHash The hash of the certificate.
     */
    error InvalidCertificateHash(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate validity period is too long compared to the issuer certificate.
     * @param certificateExpiresAt The expiration date of the certificate.
     * @param issuerCertificateExpiresAt The expiration date of the issuer certificate.
     */
    error CertificateValidityPeriodTooLong(
        uint256 certificateExpiresAt,
        uint256 issuerCertificateExpiresAt
    );

    /**
     * @notice Error emitted when the certificate is issued before the issuer certificate.
     * @param certificateIssuedAt The date the certificate was issued.
     * @param issuerCertificateIssuedAt The date the issuer certificate was issued.
     */
    error CertificateIssuedBeforeIssuerCertificate(
        uint256 certificateIssuedAt,
        uint256 issuerCertificateIssuedAt
    );

    /**
     * @notice Error emitted when the certificate is already revoked.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyRevoked(bytes32 certificateHash);

    /**
     * @dev Modifier to check if the caller is the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner, CallerNotOwner(msg.sender));

        _;
    }

    /**
     * @dev Modifier to check if the caller is the issuer of the certificate.
     * @param issuerCertificateHash The hash of the issuer certificate.
     * @param newCertificateRole The role of the new certificate to be issued.
     */
    modifier onlyIssuer(
        bytes32 issuerCertificateHash,
        CertificateRole newCertificateRole
    ) {
        Certificate memory issuerCertificate = certificates[
            issuerCertificateHash
        ];

        // Verify the caller is the owner of the issuer certificate.
        require(
            issuerCertificate.owner == msg.sender,
            CallerNotIssuer(msg.sender, issuerCertificateHash)
        );

        // Verify the issuance is allowed.
        require(
            _isIssuanceAllowed(issuerCertificate.role, newCertificateRole),
            IssuanceNotAllowed(issuerCertificate.role, newCertificateRole)
        );

        // Verify the certificate is trusted.
        require(
            isValidCertificate(issuerCertificateHash),
            IssuerNotTrusted(issuerCertificateHash)
        );

        _;
    }

    /**
     * @dev Modifier to check if the caller is the owner or the issuer of the certificate.
     * @param certificateHash The hash of the certificate.
     */
    modifier onlyCertificateOwnerOrIssuer(bytes32 certificateHash) {
        Certificate memory certificate = certificates[certificateHash];

        // Verify the certificate is registered.
        require(
            certificate.issuedAt != 0,
            CertificateNotRegistered(certificateHash)
        );

        // Verify the caller is the owner of the certificate.
        if (certificate.owner != msg.sender) {
            Certificate memory issuerCertificate = certificates[
                certificate.issuerCertificateHash
            ];

            // Verify the caller is the issuer of the certificate.
            require(
                issuerCertificate.owner == msg.sender,
                CallerNotIssuerNorOwner(msg.sender, certificateHash)
            );

            // Verify the certificate is trusted.
            require(
                isValidCertificate(certificate.issuerCertificateHash),
                IssuerNotTrusted(certificate.issuerCertificateHash)
            );
        }

        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Issues a root certificate.
     * @param certificateHash The hash of the certificate.
     * @param owner_ The owner of the certificate.
     * @param issuedAt The date the certificate was issued.
     * @param expiresAt The expiration date of the certificate.
     */
    function issueRootCertificate(
        bytes32 certificateHash,
        address owner_,
        uint256 issuedAt,
        uint256 expiresAt
    ) external onlyOwner {
        _issueCertificate(
            certificateHash,
            bytes32(0),
            owner_,
            issuedAt,
            expiresAt,
            CertificateRole.RootCA
        );
    }

    /**
     * @notice Issues a certificate.
     * @param certificateHash The hash of the certificate.
     * @param issuerCertificateHash The hash of the issuer certificate.
     * @param owner_ The owner of the certificate.
     * @param issuedAt The date the certificate was issued.
     * @param expiresAt The expiration date of the certificate.
     */
    function issueCertificate(
        bytes32 certificateHash,
        bytes32 issuerCertificateHash,
        address owner_,
        uint256 issuedAt,
        uint256 expiresAt,
        CertificateRole role
    ) external onlyIssuer(issuerCertificateHash, role) {
        _issueCertificate(
            certificateHash,
            issuerCertificateHash,
            owner_,
            issuedAt,
            expiresAt,
            role
        );
    }

    /**
     * @notice Issues a certificate.
     * @param certificateHash The hash of the certificate.
     * @param issuerCertificateHash The hash of the issuer certificate.
     * @param owner_ The owner of the certificate.
     * @param issuedAt The date the certificate was issued.
     * @param expiresAt The expiration date of the certificate.
     * @param role The role of the certificate.
     */
    function _issueCertificate(
        bytes32 certificateHash,
        bytes32 issuerCertificateHash,
        address owner_,
        uint256 issuedAt,
        uint256 expiresAt,
        CertificateRole role
    ) private {
        // Verify the certificate is not registered.
        require(
            certificates[certificateHash].issuedAt == 0,
            CertificateAlreadyRegistered(certificateHash)
        );

        // Verify the issuance timestamp isn't in the future.
        require(
            issuedAt <= block.timestamp,
            IssuanceTimestampInFuture(issuedAt, block.timestamp)
        );

        // Verify the expiration date is in the future.
        require(
            expiresAt > block.timestamp,
            CertificateAlreadyExpired(certificateHash)
        );

        // Verify the owner is not the zero address.
        require(owner_ != address(0), InvalidOwnerAddress(owner_));

        // Verify the certificate hash is not the zero hash.
        require(
            certificateHash != bytes32(0),
            InvalidCertificateHash(certificateHash)
        );

        // Verify the timestamp based on the issuer expiration date.
        if (issuerCertificateHash != bytes32(0)) {
            Certificate memory issuerCertificate = certificates[
                issuerCertificateHash
            ];

            // Verify the certificate isn't longer than the issuer certificate.
            require(
                expiresAt <= issuerCertificate.expiresAt,
                CertificateValidityPeriodTooLong(
                    expiresAt,
                    issuerCertificate.expiresAt
                )
            );

            // Verify the certificate is issued after the issuer certificate.
            require(
                issuedAt >= issuerCertificate.issuedAt,
                CertificateIssuedBeforeIssuerCertificate(
                    issuedAt,
                    issuerCertificate.issuedAt
                )
            );
        }

        // Register the certificate.
        certificates[certificateHash] = Certificate({
            owner: owner_,
            issuerCertificateHash: issuerCertificateHash,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            revokedAt: 0,
            role: role
        });

        // Add the certificate to the owner's certificates.
        certificatesByOwner[owner_].push(certificateHash);

        // Notify the event.
        emit CertificateIssued(
            owner_,
            certificateHash,
            issuerCertificateHash,
            expiresAt
        );
    }

    /**
     * @notice Revokes a certificate.
     * @param certificateHash The hash of the certificate.
     */
    function revokeCertificate(
        bytes32 certificateHash
    ) external onlyCertificateOwnerOrIssuer(certificateHash) {
        // Verify the certificate is not revoked.
        require(
            certificates[certificateHash].revokedAt == 0,
            CertificateAlreadyRevoked(certificateHash)
        );

        // Verify the certificate is not expired.
        require(
            certificates[certificateHash].expiresAt > block.timestamp,
            CertificateAlreadyExpired(certificateHash)
        );

        // Revoke the certificate.
        certificates[certificateHash].revokedAt = block.timestamp;

        emit CertificateRevoked(msg.sender, certificateHash, block.timestamp);
    }

    /**
     * @notice Verifies if a certificate is valid.
     * @param certificateHash The hash of the certificate.
     * @return True if the chain of trust is valid, false otherwise.
     */
    function isValidCertificate(
        bytes32 certificateHash
    ) public view returns (bool) {
        return _verifyChainOfTrust(certificateHash);
    }

    /**
     * @notice Verifies the chain of trust for a certificate.
     * @param _certificateHash The hash of the certificate.
     * @return True if the chain of trust is valid, false otherwise.
     */
    function _verifyChainOfTrust(
        bytes32 _certificateHash
    ) private view returns (bool) {
        Certificate memory certificate = certificates[_certificateHash];

        // Verify the certificate is registered, not revoked and not expired.
        if (
            certificate.issuedAt == 0 ||
            certificate.revokedAt != 0 ||
            block.timestamp > certificate.expiresAt
        ) {
            return false;
        }

        // If the certificate is the Root CA, then the chain of trust is valid.
        if (certificate.role == CertificateRole.RootCA) {
            return true;
        }

        // Verify the chain of trust for the issuer certificate.
        return _verifyChainOfTrust(certificate.issuerCertificateHash);
    }

    /**
     * @notice Verifies if a certificate is a valid issuance.
     * @param _issuerRole The role of the issuer certificate.
     * @param _newCertificateRole The role of the new certificate.
     * @return True if the issuance is valid, false otherwise.
     */
    function _isIssuanceAllowed(
        CertificateRole _issuerRole,
        CertificateRole _newCertificateRole
    ) private pure returns (bool) {
        if (_issuerRole == CertificateRole.RootCA) {
            return _newCertificateRole == CertificateRole.IntermediateCA;
        }

        if (_issuerRole == CertificateRole.IntermediateCA) {
            return _newCertificateRole == CertificateRole.EndEntity;
        }

        return false;
    }

    /**
     * @notice Gets the owner of the contract.
     * @return The owner of the contract.
     */
    function getOwner() external view returns (address) {
        return owner;
    }

    /**
     * @notice Gets a certificate.
     * @param certificateHash The hash of the certificate.
     * @return The certificate.
     */
    function getCertificate(
        bytes32 certificateHash
    ) external view returns (Certificate memory) {
        return certificates[certificateHash];
    }

    /**
     * @notice Gets the certificates by owner.
     * @param owner_ The owner of the certificates.
     * @return The certificates by owner.
     */
    function getCertificatesByOwner(
        address owner_
    ) external view returns (bytes32[] memory) {
        return certificatesByOwner[owner_];
    }
}
