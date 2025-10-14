// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title PKI.
 * @notice This contract is used to act as a Public Key Infrastructure (PKI).
 */
contract PKI {
    /**
     * @dev The owner is set in the constructor and cannot be changed.
     * @notice The owner of the contract.
     */
    address private immutable owner;

    /**
     * @dev The type of a certificate.
     */
    enum CertificateType {
        Root,
        Intermediate,
        EndEntity
    }

    /**
     * @dev The status of a certificate.
     */
    struct CertificateStatus {
        address owner;
        bytes32 issuerCertificateHash;
        uint256 issuedAt;
        uint256 expiresAt;
        uint256 revokedAt;
        CertificateType certificateType;
    }

    /**
     * @dev The status is stored in a mapping of certificate hash to certificate certificates.
     * @notice The status of a certificate.
     */
    mapping(bytes32 certificateHash => CertificateStatus certificateStatus) certificates;

    /**
     * @dev The certificates by owner.
     * @notice The certificates by owner.
     */
    mapping(address owner => bytes32[] certificateHashes) certificatesByOwner;

    /**
     * @notice Event emitted when a certificate is registered.
     * @param certificateHash The hash of the certificate.
     * @param owner The owner of the certificate.
     * @param expiresAt The expiration date of the certificate.
     */
    event CertificateRegistered(
        bytes32 indexed certificateHash,
        address indexed owner,
        address indexed issuer,
        uint256 expiresAt,
        CertificateType certificateType
    );

    /**
     * @notice Event emitted when a certificate is revoked.
     * @param certificateHash The hash of the certificate.
     * @param revoker The address that revoked the certificate.
     * @param revokedAt The date the certificate was revoked.
     */
    event CertificateRevoked(
        bytes32 indexed certificateHash,
        address indexed revoker,
        uint256 revokedAt
    );

    /**
     * @notice Error emitted when the caller is not the owner of the contract.
     * @param caller The address that called the function.
     */
    error OnlyOwner(address caller);

    /**
     * @notice Error emitted when the certificate is not a root CA.
     * @param certificateHash The hash of the certificate.
     */
    error OnlyRootCA(bytes32 certificateHash);

    /**
     * @notice Error emitted when the caller is not an intermediate CA.
     * @param certificateHash The hash of the certificate.
     */
    error OnlyIntermediateCA(bytes32 certificateHash);

    /**
     * @notice Error emitted when the caller is not the issuer of a given certificate.
     * @param caller The address that called the function.
     * @param certificateHash The hash of the certificate to check.
     */
    error OnlyIssuer(address caller, bytes32 certificateHash);

    /**
     * @notice Error emitted when the issuer certificate is not trusted.
     * @param certificateHash The hash of the certificate.
     */
    error IssuerCertificateNotTrusted(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate has already been registered.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyRegistered(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate is not registered.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateNotRegistered(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate has already expired.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyExpired(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate has been issued before the issuer certificate.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateIssuedBeforeIssuerCertificate(bytes32 certificateHash);

    /**
     * @notice Error emitted when the certificate has already been revoked.
     * @param certificateHash The hash of the certificate.
     */
    error CertificateAlreadyRevoked(bytes32 certificateHash);

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
     * @notice Error emitted when the revocation timestamp is out of range.
     * @param revokedAt The timestamp of the certificate revocation.
     * @param issuedAt The date the certificate was issued.
     * @param expiresAt The expiration date of the certificate.
     */
    error RevocationTimestampOutOfRange(
        uint256 revokedAt,
        uint256 issuedAt,
        uint256 expiresAt
    );

    /**
     * @notice Error emitted when the revocation timestamp is in the future.
     * @param revokedAt The timestamp of the certificate revocation.
     * @param blockTimestamp The timestamp of the block.
     */
    error RevocationTimestampInFuture(
        uint256 revokedAt,
        uint256 blockTimestamp
    );

    /**
     * @notice Error emitted when the issuance timestamp is out of range.
     * @param issuedAt The timestamp of the certificate issuance.
     * @param expiresAt The expiration date of the certificate.
     */
    error IssuanceTimestampOutOfRange(uint256 issuedAt, uint256 expiresAt);

    /**
     * @notice Error emitted when the issuance timestamp is in the future.
     * @param issuedAt The timestamp of the certificate issuance.
     * @param blockTimestamp The timestamp of the block.
     */
    error IssuanceTimestampInFuture(uint256 issuedAt, uint256 blockTimestamp);

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

    constructor() {
        // The owner is the deployer of the contract.
        owner = msg.sender;
    }

    /**
     * @dev Modifier to check if the caller is the owner.
     */
    modifier onlyOwner() {
        require(msg.sender == owner, OnlyOwner(msg.sender));

        _;
    }

    /**
     * @dev Modifier to check if the caller is the root CA.
     * @param _certificateHash The hash of the certificate.
     */
    modifier onlyRootCA(bytes32 _certificateHash) {
        CertificateStatus memory status = certificates[_certificateHash];

        require(
            status.owner == msg.sender,
            OnlyIssuer(msg.sender, _certificateHash)
        );

        require(
            status.certificateType == CertificateType.Root,
            OnlyRootCA(_certificateHash)
        );

        require(
            isCertificateValid(_certificateHash),
            IssuerCertificateNotTrusted(_certificateHash)
        );

        _;
    }

    /**
     * @dev Modifier to check if the caller is an intermediate CA.
     * @param _issuerCertificateHash The hash of the issuer certificate.
     */
    modifier onlyIntermediateCA(bytes32 _issuerCertificateHash) {
        CertificateStatus memory status = certificates[_issuerCertificateHash];

        require(
            status.owner == msg.sender,
            OnlyIssuer(msg.sender, _issuerCertificateHash)
        );

        require(
            status.certificateType == CertificateType.Intermediate,
            OnlyIntermediateCA(_issuerCertificateHash)
        );

        require(
            isCertificateValid(_issuerCertificateHash),
            IssuerCertificateNotTrusted(_issuerCertificateHash)
        );

        _;
    }

    /**
     * @dev Modifier to check if the caller is the issuer of the certificate.
     * @param _certificateHash The hash of the certificate.
     */
    modifier onlyIssuer(bytes32 _certificateHash) {
        CertificateStatus memory status = certificates[_certificateHash];

        require(
            status.issuedAt != 0,
            CertificateNotRegistered(_certificateHash)
        );

        if (status.certificateType == CertificateType.Root) {
            // Verify if the root CA is the caller.
            require(
                status.owner == msg.sender,
                OnlyIssuer(msg.sender, _certificateHash)
            );
        } else {
            // Verify the issuer certificate validity.
            CertificateStatus memory issuerStatus = certificates[
                status.issuerCertificateHash
            ];

            require(
                issuerStatus.owner == msg.sender,
                OnlyIssuer(msg.sender, status.issuerCertificateHash)
            );

            require(
                isCertificateValid(status.issuerCertificateHash),
                IssuerCertificateNotTrusted(status.issuerCertificateHash)
            );
        }

        _;
    }

    /**
     * @notice Registers a new root certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     */
    function registerRootCertificate(
        bytes32 _certificateHash,
        uint256 _issuedAt,
        uint256 _expiresAt
    ) external onlyOwner {
        _issueCertificate(
            _certificateHash,
            bytes32(0),
            msg.sender,
            _issuedAt,
            _expiresAt,
            CertificateType.Root
        );
    }

    /**
     * @notice Registers a new intermediate certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _owner The owner of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     */
    function registerIntermediateCertificate(
        bytes32 _certificateHash,
        bytes32 _issuerCertificateHash,
        address _owner,
        uint256 _issuedAt,
        uint256 _expiresAt
    ) external onlyRootCA(_issuerCertificateHash) {
        _issueCertificate(
            _certificateHash,
            _issuerCertificateHash,
            _owner,
            _issuedAt,
            _expiresAt,
            CertificateType.Intermediate
        );
    }

    /**
     * @notice Registers a new certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _issuerCertificateHash The hash of the issuer certificate.
     * @param _owner The owner of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     */
    function registerCertificate(
        bytes32 _certificateHash,
        bytes32 _issuerCertificateHash,
        address _owner,
        uint256 _issuedAt,
        uint256 _expiresAt
    ) external onlyIntermediateCA(_issuerCertificateHash) {
        _issueCertificate(
            _certificateHash,
            _issuerCertificateHash,
            _owner,
            _issuedAt,
            _expiresAt,
            CertificateType.EndEntity
        );
    }

    /**
     * @notice Issues a new certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _issuerCertificateHash The hash of the issuer certificate.
     * @param _owner The owner of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     * @param _certificateType The type of the certificate.
     */
    function _issueCertificate(
        bytes32 _certificateHash,
        bytes32 _issuerCertificateHash,
        address _owner,
        uint256 _issuedAt,
        uint256 _expiresAt,
        CertificateType _certificateType
    ) private {
        require(
            certificates[_certificateHash].issuedAt == 0,
            CertificateAlreadyRegistered(_certificateHash)
        );

        require(
            _expiresAt > block.timestamp,
            CertificateAlreadyExpired(_certificateHash)
        );

        require(
            _issuedAt < _expiresAt,
            IssuanceTimestampOutOfRange(_issuedAt, _expiresAt)
        );

        require(
            _issuedAt <= block.timestamp,
            IssuanceTimestampInFuture(_issuedAt, block.timestamp)
        );

        require(_owner != address(0), InvalidOwnerAddress(_owner));

        require(
            _certificateHash != bytes32(0),
            InvalidCertificateHash(_certificateHash)
        );

        // Check the issuer certificate validity (except for root certificates).
        if (_certificateType != CertificateType.Root) {
            CertificateStatus memory issuerStatus = certificates[
                _issuerCertificateHash
            ];

            require(
                issuerStatus.issuedAt < _issuedAt,
                CertificateIssuedBeforeIssuerCertificate(_certificateHash)
            );

            require(
                _expiresAt <= issuerStatus.expiresAt,
                CertificateValidityPeriodTooLong(
                    _expiresAt,
                    issuerStatus.expiresAt
                )
            );
        }

        // Register the certificate.
        certificates[_certificateHash] = CertificateStatus({
            owner: _owner,
            issuedAt: _issuedAt,
            expiresAt: _expiresAt,
            revokedAt: 0,
            certificateType: _certificateType,
            issuerCertificateHash: _issuerCertificateHash
        });

        // Add the certificate to the owner's certificates.
        certificatesByOwner[_owner].push(_certificateHash);

        // Notify the event.
        emit CertificateRegistered(
            _certificateHash,
            _owner,
            msg.sender,
            _expiresAt,
            _certificateType
        );
    }

    /**
     * @notice Revokes a certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _revokedAt The date the certificate was revoked.
     */
    function revokeCertificate(
        bytes32 _certificateHash,
        uint256 _revokedAt
    ) external onlyIssuer(_certificateHash) {
        CertificateStatus memory status = certificates[_certificateHash];

        require(
            status.revokedAt == 0,
            CertificateAlreadyRevoked(_certificateHash)
        );

        require(
            status.expiresAt > block.timestamp,
            CertificateAlreadyExpired(_certificateHash)
        );

        require(
            (_revokedAt >= status.issuedAt) && (_revokedAt <= status.expiresAt),
            RevocationTimestampOutOfRange(
                _revokedAt,
                status.issuedAt,
                status.expiresAt
            )
        );

        require(
            _revokedAt <= block.timestamp,
            RevocationTimestampInFuture(_revokedAt, block.timestamp)
        );

        // Revoke the certificate.
        certificates[_certificateHash].revokedAt = _revokedAt;

        // Notify the event.
        emit CertificateRevoked(_certificateHash, msg.sender, _revokedAt);
    }

    /**
     * @notice Gets the contract owner.
     * @return The owner.
     */
    function getOwner() external view returns (address) {
        return owner;
    }

    /**
     * @notice Verifies the chain of trust for a certificate.
     * @param _certificateHash The hash of the certificate.
     * @return True if the chain of trust is valid, false otherwise.
     */
    function _verifyChainOfTrust(
        bytes32 _certificateHash
    ) internal view returns (bool) {
        CertificateStatus memory status = certificates[_certificateHash];

        // Verify the certificate is registered, not revoked and not expired.
        if (
            status.issuedAt == 0 ||
            status.revokedAt != 0 ||
            block.timestamp > status.expiresAt
        ) {
            return false;
        }

        // Verify the certificate is a root CA.
        if (status.certificateType == CertificateType.Root) {
            return true;
        }

        // Verify the chain of trust for the issuer certificate.
        return _verifyChainOfTrust(status.issuerCertificateHash);
    }

    /**
     * @notice Verifies if a certificate is valid.
     * @param _certificateHash The hash of the certificate.
     * @return True if the certificate is valid, false otherwise.
     */
    function isCertificateValid(
        bytes32 _certificateHash
    ) public view returns (bool) {
        return _verifyChainOfTrust(_certificateHash);
    }

    /**
     * @notice Gets the status of a certificate.
     * @param _certificateHash The hash of the certificate.
     * @return The status of the certificate.
     */
    function getCertificateStatus(
        bytes32 _certificateHash
    ) external view returns (CertificateStatus memory) {
        return certificates[_certificateHash];
    }

    /**
     * @notice Gets the certificates by owner.
     * @param _owner The owner of the certificates.
     * @return The certificates by owner.
     * @dev This function returns an array of certificates that are owned by the given owner.
     * @dev The certificates are returned in the order they were registered.
     */
    function getCertificatesByOwner(
        address _owner
    ) public view returns (CertificateStatus[] memory) {
        // Get the certificates count.
        uint256 certificatesCount = certificatesByOwner[_owner].length;

        // Create a new array to store the certificates.
        CertificateStatus[] memory ownerCertificates = new CertificateStatus[](
            certificatesCount
        );

        if (certificatesCount == 0) return ownerCertificates;

        // Get the certificates.
        for (uint256 i = 0; i < certificatesCount; i++) {
            ownerCertificates[i] = certificates[certificatesByOwner[_owner][i]];
        }

        return ownerCertificates;
    }
}
