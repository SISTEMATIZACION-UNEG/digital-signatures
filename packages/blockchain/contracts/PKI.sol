// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title PKI.
 * @notice This contract is used to act as a Public Key Infrastructure (PKI).
 */
contract PKI {
    /**
     * @dev The root CA is set in the constructor and cannot be changed.
     * @notice The root CA that can register and revoke intermediate certificates.
     */
    address private immutable rootCA;

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
     * @param certificateHash The hash of the certificate.
     * @param owner The owner of the certificate.
     * @param expiresAt The expiration date of the certificate.
     */
    event CertificateRegistered(
        bytes32 certificateHash,
        address owner,
        address issuer,
        uint256 expiresAt
    );

    /**
     * @param certificateHash The hash of the certificate.
     * @param revoker The address that revoked the certificate.
     * @param revokedAt The date the certificate was revoked.
     */
    event CertificateRevoked(
        bytes32 certificateHash,
        address revoker,
        uint256 revokedAt
    );

    constructor() {
        // The authority is the deployer of the contract.
        rootCA = msg.sender;
    }

    /**
     * @dev Modifier to check if the caller is the root CA.
     */
    modifier onlyRootCA() {
        require(
            msg.sender == rootCA,
            "Only the root CA can call this function"
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
            status.issuedAt != 0,
            "The issuer certificate is not registered"
        );

        require(
            status.revokedAt == 0,
            "The issuer certificate has been revoked"
        );

        require(
            status.owner == msg.sender,
            "Only the issuer can call this function"
        );

        require(
            status.certificateType == CertificateType.Intermediate,
            "Only an intermediate CA can call this function"
        );

        require(
            _verifyChainOfTrust(_issuerCertificateHash),
            "The issuer certificate is not trusted"
        );

        _;
    }

    /**
     * @dev Modifier to check if the caller is the issuer of the certificate.
     * @param _certificateHash The hash of the certificate.
     */
    modifier onlyIssuer(bytes32 _certificateHash) {
        CertificateStatus memory status = certificates[_certificateHash];

        require(status.issuedAt != 0, "The certificate is not registered");

        if (status.certificateType == CertificateType.Root) {
            // Verify if the root CA is the caller.
            require(
                status.owner == msg.sender,
                "Only the issuer can revoke this certificate"
            );
        } else {
            // Verify the issuer certificate validity.
            CertificateStatus memory issuerStatus = certificates[
                status.issuerCertificateHash
            ];

            require(
                issuerStatus.issuedAt != 0,
                "The issuer certificate is not registered"
            );

            require(
                issuerStatus.revokedAt == 0,
                "The issuer certificate has been revoked"
            );

            require(
                issuerStatus.owner == msg.sender,
                "Only the issuer can revoke this certificate"
            );

            require(
                _verifyChainOfTrust(status.issuerCertificateHash),
                "The issuer certificate is not trusted"
            );
        }

        _;
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
     * @notice Registers a new root certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     */
    function registerRootCertificate(
        bytes32 _certificateHash,
        uint256 _issuedAt,
        uint256 _expiresAt
    ) external onlyRootCA {
        _issueCertificate(
            _certificateHash,
            0x00,
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
    ) external onlyRootCA {
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
        CertificateStatus memory issuerStatus = certificates[
            _issuerCertificateHash
        ];

        require(
            certificates[_certificateHash].issuedAt == 0,
            "The certificate has already been registered"
        );

        require(
            _expiresAt > block.timestamp,
            "The certificate has already expired"
        );

        require(
            issuerStatus.issuedAt < _issuedAt,
            "The certificate cannot be issued before the issuer certificate"
        );

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
            _expiresAt
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
        require(
            certificates[_certificateHash].revokedAt == 0,
            "The certificate has already been revoked"
        );

        require(
            _revokedAt > block.timestamp,
            "The certificate has already expired"
        );

        // Revoke the certificate.
        certificates[_certificateHash].revokedAt = _revokedAt;

        // Notify the event.
        emit CertificateRevoked(_certificateHash, msg.sender, _revokedAt);
    }

    /**
     * @notice Verifies if a certificate is valid.
     * @param _certificateHash The hash of the certificate.
     * @return True if the certificate is valid, false otherwise.
     */
    function isCertificateValid(
        bytes32 _certificateHash
    ) external view returns (bool) {
        return _verifyChainOfTrust(_certificateHash);
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
