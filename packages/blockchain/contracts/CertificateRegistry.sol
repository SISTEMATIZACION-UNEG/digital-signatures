// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Certificate Registry
 * @notice This contract is used to register, revoke and verify digital certificates.
 */
contract CertificateRegistry {
    /**
     * @dev The authority is set in the constructor and cannot be changed.
     * @notice The root authority that can register, revoke and verify certificates.
     */
    address private immutable authority;

    /**
     * @dev The status of a certificate.
     */
    struct CertificateStatus {
        uint256 issuedAt;
        uint256 expiresAt;
        bool isRevoked;
    }

    /**
     * @dev The status is stored in a mapping of certificate hash to certificate statuses.
     * @notice The status of a certificate.
     */
    mapping(bytes32 certificateHash => CertificateStatus certificateStatus) statuses;

    /**
     * @param certificateHash The hash of the certificate.
     * @param owner The owner of the certificate.
     * @param expiresAt The expiration date of the certificate.
     */
    event CertificateRegistered(
        bytes32 certificateHash,
        address owner,
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

    /**
     * @dev Modifier to check if the caller is the authority.
     */
    modifier onlyAuthority() {
        require(
            msg.sender == authority,
            "Only the authority can call this function"
        );
        _;
    }

    constructor() {
        // The authority is the deployer of the contract.
        authority = msg.sender;
    }

    /**
     * @notice Registers a new certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _owner The owner of the certificate.
     * @param _issuedAt The date the certificate was issued.
     * @param _expiresAt The expiration date of the certificate.
     */
    function registerCertificate(
        bytes32 _certificateHash,
        address _owner,
        uint256 _issuedAt,
        uint256 _expiresAt
    ) external onlyAuthority {
        require(
            statuses[_certificateHash].issuedAt == 0,
            "The certificate has already been registered"
        );

        require(
            _expiresAt > block.timestamp,
            "The certificate has already expired"
        );

        // Register the certificate.
        statuses[_certificateHash] = CertificateStatus({
            issuedAt: _issuedAt,
            expiresAt: _expiresAt,
            isRevoked: false
        });

        // Notify the event.
        emit CertificateRegistered(_certificateHash, _owner, _expiresAt);
    }

    /**
     * @notice Revokes a certificate.
     * @param _certificateHash The hash of the certificate.
     * @param _revokedAt The date the certificate was revoked.
     */
    function revokeCertificate(
        bytes32 _certificateHash,
        uint256 _revokedAt
    ) external onlyAuthority {
        require(
            statuses[_certificateHash].issuedAt != 0,
            "The certificate has not been registered"
        );

        require(
            !statuses[_certificateHash].isRevoked,
            "The certificate has already been revoked"
        );

        // Revoke the certificate.
        statuses[_certificateHash].isRevoked = true;

        // Notify the event.
        emit CertificateRevoked(_certificateHash, msg.sender, _revokedAt);
    }

    /**
     * @notice Gets the status of a certificate.
     * @param _certificateHash The hash of the certificate.
     * @return The status of the certificate.
     */
    function getCertificateStatus(
        bytes32 _certificateHash
    ) external view returns (CertificateStatus memory) {
        return statuses[_certificateHash];
    }

    /**
     * @notice Checks if a certificate is valid.
     * @param _certificateHash The hash of the certificate.
     * @return True if the certificate is valid, false otherwise.
     */
    function isCertificateValid(
        bytes32 _certificateHash
    ) external view returns (bool) {
        CertificateStatus memory status = statuses[_certificateHash];

        // Verify that the certificate has been registered.
        if (status.issuedAt == 0) {
            return false;
        }

        // Verify that the certificate is not expired and has not been revoked.
        return status.expiresAt > block.timestamp && !status.isRevoked;
    }
}
