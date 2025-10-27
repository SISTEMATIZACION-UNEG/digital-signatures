// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PKIRegistry} from "./PKIRegistry.sol";
import {Test} from "forge-std/Test.sol";

contract PKIRegistryTest is Test {
    PKIRegistry pkiRegistry;

    // Test addresses
    address owner;
    address intermediateCA;
    address endEntity;
    address otherUser;

    // Test certificate hashes
    bytes32 rootCertificateHash;
    bytes32 intermediateCertificateHash;
    bytes32 endEntityCertificateHash;

    function setUp() public {
        // Prepare test addresses
        owner = makeAddr("owner");
        intermediateCA = makeAddr("intermediate-ca");
        endEntity = makeAddr("end-entity");
        otherUser = makeAddr("other-user");

        // Prepare certificate hashes
        rootCertificateHash = stringToBytes32("root-ca");
        intermediateCertificateHash = stringToBytes32("intermediate-ca");
        endEntityCertificateHash = stringToBytes32("end-entity");

        // Deploy contract as owner
        vm.startPrank(owner);
        pkiRegistry = new PKIRegistry();

        // Issue root certificate
        pkiRegistry.issueRootCertificate(
            rootCertificateHash,
            owner,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        // Issue intermediate certificate
        pkiRegistry.issueCertificate(
            intermediateCertificateHash,
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();

        // Issue end entity certificate
        vm.startPrank(intermediateCA);

        pkiRegistry.issueCertificate(
            endEntityCertificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days,
            PKIRegistry.CertificateRole.EndEntity
        );

        vm.stopPrank();
    }

    function stringToBytes32(
        string memory _inputString
    ) internal pure returns (bytes32) {
        require(
            bytes(_inputString).length <= 32,
            "String too long for bytes32"
        );

        return bytes32(abi.encodePacked(_inputString));
    }

    // ============================================
    // Test: Initial State
    // ============================================

    function testInitialOwner() public view {
        require(
            pkiRegistry.getOwner() == owner,
            "Initial owner should be the deployer"
        );
    }

    // ============================================
    // Test: Issue Root Certificate
    // ============================================

    function testIssueRootCertificate() public {
        vm.startPrank(owner);

        bytes32 certificateHash = stringToBytes32("new-root-ca");
        uint256 expiresAt = block.timestamp + (365 days * 10);

        vm.expectEmit(true, true, true, true);
        emit PKIRegistry.CertificateIssued(
            owner,
            certificateHash,
            bytes32(0),
            expiresAt
        );

        pkiRegistry.issueRootCertificate(
            certificateHash,
            owner,
            block.timestamp,
            expiresAt
        );

        vm.stopPrank();

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            certificateHash
        );

        require(cert.owner == owner, "Owner should be correct");
        require(
            cert.role == PKIRegistry.CertificateRole.RootCA,
            "Role should be RootCA"
        );
        require(cert.revokedAt == 0, "Certificate should not be revoked");
        require(
            pkiRegistry.isValidCertificate(certificateHash),
            "Root certificate should be valid"
        );
    }

    function testIssueRootCertificateRevertsWhenNotOwner() public {
        vm.startPrank(otherUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CallerNotOwner.selector,
                otherUser
            )
        );

        pkiRegistry.issueRootCertificate(
            stringToBytes32("new-root-ca"),
            otherUser,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();
    }

    // ============================================
    // Test: Issue Intermediate Certificate
    // ============================================

    function testIssueIntermediateCertificate() public {
        vm.startPrank(owner);

        bytes32 certificateHash = stringToBytes32("new-intermediate-ca");
        uint256 expiresAt = block.timestamp + (365 days * 5);

        vm.expectEmit(true, true, true, true);
        emit PKIRegistry.CertificateIssued(
            intermediateCA,
            certificateHash,
            rootCertificateHash,
            expiresAt
        );

        pkiRegistry.issueCertificate(
            certificateHash,
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            expiresAt,
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            certificateHash
        );

        require(
            cert.owner == intermediateCA,
            "Owner should be intermediate CA"
        );
        require(
            cert.role == PKIRegistry.CertificateRole.IntermediateCA,
            "Role should be IntermediateCA"
        );
        require(
            cert.issuerCertificateHash == rootCertificateHash,
            "Issuer should be root CA"
        );
        require(
            pkiRegistry.isValidCertificate(certificateHash),
            "Intermediate certificate should be valid"
        );
    }

    function testIssueIntermediateCertificateRevertsWhenNotIssuer() public {
        vm.startPrank(otherUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CallerNotIssuer.selector,
                otherUser,
                rootCertificateHash
            )
        );

        pkiRegistry.issueCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();
    }

    function testIssueIntermediateCertificateRevertsWhenIssuerNotTrusted()
        public
    {
        vm.startPrank(owner);

        // Revoke root certificate
        pkiRegistry.revokeCertificate(rootCertificateHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.IssuerNotTrusted.selector,
                rootCertificateHash
            )
        );

        pkiRegistry.issueCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();
    }

    function testIssueIntermediateCertificateRevertsWhenIssuanceNotAllowed()
        public
    {
        vm.startPrank(intermediateCA);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.IssuanceNotAllowed.selector,
                PKIRegistry.CertificateRole.IntermediateCA,
                PKIRegistry.CertificateRole.IntermediateCA
            )
        );

        // Intermediate CA trying to issue another Intermediate CA (not allowed)
        pkiRegistry.issueCertificate(
            stringToBytes32("new-intermediate-ca-2"),
            intermediateCertificateHash,
            otherUser,
            block.timestamp,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();
    }

    // ============================================
    // Test: Issue End Entity Certificate
    // ============================================

    function testIssueEndEntityCertificate() public {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity");
        uint256 expiresAt = block.timestamp + 365 days;

        vm.expectEmit(true, true, true, true);
        emit PKIRegistry.CertificateIssued(
            endEntity,
            certificateHash,
            intermediateCertificateHash,
            expiresAt
        );

        pkiRegistry.issueCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            expiresAt,
            PKIRegistry.CertificateRole.EndEntity
        );

        vm.stopPrank();

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            certificateHash
        );

        require(cert.owner == endEntity, "Owner should be end entity");
        require(
            cert.role == PKIRegistry.CertificateRole.EndEntity,
            "Role should be EndEntity"
        );
        require(
            cert.issuerCertificateHash == intermediateCertificateHash,
            "Issuer should be intermediate CA"
        );
        require(
            pkiRegistry.isValidCertificate(certificateHash),
            "End entity certificate should be valid"
        );
    }

    function testIssueEndEntityCertificateRevertsWhenNotIssuer() public {
        vm.startPrank(otherUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CallerNotIssuer.selector,
                otherUser,
                intermediateCertificateHash
            )
        );

        pkiRegistry.issueCertificate(
            stringToBytes32("new-end-entity"),
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days,
            PKIRegistry.CertificateRole.EndEntity
        );

        vm.stopPrank();
    }

    function testIssueEndEntityCertificateRevertsWhenIssuanceNotAllowed()
        public
    {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.IssuanceNotAllowed.selector,
                PKIRegistry.CertificateRole.RootCA,
                PKIRegistry.CertificateRole.RootCA
            )
        );

        // Root CA trying to issue another Root CA (not allowed)
        pkiRegistry.issueCertificate(
            stringToBytes32("new-root-ca-2"),
            rootCertificateHash,
            otherUser,
            block.timestamp,
            block.timestamp + (365 days * 10),
            PKIRegistry.CertificateRole.RootCA
        );

        vm.stopPrank();
    }

    // ============================================
    // Test: Certificate Validation Errors
    // ============================================

    function testIssueCertificateRevertsWhenAlreadyRegistered() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateAlreadyRegistered.selector,
                rootCertificateHash
            )
        );

        pkiRegistry.issueRootCertificate(
            rootCertificateHash,
            owner,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenIssuanceTimestampInFuture() public {
        vm.startPrank(owner);

        uint256 futureTimestamp = block.timestamp + 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.IssuanceTimestampInFuture.selector,
                futureTimestamp,
                block.timestamp
            )
        );

        pkiRegistry.issueRootCertificate(
            stringToBytes32("new-root-ca"),
            owner,
            futureTimestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenAlreadyExpired() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateAlreadyExpired.selector,
                stringToBytes32("new-root-ca")
            )
        );

        pkiRegistry.issueRootCertificate(
            stringToBytes32("new-root-ca"),
            owner,
            block.timestamp,
            block.timestamp - 1
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenInvalidOwnerAddress() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.InvalidOwnerAddress.selector,
                address(0)
            )
        );

        pkiRegistry.issueRootCertificate(
            stringToBytes32("new-root-ca"),
            address(0),
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenInvalidCertificateHash() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.InvalidCertificateHash.selector,
                bytes32(0)
            )
        );

        pkiRegistry.issueRootCertificate(
            bytes32(0),
            owner,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenValidityPeriodTooLong() public {
        vm.startPrank(owner);

        PKIRegistry.Certificate memory rootCert = pkiRegistry.getCertificate(
            rootCertificateHash
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateValidityPeriodTooLong.selector,
                rootCert.expiresAt + 1,
                rootCert.expiresAt
            )
        );

        pkiRegistry.issueCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            rootCert.expiresAt + 1,
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenIssuedBeforeIssuerCertificate()
        public
    {
        vm.startPrank(owner);

        PKIRegistry.Certificate memory rootCert = pkiRegistry.getCertificate(
            rootCertificateHash
        );

        uint256 issuedAt = rootCert.issuedAt - 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateIssuedBeforeIssuerCertificate.selector,
                issuedAt,
                rootCert.issuedAt
            )
        );

        pkiRegistry.issueCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            issuedAt,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();
    }

    // ============================================
    // Test: Revoke Certificate
    // ============================================

    function testRevokeCertificateByOwner() public {
        vm.startPrank(owner);

        vm.expectEmit(true, true, true, true);
        emit PKIRegistry.CertificateRevoked(
            owner,
            rootCertificateHash,
            block.timestamp
        );

        pkiRegistry.revokeCertificate(rootCertificateHash);

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            rootCertificateHash
        );

        require(cert.revokedAt == block.timestamp, "Should be revoked");
        require(
            !pkiRegistry.isValidCertificate(rootCertificateHash),
            "Should not be valid"
        );

        vm.stopPrank();
    }

    function testRevokeCertificateByIssuer() public {
        vm.startPrank(owner);

        vm.expectEmit(true, true, true, true);
        emit PKIRegistry.CertificateRevoked(
            owner,
            intermediateCertificateHash,
            block.timestamp
        );

        pkiRegistry.revokeCertificate(intermediateCertificateHash);

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            intermediateCertificateHash
        );

        require(cert.revokedAt == block.timestamp, "Should be revoked");
        require(
            !pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "Should not be valid"
        );

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenNotOwnerOrIssuer() public {
        vm.startPrank(otherUser);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CallerNotIssuerNorOwner.selector,
                otherUser,
                intermediateCertificateHash
            )
        );

        pkiRegistry.revokeCertificate(intermediateCertificateHash);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenAlreadyRevoked() public {
        vm.startPrank(owner);

        pkiRegistry.revokeCertificate(rootCertificateHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateAlreadyRevoked.selector,
                rootCertificateHash
            )
        );

        pkiRegistry.revokeCertificate(rootCertificateHash);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenAlreadyExpired() public {
        vm.startPrank(owner);

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            rootCertificateHash
        );

        // Warp time to after expiration
        vm.warp(cert.expiresAt + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateAlreadyExpired.selector,
                rootCertificateHash
            )
        );

        pkiRegistry.revokeCertificate(rootCertificateHash);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenCertificateNotRegistered() public {
        vm.startPrank(owner);

        bytes32 nonExistentHash = stringToBytes32("non-existent");

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.CertificateNotRegistered.selector,
                nonExistentHash
            )
        );

        pkiRegistry.revokeCertificate(nonExistentHash);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenIssuerNotTrusted() public {
        // Revoke intermediate certificate
        vm.startPrank(owner);
        pkiRegistry.revokeCertificate(intermediateCertificateHash);
        vm.stopPrank();

        // Try to revoke end entity certificate with revoked issuer
        vm.startPrank(intermediateCA);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKIRegistry.IssuerNotTrusted.selector,
                intermediateCertificateHash
            )
        );

        pkiRegistry.revokeCertificate(endEntityCertificateHash);

        vm.stopPrank();
    }

    // ============================================
    // Test: Chain of Trust Validation
    // ============================================

    function testIsValidCertificateReturnsTrueForValidChain() public view {
        require(
            pkiRegistry.isValidCertificate(rootCertificateHash),
            "Root should be valid"
        );
        require(
            pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "Intermediate should be valid"
        );
        require(
            pkiRegistry.isValidCertificate(endEntityCertificateHash),
            "End entity should be valid"
        );
    }

    function testIsValidCertificateReturnsFalseWhenRootRevoked() public {
        vm.startPrank(owner);
        pkiRegistry.revokeCertificate(rootCertificateHash);
        vm.stopPrank();

        require(
            !pkiRegistry.isValidCertificate(rootCertificateHash),
            "Root should not be valid"
        );
        require(
            !pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "Intermediate should not be valid"
        );
        require(
            !pkiRegistry.isValidCertificate(endEntityCertificateHash),
            "End entity should not be valid"
        );
    }

    function testIsValidCertificateReturnsFalseWhenIntermediateRevoked()
        public
    {
        vm.startPrank(owner);
        pkiRegistry.revokeCertificate(intermediateCertificateHash);
        vm.stopPrank();

        require(
            pkiRegistry.isValidCertificate(rootCertificateHash),
            "Root should still be valid"
        );
        require(
            !pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "Intermediate should not be valid"
        );
        require(
            !pkiRegistry.isValidCertificate(endEntityCertificateHash),
            "End entity should not be valid"
        );
    }

    function testIsValidCertificateReturnsFalseWhenExpired() public {
        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            endEntityCertificateHash
        );

        // Warp time to after expiration
        vm.warp(cert.expiresAt + 1);

        require(
            !pkiRegistry.isValidCertificate(endEntityCertificateHash),
            "Expired certificate should not be valid"
        );
    }

    function testIsValidCertificateReturnsFalseWhenNotRegistered() public view {
        require(
            !pkiRegistry.isValidCertificate(stringToBytes32("non-existent")),
            "Non-existent certificate should not be valid"
        );
    }

    // ============================================
    // Test: Getter Functions
    // ============================================

    function testGetCertificate() public view {
        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            rootCertificateHash
        );

        require(cert.owner == owner, "Owner should match");
        require(cert.issuedAt > 0, "IssuedAt should be set");
        require(cert.expiresAt > 0, "ExpiresAt should be set");
        require(cert.revokedAt == 0, "Should not be revoked");
        require(
            cert.role == PKIRegistry.CertificateRole.RootCA,
            "Role should be RootCA"
        );
    }

    function testGetCertificatesByOwner() public view {
        bytes32[] memory certs = pkiRegistry.getCertificatesByOwner(owner);

        require(certs.length == 1, "Owner should have 1 certificate");
        require(
            certs[0] == rootCertificateHash,
            "Certificate hash should match"
        );
    }

    function testGetCertificatesByOwnerReturnsMultipleCertificates() public {
        vm.startPrank(owner);

        bytes32 newRootHash = stringToBytes32("new-root-ca");
        pkiRegistry.issueRootCertificate(
            newRootHash,
            owner,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        vm.stopPrank();

        bytes32[] memory certs = pkiRegistry.getCertificatesByOwner(owner);

        require(certs.length == 2, "Owner should have 2 certificates");
    }

    function testGetCertificatesByOwnerReturnsEmptyForNewOwner() public view {
        bytes32[] memory certs = pkiRegistry.getCertificatesByOwner(otherUser);

        require(certs.length == 0, "New owner should have 0 certificates");
    }

    function testGetOwner() public view {
        require(pkiRegistry.getOwner() == owner, "Owner should match deployer");
    }

    // ============================================
    // Test: Complex Scenarios
    // ============================================

    function testMultipleCertificateIssuanceAndRevocation() public {
        // Issue multiple certificates
        vm.startPrank(owner);

        bytes32 root2Hash = stringToBytes32("root-ca-2");
        pkiRegistry.issueRootCertificate(
            root2Hash,
            owner,
            block.timestamp,
            block.timestamp + (365 days * 10)
        );

        bytes32 intermediate2Hash = stringToBytes32("intermediate-ca-2");
        pkiRegistry.issueCertificate(
            intermediate2Hash,
            root2Hash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5),
            PKIRegistry.CertificateRole.IntermediateCA
        );

        vm.stopPrank();

        // Verify both chains are valid
        require(
            pkiRegistry.isValidCertificate(rootCertificateHash),
            "First root should be valid"
        );
        require(
            pkiRegistry.isValidCertificate(root2Hash),
            "Second root should be valid"
        );
        require(
            pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "First intermediate should be valid"
        );
        require(
            pkiRegistry.isValidCertificate(intermediate2Hash),
            "Second intermediate should be valid"
        );

        // Revoke first root
        vm.startPrank(owner);
        pkiRegistry.revokeCertificate(rootCertificateHash);
        vm.stopPrank();

        // Verify first chain is invalid, second is still valid
        require(
            !pkiRegistry.isValidCertificate(rootCertificateHash),
            "First root should be invalid"
        );
        require(
            !pkiRegistry.isValidCertificate(intermediateCertificateHash),
            "First intermediate should be invalid"
        );
        require(
            pkiRegistry.isValidCertificate(root2Hash),
            "Second root should still be valid"
        );
        require(
            pkiRegistry.isValidCertificate(intermediate2Hash),
            "Second intermediate should still be valid"
        );
    }

    function testCertificateOwnerCanRevokeSelfIssuedCertificate() public {
        vm.startPrank(intermediateCA);

        pkiRegistry.revokeCertificate(endEntityCertificateHash);

        PKIRegistry.Certificate memory cert = pkiRegistry.getCertificate(
            endEntityCertificateHash
        );

        require(cert.revokedAt == block.timestamp, "Should be revoked");

        vm.stopPrank();
    }
}
