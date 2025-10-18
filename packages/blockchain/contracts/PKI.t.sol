// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PKI} from "./PKI.sol";
import {Test} from "forge-std/Test.sol";

contract PKITest is Test {
    PKI pki;

    // The addresses of the owner, intermediate CA and end entity.
    address owner;
    address intermediateCA;
    address endEntity;

    // The hashes of the root, intermediate and end entity certificates.
    bytes32 rootCertificateHash;
    bytes32 intermediateCertificateHash;
    bytes32 endEntityCertificateHash;

    function setUp() public {
        // Prepare the addresses.
        owner = makeAddr("owner");
        intermediateCA = makeAddr("intermediate-ca");
        endEntity = makeAddr("end-entity-ca");

        // Prepare the certificate hashes.
        rootCertificateHash = stringToBytes32("root-ca");
        intermediateCertificateHash = stringToBytes32("intermediate-ca");
        endEntityCertificateHash = stringToBytes32("end-entity-ca");

        vm.startPrank(owner);

        pki = new PKI();

        // Register the root certificate.
        pki.registerRootCertificate(
            rootCertificateHash,
            block.timestamp,
            // 10 years from now.
            block.timestamp + (365 days * 10)
        );

        // Register the intermediate certificate.
        pki.registerIntermediateCertificate(
            intermediateCertificateHash,
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5)
        );

        vm.stopPrank();

        // Register the end entity certificate.
        vm.startPrank(intermediateCA);

        pki.registerCertificate(
            endEntityCertificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
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

    function testInitialValue() public view {
        require(
            pki.getOwner() == owner,
            "Initial owner should be the deployer"
        );
    }

    function testRegisterRootCertificate() public {
        vm.startPrank(owner);

        bytes32 certificateHash = stringToBytes32("new-root-ca");
        uint256 expiresAt = block.timestamp + (365 days * 10);

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRegistered(
            certificateHash,
            owner,
            owner,
            expiresAt,
            PKI.CertificateType.Root
        );

        // Register the root certificate.
        pki.registerRootCertificate(
            certificateHash,
            block.timestamp,
            expiresAt
        );

        vm.stopPrank();

        PKI.CertificateStatus memory status = pki.getCertificateStatus(
            certificateHash
        );

        // Verify the certificate is registered and the owner is the deployer.
        require(status.owner == owner, "Owner should be the deployer");

        // Verify the certificate type is root.
        require(
            status.certificateType == PKI.CertificateType.Root,
            "Certificate type should be root"
        );

        require(
            pki.isCertificateValid(certificateHash),
            "Root certificate should be valid"
        );
    }

    function testRegisterRootCertificateRevertsWhenIsNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(PKI.OnlyOwner.selector, address(this))
        );

        pki.registerRootCertificate(
            stringToBytes32("new-root-ca"),
            block.timestamp,
            block.timestamp + (365 days * 10)
        );
    }

    function testRegisterIntermediateCertificate() public {
        vm.startPrank(owner);

        bytes32 certificateHash = stringToBytes32("new-intermediate-ca");
        uint256 expiresAt = block.timestamp + (365 days * 5);

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRegistered(
            certificateHash,
            intermediateCA,
            owner,
            expiresAt,
            PKI.CertificateType.Intermediate
        );

        // Register the intermediate certificate.
        pki.registerIntermediateCertificate(
            certificateHash,
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            expiresAt
        );

        vm.stopPrank();

        // Verify the status of the certificate.
        PKI.CertificateStatus memory status = pki.getCertificateStatus(
            certificateHash
        );

        require(
            status.owner == intermediateCA,
            "Owner should be the intermediate CA"
        );

        require(
            status.certificateType == PKI.CertificateType.Intermediate,
            "Certificate type should be intermediate"
        );

        require(
            pki.isCertificateValid(certificateHash),
            "Intermediate certificate should be valid"
        );
    }

    function testRegisterIntermediateCertificateRevertsWhenIsNotIssuer()
        public
    {
        address issuer = address(this);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyCertificateOwner.selector,
                issuer,
                rootCertificateHash
            )
        );

        pki.registerIntermediateCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5)
        );
    }

    function testRegisterIntermediateCertificateRevertsWhenIsNotRootCA()
        public
    {
        vm.startPrank(intermediateCA);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyRootCA.selector,
                intermediateCertificateHash
            )
        );

        pki.registerIntermediateCertificate(
            stringToBytes32("new-intermediate-ca"),
            intermediateCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5)
        );

        vm.stopPrank();
    }

    function testRegisterIntermediateCertificateRevertsWhenIssuerCertificateIsNotTrusted()
        public
    {
        vm.startPrank(owner);

        // Revoke the root certificate (so it is not trusted).
        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        // Try to register the intermediate certificate.
        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.IssuerCertificateNotTrusted.selector,
                rootCertificateHash
            )
        );

        pki.registerIntermediateCertificate(
            stringToBytes32("new-intermediate-ca"),
            rootCertificateHash,
            intermediateCA,
            block.timestamp,
            block.timestamp + (365 days * 5)
        );

        vm.stopPrank();
    }

    function testRegisterEndEntityCertificate() public {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");
        uint256 expiresAt = block.timestamp + 365 days;

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRegistered(
            certificateHash,
            endEntity,
            intermediateCA,
            expiresAt,
            PKI.CertificateType.EndEntity
        );

        // Register the end entity certificate.
        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            expiresAt
        );

        vm.stopPrank();

        // Verify the status of the certificate.
        PKI.CertificateStatus memory status = pki.getCertificateStatus(
            certificateHash
        );

        require(status.owner == endEntity, "Owner should be the end entity");

        require(
            status.certificateType == PKI.CertificateType.EndEntity,
            "Certificate type should be end entity"
        );

        require(
            pki.isCertificateValid(certificateHash),
            "End entity certificate should be valid"
        );
    }

    function testRegisterEndEntityCertificateRevertsWhenIsNotIssuer() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyCertificateOwner.selector,
                address(this),
                intermediateCertificateHash
            )
        );

        pki.registerIntermediateCertificate(
            stringToBytes32("new-intermediate-ca"),
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
        );
    }

    function testRegisterEndEntityCertificateRevertsWhenIsNotIntermediateCA()
        public
    {
        vm.startPrank(endEntity);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyIntermediateCA.selector,
                endEntityCertificateHash
            )
        );

        pki.registerCertificate(
            stringToBytes32("new-end-entity-ca"),
            endEntityCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
        );

        vm.stopPrank();
    }

    function testRegisterEndEntityCertificateRevertsWhenIssuerCertificateIsNotTrusted()
        public
    {
        vm.startPrank(owner);

        // Revoke the intermediate certificate (so it is not trusted).
        pki.revokeCertificate(intermediateCertificateHash, block.timestamp);

        vm.stopPrank();

        // Try to register the end entity certificate with the revoked intermediate certificate.
        vm.startPrank(intermediateCA);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.IssuerCertificateNotTrusted.selector,
                intermediateCertificateHash
            )
        );

        pki.registerCertificate(
            stringToBytes32("new-end-entity-ca"),
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
        );

        vm.stopPrank();
    }

    function testIssueCeritificateRevertsWhenCertificateIsAlreadyRegistered()
        public
    {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = endEntityCertificateHash;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateAlreadyRegistered.selector,
                certificateHash
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
        );

        vm.stopPrank();
    }

    function testIssueCeritificateRevertsWhenCertificateIsAlreadyExpired()
        public
    {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateAlreadyExpired.selector,
                certificateHash
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp - 1
        );

        vm.stopPrank();
    }

    function testIssueCeritificateRevertsWhenCertificateIssuedAtIsInFuture()
        public
    {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");
        uint256 issuedAt = block.timestamp + 1;
        uint256 expiresAt = issuedAt + 365 days;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.IssuanceTimestampInFuture.selector,
                issuedAt,
                block.timestamp
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            issuedAt,
            expiresAt
        );

        vm.stopPrank();
    }

    function testIssueCeritificateRevertsWhenOwnerIsInvalid() public {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");
        address invalidOwner = address(0);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.InvalidOwnerAddress.selector,
                invalidOwner
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            invalidOwner,
            block.timestamp,
            block.timestamp + 365 days
        );

        vm.stopPrank();
    }

    function testIssueCeritificateRevertsWhenCertificateHashIsInvalid() public {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = bytes32(0);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.InvalidCertificateHash.selector,
                certificateHash
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            block.timestamp,
            block.timestamp + 365 days
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenIssuerCertificateHasBeenIssuedAfterTheCertificate()
        public
    {
        vm.startPrank(intermediateCA);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");
        uint256 issuedAt = block.timestamp - 1;
        uint256 expiresAt = issuedAt + 365 days;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateIssuedBeforeIssuerCertificate.selector,
                certificateHash
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            issuedAt,
            expiresAt
        );

        vm.stopPrank();
    }

    function testIssueCertificateRevertsWhenCertificateValidityPeriodIsTooLong()
        public
    {
        vm.startPrank(intermediateCA);

        PKI.CertificateStatus memory intermediateCertificateStatus = pki
            .getCertificateStatus(intermediateCertificateHash);

        bytes32 certificateHash = stringToBytes32("new-end-entity-ca");
        uint256 issuedAt = block.timestamp;
        uint256 expiresAt = intermediateCertificateStatus.expiresAt + 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateValidityPeriodTooLong.selector,
                expiresAt,
                intermediateCertificateStatus.expiresAt
            )
        );

        pki.registerCertificate(
            certificateHash,
            intermediateCertificateHash,
            endEntity,
            issuedAt,
            expiresAt
        );

        vm.stopPrank();
    }

    function testRevokeCertificateWhenIsRootCertificate() public {
        vm.startPrank(owner);

        uint256 revokedAt = block.timestamp;

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRevoked(rootCertificateHash, owner, revokedAt);

        pki.revokeCertificate(rootCertificateHash, revokedAt);

        require(
            pki.getCertificateStatus(rootCertificateHash).revokedAt ==
                block.timestamp,
            "Root certificate should be revoked"
        );

        require(
            !pki.isCertificateValid(rootCertificateHash),
            "Root certificate should not be valid"
        );

        vm.stopPrank();
    }

    function testRevokeCertificateWhenIsIntermediateCertificate() public {
        vm.startPrank(owner);
        uint256 revokedAt = block.timestamp;

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRevoked(
            intermediateCertificateHash,
            owner,
            revokedAt
        );

        pki.revokeCertificate(intermediateCertificateHash, revokedAt);

        require(
            pki.getCertificateStatus(intermediateCertificateHash).revokedAt ==
                block.timestamp,
            "Intermediate certificate should be revoked"
        );

        require(
            !pki.isCertificateValid(intermediateCertificateHash),
            "Intermediate certificate should not be valid"
        );

        vm.stopPrank();
    }

    function testRevokeCertificateWhenIsEndEntityCertificate() public {
        vm.startPrank(intermediateCA);

        uint256 revokedAt = block.timestamp;

        vm.expectEmit(true, true, true, true);

        emit PKI.CertificateRevoked(
            endEntityCertificateHash,
            intermediateCA,
            revokedAt
        );

        pki.revokeCertificate(endEntityCertificateHash, revokedAt);

        require(
            pki.getCertificateStatus(endEntityCertificateHash).revokedAt ==
                block.timestamp,
            "End entity certificate should be revoked"
        );

        require(
            !pki.isCertificateValid(endEntityCertificateHash),
            "End entity certificate should not be valid"
        );

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenCertificateIsRootAndCallerIsNotOwner()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyCertificateOwnerOrIssuer.selector,
                address(this),
                rootCertificateHash
            )
        );

        pki.revokeCertificate(rootCertificateHash, block.timestamp);
    }

    function testRevokeCertificateWhenCallerIsTheCertificateOwner() public {
        vm.startPrank(owner);

        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateWhenCallerIsTheCertificateIssuer() public {
        vm.startPrank(owner);

        pki.revokeCertificate(intermediateCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenIsNotIssuer() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.OnlyCertificateOwnerOrIssuer.selector,
                owner,
                endEntityCertificateHash
            )
        );

        pki.revokeCertificate(endEntityCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenIssuerIsNotTrusted() public {
        // Revoke the intermediate certificate (so it is not trusted).
        vm.startPrank(owner);
        pki.revokeCertificate(intermediateCertificateHash, block.timestamp);
        vm.stopPrank();

        // Try to revoke the end entity certificate with the revoked intermediate certificate.
        vm.startPrank(intermediateCA);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.IssuerCertificateNotTrusted.selector,
                intermediateCertificateHash
            )
        );

        pki.revokeCertificate(endEntityCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenCertificateIsAlreadyRevoked()
        public
    {
        vm.startPrank(owner);

        // Revoke the root certificate.
        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateAlreadyRevoked.selector,
                rootCertificateHash
            )
        );

        // Try to revoke the root certificate again.
        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenCertificateIsAlreadyExpired()
        public
    {
        vm.startPrank(owner);

        PKI.CertificateStatus memory certificateStatus = pki
            .getCertificateStatus(rootCertificateHash);

        // Set the time to after the expiration date.
        vm.warp(certificateStatus.expiresAt + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.CertificateAlreadyExpired.selector,
                rootCertificateHash
            )
        );

        // Try to revoke the root certificate.
        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenRevokedAtIsOutOfRange() public {
        vm.startPrank(owner);

        PKI.CertificateStatus memory certificateStatus = pki
            .getCertificateStatus(rootCertificateHash);

        // Try to revoke the root certificate before the issue date.
        uint256 revokedAtBeforeIssue = certificateStatus.issuedAt - 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.RevocationTimestampOutOfRange.selector,
                revokedAtBeforeIssue,
                certificateStatus.issuedAt,
                certificateStatus.expiresAt
            )
        );

        pki.revokeCertificate(rootCertificateHash, revokedAtBeforeIssue);

        // Try to revoke the root certificate after the expiration date.
        uint256 revokedAtAfterExpiration = certificateStatus.expiresAt + 1;

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.RevocationTimestampOutOfRange.selector,
                revokedAtAfterExpiration,
                certificateStatus.issuedAt,
                certificateStatus.expiresAt
            )
        );

        pki.revokeCertificate(rootCertificateHash, revokedAtAfterExpiration);

        vm.stopPrank();
    }

    function testRevokeCertificateRevertsWhenRevokedAtIsInFuture() public {
        vm.startPrank(owner);

        vm.expectRevert(
            abi.encodeWithSelector(
                PKI.RevocationTimestampInFuture.selector,
                block.timestamp + 1,
                block.timestamp
            )
        );

        pki.revokeCertificate(rootCertificateHash, block.timestamp + 1);

        vm.stopPrank();
    }

    function testIsCertificateValidWhenRootCertificateIsRevoked() public {
        vm.startPrank(owner);

        pki.revokeCertificate(rootCertificateHash, block.timestamp);

        require(
            !pki.isCertificateValid(rootCertificateHash),
            "Root certificate should not be valid when it is revoked"
        );

        require(
            !pki.isCertificateValid(intermediateCertificateHash),
            "Intermediate certificate should not be valid when its issuer is revoked"
        );

        require(
            !pki.isCertificateValid(endEntityCertificateHash),
            "End entity certificate should not be valid when the issuer of the intermediate certificate is revoked"
        );

        vm.stopPrank();
    }

    function testIsCertificateValidWhenIntermediateCertificateIsRevoked()
        public
    {
        vm.startPrank(owner);

        pki.revokeCertificate(intermediateCertificateHash, block.timestamp);

        require(
            !pki.isCertificateValid(intermediateCertificateHash),
            "Intermediate certificate should not be valid when it is revoked"
        );

        require(
            !pki.isCertificateValid(endEntityCertificateHash),
            "End entity certificate should not be valid when its issuer is revoked"
        );

        vm.stopPrank();
    }

    function testIsCertificateValidWhenEndEntityCertificateIsRevoked() public {
        vm.startPrank(intermediateCA);

        pki.revokeCertificate(endEntityCertificateHash, block.timestamp);

        require(
            !pki.isCertificateValid(endEntityCertificateHash),
            "End entity certificate should not be valid when it is revoked"
        );

        vm.stopPrank();
    }

    function testIsCertificateValidWhenCertificateIsNotRegistered()
        public
        view
    {
        require(
            !pki.isCertificateValid(
                stringToBytes32("not-registered-certificate")
            ),
            "Certificate should not be valid when it is not registered"
        );
    }
}
