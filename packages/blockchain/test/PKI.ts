import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isAddressEqual, getAddress, type WalletClient } from "viem";
import { network } from "hardhat";

describe("PKI", async function () {
  const { viem } = await network.connect();
  const publicClient = await viem.getPublicClient();
  const walletClients = await viem.getWalletClients();
  const [ownerClient, intermediateClient, endEntityClient, unauthorizedClient] =
    walletClients;

  /** Converts a string to a SHA-256 hash. */
  const sha256 = async (input: string): Promise<`0x${string}`> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const digest = await crypto.subtle.digest("SHA-256", data);
    const hex = Array.from(new Uint8Array(digest))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    return `0x${hex}`;
  };

  /** Gets the validity period for a certificate. */
  const getValidityPeriod = async (years: bigint) => {
    const { timestamp } = await publicClient.getBlock();
    return {
      issuedAt: timestamp,
      expiresAt: timestamp + years * 365n * 24n * 60n * 60n,
    };
  };

  /** The type of a certificate. */
  const CertificateType = {
    Root: 0,
    Intermediate: 1,
    EndEntity: 2,
  };

  /** Helper to deploy PKI and register root certificate */
  const deployWithRoot = async () => {
    const pki = await viem.deployContract("PKI");
    const { issuedAt, expiresAt } = await getValidityPeriod(10n);
    const rootHash = await sha256("root-ca");

    await pki.write.registerRootCertificate([rootHash, issuedAt, expiresAt]);

    return { pki, rootHash, issuedAt, expiresAt };
  };

  /** Helper to deploy PKI with root and intermediate certificates */
  const deployWithRootAndIntermediate = async () => {
    const { pki, rootHash, issuedAt: rootIssuedAt } = await deployWithRoot();

    const { issuedAt, expiresAt } = await getValidityPeriod(5n);
    const intermediateHash = await sha256("intermediate-ca");

    await pki.write.registerIntermediateCertificate([
      intermediateHash,
      rootHash,
      intermediateClient.account.address,
      issuedAt,
      expiresAt,
    ]);

    return {
      pki,
      rootHash,
      intermediateHash,
      issuedAt,
      expiresAt,
      rootIssuedAt,
    };
  };

  describe("Contract Deployment", () => {
    it("Should set the deployer as the owner", async () => {
      const pki = await viem.deployContract("PKI");
      const owner = await pki.read.getOwner();

      assert.ok(
        isAddressEqual(owner, ownerClient.account.address),
        "Owner should be the deployer",
      );
    });
  });

  describe("Root Certificate Registration", () => {
    it("Should register a root certificate successfully", async () => {
      const pki = await viem.deployContract("PKI");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await pki.write.registerRootCertificate([
        certificateHash,
        issuedAt,
        expiresAt,
      ]);

      const status = await pki.read.getCertificateStatus([certificateHash]);

      assert.ok(
        isAddressEqual(status.owner, ownerClient.account.address),
        "Certificate owner should be the deployer",
      );
      assert.equal(status.issuedAt, issuedAt, "Issued at should match");
      assert.equal(status.expiresAt, expiresAt, "Expires at should match");
      assert.equal(status.revokedAt, 0n, "Should not be revoked");
      assert.equal(
        status.certificateType,
        CertificateType.Root,
        "Should be a root certificate",
      );
    });

    it("Should emit CertificateRegistered event when registering root certificate", async () => {
      const pki = await viem.deployContract("PKI");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");
      const contractOwner = await pki.read.getOwner();

      await viem.assertions.emitWithArgs(
        pki.write.registerRootCertificate([
          certificateHash,
          issuedAt,
          expiresAt,
        ]),
        pki,
        "CertificateRegistered",
        [
          certificateHash,
          contractOwner,
          contractOwner,
          expiresAt,
          CertificateType.Root,
        ],
      );
    });

    it("Should revert if non-owner tries to register root certificate", async () => {
      const pki = await viem.deployContract("PKI");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await assert.rejects(
        async () => {
          await pki.write.registerRootCertificate(
            [certificateHash, issuedAt, expiresAt],
            { account: unauthorizedClient.account },
          );
        },
        /OnlyOwner/,
        "Should revert with OnlyOwner error",
      );
    });

    it("Should revert if certificate is already registered", async () => {
      const pki = await viem.deployContract("PKI");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await pki.write.registerRootCertificate([
        certificateHash,
        issuedAt,
        expiresAt,
      ]);

      await assert.rejects(
        async () => {
          await pki.write.registerRootCertificate([
            certificateHash,
            issuedAt,
            expiresAt,
          ]);
        },
        /CertificateAlreadyRegistered/,
        "Should revert with CertificateAlreadyRegistered error",
      );
    });

    it("Should revert if issuance timestamp is in the future", async () => {
      const pki = await viem.deployContract("PKI");
      const { timestamp } = await publicClient.getBlock();
      const certificateHash = await sha256("root-ca");

      const futureIssuedAt = timestamp + 3600n; // 1 hour in the future
      const expiresAt = timestamp + 365n * 24n * 60n * 60n;

      await assert.rejects(
        async () => {
          await pki.write.registerRootCertificate([
            certificateHash,
            futureIssuedAt,
            expiresAt,
          ]);
        },
        /IssuanceTimestampInFuture/,
        "Should revert with IssuanceTimestampInFuture error",
      );
    });

    it("Should revert if certificate is already expired", async () => {
      const pki = await viem.deployContract("PKI");
      const { timestamp } = await publicClient.getBlock();
      const certificateHash = await sha256("root-ca");

      const issuedAt = timestamp - 3600n; // 1 hour ago
      const expiresAt = timestamp - 1800n; // 30 minutes ago

      await assert.rejects(
        async () => {
          await pki.write.registerRootCertificate([
            certificateHash,
            issuedAt,
            expiresAt,
          ]);
        },
        /CertificateAlreadyExpired/,
        "Should revert with CertificateAlreadyExpired error",
      );
    });

    it("Should revert if certificate hash is invalid (zero)", async () => {
      const pki = await viem.deployContract("PKI");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const zeroCertificateHash =
        "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;

      await assert.rejects(
        async () => {
          await pki.write.registerRootCertificate([
            zeroCertificateHash,
            issuedAt,
            expiresAt,
          ]);
        },
        /InvalidCertificateHash/,
        "Should revert with InvalidCertificateHash error",
      );
    });
  });

  describe("Intermediate Certificate Registration", () => {
    it("Should register an intermediate certificate successfully", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await pki.write.registerIntermediateCertificate([
        intermediateHash,
        rootHash,
        intermediateClient.account.address,
        issuedAt,
        expiresAt,
      ]);

      const status = await pki.read.getCertificateStatus([intermediateHash]);

      assert.ok(
        isAddressEqual(status.owner, intermediateClient.account.address),
        "Certificate owner should be the intermediate CA",
      );
      assert.equal(
        status.issuerCertificateHash,
        rootHash,
        "Issuer should be the root CA",
      );
      assert.equal(
        status.certificateType,
        CertificateType.Intermediate,
        "Should be an intermediate certificate",
      );
    });

    it("Should emit CertificateRegistered event when registering intermediate certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");
      const owner = await pki.read.getOwner();

      await viem.assertions.emitWithArgs(
        pki.write.registerIntermediateCertificate([
          intermediateHash,
          rootHash,
          intermediateClient.account.address,
          issuedAt,
          expiresAt,
        ]),
        pki,
        "CertificateRegistered",
        [
          intermediateHash,
          getAddress(intermediateClient.account.address),
          owner,
          expiresAt,
          CertificateType.Intermediate,
        ],
      );
    });

    it("Should revert if non-root CA tries to register intermediate certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await assert.rejects(
        async () => {
          await pki.write.registerIntermediateCertificate(
            [
              intermediateHash,
              rootHash,
              intermediateClient.account.address,
              issuedAt,
              expiresAt,
            ],
            { account: unauthorizedClient.account },
          );
        },
        /OnlyCertificateOwner/,
        "Should revert with OnlyCertificateOwner error",
      );
    });

    it("Should revert if issuer certificate is not a root CA", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity-2");

      // Attempting to register an intermediate cert with an intermediate as issuer
      // should fail - the modifier checks ownership first (OnlyIssuer), then type (OnlyRootCA)
      await assert.rejects(
        async () => {
          await pki.write.registerIntermediateCertificate(
            [
              endEntityHash,
              intermediateHash,
              endEntityClient.account.address,
              issuedAt,
              expiresAt,
            ],
            { account: intermediateClient.account }, // Call as intermediate CA owner
          );
        },
        (error: any) => {
          // The error should be OnlyRootCA since we're calling as the intermediate owner
          return (
            error.message.includes("OnlyRootCA") ||
            error.toString().includes("OnlyRootCA")
          );
        },
        "Should revert with OnlyRootCA error",
      );
    });

    it("Should revert if certificate expires after issuer certificate", async () => {
      const {
        pki,
        rootHash,
        expiresAt: rootExpiresAt,
      } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();
      const intermediateHash = await sha256("intermediate-ca");

      const issuedAt = timestamp;
      const expiresAt = rootExpiresAt + 1n; // Expires after root

      await assert.rejects(
        async () => {
          await pki.write.registerIntermediateCertificate([
            intermediateHash,
            rootHash,
            intermediateClient.account.address,
            issuedAt,
            expiresAt,
          ]);
        },
        /CertificateValidityPeriodTooLong/,
        "Should revert with CertificateValidityPeriodTooLong error",
      );
    });

    it("Should revert if certificate is issued before issuer certificate", async () => {
      const { pki, rootHash, issuedAt: rootIssuedAt } = await deployWithRoot();
      const { expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      const issuedAt = rootIssuedAt - 1n; // Issued before root

      await assert.rejects(
        async () => {
          await pki.write.registerIntermediateCertificate([
            intermediateHash,
            rootHash,
            intermediateClient.account.address,
            issuedAt,
            expiresAt,
          ]);
        },
        /CertificateIssuedBeforeIssuerCertificate/,
        "Should revert with CertificateIssuedBeforeIssuerCertificate error",
      );
    });

    it("Should revert if owner address is invalid (zero address)", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");
      const zeroAddress =
        "0x0000000000000000000000000000000000000000" as `0x${string}`;

      await assert.rejects(
        async () => {
          await pki.write.registerIntermediateCertificate([
            intermediateHash,
            rootHash,
            zeroAddress,
            issuedAt,
            expiresAt,
          ]);
        },
        /InvalidOwnerAddress/,
        "Should revert with InvalidOwnerAddress error",
      );
    });
  });

  describe("End Entity Certificate Registration", () => {
    it("Should register an end entity certificate successfully", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await pki.write.registerCertificate(
        [
          endEntityHash,
          intermediateHash,
          endEntityClient.account.address,
          issuedAt,
          expiresAt,
        ],
        { account: intermediateClient.account },
      );

      const status = await pki.read.getCertificateStatus([endEntityHash]);

      assert.ok(
        isAddressEqual(status.owner, endEntityClient.account.address),
        "Certificate owner should be the end entity",
      );
      assert.equal(
        status.issuerCertificateHash,
        intermediateHash,
        "Issuer should be the intermediate CA",
      );
      assert.equal(
        status.certificateType,
        CertificateType.EndEntity,
        "Should be an end entity certificate",
      );
    });

    it("Should emit CertificateRegistered event when registering end entity certificate", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await viem.assertions.emitWithArgs(
        pki.write.registerCertificate(
          [
            endEntityHash,
            intermediateHash,
            endEntityClient.account.address,
            issuedAt,
            expiresAt,
          ],
          { account: intermediateClient.account },
        ),
        pki,
        "CertificateRegistered",
        [
          endEntityHash,
          getAddress(endEntityClient.account.address),
          getAddress(intermediateClient.account.address),
          expiresAt,
          CertificateType.EndEntity,
        ],
      );
    });

    it("Should revert if non-intermediate CA tries to register end entity certificate", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await assert.rejects(
        async () => {
          await pki.write.registerCertificate(
            [
              endEntityHash,
              intermediateHash,
              endEntityClient.account.address,
              issuedAt,
              expiresAt,
            ],
            { account: unauthorizedClient.account },
          );
        },
        /OnlyCertificateOwner/,
        "Should revert with OnlyCertificateOwner error",
      );
    });

    it("Should revert if issuer is not an intermediate CA", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await assert.rejects(
        async () => {
          await pki.write.registerCertificate([
            endEntityHash,
            rootHash,
            endEntityClient.account.address,
            issuedAt,
            expiresAt,
          ]);
        },
        /OnlyIntermediateCA/,
        "Should revert with OnlyIntermediateCA error",
      );
    });
  });

  describe("Certificate Validation", () => {
    it("Should validate a valid root certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();

      const isValid = await pki.read.isCertificateValid([rootHash]);
      assert.ok(isValid, "Root certificate should be valid");
    });

    it("Should validate a valid intermediate certificate", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();

      const isValid = await pki.read.isCertificateValid([intermediateHash]);
      assert.ok(isValid, "Intermediate certificate should be valid");
    });

    it("Should validate a valid end entity certificate with full chain", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await pki.write.registerCertificate(
        [
          endEntityHash,
          intermediateHash,
          endEntityClient.account.address,
          issuedAt,
          expiresAt,
        ],
        { account: intermediateClient.account },
      );

      const isValid = await pki.read.isCertificateValid([endEntityHash]);
      assert.ok(
        isValid,
        "End entity certificate should be valid with valid chain",
      );
    });

    it("Should invalidate an unregistered certificate", async () => {
      const { pki } = await deployWithRoot();
      const unregisteredHash = await sha256("unregistered");

      const isValid = await pki.read.isCertificateValid([unregisteredHash]);
      assert.equal(
        isValid,
        false,
        "Unregistered certificate should be invalid",
      );
    });

    it("Should invalidate a revoked certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();

      await pki.write.revokeCertificate([rootHash, timestamp]);

      const isValid = await pki.read.isCertificateValid([rootHash]);
      assert.equal(isValid, false, "Revoked certificate should be invalid");
    });

    it("Should invalidate certificate chain when root is revoked", async () => {
      const { pki, rootHash, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { timestamp } = await publicClient.getBlock();

      // Revoke the root certificate
      await pki.write.revokeCertificate([rootHash, timestamp]);

      // Both root and intermediate should be invalid
      const rootValid = await pki.read.isCertificateValid([rootHash]);
      const intermediateValid = await pki.read.isCertificateValid([
        intermediateHash,
      ]);

      assert.equal(rootValid, false, "Revoked root should be invalid");
      assert.equal(
        intermediateValid,
        false,
        "Intermediate should be invalid when root is revoked",
      );
    });

    it("Should invalidate certificate chain when intermediate is revoked", async () => {
      const { pki, rootHash, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      // Register end entity certificate
      await pki.write.registerCertificate(
        [
          endEntityHash,
          intermediateHash,
          endEntityClient.account.address,
          issuedAt,
          expiresAt,
        ],
        { account: intermediateClient.account },
      );

      // Revoke the intermediate certificate
      const { timestamp } = await publicClient.getBlock();
      await pki.write.revokeCertificate([intermediateHash, timestamp]);

      // Root should still be valid
      const rootValid = await pki.read.isCertificateValid([rootHash]);
      assert.ok(rootValid, "Root should still be valid");

      // Intermediate and end entity should be invalid
      const intermediateValid = await pki.read.isCertificateValid([
        intermediateHash,
      ]);
      const endEntityValid = await pki.read.isCertificateValid([endEntityHash]);

      assert.equal(
        intermediateValid,
        false,
        "Revoked intermediate should be invalid",
      );
      assert.equal(
        endEntityValid,
        false,
        "End entity should be invalid when intermediate is revoked",
      );
    });
  });

  describe("Certificate Revocation", () => {
    it("Should revoke a root certificate successfully", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();

      await pki.write.revokeCertificate([rootHash, timestamp]);

      const status = await pki.read.getCertificateStatus([rootHash]);
      assert.equal(
        status.revokedAt,
        timestamp,
        "Certificate should be revoked at current timestamp",
      );
    });

    it("Should emit CertificateRevoked event when revoking certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();
      const owner = await pki.read.getOwner();

      await viem.assertions.emitWithArgs(
        pki.write.revokeCertificate([rootHash, timestamp]),
        pki,
        "CertificateRevoked",
        [rootHash, owner, timestamp],
      );
    });

    it("Should allow issuer (root CA) to revoke intermediate certificate", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { timestamp } = await publicClient.getBlock();

      // Root CA (issuer) should be able to revoke intermediate certificate
      await pki.write.revokeCertificate([intermediateHash, timestamp]);

      const status = await pki.read.getCertificateStatus([intermediateHash]);
      assert.equal(
        status.revokedAt,
        timestamp,
        "Intermediate certificate should be revoked by issuer",
      );
    });

    it("Should allow certificate owner to revoke their own certificate", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { timestamp } = await publicClient.getBlock();

      // Intermediate CA (owner) should be able to revoke their own certificate
      await pki.write.revokeCertificate([intermediateHash, timestamp], {
        account: intermediateClient.account,
      });

      const status = await pki.read.getCertificateStatus([intermediateHash]);
      assert.equal(
        status.revokedAt,
        timestamp,
        "Certificate should be revoked by owner",
      );
    });

    it("Should revert if non-owner and non-issuer tries to revoke certificate", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([rootHash, timestamp], {
            account: unauthorizedClient.account,
          });
        },
        /OnlyCertificateOwnerOrIssuer/,
        "Should revert with OnlyCertificateOwnerOrIssuer error",
      );
    });

    it("Should revert if certificate is already revoked", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();

      await pki.write.revokeCertificate([rootHash, timestamp]);

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([rootHash, timestamp]);
        },
        /CertificateAlreadyRevoked/,
        "Should revert with CertificateAlreadyRevoked error",
      );
    });

    it("Should revert if trying to revoke unregistered certificate", async () => {
      const { pki } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();
      const unregisteredHash = await sha256("unregistered");

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([unregisteredHash, timestamp]);
        },
        /CertificateNotRegistered/,
        "Should revert with CertificateNotRegistered error",
      );
    });

    it("Should revert if revocation timestamp is in the future", async () => {
      const { pki, rootHash } = await deployWithRoot();
      const { timestamp } = await publicClient.getBlock();
      const futureTimestamp = timestamp + 3600n;

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([rootHash, futureTimestamp]);
        },
        /RevocationTimestampInFuture/,
        "Should revert with RevocationTimestampInFuture error",
      );
    });

    it("Should revert if revocation timestamp is before issuance", async () => {
      const { pki, rootHash, issuedAt } = await deployWithRoot();
      const beforeIssuance = issuedAt - 1n;

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([rootHash, beforeIssuance]);
        },
        /RevocationTimestampOutOfRange/,
        "Should revert with RevocationTimestampOutOfRange error",
      );
    });

    it("Should revert if revocation timestamp is after expiration", async () => {
      const { pki, rootHash, expiresAt } = await deployWithRoot();
      const afterExpiration = expiresAt + 1n;

      await assert.rejects(
        async () => {
          await pki.write.revokeCertificate([rootHash, afterExpiration]);
        },
        /RevocationTimestampOutOfRange/,
        "Should revert with RevocationTimestampOutOfRange error",
      );
    });
  });

  describe("Certificate Status and Queries", () => {
    it("Should return correct certificate status", async () => {
      const { pki, rootHash, issuedAt, expiresAt } = await deployWithRoot();

      const status = await pki.read.getCertificateStatus([rootHash]);

      assert.ok(
        isAddressEqual(status.owner, ownerClient.account.address),
        "Owner should match",
      );
      assert.equal(status.issuedAt, issuedAt, "Issued at should match");
      assert.equal(status.expiresAt, expiresAt, "Expires at should match");
      assert.equal(status.revokedAt, 0n, "Should not be revoked");
      assert.equal(
        status.certificateType,
        CertificateType.Root,
        "Type should match",
      );
    });

    it("Should return certificates by owner", async () => {
      const { pki, rootHash } = await deployWithRoot();

      const certificates = await pki.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);

      assert.equal(certificates.length, 1, "Should have one certificate");
      assert.ok(
        isAddressEqual(certificates[0].owner, ownerClient.account.address),
        "Certificate owner should match",
      );
    });

    it("Should return multiple certificates for owner with multiple certificates", async () => {
      const { pki, rootHash } = await deployWithRoot();

      // Register another root certificate
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const rootHash2 = await sha256("root-ca-2");
      await pki.write.registerRootCertificate([rootHash2, issuedAt, expiresAt]);

      const certificates = await pki.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);

      assert.equal(certificates.length, 2, "Should have two certificates");
    });

    it("Should return empty array for owner with no certificates", async () => {
      const { pki } = await deployWithRoot();

      const certificates = await pki.read.getCertificatesByOwner([
        endEntityClient.account.address,
      ]);

      assert.equal(
        certificates.length,
        0,
        "Should have no certificates for address without certificates",
      );
    });

    it("Should track certificates across the full chain", async () => {
      const { pki, intermediateHash } = await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(2n);
      const endEntityHash = await sha256("end-entity");

      await pki.write.registerCertificate(
        [
          endEntityHash,
          intermediateHash,
          endEntityClient.account.address,
          issuedAt,
          expiresAt,
        ],
        { account: intermediateClient.account },
      );

      // Check owner has 1 certificate (root)
      const ownerCerts = await pki.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);
      assert.equal(ownerCerts.length, 1, "Owner should have 1 certificate");

      // Check intermediate CA has 1 certificate
      const intermediateCerts = await pki.read.getCertificatesByOwner([
        intermediateClient.account.address,
      ]);
      assert.equal(
        intermediateCerts.length,
        1,
        "Intermediate CA should have 1 certificate",
      );

      // Check end entity has 1 certificate
      const endEntityCerts = await pki.read.getCertificatesByOwner([
        endEntityClient.account.address,
      ]);
      assert.equal(
        endEntityCerts.length,
        1,
        "End entity should have 1 certificate",
      );
    });
  });
});
