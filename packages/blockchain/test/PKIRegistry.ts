import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isAddressEqual, getAddress } from "viem";
import { network } from "hardhat";

describe("PKIRegistry", async function () {
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

  /** The role of a certificate. */
  const CertificateRole = {
    RootCA: 0,
    IntermediateCA: 1,
    EndEntity: 2,
  };

  /** Helper to deploy PKIRegistry and issue root certificate */
  const deployWithRoot = async () => {
    const pkiRegistry = await viem.deployContract("PKIRegistry");
    const { issuedAt, expiresAt } = await getValidityPeriod(10n);
    const rootHash = await sha256("root-ca");

    await pkiRegistry.write.issueRootCertificate([
      rootHash,
      ownerClient.account.address,
      issuedAt,
      expiresAt,
    ]);

    return { pkiRegistry, rootHash, issuedAt, expiresAt };
  };

  /** Helper to deploy PKIRegistry with root and intermediate certificates */
  const deployWithRootAndIntermediate = async () => {
    const {
      pkiRegistry,
      rootHash,
      issuedAt: rootIssuedAt,
    } = await deployWithRoot();

    const { issuedAt, expiresAt } = await getValidityPeriod(5n);
    const intermediateHash = await sha256("intermediate-ca");

    await pkiRegistry.write.issueCertificate([
      intermediateHash,
      rootHash,
      intermediateClient.account.address,
      issuedAt,
      expiresAt,
      CertificateRole.IntermediateCA,
    ]);

    return {
      pkiRegistry,
      rootHash,
      intermediateHash,
      issuedAt,
      expiresAt,
      rootIssuedAt,
    };
  };

  /** Helper to deploy PKIRegistry with full certificate chain */
  const deployWithFullChain = async () => {
    const {
      pkiRegistry,
      rootHash,
      intermediateHash,
      issuedAt: intermediateIssuedAt,
      expiresAt: intermediateExpiresAt,
    } = await deployWithRootAndIntermediate();

    const { issuedAt, expiresAt } = await getValidityPeriod(1n);
    const endEntityHash = await sha256("end-entity");

    await pkiRegistry.write.issueCertificate(
      [
        endEntityHash,
        intermediateHash,
        endEntityClient.account.address,
        issuedAt,
        expiresAt,
        CertificateRole.EndEntity,
      ],
      { account: intermediateClient.account },
    );

    return {
      pkiRegistry,
      rootHash,
      intermediateHash,
      endEntityHash,
      issuedAt,
      expiresAt,
    };
  };

  describe("Contract Deployment", () => {
    it("Should set the deployer as the owner", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const owner = await pkiRegistry.read.getOwner();

      assert.ok(
        isAddressEqual(owner, ownerClient.account.address),
        "Owner should be the deployer",
      );
    });
  });

  describe("Root Certificate Issuance", () => {
    it("Should issue a root certificate successfully", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await pkiRegistry.write.issueRootCertificate([
        certificateHash,
        ownerClient.account.address,
        issuedAt,
        expiresAt,
      ]);

      const certificate = await pkiRegistry.read.getCertificate([
        certificateHash,
      ]);

      assert.ok(
        isAddressEqual(certificate.owner, ownerClient.account.address),
        "Certificate owner should be the deployer",
      );
      assert.equal(certificate.issuedAt, issuedAt, "Issued at should match");
      assert.equal(certificate.expiresAt, expiresAt, "Expires at should match");
      assert.equal(certificate.revokedAt, 0n, "Should not be revoked");
      assert.equal(
        certificate.role,
        CertificateRole.RootCA,
        "Should be a root CA certificate",
      );
    });

    it("Should emit CertificateIssued event when issuing root certificate", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await viem.assertions.emitWithArgs(
        pkiRegistry.write.issueRootCertificate([
          certificateHash,
          ownerClient.account.address,
          issuedAt,
          expiresAt,
        ]),
        pkiRegistry,
        "CertificateIssued",
        [
          getAddress(ownerClient.account.address),
          certificateHash,
          "0x" + "0".repeat(64),
          expiresAt,
        ],
      );
    });

    it("Should revert if non-owner tries to issue root certificate", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate(
            [
              certificateHash,
              unauthorizedClient.account.address,
              issuedAt,
              expiresAt,
            ],
            { account: unauthorizedClient.account },
          );
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate is already registered", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate([
            rootHash,
            ownerClient.account.address,
            issuedAt,
            expiresAt,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if issuance timestamp is in the future", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const certificateHash = await sha256("root-ca");
      const { timestamp } = await publicClient.getBlock();
      const futureTimestamp = timestamp + 100n;

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate([
            certificateHash,
            ownerClient.account.address,
            futureTimestamp,
            futureTimestamp + 365n * 24n * 60n * 60n * 10n,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate is already expired", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const certificateHash = await sha256("root-ca");
      const { timestamp } = await publicClient.getBlock();

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate([
            certificateHash,
            ownerClient.account.address,
            timestamp,
            timestamp - 1n,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if owner address is invalid (zero address)", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const certificateHash = await sha256("root-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate([
            certificateHash,
            "0x0000000000000000000000000000000000000000",
            issuedAt,
            expiresAt,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate hash is invalid (zero)", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueRootCertificate([
            ("0x" + "0".repeat(64)) as `0x${string}`,
            ownerClient.account.address,
            issuedAt,
            expiresAt,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });
  });

  describe("Intermediate Certificate Issuance", () => {
    it("Should issue an intermediate certificate successfully", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await pkiRegistry.write.issueCertificate([
        intermediateHash,
        rootHash,
        intermediateClient.account.address,
        issuedAt,
        expiresAt,
        CertificateRole.IntermediateCA,
      ]);

      const certificate = await pkiRegistry.read.getCertificate([
        intermediateHash,
      ]);

      assert.ok(
        isAddressEqual(certificate.owner, intermediateClient.account.address),
        "Certificate owner should be the intermediate CA",
      );
      assert.equal(
        certificate.issuerCertificateHash,
        rootHash,
        "Issuer should be root CA",
      );
      assert.equal(
        certificate.role,
        CertificateRole.IntermediateCA,
        "Should be an intermediate CA certificate",
      );
    });

    it("Should emit CertificateIssued event when issuing intermediate certificate", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await viem.assertions.emitWithArgs(
        pkiRegistry.write.issueCertificate([
          intermediateHash,
          rootHash,
          intermediateClient.account.address,
          issuedAt,
          expiresAt,
          CertificateRole.IntermediateCA,
        ]),
        pkiRegistry,
        "CertificateIssued",
        [
          getAddress(intermediateClient.account.address),
          intermediateHash,
          rootHash,
          expiresAt,
        ],
      );
    });

    it("Should revert if non-issuer tries to issue intermediate certificate", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate(
            [
              intermediateHash,
              rootHash,
              intermediateClient.account.address,
              issuedAt,
              expiresAt,
              CertificateRole.IntermediateCA,
            ],
            { account: unauthorizedClient.account },
          );
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if issuer certificate is not trusted", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      // Revoke root certificate
      await pkiRegistry.write.revokeCertificate([rootHash]);

      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate([
            intermediateHash,
            rootHash,
            intermediateClient.account.address,
            issuedAt,
            expiresAt,
            CertificateRole.IntermediateCA,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if issuance is not allowed (wrong role)", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const newRootHash = await sha256("new-root-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate([
            newRootHash,
            rootHash,
            ownerClient.account.address,
            issuedAt,
            expiresAt,
            CertificateRole.RootCA,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate expires after issuer certificate", async () => {
      const {
        pkiRegistry,
        rootHash,
        expiresAt: rootExpiresAt,
      } = await deployWithRoot();
      const { issuedAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate([
            intermediateHash,
            rootHash,
            intermediateClient.account.address,
            issuedAt,
            rootExpiresAt + 1n,
            CertificateRole.IntermediateCA,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate is issued before issuer certificate", async () => {
      const {
        pkiRegistry,
        rootHash,
        issuedAt: rootIssuedAt,
      } = await deployWithRoot();
      const { expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate([
            intermediateHash,
            rootHash,
            intermediateClient.account.address,
            rootIssuedAt - 1n,
            expiresAt,
            CertificateRole.IntermediateCA,
          ]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });
  });

  describe("End Entity Certificate Issuance", () => {
    it("Should issue an end entity certificate successfully", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(1n);
      const endEntityHash = await sha256("end-entity");

      await pkiRegistry.write.issueCertificate(
        [
          endEntityHash,
          intermediateHash,
          endEntityClient.account.address,
          issuedAt,
          expiresAt,
          CertificateRole.EndEntity,
        ],
        { account: intermediateClient.account },
      );

      const certificate = await pkiRegistry.read.getCertificate([
        endEntityHash,
      ]);

      assert.ok(
        isAddressEqual(certificate.owner, endEntityClient.account.address),
        "Certificate owner should be the end entity",
      );
      assert.equal(
        certificate.issuerCertificateHash,
        intermediateHash,
        "Issuer should be intermediate CA",
      );
      assert.equal(
        certificate.role,
        CertificateRole.EndEntity,
        "Should be an end entity certificate",
      );
    });

    it("Should emit CertificateIssued event when issuing end entity certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(1n);
      const endEntityHash = await sha256("end-entity");

      await viem.assertions.emitWithArgs(
        pkiRegistry.write.issueCertificate(
          [
            endEntityHash,
            intermediateHash,
            endEntityClient.account.address,
            issuedAt,
            expiresAt,
            CertificateRole.EndEntity,
          ],
          { account: intermediateClient.account },
        ),
        pkiRegistry,
        "CertificateIssued",
        [
          getAddress(endEntityClient.account.address),
          endEntityHash,
          intermediateHash,
          expiresAt,
        ],
      );
    });

    it("Should revert if non-issuer tries to issue end entity certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(1n);
      const endEntityHash = await sha256("end-entity");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate(
            [
              endEntityHash,
              intermediateHash,
              endEntityClient.account.address,
              issuedAt,
              expiresAt,
              CertificateRole.EndEntity,
            ],
            { account: unauthorizedClient.account },
          );
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if intermediate CA tries to issue another intermediate CA", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();
      const { issuedAt, expiresAt } = await getValidityPeriod(5n);
      const newIntermediateHash = await sha256("new-intermediate-ca");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.issueCertificate(
            [
              newIntermediateHash,
              intermediateHash,
              intermediateClient.account.address,
              issuedAt,
              expiresAt,
              CertificateRole.IntermediateCA,
            ],
            { account: intermediateClient.account },
          );
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });
  });

  describe("Certificate Validation", () => {
    it("Should validate a valid root certificate", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      const isValid = await pkiRegistry.read.isValidCertificate([rootHash]);

      assert.equal(isValid, true, "Root certificate should be valid");
    });

    it("Should validate a valid intermediate certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();

      const isValid = await pkiRegistry.read.isValidCertificate([
        intermediateHash,
      ]);

      assert.equal(isValid, true, "Intermediate certificate should be valid");
    });

    it("Should validate a valid end entity certificate with full chain", async () => {
      const { pkiRegistry, endEntityHash } = await deployWithFullChain();

      const isValid = await pkiRegistry.read.isValidCertificate([
        endEntityHash,
      ]);

      assert.equal(isValid, true, "End entity certificate should be valid");
    });

    it("Should invalidate an unregistered certificate", async () => {
      const { pkiRegistry } = await deployWithRoot();
      const unregisteredHash = await sha256("unregistered");

      const isValid = await pkiRegistry.read.isValidCertificate([
        unregisteredHash,
      ]);

      assert.equal(
        isValid,
        false,
        "Unregistered certificate should be invalid",
      );
    });

    it("Should invalidate a revoked certificate", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      await pkiRegistry.write.revokeCertificate([rootHash]);

      const isValid = await pkiRegistry.read.isValidCertificate([rootHash]);

      assert.equal(isValid, false, "Revoked certificate should be invalid");
    });

    it("Should invalidate certificate chain when root is revoked", async () => {
      const { pkiRegistry, rootHash, intermediateHash, endEntityHash } =
        await deployWithFullChain();

      await pkiRegistry.write.revokeCertificate([rootHash]);

      const rootValid = await pkiRegistry.read.isValidCertificate([rootHash]);
      const intermediateValid = await pkiRegistry.read.isValidCertificate([
        intermediateHash,
      ]);
      const endEntityValid = await pkiRegistry.read.isValidCertificate([
        endEntityHash,
      ]);

      assert.equal(rootValid, false, "Root should be invalid");
      assert.equal(intermediateValid, false, "Intermediate should be invalid");
      assert.equal(endEntityValid, false, "End entity should be invalid");
    });

    it("Should invalidate certificate chain when intermediate is revoked", async () => {
      const { pkiRegistry, rootHash, intermediateHash, endEntityHash } =
        await deployWithFullChain();

      await pkiRegistry.write.revokeCertificate([intermediateHash]);

      const rootValid = await pkiRegistry.read.isValidCertificate([rootHash]);
      const intermediateValid = await pkiRegistry.read.isValidCertificate([
        intermediateHash,
      ]);
      const endEntityValid = await pkiRegistry.read.isValidCertificate([
        endEntityHash,
      ]);

      assert.equal(rootValid, true, "Root should still be valid");
      assert.equal(intermediateValid, false, "Intermediate should be invalid");
      assert.equal(endEntityValid, false, "End entity should be invalid");
    });

    // Note: Testing expired certificates requires blockchain time manipulation
    // which is not easily available in the current test setup. The expiration
    // logic is covered by the Solidity tests in PKIRegistry.t.sol
  });

  describe("Certificate Revocation", () => {
    it("Should revoke a root certificate successfully", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      await pkiRegistry.write.revokeCertificate([rootHash]);

      const certificate = await pkiRegistry.read.getCertificate([rootHash]);

      assert.notEqual(
        certificate.revokedAt,
        0n,
        "Certificate should be revoked",
      );
    });

    it("Should emit CertificateRevoked event when revoking certificate", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      const txHash = await pkiRegistry.write.revokeCertificate([rootHash]);
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: txHash,
      });

      const logs = await pkiRegistry.getEvents.CertificateRevoked();
      const log = logs[logs.length - 1];

      assert.ok(
        isAddressEqual(log.args.revoker!, ownerClient.account.address),
        "Revoker should be the owner",
      );
      assert.equal(
        log.args.certificateHash,
        rootHash,
        "Certificate hash should match",
      );
      assert.ok(log.args.revokedAt! > 0n, "RevokedAt should be set");
    });

    it("Should allow issuer (root CA) to revoke intermediate certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();

      await pkiRegistry.write.revokeCertificate([intermediateHash]);

      const certificate = await pkiRegistry.read.getCertificate([
        intermediateHash,
      ]);

      assert.notEqual(
        certificate.revokedAt,
        0n,
        "Certificate should be revoked",
      );
    });

    it("Should allow certificate owner to revoke their own certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();

      await pkiRegistry.write.revokeCertificate([intermediateHash], {
        account: intermediateClient.account,
      });

      const certificate = await pkiRegistry.read.getCertificate([
        intermediateHash,
      ]);

      assert.notEqual(
        certificate.revokedAt,
        0n,
        "Certificate should be revoked",
      );
    });

    it("Should revert if non-owner and non-issuer tries to revoke certificate", async () => {
      const { pkiRegistry, intermediateHash } =
        await deployWithRootAndIntermediate();

      await assert.rejects(
        async () => {
          await pkiRegistry.write.revokeCertificate([intermediateHash], {
            account: unauthorizedClient.account,
          });
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if certificate is already revoked", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      await pkiRegistry.write.revokeCertificate([rootHash]);

      await assert.rejects(
        async () => {
          await pkiRegistry.write.revokeCertificate([rootHash]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    it("Should revert if trying to revoke unregistered certificate", async () => {
      const { pkiRegistry } = await deployWithRoot();
      const unregisteredHash = await sha256("unregistered");

      await assert.rejects(
        async () => {
          await pkiRegistry.write.revokeCertificate([unregisteredHash]);
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });

    // Note: Testing expired certificate revocation requires blockchain time manipulation
    // which is not easily available in the current test setup. The expiration
    // logic is covered by the Solidity tests in PKIRegistry.t.sol

    it("Should revert if issuer is not trusted when trying to revoke", async () => {
      const { pkiRegistry, intermediateHash, endEntityHash } =
        await deployWithFullChain();

      // Revoke intermediate certificate
      await pkiRegistry.write.revokeCertificate([intermediateHash]);

      // Try to revoke end entity certificate with revoked issuer
      await assert.rejects(
        async () => {
          await pkiRegistry.write.revokeCertificate([endEntityHash], {
            account: intermediateClient.account,
          });
        },
        {
          name: "ContractFunctionExecutionError",
        },
      );
    });
  });

  describe("Certificate Status and Queries", () => {
    it("Should return correct certificate information", async () => {
      const { pkiRegistry, rootHash, issuedAt, expiresAt } =
        await deployWithRoot();

      const certificate = await pkiRegistry.read.getCertificate([rootHash]);

      assert.ok(
        isAddressEqual(certificate.owner, ownerClient.account.address),
        "Owner should match",
      );
      assert.equal(certificate.issuedAt, issuedAt, "IssuedAt should match");
      assert.equal(certificate.expiresAt, expiresAt, "ExpiresAt should match");
      assert.equal(certificate.revokedAt, 0n, "Should not be revoked");
      assert.equal(
        certificate.role,
        CertificateRole.RootCA,
        "Role should be RootCA",
      );
    });

    it("Should return certificates by owner", async () => {
      const { pkiRegistry, rootHash } = await deployWithRoot();

      const certificates = await pkiRegistry.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);

      assert.equal(certificates.length, 1, "Owner should have 1 certificate");
      assert.equal(certificates[0], rootHash, "Certificate hash should match");
    });

    it("Should return multiple certificates for owner with multiple certificates", async () => {
      const { pkiRegistry } = await deployWithRoot();
      const { issuedAt, expiresAt } = await getValidityPeriod(10n);
      const secondRootHash = await sha256("second-root-ca");

      await pkiRegistry.write.issueRootCertificate([
        secondRootHash,
        ownerClient.account.address,
        issuedAt,
        expiresAt,
      ]);

      const certificates = await pkiRegistry.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);

      assert.equal(certificates.length, 2, "Owner should have 2 certificates");
    });

    it("Should return empty array for owner with no certificates", async () => {
      const { pkiRegistry } = await deployWithRoot();

      const certificates = await pkiRegistry.read.getCertificatesByOwner([
        unauthorizedClient.account.address,
      ]);

      assert.equal(certificates.length, 0, "Owner should have 0 certificates");
    });

    it("Should track certificates across the full chain", async () => {
      const { pkiRegistry } = await deployWithFullChain();

      const ownerCerts = await pkiRegistry.read.getCertificatesByOwner([
        ownerClient.account.address,
      ]);
      const intermediateCerts = await pkiRegistry.read.getCertificatesByOwner([
        intermediateClient.account.address,
      ]);
      const endEntityCerts = await pkiRegistry.read.getCertificatesByOwner([
        endEntityClient.account.address,
      ]);

      assert.equal(ownerCerts.length, 1, "Owner should have 1 certificate");
      assert.equal(
        intermediateCerts.length,
        1,
        "Intermediate should have 1 certificate",
      );
      assert.equal(
        endEntityCerts.length,
        1,
        "End entity should have 1 certificate",
      );
    });
  });

  describe("Complex Scenarios", () => {
    it("Should handle multiple independent certificate chains", async () => {
      const pkiRegistry = await viem.deployContract("PKIRegistry");

      // First chain
      const { issuedAt: issuedAt1, expiresAt: expiresAt1 } =
        await getValidityPeriod(10n);
      const rootHash1 = await sha256("root-ca-1");
      await pkiRegistry.write.issueRootCertificate([
        rootHash1,
        ownerClient.account.address,
        issuedAt1,
        expiresAt1,
      ]);

      // Second chain
      const { issuedAt: issuedAt2, expiresAt: expiresAt2 } =
        await getValidityPeriod(10n);
      const rootHash2 = await sha256("root-ca-2");
      await pkiRegistry.write.issueRootCertificate([
        rootHash2,
        ownerClient.account.address,
        issuedAt2,
        expiresAt2,
      ]);

      // Both chains should be valid
      const isValid1 = await pkiRegistry.read.isValidCertificate([rootHash1]);
      const isValid2 = await pkiRegistry.read.isValidCertificate([rootHash2]);

      assert.equal(isValid1, true, "First chain should be valid");
      assert.equal(isValid2, true, "Second chain should be valid");

      // Revoke first chain
      await pkiRegistry.write.revokeCertificate([rootHash1]);

      // First chain should be invalid, second should still be valid
      const isValid1After = await pkiRegistry.read.isValidCertificate([
        rootHash1,
      ]);
      const isValid2After = await pkiRegistry.read.isValidCertificate([
        rootHash2,
      ]);

      assert.equal(isValid1After, false, "First chain should be invalid");
      assert.equal(isValid2After, true, "Second chain should still be valid");
    });

    it("Should handle certificate issued at the same time as issuer", async () => {
      const {
        pkiRegistry,
        rootHash,
        issuedAt: rootIssuedAt,
      } = await deployWithRoot();
      const { expiresAt } = await getValidityPeriod(5n);
      const intermediateHash = await sha256("intermediate-ca-same-time");

      // Issue intermediate at the same time as root (should be allowed)
      await pkiRegistry.write.issueCertificate([
        intermediateHash,
        rootHash,
        intermediateClient.account.address,
        rootIssuedAt,
        expiresAt,
        CertificateRole.IntermediateCA,
      ]);

      const certificate = await pkiRegistry.read.getCertificate([
        intermediateHash,
      ]);

      assert.equal(
        certificate.issuedAt,
        rootIssuedAt,
        "Certificate should be issued at the same time as issuer",
      );
    });
  });
});
