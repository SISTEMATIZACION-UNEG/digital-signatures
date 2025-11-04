import forge from "node-forge";
import { promises, watch, type FSWatcher } from "node:fs";

import { env } from "../utils/env";

interface CredentialsCache {
  certificate: forge.pki.Certificate;
  key: forge.pki.rsa.PrivateKey;
  certificateWatcher: FSWatcher;
  keyWatcher: FSWatcher;
}

// The certificate cache.
let cache: CredentialsCache | null = null;

/**
 * @description Closes the CA credentials file watchers.
 */
function closeWatchers() {
  cache?.certificateWatcher.close();
  cache?.keyWatcher.close();
}

export class CertificateAuthorityService {
  /**
   * @description Invalidates the CA cache.
   */
  private static invalidateCache() {
    // No cache to invalidate.
    if (!cache) return;

    // Close the watchers and set to null.
    closeWatchers();
    cache = null;
  }

  /**
   * @description Loads the credentials to the cache.
   * @returns The credentials.
   */
  private static async loadCredentials(): Promise<CredentialsCache> {
    const [pemCertificate, pemKey] = await Promise.all([
      promises.readFile(env.CA_CERTIFICATE_PATH, "utf-8"),
      promises.readFile(env.CA_KEY_PATH, "utf-8"),
    ]);

    // Convert from PEM.
    const certificate = forge.pki.certificateFromPem(pemCertificate);
    const key = forge.pki.privateKeyFromPem(pemKey);

    // Set the cache.
    cache = {
      certificate,
      key,
      certificateWatcher: watch(env.CA_CERTIFICATE_PATH, (_, filename) => {
        if (filename) this.invalidateCache();
      }),
      keyWatcher: watch(env.CA_KEY_PATH, (_, filename) => {
        if (filename) this.invalidateCache();
      }),
    };

    return cache;
  }

  /**
   * @description Gets the CA.
   * @returns The CA credentials.
   */
  static async getCertificateAuthority(): Promise<
    Pick<CredentialsCache, "certificate" | "key">
  > {
    // Get from cache.
    if (cache) {
      return {
        certificate: cache.certificate,
        key: cache.key,
      };
    }

    // Load the cache.
    const { certificate, key } = await this.loadCredentials();

    return { certificate, key };
  }
}

// Close the watchers when the process exits.
process.on("SIGINT", () => {
  closeWatchers();
});
