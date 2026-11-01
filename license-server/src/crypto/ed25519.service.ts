import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface RuntimeBootstrapTokens {
  runtime_salt: string;
  render_signature: string;
  css_scope_token: string;
  hydrated_hooks: string[];
}

export interface SignedLicenseCertificatePayload {
  ver: number;
  nonce: string;
  iat: number; // Issued At (Unix seconds)
  exp: number; // Lease Expires At (Unix seconds - e.g. +24h)
  grace_until: number; // Offline Grace Period Until (Unix seconds - e.g. +72h)
  license_key: string;
  product_slug: string;
  license_status: 'ACTIVE' | 'INACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
  code:
    | 'VALID'
    | 'ACTIVATED'
    | 'DEACTIVATED'
    | 'ENV_MISMATCH'
    | 'EXPIRED'
    | 'SUSPENDED'
    | 'REVOKED'
    | 'INVALID_KEY'
    | 'PRODUCT_MISMATCH'
    | 'MAX_ACTIVATIONS_REACHED'
    | 'TRANSFER_PENDING'
    | 'TRANSFER_LIMIT_REACHED';
  message: string;
  activation_token: string | null;
  domain: string;
  server_ip: string;
  expires_at: string | null;
  max_activations: number;
  features: string[];
  runtime_tokens?: RuntimeBootstrapTokens | null;
}

export interface SignedEnvelope {
  payload: SignedLicenseCertificatePayload;
  payload_raw: string;
  signature: string; // Base64 64-byte Ed25519 signature over payload_raw
  alg: 'Ed25519';
  key_id: string;
}

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Module 4: Ed25519 Asymmetric Digital Signature & Request HMAC Service.
 * - Private signing key remains strictly on Central License Server.
 * - WordPress Plugin holds only the 32-byte raw Ed25519 Public Key (compatible with PHP ext-sodium).
 */
export class Ed25519Service {
  private privateKey!: crypto.KeyObject;
  private publicKey!: crypto.KeyObject;
  private rawPublicKeyBase64!: string;
  private rawPrivateSeedBase64!: string;
  private keyId!: string;
  private replaySignatureCache = new Map<string, number>();

  constructor() {
    this.initKeys();
  }

  private initKeys(): void {
    const envPriv = process.env.ED25519_PRIVATE_KEY_BASE64?.trim();
    const envPub = process.env.ED25519_PUBLIC_KEY_BASE64?.trim();
    const dataCandidates = [
      path.resolve(__dirname, '..', '..', 'data'),
      path.join(process.cwd(), 'license-server', 'data'),
      path.join(process.cwd(), 'data')
    ];
    const dataDir = dataCandidates.find((d) => fs.existsSync(d)) || dataCandidates[0];
    const keyFilePath = path.join(dataDir, 'ed25519-keys.json');

    if (envPriv && envPub) {
      this.loadFromRawBase64(envPriv, envPub);
      return;
    }

    if (fs.existsSync(keyFilePath)) {
      const saved = JSON.parse(fs.readFileSync(keyFilePath, 'utf8'));
      this.loadFromRawBase64(saved.privateSeedBase64, saved.publicKeyBase64);
      return;
    }

    // Generate deterministic-safe fresh keypair and persist to data/ed25519-keys.json if writable
    const generated = Ed25519Service.generateRawKeyPair();
    try {
      fs.mkdirSync(path.dirname(keyFilePath), { recursive: true });
      fs.writeFileSync(
        keyFilePath,
        JSON.stringify(
          {
            alg: 'Ed25519',
            createdAt: new Date().toISOString(),
            publicKeyBase64: generated.publicKeyBase64,
            privateSeedBase64: generated.privateSeedBase64,
            note: 'CRITICAL: Keep privateSeedBase64 strictly on Central License Server. Embed ONLY publicKeyBase64 in WordPress Plugin.'
          },
          null,
          2
        ),
        'utf8'
      );
    } catch {
      // Ignore on read-only Vercel Serverless filesystem
    }
    this.loadFromRawBase64(generated.privateSeedBase64, generated.publicKeyBase64);
  }

  private loadFromRawBase64(privateSeedBase64: string, publicKeyBase64: string): void {
    const rawPrivSeed = Buffer.from(privateSeedBase64, 'base64');
    const rawPub = Buffer.from(publicKeyBase64, 'base64');

    if (rawPrivSeed.length !== 32 || rawPub.length !== 32) {
      throw new Error('Invalid Ed25519 key length: Both private seed and public key must be 32 bytes.');
    }

    const pkcs8Der = Buffer.concat([PKCS8_ED25519_PREFIX, rawPrivSeed]);
    const spkiDer = Buffer.concat([SPKI_ED25519_PREFIX, rawPub]);

    this.privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    this.publicKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    this.rawPrivateSeedBase64 = privateSeedBase64;
    this.rawPublicKeyBase64 = publicKeyBase64;
    this.keyId = crypto.createHash('sha256').update(rawPub).digest('hex').slice(0, 16);
  }

  public static generateRawKeyPair(): {
    publicKeyBase64: string;
    privateSeedBase64: string;
    keyId: string;
  } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spkiDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const pkcs8Der = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;

    // Extract raw 32-byte key material (compatible with PHP sodium_crypto_sign_verify_detached)
    const rawPub = spkiDer.subarray(spkiDer.length - 32);
    const rawPrivSeed = pkcs8Der.subarray(pkcs8Der.length - 32);
    const keyId = crypto.createHash('sha256').update(rawPub).digest('hex').slice(0, 16);

    return {
      publicKeyBase64: rawPub.toString('base64'),
      privateSeedBase64: rawPrivSeed.toString('base64'),
      keyId
    };
  }

  /**
   * Returns the 32-byte raw Base64 Public Key for embedding in the WordPress Plugin.
   */
  public getPublicKeyBase64(): string {
    return this.rawPublicKeyBase64;
  }

  public getKeyId(): string {
    return this.keyId;
  }

  /**
   * Canonicalizes and signs a License Certificate Payload using Ed25519 Private Key.
   */
  public signPayload(payload: SignedLicenseCertificatePayload): SignedEnvelope {
    const payloadRaw = JSON.stringify(payload);
    const signatureBuffer = crypto.sign(null, Buffer.from(payloadRaw, 'utf8'), this.privateKey);

    return {
      payload,
      payload_raw: payloadRaw,
      signature: signatureBuffer.toString('base64'),
      alg: 'Ed25519',
      key_id: this.keyId
    };
  }

  /**
   * Verifies a SignedEnvelope using the Ed25519 Public Key (simulates WordPress Plugin verification).
   */
  public verifyEnvelope(envelope: SignedEnvelope, expectedNonce?: string): {
    valid: boolean;
    reason?: string;
    payload?: SignedLicenseCertificatePayload;
  } {
    try {
      const sigBuf = Buffer.from(envelope.signature, 'base64');
      if (sigBuf.length !== 64) {
        return { valid: false, reason: 'INVALID_SIGNATURE_LENGTH' };
      }

      const isSignatureValid = crypto.verify(
        null,
        Buffer.from(envelope.payload_raw, 'utf8'),
        this.publicKey,
        sigBuf
      );

      if (!isSignatureValid) {
        return { valid: false, reason: 'ED25519_SIGNATURE_MISMATCH' };
      }

      const parsedPayload = JSON.parse(envelope.payload_raw) as SignedLicenseCertificatePayload;
      const nowSec = Math.floor(Date.now() / 1000);

      if (expectedNonce && parsedPayload.nonce !== expectedNonce) {
        return { valid: false, reason: 'NONCE_MISMATCH_REPLAY_DETECTED' };
      }

      if (parsedPayload.exp < nowSec) {
        return { valid: false, reason: 'CERTIFICATE_LEASE_EXPIRED' };
      }

      return { valid: true, payload: parsedPayload };
    } catch (err) {
      return { valid: false, reason: 'MALFORMED_ENVELOPE' };
    }
  }

  /**
   * Creates or verifies HMAC-SHA256 signature for Module 7 (Remote Commercial Feature execution)
   * using the dynamic per-site activation_token as the shared session secret.
   */
  public computeActivationHmac(
    activationToken: string,
    timestamp: string,
    featureCode: string,
    bodyRaw: string
  ): string {
    const dataToSign = `${timestamp}.${featureCode}.${bodyRaw}`;
    return crypto.createHmac('sha256', activationToken).update(dataToSign, 'utf8').digest('hex');
  }

  public verifyActivationHmac(
    activationToken: string,
    timestamp: string,
    featureCode: string,
    bodyRaw: string,
    providedHmac: string,
    maxSkewSeconds = 300
  ): { valid: boolean; reason?: string } {
    const reqTs = Number(timestamp);
    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(reqTs) || Math.abs(nowSec - reqTs) > maxSkewSeconds) {
      return { valid: false, reason: 'REQUEST_TIMESTAMP_EXPIRED' };
    }

    const expectedHmac = this.computeActivationHmac(activationToken, timestamp, featureCode, bodyRaw);
    const a = Buffer.from(expectedHmac, 'utf8');
    const b = Buffer.from(providedHmac || '', 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { valid: false, reason: 'INVALID_REQUEST_HMAC' };
    }

    // Anti-Replay Sliding Window Cache: Reject duplicate request signatures within maxSkewSeconds
    for (const [sig, expSec] of this.replaySignatureCache.entries()) {
      if (expSec < nowSec) {
        this.replaySignatureCache.delete(sig);
      }
    }
    if (this.replaySignatureCache.has(providedHmac)) {
      return { valid: false, reason: 'REPLAY_REQUEST_DETECTED' };
    }
    this.replaySignatureCache.set(providedHmac, nowSec + maxSkewSeconds);

    return { valid: true };
  }
}

export const ed25519Service = new Ed25519Service();

