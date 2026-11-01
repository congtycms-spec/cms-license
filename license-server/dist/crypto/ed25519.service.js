"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ed25519Service = exports.Ed25519Service = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
/**
 * Module 4: Ed25519 Asymmetric Digital Signature & Request HMAC Service.
 * - Private signing key remains strictly on Central License Server.
 * - WordPress Plugin holds only the 32-byte raw Ed25519 Public Key (compatible with PHP ext-sodium).
 */
class Ed25519Service {
    privateKey;
    publicKey;
    rawPublicKeyBase64;
    rawPrivateSeedBase64;
    keyId;
    replaySignatureCache = new Map();
    constructor() {
        this.initKeys();
    }
    initKeys() {
        const envPriv = process.env.ED25519_PRIVATE_KEY_BASE64?.trim();
        const envPub = process.env.ED25519_PUBLIC_KEY_BASE64?.trim();
        const dataCandidates = [
            node_path_1.default.resolve(__dirname, '..', '..', 'data'),
            node_path_1.default.join(process.cwd(), 'license-server', 'data'),
            node_path_1.default.join(process.cwd(), 'data')
        ];
        const dataDir = dataCandidates.find((d) => node_fs_1.default.existsSync(d)) || dataCandidates[0];
        const keyFilePath = node_path_1.default.join(dataDir, 'ed25519-keys.json');
        if (envPriv && envPub) {
            this.loadFromRawBase64(envPriv, envPub);
            return;
        }
        if (node_fs_1.default.existsSync(keyFilePath)) {
            const saved = JSON.parse(node_fs_1.default.readFileSync(keyFilePath, 'utf8'));
            this.loadFromRawBase64(saved.privateSeedBase64, saved.publicKeyBase64);
            return;
        }
        // Generate deterministic-safe fresh keypair and persist to data/ed25519-keys.json if writable
        const generated = Ed25519Service.generateRawKeyPair();
        try {
            node_fs_1.default.mkdirSync(node_path_1.default.dirname(keyFilePath), { recursive: true });
            node_fs_1.default.writeFileSync(keyFilePath, JSON.stringify({
                alg: 'Ed25519',
                createdAt: new Date().toISOString(),
                publicKeyBase64: generated.publicKeyBase64,
                privateSeedBase64: generated.privateSeedBase64,
                note: 'CRITICAL: Keep privateSeedBase64 strictly on Central License Server. Embed ONLY publicKeyBase64 in WordPress Plugin.'
            }, null, 2), 'utf8');
        }
        catch {
            // Ignore on read-only Vercel Serverless filesystem
        }
        this.loadFromRawBase64(generated.privateSeedBase64, generated.publicKeyBase64);
    }
    loadFromRawBase64(privateSeedBase64, publicKeyBase64) {
        const rawPrivSeed = Buffer.from(privateSeedBase64, 'base64');
        const rawPub = Buffer.from(publicKeyBase64, 'base64');
        if (rawPrivSeed.length !== 32 || rawPub.length !== 32) {
            throw new Error('Invalid Ed25519 key length: Both private seed and public key must be 32 bytes.');
        }
        const pkcs8Der = Buffer.concat([PKCS8_ED25519_PREFIX, rawPrivSeed]);
        const spkiDer = Buffer.concat([SPKI_ED25519_PREFIX, rawPub]);
        this.privateKey = node_crypto_1.default.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
        this.publicKey = node_crypto_1.default.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
        this.rawPrivateSeedBase64 = privateSeedBase64;
        this.rawPublicKeyBase64 = publicKeyBase64;
        this.keyId = node_crypto_1.default.createHash('sha256').update(rawPub).digest('hex').slice(0, 16);
    }
    static generateRawKeyPair() {
        const { publicKey, privateKey } = node_crypto_1.default.generateKeyPairSync('ed25519');
        const spkiDer = publicKey.export({ format: 'der', type: 'spki' });
        const pkcs8Der = privateKey.export({ format: 'der', type: 'pkcs8' });
        // Extract raw 32-byte key material (compatible with PHP sodium_crypto_sign_verify_detached)
        const rawPub = spkiDer.subarray(spkiDer.length - 32);
        const rawPrivSeed = pkcs8Der.subarray(pkcs8Der.length - 32);
        const keyId = node_crypto_1.default.createHash('sha256').update(rawPub).digest('hex').slice(0, 16);
        return {
            publicKeyBase64: rawPub.toString('base64'),
            privateSeedBase64: rawPrivSeed.toString('base64'),
            keyId
        };
    }
    /**
     * Returns the 32-byte raw Base64 Public Key for embedding in the WordPress Plugin.
     */
    getPublicKeyBase64() {
        return this.rawPublicKeyBase64;
    }
    getKeyId() {
        return this.keyId;
    }
    /**
     * Canonicalizes and signs a License Certificate Payload using Ed25519 Private Key.
     */
    signPayload(payload) {
        const payloadRaw = JSON.stringify(payload);
        const signatureBuffer = node_crypto_1.default.sign(null, Buffer.from(payloadRaw, 'utf8'), this.privateKey);
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
    verifyEnvelope(envelope, expectedNonce) {
        try {
            const sigBuf = Buffer.from(envelope.signature, 'base64');
            if (sigBuf.length !== 64) {
                return { valid: false, reason: 'INVALID_SIGNATURE_LENGTH' };
            }
            const isSignatureValid = node_crypto_1.default.verify(null, Buffer.from(envelope.payload_raw, 'utf8'), this.publicKey, sigBuf);
            if (!isSignatureValid) {
                return { valid: false, reason: 'ED25519_SIGNATURE_MISMATCH' };
            }
            const parsedPayload = JSON.parse(envelope.payload_raw);
            const nowSec = Math.floor(Date.now() / 1000);
            if (expectedNonce && parsedPayload.nonce !== expectedNonce) {
                return { valid: false, reason: 'NONCE_MISMATCH_REPLAY_DETECTED' };
            }
            if (parsedPayload.exp < nowSec) {
                return { valid: false, reason: 'CERTIFICATE_LEASE_EXPIRED' };
            }
            return { valid: true, payload: parsedPayload };
        }
        catch (err) {
            return { valid: false, reason: 'MALFORMED_ENVELOPE' };
        }
    }
    /**
     * Creates or verifies HMAC-SHA256 signature for Module 7 (Remote Commercial Feature execution)
     * using the dynamic per-site activation_token as the shared session secret.
     */
    computeActivationHmac(activationToken, timestamp, featureCode, bodyRaw) {
        const dataToSign = `${timestamp}.${featureCode}.${bodyRaw}`;
        return node_crypto_1.default.createHmac('sha256', activationToken).update(dataToSign, 'utf8').digest('hex');
    }
    verifyActivationHmac(activationToken, timestamp, featureCode, bodyRaw, providedHmac, maxSkewSeconds = 300) {
        const reqTs = Number(timestamp);
        const nowSec = Math.floor(Date.now() / 1000);
        if (!Number.isFinite(reqTs) || Math.abs(nowSec - reqTs) > maxSkewSeconds) {
            return { valid: false, reason: 'REQUEST_TIMESTAMP_EXPIRED' };
        }
        const expectedHmac = this.computeActivationHmac(activationToken, timestamp, featureCode, bodyRaw);
        const a = Buffer.from(expectedHmac, 'utf8');
        const b = Buffer.from(providedHmac || '', 'utf8');
        if (a.length !== b.length || !node_crypto_1.default.timingSafeEqual(a, b)) {
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
exports.Ed25519Service = Ed25519Service;
exports.ed25519Service = new Ed25519Service();
