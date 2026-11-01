export interface RuntimeBootstrapTokens {
    runtime_salt: string;
    render_signature: string;
    css_scope_token: string;
    hydrated_hooks: string[];
}
export interface SignedLicenseCertificatePayload {
    ver: number;
    nonce: string;
    iat: number;
    exp: number;
    grace_until: number;
    license_key: string;
    product_slug: string;
    license_status: 'ACTIVE' | 'INACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
    code: 'VALID' | 'ACTIVATED' | 'DEACTIVATED' | 'ENV_MISMATCH' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED' | 'INVALID_KEY' | 'PRODUCT_MISMATCH' | 'MAX_ACTIVATIONS_REACHED' | 'TRANSFER_PENDING' | 'TRANSFER_LIMIT_REACHED';
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
    signature: string;
    alg: 'Ed25519';
    key_id: string;
}
/**
 * Module 4: Ed25519 Asymmetric Digital Signature & Request HMAC Service.
 * - Private signing key remains strictly on Central License Server.
 * - WordPress Plugin holds only the 32-byte raw Ed25519 Public Key (compatible with PHP ext-sodium).
 */
export declare class Ed25519Service {
    private privateKey;
    private publicKey;
    private rawPublicKeyBase64;
    private rawPrivateSeedBase64;
    private keyId;
    private replaySignatureCache;
    constructor();
    private initKeys;
    private loadFromRawBase64;
    static generateRawKeyPair(): {
        publicKeyBase64: string;
        privateSeedBase64: string;
        keyId: string;
    };
    /**
     * Returns the 32-byte raw Base64 Public Key for embedding in the WordPress Plugin.
     */
    getPublicKeyBase64(): string;
    getKeyId(): string;
    /**
     * Canonicalizes and signs a License Certificate Payload using Ed25519 Private Key.
     */
    signPayload(payload: SignedLicenseCertificatePayload): SignedEnvelope;
    /**
     * Verifies a SignedEnvelope using the Ed25519 Public Key (simulates WordPress Plugin verification).
     */
    verifyEnvelope(envelope: SignedEnvelope, expectedNonce?: string): {
        valid: boolean;
        reason?: string;
        payload?: SignedLicenseCertificatePayload;
    };
    /**
     * Creates or verifies HMAC-SHA256 signature for Module 7 (Remote Commercial Feature execution)
     * using the dynamic per-site activation_token as the shared session secret.
     */
    computeActivationHmac(activationToken: string, timestamp: string, featureCode: string, bodyRaw: string): string;
    verifyActivationHmac(activationToken: string, timestamp: string, featureCode: string, bodyRaw: string, providedHmac: string, maxSkewSeconds?: number): {
        valid: boolean;
        reason?: string;
    };
}
export declare const ed25519Service: Ed25519Service;
