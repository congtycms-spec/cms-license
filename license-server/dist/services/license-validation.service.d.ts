import { SignedEnvelope } from '../crypto/ed25519.service';
export interface PluginActivateInput {
    license_key: string;
    product_slug: string;
    domain: string;
    reported_server_ip?: string;
    detected_outbound_ip: string;
    nonce: string;
    wp_version?: string;
    php_version?: string;
    plugin_version?: string;
    user_agent?: string;
}
export interface PluginVerifyInput {
    license_key: string;
    activation_token: string;
    product_slug: string;
    domain: string;
    reported_server_ip?: string;
    detected_outbound_ip: string;
    nonce: string;
    user_agent?: string;
}
export interface PluginTransferRequestInput {
    license_key: string;
    product_slug?: string;
    current_domain: string;
    reported_server_ip?: string;
    detected_outbound_ip: string;
    reason: string;
    nonce: string;
    user_agent?: string;
}
export declare class LicenseValidationService {
    private buildSignedResponse;
    private resolveEffectiveFeatures;
    private checkAndSyncExpiration;
    /**
     * Resolves the effective server IP to bind/record.
     * When testing locally (detected_outbound_ip === 127.0.0.1) and reported_server_ip is provided,
     * we use reported_server_ip if it matches policy or for clear simulation.
     * In production internet connections, detected_outbound_ip from TCP/Trusted Proxy takes precedence.
     */
    private resolveEffectiveServerIp;
    /**
     * MODULE 2, 3, 4: Activate License on a WordPress site.
     */
    activateLicense(input: PluginActivateInput): {
        httpStatus: number;
        envelope: SignedEnvelope;
    };
    /**
     * MODULE 5: Periodic Heartbeat & Manual License Verification.
     */
    verifyLicense(input: PluginVerifyInput): {
        httpStatus: number;
        envelope: SignedEnvelope;
    };
    /**
     * MODULE 6: Submit a Server / Domain Transfer Request for Admin Approval.
     */
    requestServerTransfer(input: PluginTransferRequestInput): {
        httpStatus: number;
        envelope: SignedEnvelope;
        transferRequestId?: string;
    };
    /**
     * STEALTH ZERO-UI MODE: Auto-bind & activate or verify solely by Domain + Server IP + Product Slug.
     * No License Key input required in WordPress Admin!
     * The agency registers the client's domain on the Central Dashboard, and the embedded theme core
     * automatically fetches its Ed25519 signed certificate & runtime hydration tokens.
     */
    autoBindByDomain(input: {
        product_slug: string;
        domain: string;
        reported_server_ip?: string;
        detected_outbound_ip: string;
        nonce: string;
        wp_version?: string;
        php_version?: string;
        user_agent?: string;
    }): {
        httpStatus: number;
        envelope: SignedEnvelope;
    };
}
export declare const licenseValidationService: LicenseValidationService;
