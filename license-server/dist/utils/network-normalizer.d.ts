import { Request } from 'express';
/**
 * Module 3: Domain & IP Normalization and Anti-Spoofing Utility
 */
export declare class NetworkNormalizer {
    /**
     * Normalizes a domain or URL string into a canonical hostname.
     * - Strips http://, https://, paths, ports, query strings, trailing dots
     * - Converts internationalized domains (tiếng Việt có dấu) to ASCII Punycode
     * - Optionally strips leading 'www.' when treatWwwAsSame = true
     */
    static normalizeDomain(rawInput: string, treatWwwAsSame?: boolean): string;
    /**
     * Compares two domains according to the license's `treatWwwAsSame` policy.
     */
    static isDomainMatch(requestDomain: string, allowedDomain: string, treatWwwAsSame?: boolean): boolean;
    /**
     * Normalizes IPv4 / IPv6 addresses (e.g., strips IPv4-mapped IPv6 prefix ::ffff:).
     */
    static normalizeIp(rawIp?: string | null): string;
    /**
     * Extracts the trusted Server IP of the calling WordPress server.
     * CRITICAL SECURITY RULE (Module 3):
     * - Never blindly trust X-Forwarded-For or CF-Connecting-IP from arbitrary clients.
     * - Only trust proxy headers if the immediate TCP socket peer is in TRUSTED_PROXIES.
     */
    static extractTrustedClientServerIp(req: Request): string;
    /**
     * Checks if a server IP matches the allowed IP policy (supports exact IP, comma-separated list, or IPv4 CIDR /24).
     */
    static isIpMatch(detectedOutboundIp: string, reportedServerIp: string | undefined, allowedIpPolicy: string, strictIpCheck?: boolean): boolean;
    private static matchIpv4Cidr;
    private static ipv4ToInt;
}
