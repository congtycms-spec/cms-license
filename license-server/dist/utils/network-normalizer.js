"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.NetworkNormalizer = void 0;
const node_url_1 = __importDefault(require("node:url"));
const node_net_1 = __importDefault(require("node:net"));
/**
 * Module 3: Domain & IP Normalization and Anti-Spoofing Utility
 */
class NetworkNormalizer {
    /**
     * Normalizes a domain or URL string into a canonical hostname.
     * - Strips http://, https://, paths, ports, query strings, trailing dots
     * - Converts internationalized domains (tiếng Việt có dấu) to ASCII Punycode
     * - Optionally strips leading 'www.' when treatWwwAsSame = true
     */
    static normalizeDomain(rawInput, treatWwwAsSame = true) {
        if (!rawInput || typeof rawInput !== 'string') {
            return '';
        }
        let cleaned = rawInput.trim().toLowerCase();
        if (!cleaned.includes('://')) {
            cleaned = `https://${cleaned}`;
        }
        try {
            const parsed = new URL(cleaned);
            let hostname = node_url_1.default.domainToASCII(parsed.hostname || '').toLowerCase();
            hostname = hostname.replace(/\.+$/, ''); // Remove trailing dots
            if (treatWwwAsSame && hostname.startsWith('www.') && hostname.split('.').length > 2) {
                hostname = hostname.slice(4);
            }
            return hostname;
        }
        catch {
            // Fallback manual cleanup
            let fallback = rawInput
                .trim()
                .toLowerCase()
                .replace(/^https?:\/\//, '')
                .split('/')[0]
                .split('?')[0]
                .split(':')[0]
                .replace(/\.+$/, '');
            if (treatWwwAsSame && fallback.startsWith('www.') && fallback.split('.').length > 2) {
                fallback = fallback.slice(4);
            }
            return node_url_1.default.domainToASCII(fallback) || fallback;
        }
    }
    /**
     * Compares two domains according to the license's `treatWwwAsSame` policy.
     */
    static isDomainMatch(requestDomain, allowedDomain, treatWwwAsSame = true) {
        const normReq = this.normalizeDomain(requestDomain, treatWwwAsSame);
        const normAllowed = this.normalizeDomain(allowedDomain, treatWwwAsSame);
        if (!normReq || !normAllowed)
            return false;
        return normReq === normAllowed;
    }
    /**
     * Normalizes IPv4 / IPv6 addresses (e.g., strips IPv4-mapped IPv6 prefix ::ffff:).
     */
    static normalizeIp(rawIp) {
        if (!rawIp || typeof rawIp !== 'string')
            return '';
        let ip = rawIp.trim();
        // If multiple IPs in X-Forwarded-For, take the first one
        if (ip.includes(',')) {
            ip = ip.split(',')[0].trim();
        }
        if (ip.startsWith('::ffff:')) {
            ip = ip.slice(7);
        }
        if (ip === '::1') {
            return '127.0.0.1';
        }
        return node_net_1.default.isIP(ip) ? ip : '';
    }
    /**
     * Extracts the trusted Server IP of the calling WordPress server.
     * CRITICAL SECURITY RULE (Module 3):
     * - Never blindly trust X-Forwarded-For or CF-Connecting-IP from arbitrary clients.
     * - Only trust proxy headers if the immediate TCP socket peer is in TRUSTED_PROXIES.
     */
    static extractTrustedClientServerIp(req) {
        const socketIp = this.normalizeIp(req.socket?.remoteAddress || req.ip || '127.0.0.1');
        const trustedProxiesRaw = process.env.TRUSTED_PROXIES || '127.0.0.1,::1';
        const trustedProxies = trustedProxiesRaw
            .split(',')
            .map((p) => this.normalizeIp(p))
            .filter(Boolean);
        const isFromTrustedProxy = trustedProxies.includes(socketIp) || trustedProxies.includes('*');
        if (isFromTrustedProxy) {
            const cfIp = this.normalizeIp(req.headers['cf-connecting-ip']);
            if (cfIp)
                return cfIp;
            const realIp = this.normalizeIp(req.headers['x-real-ip']);
            if (realIp)
                return realIp;
            const forwardedFor = this.normalizeIp(req.headers['x-forwarded-for']);
            if (forwardedFor)
                return forwardedFor;
        }
        return socketIp || '127.0.0.1';
    }
    /**
     * Checks if a server IP matches the allowed IP policy (supports exact IP, comma-separated list, or IPv4 CIDR /24).
     */
    static isIpMatch(detectedOutboundIp, reportedServerIp, allowedIpPolicy, strictIpCheck = true) {
        if (!strictIpCheck) {
            return true;
        }
        if (!allowedIpPolicy || allowedIpPolicy.trim() === '*') {
            return true;
        }
        const normDetected = this.normalizeIp(detectedOutboundIp);
        const normReported = this.normalizeIp(reportedServerIp);
        const allowedEntries = allowedIpPolicy
            .split(',')
            .map((item) => item.trim())
            .filter(Boolean);
        for (const entry of allowedEntries) {
            if (entry.includes('/')) {
                // Basic IPv4 CIDR check
                if (this.matchIpv4Cidr(normDetected, entry))
                    return true;
            }
            else {
                const normAllowed = this.normalizeIp(entry);
                if (normAllowed && normDetected === normAllowed) {
                    return true;
                }
                // Only allow reportedServerIp match if detectedOutboundIp is localhost/internal gateway in dev/proxy setups
                if (normAllowed &&
                    normDetected === '127.0.0.1' &&
                    normReported &&
                    normReported === normAllowed) {
                    return true;
                }
            }
        }
        return false;
    }
    static matchIpv4Cidr(ip, cidr) {
        const [range, bitsStr] = cidr.split('/');
        const bits = parseInt(bitsStr, 10);
        if (node_net_1.default.isIPv4(ip) && node_net_1.default.isIPv4(range) && bits >= 0 && bits <= 32) {
            const ipNum = this.ipv4ToInt(ip);
            const rangeNum = this.ipv4ToInt(range);
            const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
            return (ipNum & mask) === (rangeNum & mask);
        }
        return false;
    }
    static ipv4ToInt(ip) {
        return (ip
            .split('.')
            .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0);
    }
}
exports.NetworkNormalizer = NetworkNormalizer;
