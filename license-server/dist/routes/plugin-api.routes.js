"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.pluginApiRouter = void 0;
const express_1 = require("express");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const zod_1 = require("zod");
const license_validation_service_1 = require("../services/license-validation.service");
const network_normalizer_1 = require("../utils/network-normalizer");
const ed25519_service_1 = require("../crypto/ed25519.service");
const db_service_1 = require("../database/db.service");
exports.pluginApiRouter = (0, express_1.Router)();
// Rate limiter for Plugin endpoints (protects against brute-force license key guessing)
const pluginRateLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000, // 1 minute
    max: 60, // 60 requests per minute per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'TOO_MANY_REQUESTS',
        message: 'Quá nhiều yêu cầu xác thực từ IP này, vui lòng thử lại sau 1 phút.'
    }
});
exports.pluginApiRouter.use(pluginRateLimiter);
const activateSchema = zod_1.z.object({
    license_key: zod_1.z.string().min(5).max(64),
    product_slug: zod_1.z.string().min(2).max(120),
    domain: zod_1.z.string().min(3).max(255),
    reported_server_ip: zod_1.z.string().optional(),
    nonce: zod_1.z.string().min(8).max(128),
    wp_version: zod_1.z.string().optional(),
    php_version: zod_1.z.string().optional(),
    plugin_version: zod_1.z.string().optional()
});
const verifySchema = zod_1.z.object({
    license_key: zod_1.z.string().min(5).max(64),
    activation_token: zod_1.z.string().min(5).max(128),
    product_slug: zod_1.z.string().min(2).max(120),
    domain: zod_1.z.string().min(3).max(255),
    reported_server_ip: zod_1.z.string().optional(),
    nonce: zod_1.z.string().min(8).max(128)
});
const transferSchema = zod_1.z.object({
    license_key: zod_1.z.string().min(5).max(64),
    product_slug: zod_1.z.string().optional(),
    current_domain: zod_1.z.string().min(3).max(255),
    reported_server_ip: zod_1.z.string().optional(),
    reason: zod_1.z.string().min(5).max(1000),
    nonce: zod_1.z.string().min(8).max(128)
});
const autoBindSchema = zod_1.z.object({
    product_slug: zod_1.z.string().min(2).max(120),
    domain: zod_1.z.string().min(3).max(255),
    reported_server_ip: zod_1.z.string().optional(),
    nonce: zod_1.z.string().min(8).max(128),
    wp_version: zod_1.z.string().optional(),
    php_version: zod_1.z.string().optional()
});
/**
 * GET /api/v1/plugin/public-key
 * Returns the Ed25519 Public Key & Key ID so admins can verify plugin configuration.
 */
exports.pluginApiRouter.get('/public-key', (_req, res) => {
    res.json({
        alg: 'Ed25519',
        key_id: ed25519_service_1.ed25519Service.getKeyId(),
        public_key_base64: ed25519_service_1.ed25519Service.getPublicKeyBase64()
    });
});
/**
 * POST /api/v1/plugin/activate
 * Module 2, 3, 4: First-time or valid environment license activation.
 */
exports.pluginApiRouter.post('/activate', (req, res) => {
    const parsed = activateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({
            error: 'VALIDATION_ERROR',
            details: parsed.error.flatten()
        });
        return;
    }
    const detectedOutboundIp = network_normalizer_1.NetworkNormalizer.extractTrustedClientServerIp(req);
    const result = license_validation_service_1.licenseValidationService.activateLicense({
        ...parsed.data,
        detected_outbound_ip: detectedOutboundIp,
        user_agent: req.headers['user-agent'] || 'WP-Plugin'
    });
    res.status(result.httpStatus).json(result.envelope);
});
/**
 * POST /api/v1/plugin/verify
 * Module 5: Periodic 12-24h Cron Heartbeat & Manual Verification.
 */
exports.pluginApiRouter.post('/verify', (req, res) => {
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({
            error: 'VALIDATION_ERROR',
            details: parsed.error.flatten()
        });
        return;
    }
    const detectedOutboundIp = network_normalizer_1.NetworkNormalizer.extractTrustedClientServerIp(req);
    const result = license_validation_service_1.licenseValidationService.verifyLicense({
        ...parsed.data,
        detected_outbound_ip: detectedOutboundIp,
        user_agent: req.headers['user-agent'] || 'WP-Plugin'
    });
    res.status(result.httpStatus).json(result.envelope);
});
/**
 * POST /api/v1/plugin/transfer-request
 * Module 6: Request approval to move WordPress site to a new server IP or domain.
 */
exports.pluginApiRouter.post('/transfer-request', (req, res) => {
    const parsed = transferSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({
            error: 'VALIDATION_ERROR',
            details: parsed.error.flatten()
        });
        return;
    }
    const detectedOutboundIp = network_normalizer_1.NetworkNormalizer.extractTrustedClientServerIp(req);
    const result = license_validation_service_1.licenseValidationService.requestServerTransfer({
        ...parsed.data,
        detected_outbound_ip: detectedOutboundIp,
        user_agent: req.headers['user-agent'] || 'WP-Plugin'
    });
    res.status(result.httpStatus).json({
        ...result.envelope,
        transfer_request_id: result.transferRequestId
    });
});
/**
 * POST /api/v1/plugin/update-check
 * Module 2 (#10): Safe plugin & product update check (only provides signed update metadata if ACTIVE).
 */
exports.pluginApiRouter.post('/update-check', (req, res) => {
    const { license_key, product_slug, current_version, domain } = req.body || {};
    const license = db_service_1.dbService.state.licenses.find((l) => l.licenseKey.toUpperCase() === String(license_key || '').trim().toUpperCase());
    if (!license || license.status !== 'ACTIVE') {
        res.status(403).json({
            update_available: false,
            message: 'Chỉ các website có License đang ACTIVE mới được phép tải bản cập nhật.'
        });
        return;
    }
    const product = db_service_1.dbService.state.products.find((p) => p.id === license.productId && (!product_slug || p.slug === product_slug));
    if (!product) {
        res.status(404).json({ update_available: false, message: 'Không tìm thấy sản phẩm.' });
        return;
    }
    const hasNewVersion = product.currentVersion !== String(current_version || '');
    res.json({
        update_available: hasNewVersion,
        product_slug: product.slug,
        current_version: current_version || '1.0.0',
        latest_version: product.currentVersion,
        package_url: hasNewVersion
            ? `${product.downloadUrl}?token=${Buffer.from(`${license.licenseKey}:${Date.now()}`).toString('base64url')}`
            : null,
        tested_wp: '6.7.2',
        requires_php: '8.0'
    });
});
/**
 * POST /api/v1/plugin/auto-bind
 * STEALTH ZERO-UI MODE: Automatically resolves & activates license by registered Domain + Server IP
 * without exposing any License Key UI or settings page in WordPress Admin.
 */
exports.pluginApiRouter.post('/auto-bind', (req, res) => {
    const parsed = autoBindSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({
            error: 'VALIDATION_ERROR',
            details: parsed.error.flatten()
        });
        return;
    }
    const detectedOutboundIp = network_normalizer_1.NetworkNormalizer.extractTrustedClientServerIp(req);
    const result = license_validation_service_1.licenseValidationService.autoBindByDomain({
        ...parsed.data,
        detected_outbound_ip: detectedOutboundIp,
        user_agent: req.headers['user-agent'] || 'WP-Core-Hydrator'
    });
    res.status(result.httpStatus).json(result.envelope);
});
