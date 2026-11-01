import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { licenseValidationService } from '../services/license-validation.service';
import { NetworkNormalizer } from '../utils/network-normalizer';
import { ed25519Service } from '../crypto/ed25519.service';
import { dbService } from '../database/db.service';

export const pluginApiRouter = Router();

// Rate limiter for Plugin endpoints (protects against brute-force license key guessing)
const pluginRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'TOO_MANY_REQUESTS',
    message: 'Quá nhiều yêu cầu xác thực từ IP này, vui lòng thử lại sau 1 phút.'
  }
});

pluginApiRouter.use(pluginRateLimiter);

const activateSchema = z.object({
  license_key: z.string().min(5).max(64),
  product_slug: z.string().min(2).max(120),
  domain: z.string().min(3).max(255),
  reported_server_ip: z.string().optional(),
  nonce: z.string().min(8).max(128),
  wp_version: z.string().optional(),
  php_version: z.string().optional(),
  plugin_version: z.string().optional()
});

const verifySchema = z.object({
  license_key: z.string().min(5).max(64),
  activation_token: z.string().min(5).max(128),
  product_slug: z.string().min(2).max(120),
  domain: z.string().min(3).max(255),
  reported_server_ip: z.string().optional(),
  nonce: z.string().min(8).max(128)
});

const transferSchema = z.object({
  license_key: z.string().min(5).max(64),
  product_slug: z.string().optional(),
  current_domain: z.string().min(3).max(255),
  reported_server_ip: z.string().optional(),
  reason: z.string().min(5).max(1000),
  nonce: z.string().min(8).max(128)
});

const autoBindSchema = z.object({
  product_slug: z.string().min(2).max(120),
  domain: z.string().min(3).max(255),
  reported_server_ip: z.string().optional(),
  nonce: z.string().min(8).max(128),
  wp_version: z.string().optional(),
  php_version: z.string().optional()
});

/**
 * GET /api/v1/plugin/public-key
 * Returns the Ed25519 Public Key & Key ID so admins can verify plugin configuration.
 */
pluginApiRouter.get('/public-key', (_req: Request, res: Response) => {
  res.json({
    alg: 'Ed25519',
    key_id: ed25519Service.getKeyId(),
    public_key_base64: ed25519Service.getPublicKeyBase64()
  });
});

/**
 * POST /api/v1/plugin/activate
 * Module 2, 3, 4: First-time or valid environment license activation.
 */
pluginApiRouter.post('/activate', (req: Request, res: Response) => {
  const parsed = activateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: parsed.error.flatten()
    });
    return;
  }

  const detectedOutboundIp = NetworkNormalizer.extractTrustedClientServerIp(req);
  const result = licenseValidationService.activateLicense({
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
pluginApiRouter.post('/verify', (req: Request, res: Response) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: parsed.error.flatten()
    });
    return;
  }

  const detectedOutboundIp = NetworkNormalizer.extractTrustedClientServerIp(req);
  const result = licenseValidationService.verifyLicense({
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
pluginApiRouter.post('/transfer-request', (req: Request, res: Response) => {
  const parsed = transferSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: parsed.error.flatten()
    });
    return;
  }

  const detectedOutboundIp = NetworkNormalizer.extractTrustedClientServerIp(req);
  const result = licenseValidationService.requestServerTransfer({
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
pluginApiRouter.post('/update-check', (req: Request, res: Response) => {
  const { license_key, product_slug, current_version, domain } = req.body || {};
  const license = dbService.state.licenses.find(
    (l) => l.licenseKey.toUpperCase() === String(license_key || '').trim().toUpperCase()
  );

  if (!license || license.status !== 'ACTIVE') {
    res.status(403).json({
      update_available: false,
      message: 'Chỉ các website có License đang ACTIVE mới được phép tải bản cập nhật.'
    });
    return;
  }

  const product = dbService.state.products.find(
    (p) => p.id === license.productId && (!product_slug || p.slug === product_slug)
  );

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
pluginApiRouter.post('/auto-bind', (req: Request, res: Response) => {
  const parsed = autoBindSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'VALIDATION_ERROR',
      details: parsed.error.flatten()
    });
    return;
  }

  const detectedOutboundIp = NetworkNormalizer.extractTrustedClientServerIp(req);
  const result = licenseValidationService.autoBindByDomain({
    ...parsed.data,
    detected_outbound_ip: detectedOutboundIp,
    user_agent: req.headers['user-agent'] || 'WP-Core-Hydrator'
  });

  res.status(result.httpStatus).json(result.envelope);
});


