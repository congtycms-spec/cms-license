"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminApiRouter = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const express_1 = require("express");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const db_service_1 = require("../database/db.service");
const network_normalizer_1 = require("../utils/network-normalizer");
const ed25519_service_1 = require("../crypto/ed25519.service");
exports.adminApiRouter = (0, express_1.Router)();
function loadOrGenerateJwtSecret() {
    const envSecret = process.env.ADMIN_JWT_SECRET?.trim();
    if (envSecret && envSecret !== 'replace-with-strong-64-byte-secret-in-production') {
        return envSecret;
    }
    const dataCandidates = [
        node_path_1.default.resolve(__dirname, '..', '..', 'data'),
        node_path_1.default.join(process.cwd(), 'license-server', 'data'),
        node_path_1.default.join(process.cwd(), 'data')
    ];
    const dataDir = dataCandidates.find((d) => node_fs_1.default.existsSync(d)) || dataCandidates[0];
    const secretFile = node_path_1.default.join(dataDir, 'jwt-secret.json');
    if (node_fs_1.default.existsSync(secretFile)) {
        try {
            const parsed = JSON.parse(node_fs_1.default.readFileSync(secretFile, 'utf8'));
            if (parsed.jwtSecret && parsed.jwtSecret.length >= 64) {
                return parsed.jwtSecret;
            }
        }
        catch {
            // Regenerate below
        }
    }
    const generated = node_crypto_1.default.randomBytes(64).toString('hex');
    try {
        node_fs_1.default.mkdirSync(node_path_1.default.dirname(secretFile), { recursive: true });
        node_fs_1.default.writeFileSync(secretFile, JSON.stringify({ jwtSecret: generated }, null, 2), 'utf8');
    }
    catch {
        // Ignore on read-only Vercel Serverless filesystem
    }
    return generated;
}
const JWT_SECRET = loadOrGenerateJwtSecret();
const adminAuthLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Max 20 login/setup attempts per 15 minutes per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'TOO_MANY_LOGIN_ATTEMPTS',
        message: 'Quá nhiều lần thử đăng nhập sai. Vui lòng thử lại sau 15 phút.'
    }
});
/**
 * RBAC Authentication & Authorization Middleware
 */
function requireAuth(allowedRoles) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(401).json({ error: 'UNAUTHORIZED', message: 'Vui lòng đăng nhập quản trị.' });
            return;
        }
        const token = authHeader.slice(7);
        try {
            const decoded = jsonwebtoken_1.default.verify(token, JWT_SECRET);
            const existingUser = decoded
                ? db_service_1.dbService.state.users.find((u) => u.id === decoded.id && u.isActive)
                : undefined;
            if (!decoded || !existingUser) {
                res.status(401).json({ error: 'INVALID_TOKEN', message: 'Phiên đăng nhập đã hết hạn hoặc tài khoản không tồn tại.' });
                return;
            }
            if (allowedRoles && allowedRoles.length > 0 && !allowedRoles.includes(decoded.role)) {
                res.status(403).json({
                    error: 'FORBIDDEN_ROLE',
                    message: `Quyền hiện tại (${decoded.role}) không được phép thực hiện thao tác này. Yêu cầu: ${allowedRoles.join(', ')}`
                });
                return;
            }
            req.adminUser = decoded;
            next();
        }
        catch {
            res.status(401).json({ error: 'TOKEN_EXPIRED', message: 'Phiên đăng nhập đã hết hạn.' });
        }
    };
}
// ==========================================================
// 14. QUẢN LÝ NHÂN VIÊN & ĐĂNG NHẬP PHÂN QUYỀN (RBAC)
// ==========================================================
exports.adminApiRouter.get('/auth/setup-status', (_req, res) => {
    res.json({
        needsInitialSetup: db_service_1.dbService.state.users.length === 0
    });
});
exports.adminApiRouter.post('/auth/setup-initial-admin', adminAuthLimiter, (req, res) => {
    if (db_service_1.dbService.state.users.length > 0) {
        res.status(403).json({
            error: 'ALREADY_INITIALIZED',
            message: 'Hệ thống đã có tài khoản Super Admin. Vui lòng đăng nhập.'
        });
        return;
    }
    const { fullName, email, password } = req.body || {};
    if (!fullName || !email || !password || String(password).length < 6) {
        res.status(400).json({
            error: 'INVALID_INPUT',
            message: 'Vui lòng nhập đầy đủ Họ tên, Email và Mật khẩu (tối thiểu 6 ký tự).'
        });
        return;
    }
    const now = new Date().toISOString();
    const adminUser = {
        id: node_crypto_1.default.randomUUID(),
        email: String(email).trim().toLowerCase(),
        passwordHash: db_service_1.DatabaseService.hashPassword(String(password)),
        fullName: String(fullName).trim(),
        role: 'SUPER_ADMIN',
        isActive: true,
        createdAt: now,
        updatedAt: now
    };
    db_service_1.dbService.state.users.push(adminUser);
    db_service_1.dbService.save();
    const token = jsonwebtoken_1.default.sign({
        id: adminUser.id,
        email: adminUser.email,
        fullName: adminUser.fullName,
        role: adminUser.role
    }, JWT_SECRET, { expiresIn: '12h' });
    res.status(201).json({
        token,
        user: {
            id: adminUser.id,
            email: adminUser.email,
            fullName: adminUser.fullName,
            role: adminUser.role
        }
    });
});
exports.adminApiRouter.post('/auth/login', adminAuthLimiter, (req, res) => {
    const { email, password } = req.body || {};
    const user = db_service_1.dbService.state.users.find((u) => u.email.toLowerCase() === String(email || '').trim().toLowerCase());
    if (!user || !user.isActive || !db_service_1.DatabaseService.verifyPassword(String(password || ''), user.passwordHash)) {
        res.status(401).json({
            error: 'INVALID_CREDENTIALS',
            message: 'Email hoặc mật khẩu quản trị không chính xác.'
        });
        return;
    }
    const token = jsonwebtoken_1.default.sign({
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role
    }, JWT_SECRET, { expiresIn: '12h' });
    res.json({
        token,
        user: {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            role: user.role
        }
    });
});
exports.adminApiRouter.get('/users', requireAuth(['SUPER_ADMIN', 'MANAGER']), (_req, res) => {
    const users = db_service_1.dbService.state.users.map(({ passwordHash, ...rest }) => rest);
    res.json({ users });
});
exports.adminApiRouter.post('/users', requireAuth(['SUPER_ADMIN']), (req, res) => {
    const { email, password, fullName, role } = req.body || {};
    if (!email || !password || !fullName) {
        res.status(400).json({ error: 'MISSING_FIELDS', message: 'Vui lòng nhập đủ email, mật khẩu, họ tên.' });
        return;
    }
    if (db_service_1.dbService.state.users.some((u) => u.email.toLowerCase() === String(email).toLowerCase())) {
        res.status(409).json({ error: 'EMAIL_EXISTS', message: 'Email nhân viên đã tồn tại.' });
        return;
    }
    const now = new Date().toISOString();
    const newUser = {
        id: node_crypto_1.default.randomUUID(),
        email: String(email).trim().toLowerCase(),
        passwordHash: db_service_1.DatabaseService.hashPassword(String(password)),
        fullName: String(fullName).trim(),
        role: (['SUPER_ADMIN', 'MANAGER', 'SUPPORT'].includes(role) ? role : 'SUPPORT'),
        isActive: true,
        createdAt: now,
        updatedAt: now
    };
    db_service_1.dbService.state.users.push(newUser);
    db_service_1.dbService.save();
    const { passwordHash, ...safeUser } = newUser;
    res.status(201).json({ user: safeUser });
});
exports.adminApiRouter.delete('/users/:id', requireAuth(['SUPER_ADMIN']), (req, res) => {
    const targetId = String(req.params.id || '');
    const index = db_service_1.dbService.state.users.findIndex((u) => u.id === targetId);
    if (index === -1) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy tài khoản nhân viên.' });
        return;
    }
    db_service_1.dbService.state.users.splice(index, 1);
    db_service_1.dbService.save();
    res.json({ success: true, message: 'Đã xóa tài khoản nhân viên.' });
});
// ==========================================================
// 15. THỐNG KÊ TỔNG QUAN & LICENSE SẮP HẾT HẠN (DASHBOARD STATS)
// ==========================================================
exports.adminApiRouter.get('/dashboard/stats', requireAuth(), (_req, res) => {
    const nowMs = Date.now();
    const in30DaysMs = nowMs + 30 * 24 * 3600 * 1000;
    const licenses = db_service_1.dbService.state.licenses;
    const expiringSoon = licenses
        .filter((l) => {
        const expMs = new Date(l.expiresAt).getTime();
        return l.status === 'ACTIVE' && expMs > nowMs && expMs <= in30DaysMs;
    })
        .map((l) => {
        const customer = db_service_1.dbService.state.customers.find((c) => c.id === l.customerId);
        const product = db_service_1.dbService.state.products.find((p) => p.id === l.productId);
        const daysLeft = Math.ceil((new Date(l.expiresAt).getTime() - nowMs) / (24 * 3600 * 1000));
        return {
            ...l,
            customerName: customer?.name || 'N/A',
            customerCompany: customer?.company || '',
            productName: product?.name || 'N/A',
            daysLeft
        };
    });
    const pendingTransfers = db_service_1.dbService.state.transferRequests.filter((t) => t.status === 'PENDING');
    res.json({
        summary: {
            totalCustomers: db_service_1.dbService.state.customers.length,
            totalProducts: db_service_1.dbService.state.products.length,
            totalLicenses: licenses.length,
            activeLicenses: licenses.filter((l) => l.status === 'ACTIVE').length,
            expiredLicenses: licenses.filter((l) => l.status === 'EXPIRED').length,
            suspendedLicenses: licenses.filter((l) => l.status === 'SUSPENDED').length,
            revokedLicenses: licenses.filter((l) => l.status === 'REVOKED').length,
            expiringWithin30DaysCount: expiringSoon.length,
            pendingTransferRequestsCount: pendingTransfers.length,
            totalRemoteFeatureCalls: db_service_1.dbService.state.remoteFeatureLogs.length
        },
        cryptography: {
            algorithm: 'Ed25519 (RFC 8032)',
            keyId: ed25519_service_1.ed25519Service.getKeyId(),
            publicKeyBase64: ed25519_service_1.ed25519Service.getPublicKeyBase64()
        },
        expiringSoonLicenses: expiringSoon,
        recentValidationFailures: db_service_1.dbService.state.validationLogs
            .filter((v) => !v.isValid)
            .slice(-10)
            .reverse()
    });
});
// ==========================================================
// 1. QUẢN LÝ KHÁCH HÀNG (CUSTOMERS)
// ==========================================================
exports.adminApiRouter.get('/customers', requireAuth(), (_req, res) => {
    const customers = db_service_1.dbService.state.customers.map((c) => ({
        ...c,
        licenseCount: db_service_1.dbService.state.licenses.filter((l) => l.customerId === c.id).length
    }));
    res.json({ customers });
});
exports.adminApiRouter.post('/customers', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const { name, email, phone, company, notes } = req.body || {};
    if (!name || !email) {
        res.status(400).json({ error: 'MISSING_FIELDS', message: 'Họ tên và Email là bắt buộc.' });
        return;
    }
    const now = new Date().toISOString();
    const customer = {
        id: node_crypto_1.default.randomUUID(),
        name: String(name).trim(),
        email: String(email).trim().toLowerCase(),
        phone: String(phone || '').trim(),
        company: String(company || '').trim(),
        notes: String(notes || '').trim(),
        createdAt: now,
        updatedAt: now
    };
    db_service_1.dbService.state.customers.push(customer);
    db_service_1.dbService.save();
    res.status(201).json({ customer });
});
exports.adminApiRouter.delete('/customers/:id', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const targetId = String(req.params.id || '');
    const index = db_service_1.dbService.state.customers.findIndex((c) => c.id === targetId);
    if (index === -1) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy khách hàng.' });
        return;
    }
    // Also remove licenses belonging to this customer
    db_service_1.dbService.state.licenses = db_service_1.dbService.state.licenses.filter((l) => l.customerId !== targetId);
    db_service_1.dbService.state.customers.splice(index, 1);
    db_service_1.dbService.save();
    res.json({ success: true, message: 'Đã xóa khách hàng.' });
});
// ==========================================================
// 2. QUẢN LÝ SẢN PHẨM WORDPRESS (PRODUCTS)
// ==========================================================
exports.adminApiRouter.get('/products', requireAuth(), (_req, res) => {
    res.json({ products: db_service_1.dbService.state.products });
});
exports.adminApiRouter.post('/products', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const { slug, name, currentVersion, commercialFeatures, defaultMaxActivations, defaultMaxTransfers, gracePeriodHours, downloadUrl } = req.body || {};
    if (!slug || !name) {
        res.status(400).json({ error: 'MISSING_FIELDS', message: 'Mã sản phẩm (slug) và tên là bắt buộc.' });
        return;
    }
    const now = new Date().toISOString();
    const product = {
        id: node_crypto_1.default.randomUUID(),
        slug: String(slug).trim().toLowerCase(),
        name: String(name).trim(),
        currentVersion: String(currentVersion || '1.0.0'),
        commercialFeatures: Array.isArray(commercialFeatures)
            ? commercialFeatures.map(String)
            : String(commercialFeatures || '')
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean),
        defaultMaxActivations: Number(defaultMaxActivations || 1),
        defaultMaxTransfers: Number(defaultMaxTransfers || 3),
        gracePeriodHours: Number(gracePeriodHours || 72),
        downloadUrl: String(downloadUrl || `https://releases.company.vn/${slug}.zip`),
        isActive: true,
        createdAt: now,
        updatedAt: now
    };
    db_service_1.dbService.state.products.push(product);
    db_service_1.dbService.save();
    res.status(201).json({ product });
});
exports.adminApiRouter.delete('/products/:id', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const targetId = String(req.params.id || '');
    const index = db_service_1.dbService.state.products.findIndex((p) => p.id === targetId);
    if (index === -1) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy sản phẩm.' });
        return;
    }
    db_service_1.dbService.state.licenses = db_service_1.dbService.state.licenses.filter((l) => l.productId !== targetId);
    db_service_1.dbService.state.products.splice(index, 1);
    db_service_1.dbService.save();
    res.json({ success: true, message: 'Đã xóa sản phẩm.' });
});
// ==========================================================
// 3 -> 10. QUẢN LÝ LICENSE (TẠO, KÍCH HOẠT, GIA HẠN, TẠM NGỪNG, THU HỒI, ĐỔI DOMAIN/IP, GIỚI HẠN)
// ==========================================================
exports.adminApiRouter.get('/licenses', requireAuth(), (_req, res) => {
    const enriched = db_service_1.dbService.state.licenses.map((l) => {
        const customer = db_service_1.dbService.state.customers.find((c) => c.id === l.customerId);
        const product = db_service_1.dbService.state.products.find((p) => p.id === l.productId);
        const activations = db_service_1.dbService.state.activations.filter((a) => a.licenseId === l.id);
        const transfers = db_service_1.dbService.state.transferRequests.filter((t) => t.licenseId === l.id);
        return {
            ...l,
            customerName: customer?.name || 'N/A',
            customerEmail: customer?.email || '',
            customerCompany: customer?.company || '',
            productName: product?.name || 'N/A',
            productSlug: product?.slug || '',
            activeInstallationsCount: activations.filter((a) => a.status === 'ACTIVE').length,
            activations,
            transfers
        };
    });
    res.json({ licenses: enriched });
});
exports.adminApiRouter.post('/licenses', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const { customerId, productId, allowedDomain, allowedIp, strictIpCheck, treatWwwAsSame, maxActivations, maxTransfers, durationDays, notes } = req.body || {};
    const customer = db_service_1.dbService.state.customers.find((c) => c.id === customerId);
    const product = db_service_1.dbService.state.products.find((p) => p.id === productId);
    if (!customer || !product) {
        res.status(400).json({ error: 'INVALID_RELATIONS', message: 'Khách hàng hoặc Sản phẩm không tồn tại.' });
        return;
    }
    const now = new Date();
    const days = Math.max(1, Number(durationDays || 365));
    const expiresAt = new Date(now.getTime() + days * 24 * 3600 * 1000).toISOString();
    const normDomain = allowedDomain
        ? network_normalizer_1.NetworkNormalizer.normalizeDomain(String(allowedDomain), treatWwwAsSame !== false)
        : null;
    const normIp = allowedIp ? network_normalizer_1.NetworkNormalizer.normalizeIp(String(allowedIp)) || String(allowedIp).trim() : null;
    const newLicense = {
        id: node_crypto_1.default.randomUUID(),
        licenseKey: db_service_1.DatabaseService.generateLicenseKey(),
        customerId: customer.id,
        productId: product.id,
        status: 'ACTIVE',
        allowedDomain: normDomain,
        allowedIp: normIp,
        strictIpCheck: strictIpCheck !== false,
        treatWwwAsSame: treatWwwAsSame !== false,
        maxActivations: Number(maxActivations || product.defaultMaxActivations || 1),
        maxTransfers: Number(maxTransfers || product.defaultMaxTransfers || 3),
        transferCount: 0,
        startsAt: now.toISOString(),
        expiresAt,
        customFeatures: null,
        notes: String(notes || ''),
        createdAt: now.toISOString(),
        updatedAt: now.toISOString()
    };
    db_service_1.dbService.state.licenses.push(newLicense);
    db_service_1.dbService.addAuditLog({
        licenseId: newLicense.id,
        actorUserId: req.adminUser.id,
        eventType: 'LICENSE_CREATED',
        oldValue: null,
        newValue: {
            licenseKey: newLicense.licenseKey,
            allowedDomain: newLicense.allowedDomain,
            allowedIp: newLicense.allowedIp,
            expiresAt: newLicense.expiresAt
        },
        ipAddress: req.ip || '127.0.0.1',
        note: `Tạo mới license cho khách hàng ${customer.name}`
    });
    db_service_1.dbService.save();
    res.status(201).json({ license: newLicense });
});
// 4, 6, 7. Đổi trạng thái License: ACTIVE (Kích hoạt), SUSPENDED (Tạm ngừng), REVOKED (Thu hồi)
exports.adminApiRouter.patch('/licenses/:id/status', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const license = db_service_1.dbService.state.licenses.find((l) => l.id === req.params.id);
    if (!license) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
        return;
    }
    const { status, note } = req.body || {};
    const validStatuses = ['ACTIVE', 'INACTIVE', 'EXPIRED', 'SUSPENDED', 'REVOKED'];
    if (!validStatuses.includes(status)) {
        res.status(400).json({ error: 'INVALID_STATUS', message: 'Trạng thái không hợp lệ.' });
        return;
    }
    const oldStatus = license.status;
    license.status = status;
    license.updatedAt = new Date().toISOString();
    if (status === 'REVOKED' || status === 'SUSPENDED') {
        db_service_1.dbService.state.activations
            .filter((a) => a.licenseId === license.id && a.status === 'ACTIVE')
            .forEach((a) => {
            a.status = 'DEACTIVATED';
        });
    }
    db_service_1.dbService.addAuditLog({
        licenseId: license.id,
        actorUserId: req.adminUser.id,
        eventType: `STATUS_CHANGED_TO_${status}`,
        oldValue: { status: oldStatus },
        newValue: { status },
        ipAddress: req.ip || '127.0.0.1',
        note: String(note || `Nhân viên ${req.adminUser.fullName} đổi trạng thái sang ${status}`)
    });
    db_service_1.dbService.save();
    res.json({ license });
});
// 5. Gia hạn License (Renew License)
exports.adminApiRouter.patch('/licenses/:id/renew', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const license = db_service_1.dbService.state.licenses.find((l) => l.id === req.params.id);
    if (!license) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
        return;
    }
    const addDays = Math.max(1, Number(req.body?.addDays || 365));
    const currentExpMs = new Date(license.expiresAt).getTime();
    const baseMs = Math.max(Date.now(), currentExpMs);
    const oldExpiresAt = license.expiresAt;
    const oldStatus = license.status;
    license.expiresAt = new Date(baseMs + addDays * 24 * 3600 * 1000).toISOString();
    if (license.status === 'EXPIRED') {
        license.status = 'ACTIVE';
    }
    license.updatedAt = new Date().toISOString();
    db_service_1.dbService.addAuditLog({
        licenseId: license.id,
        actorUserId: req.adminUser.id,
        eventType: 'LICENSE_RENEWED',
        oldValue: { expiresAt: oldExpiresAt, status: oldStatus },
        newValue: { expiresAt: license.expiresAt, status: license.status, addDays },
        ipAddress: req.ip || '127.0.0.1',
        note: `Gia hạn thêm ${addDays} ngày bởi ${req.adminUser.fullName}`
    });
    db_service_1.dbService.save();
    res.json({ license });
});
// 8, 9, 10. Đổi Tên miền, Đổi IP máy chủ, Giới hạn số website & số lần chuyển
exports.adminApiRouter.patch('/licenses/:id/environment', requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']), (req, res) => {
    const license = db_service_1.dbService.state.licenses.find((l) => l.id === req.params.id);
    if (!license) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
        return;
    }
    const { allowedDomain, allowedIp, strictIpCheck, maxActivations, maxTransfers, note } = req.body || {};
    const oldSnapshot = {
        allowedDomain: license.allowedDomain,
        allowedIp: license.allowedIp,
        strictIpCheck: license.strictIpCheck,
        maxActivations: license.maxActivations,
        maxTransfers: license.maxTransfers
    };
    if (allowedDomain !== undefined) {
        license.allowedDomain = allowedDomain
            ? network_normalizer_1.NetworkNormalizer.normalizeDomain(String(allowedDomain), license.treatWwwAsSame)
            : null;
    }
    if (allowedIp !== undefined) {
        license.allowedIp = allowedIp ? String(allowedIp).trim() : null;
    }
    if (strictIpCheck !== undefined) {
        license.strictIpCheck = Boolean(strictIpCheck);
    }
    if (maxActivations !== undefined) {
        license.maxActivations = Math.max(1, Number(maxActivations));
    }
    if (maxTransfers !== undefined) {
        license.maxTransfers = Math.max(0, Number(maxTransfers));
    }
    license.updatedAt = new Date().toISOString();
    db_service_1.dbService.addAuditLog({
        licenseId: license.id,
        actorUserId: req.adminUser.id,
        eventType: 'ENVIRONMENT_OR_LIMITS_UPDATED',
        oldValue: oldSnapshot,
        newValue: {
            allowedDomain: license.allowedDomain,
            allowedIp: license.allowedIp,
            strictIpCheck: license.strictIpCheck,
            maxActivations: license.maxActivations,
            maxTransfers: license.maxTransfers
        },
        ipAddress: req.ip || '127.0.0.1',
        note: String(note || 'Cập nhật cấu hình Tên miền / IP / Giới hạn kích hoạt')
    });
    db_service_1.dbService.save();
    res.json({ license });
});
exports.adminApiRouter.delete('/licenses/:id', requireAuth(['SUPER_ADMIN', 'MANAGER']), (req, res) => {
    const targetId = String(req.params.id || '');
    const index = db_service_1.dbService.state.licenses.findIndex((l) => l.id === targetId);
    if (index === -1) {
        res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
        return;
    }
    db_service_1.dbService.state.activations = db_service_1.dbService.state.activations.filter((a) => a.licenseId !== targetId);
    db_service_1.dbService.state.transferRequests = db_service_1.dbService.state.transferRequests.filter((t) => t.licenseId !== targetId);
    db_service_1.dbService.state.licenses.splice(index, 1);
    db_service_1.dbService.save();
    res.json({ success: true, message: 'Đã xóa License Key.' });
});
// ==========================================================
// 11. QUẢN LÝ & PHÊ DUYỆT YÊU CẦU CHUYỂN MÁY CHỦ (MODULE 6)
// ==========================================================
exports.adminApiRouter.get('/transfer-requests', requireAuth(), (_req, res) => {
    const requests = db_service_1.dbService.state.transferRequests
        .map((r) => {
        const license = db_service_1.dbService.state.licenses.find((l) => l.id === r.licenseId);
        const customer = license
            ? db_service_1.dbService.state.customers.find((c) => c.id === license.customerId)
            : undefined;
        return {
            ...r,
            licenseKey: license?.licenseKey || 'N/A',
            customerName: customer?.name || 'N/A',
            customerCompany: customer?.company || '',
            transferCount: license?.transferCount || 0,
            maxTransfers: license?.maxTransfers || 3
        };
    })
        .reverse();
    res.json({ transferRequests: requests });
});
exports.adminApiRouter.post('/transfer-requests/:id/approve', requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']), (req, res) => {
    const transferReq = db_service_1.dbService.state.transferRequests.find((r) => r.id === req.params.id);
    if (!transferReq || transferReq.status !== 'PENDING') {
        res.status(404).json({
            error: 'NOT_FOUND_OR_PROCESSED',
            message: 'Yêu cầu chuyển máy chủ không tồn tại hoặc đã được xử lý.'
        });
        return;
    }
    const license = db_service_1.dbService.state.licenses.find((l) => l.id === transferReq.licenseId);
    if (!license) {
        res.status(404).json({ error: 'LICENSE_NOT_FOUND', message: 'Không tìm thấy License.' });
        return;
    }
    const oldDomain = license.allowedDomain;
    const oldIp = license.allowedIp;
    // 1. Revoke old server activations (Module 6 step 7: Old server handled per license policy without deleting data)
    db_service_1.dbService.state.activations
        .filter((a) => a.licenseId === license.id && a.status === 'ACTIVE')
        .forEach((a) => {
        a.status = 'REVOKED_BY_TRANSFER';
    });
    // 2. Update license allowed Domain & IP to the new server
    license.allowedDomain = network_normalizer_1.NetworkNormalizer.normalizeDomain(transferReq.newDomain, license.treatWwwAsSame);
    license.allowedIp = transferReq.newIp;
    license.transferCount += 1;
    license.updatedAt = new Date().toISOString();
    // 3. Mark transfer request as APPROVED
    transferReq.status = 'APPROVED';
    transferReq.reviewedByUserId = req.adminUser.id;
    transferReq.reviewNote = String(req.body?.reviewNote || 'Đã phê duyệt chuyển máy chủ.');
    transferReq.reviewedAt = new Date().toISOString();
    // 4. Record audit log
    db_service_1.dbService.addAuditLog({
        licenseId: license.id,
        actorUserId: req.adminUser.id,
        eventType: 'SERVER_TRANSFER_APPROVED',
        oldValue: { domain: oldDomain, ip: oldIp },
        newValue: {
            domain: license.allowedDomain,
            ip: license.allowedIp,
            transferCount: license.transferCount
        },
        ipAddress: req.ip || '127.0.0.1',
        note: `Phê duyệt chuyển máy chủ bởi ${req.adminUser.fullName}. Ghi chú: ${transferReq.reviewNote}`
    });
    db_service_1.dbService.save();
    res.json({ transferRequest: transferReq, license });
});
exports.adminApiRouter.post('/transfer-requests/:id/reject', requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']), (req, res) => {
    const transferReq = db_service_1.dbService.state.transferRequests.find((r) => r.id === req.params.id);
    if (!transferReq || transferReq.status !== 'PENDING') {
        res.status(404).json({
            error: 'NOT_FOUND_OR_PROCESSED',
            message: 'Yêu cầu chuyển máy chủ không tồn tại hoặc đã được xử lý.'
        });
        return;
    }
    transferReq.status = 'REJECTED';
    transferReq.reviewedByUserId = req.adminUser.id;
    transferReq.reviewNote = String(req.body?.reviewNote || 'Từ chối yêu cầu chuyển máy chủ.');
    transferReq.reviewedAt = new Date().toISOString();
    db_service_1.dbService.addAuditLog({
        licenseId: transferReq.licenseId,
        actorUserId: req.adminUser.id,
        eventType: 'SERVER_TRANSFER_REJECTED',
        oldValue: { status: 'PENDING' },
        newValue: {
            status: 'REJECTED',
            requestedDomain: transferReq.newDomain,
            requestedIp: transferReq.newIp
        },
        ipAddress: req.ip || '127.0.0.1',
        note: `Từ chối chuyển máy chủ bởi ${req.adminUser.fullName}: ${transferReq.reviewNote}`
    });
    db_service_1.dbService.save();
    res.json({ transferRequest: transferReq });
});
// ==========================================================
// 12 & 13. XEM LỊCH SỬ XÁC THỰC & LỊCH SỬ THAY ĐỔI LICENSE
// ==========================================================
exports.adminApiRouter.get('/logs/validations', requireAuth(), (_req, res) => {
    const logs = db_service_1.dbService.state.validationLogs.slice(-200).reverse();
    res.json({ validationLogs: logs });
});
exports.adminApiRouter.get('/logs/audits', requireAuth(), (_req, res) => {
    const logs = db_service_1.dbService.state.auditLogs
        .slice(-200)
        .map((a) => {
        const actor = db_service_1.dbService.state.users.find((u) => u.id === a.actorUserId);
        const lic = db_service_1.dbService.state.licenses.find((l) => l.id === a.licenseId);
        return {
            ...a,
            actorName: actor ? `${actor.fullName} (${actor.role})` : 'Hệ thống tự động',
            licenseKey: lic?.licenseKey || 'N/A'
        };
    })
        .reverse();
    res.json({ auditLogs: logs });
});
exports.adminApiRouter.get('/logs/remote-features', requireAuth(), (_req, res) => {
    const logs = db_service_1.dbService.state.remoteFeatureLogs
        .slice(-100)
        .map((r) => {
        const lic = db_service_1.dbService.state.licenses.find((l) => l.id === r.licenseId);
        return {
            ...r,
            licenseKey: lic?.licenseKey || 'N/A'
        };
    })
        .reverse();
    res.json({ remoteFeatureLogs: logs });
});
