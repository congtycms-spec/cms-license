import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import { Router, Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import {
  dbService,
  DatabaseService,
  StaffRole,
  LicenseStatus,
  LicenseRecord,
  MonitorSettingsRecord,
  SiteHealthRecord
} from '../database/db.service';
import { NetworkNormalizer } from '../utils/network-normalizer';
import { ed25519Service } from '../crypto/ed25519.service';

export const adminApiRouter = Router();

function loadOrGenerateJwtSecret(): string {
  const envSecret = process.env.ADMIN_JWT_SECRET?.trim();
  if (envSecret && envSecret !== 'replace-with-strong-64-byte-secret-in-production') {
    return envSecret;
  }
  const dataCandidates = [
    path.resolve(__dirname, '..', '..', 'data'),
    path.join(process.cwd(), 'license-server', 'data'),
    path.join(process.cwd(), 'data')
  ];
  const dataDir = dataCandidates.find((d) => fs.existsSync(d)) || dataCandidates[0];
  const secretFile = path.join(dataDir, 'jwt-secret.json');
  if (fs.existsSync(secretFile)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(secretFile, 'utf8'));
      if (parsed.jwtSecret && parsed.jwtSecret.length >= 64) {
        return parsed.jwtSecret;
      }
    } catch {
      // Regenerate below
    }
  }
  const generated = crypto.randomBytes(64).toString('hex');
  try {
    fs.mkdirSync(path.dirname(secretFile), { recursive: true });
    fs.writeFileSync(secretFile, JSON.stringify({ jwtSecret: generated }, null, 2), 'utf8');
  } catch {
    // Ignore on read-only Vercel Serverless filesystem
  }
  return generated;
}

const JWT_SECRET = loadOrGenerateJwtSecret();

const adminAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Max 20 login/setup attempts per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'TOO_MANY_LOGIN_ATTEMPTS',
    message: 'Quá nhiều lần thử đăng nhập sai. Vui lòng thử lại sau 15 phút.'
  }
});

export interface AuthenticatedAdminRequest extends Request {
  adminUser?: {
    id: string;
    email: string;
    fullName: string;
    role: StaffRole;
  };
}

/**
 * RBAC Authentication & Authorization Middleware
 */
function requireAuth(allowedRoles?: StaffRole[]) {
  return (req: AuthenticatedAdminRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'UNAUTHORIZED', message: 'Vui lòng đăng nhập quản trị.' });
      return;
    }

    const token = authHeader.slice(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as AuthenticatedAdminRequest['adminUser'];
      const existingUser = decoded
        ? dbService.state.users.find((u) => u.id === decoded.id && u.isActive)
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
    } catch {
      res.status(401).json({ error: 'TOKEN_EXPIRED', message: 'Phiên đăng nhập đã hết hạn.' });
    }
  };
}

// ==========================================================
// 14. QUẢN LÝ NHÂN VIÊN & ĐĂNG NHẬP PHÂN QUYỀN (RBAC)
// ==========================================================
adminApiRouter.get('/auth/setup-status', (_req: Request, res: Response) => {
  res.json({
    needsInitialSetup: dbService.state.users.length === 0
  });
});

adminApiRouter.post('/auth/setup-initial-admin', adminAuthLimiter, (req: Request, res: Response) => {
  if (dbService.state.users.length > 0) {
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
    id: crypto.randomUUID(),
    email: String(email).trim().toLowerCase(),
    passwordHash: DatabaseService.hashPassword(String(password)),
    fullName: String(fullName).trim(),
    role: 'SUPER_ADMIN' as StaffRole,
    isActive: true,
    createdAt: now,
    updatedAt: now
  };

  dbService.state.users.push(adminUser);
  dbService.save();

  const token = jwt.sign(
    {
      id: adminUser.id,
      email: adminUser.email,
      fullName: adminUser.fullName,
      role: adminUser.role
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

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

adminApiRouter.post('/auth/login', adminAuthLimiter, (req: Request, res: Response) => {
  const { email, password } = req.body || {};
  const user = dbService.state.users.find(
    (u) => u.email.toLowerCase() === String(email || '').trim().toLowerCase()
  );

  if (!user || !user.isActive || !DatabaseService.verifyPassword(String(password || ''), user.passwordHash)) {
    res.status(401).json({
      error: 'INVALID_CREDENTIALS',
      message: 'Email hoặc mật khẩu quản trị không chính xác.'
    });
    return;
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

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

adminApiRouter.get('/users', requireAuth(['SUPER_ADMIN', 'MANAGER']), (_req, res) => {
  const users = dbService.state.users.map(({ passwordHash, ...rest }) => rest);
  res.json({ users });
});

adminApiRouter.post('/users', requireAuth(['SUPER_ADMIN']), (req: AuthenticatedAdminRequest, res) => {
  const { email, password, fullName, role } = req.body || {};
  if (!email || !password || !fullName) {
    res.status(400).json({ error: 'MISSING_FIELDS', message: 'Vui lòng nhập đủ email, mật khẩu, họ tên.' });
    return;
  }

  if (dbService.state.users.some((u) => u.email.toLowerCase() === String(email).toLowerCase())) {
    res.status(409).json({ error: 'EMAIL_EXISTS', message: 'Email nhân viên đã tồn tại.' });
    return;
  }

  const now = new Date().toISOString();
  const newUser = {
    id: crypto.randomUUID(),
    email: String(email).trim().toLowerCase(),
    passwordHash: DatabaseService.hashPassword(String(password)),
    fullName: String(fullName).trim(),
    role: (['SUPER_ADMIN', 'MANAGER', 'SUPPORT'].includes(role) ? role : 'SUPPORT') as StaffRole,
    isActive: true,
    createdAt: now,
    updatedAt: now
  };

  dbService.state.users.push(newUser);
  dbService.save();

  const { passwordHash, ...safeUser } = newUser;
  res.status(201).json({ user: safeUser });
});

adminApiRouter.delete(
  '/users/:id',
  requireAuth(['SUPER_ADMIN']),
  (req: AuthenticatedAdminRequest, res: Response) => {
    const targetId = String(req.params.id || '');
    const index = dbService.state.users.findIndex((u) => u.id === targetId);
    if (index === -1) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy tài khoản nhân viên.' });
      return;
    }

    dbService.state.users.splice(index, 1);
    dbService.save();
    res.json({ success: true, message: 'Đã xóa tài khoản nhân viên.' });
  }
);

// ==========================================================
// HỆ THỐNG GIÁM SÁT SỨC KHỎE WEBSITE & THÔNG BÁO ĐẨY TELEGRAM 24/7
// ==========================================================
const PERMANENT_EXPIRES_AT = '2099-12-31T23:59:59.000Z';

function getMonitorSettings(): MonitorSettingsRecord {
  if (!dbService.state.monitorSettings) {
    dbService.state.monitorSettings = {
      enabled: true,
      telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
      telegramChatId: process.env.TELEGRAM_CHAT_ID || '',
      notifyOnRecovery: true,
      slowThresholdMs: 3500,
      lastSweepAt: null
    };
  }
  return dbService.state.monitorSettings;
}

function getSiteHealthMap(): Record<string, SiteHealthRecord> {
  if (!dbService.state.siteHealth) {
    dbService.state.siteHealth = {};
  }
  return dbService.state.siteHealth;
}

async function sendTelegramAlert(
  htmlMessage: string,
  overrideToken?: string,
  overrideChatId?: string
): Promise<{ sent: boolean; error?: string }> {
  const settings = getMonitorSettings();
  const botToken = (overrideToken ?? settings.telegramBotToken ?? '').trim();
  const chatId = (overrideChatId ?? settings.telegramChatId ?? '').trim();
  if (!botToken || !chatId) {
    return { sent: false, error: 'Chưa cấu hình Telegram Bot Token hoặc Chat ID.' };
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text: htmlMessage,
        parse_mode: 'HTML',
        disable_web_page_preview: true
      }),
      signal: controller.signal
    });
    clearTimeout(timer);
    const data = (await resp.json().catch(() => ({}))) as { ok?: boolean; description?: string };
    if (!resp.ok || !data.ok) {
      return { sent: false, error: data.description || `HTTP ${resp.status}` };
    }
    return { sent: true };
  } catch (err) {
    return { sent: false, error: (err as Error).message };
  }
}

async function checkWebsiteHealth(
  domainRaw: string,
  lic?: LicenseRecord,
  options?: { forceSync?: boolean; sendNotifications?: boolean }
): Promise<{ record: SiteHealthRecord; stateChangedToDown: boolean; stateChangedToUp: boolean }> {
  const domain = NetworkNormalizer.normalizeDomain(domainRaw, true);
  const settings = getMonitorSettings();
  const healthMap = getSiteHealthMap();
  const prev = healthMap[domain];
  const nowIso = new Date().toISOString();

  if (options?.forceSync) {
    await triggerRemoteClientSync(domain);
  }

  const startMs = Date.now();
  let status: SiteHealthRecord['status'] = 'UP';
  let httpStatus = 0;
  let latencyMs = 0;
  let errorDetail: string | null = null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 9000);
    const response = await fetch(`https://${domain}/`, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; CLPS-Uptime-Monitor/3.5)',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        Pragma: 'no-cache'
      },
      signal: controller.signal
    });
    clearTimeout(timer);

    latencyMs = Date.now() - startMs;
    httpStatus = response.status;
    const bodySnippet = (await response.text().catch(() => '')).slice(0, 8000);

    const isIntentionalLock =
      bodySnippet.includes('Ed25519 Hardware/Domain Lock') ||
      bodySnippet.includes('Website đang tạm ngưng hoạt động') ||
      (httpStatus === 503 && (lic?.status === 'SUSPENDED' || lic?.status === 'REVOKED'));

    const hasWpDbError =
      bodySnippet.includes('Error establishing a database connection') ||
      bodySnippet.includes('Lỗi thiết lập kết nối cơ sở dữ liệu');
    const hasWpCriticalError =
      bodySnippet.includes('There has been a critical error on this website') ||
      bodySnippet.includes('Đã có lỗi nghiêm trọng trên trang web này') ||
      bodySnippet.includes('Fatal error:') ||
      bodySnippet.includes('Parse error:');

    if (isIntentionalLock) {
      status = 'LOCKED';
      errorDetail = 'Đang hiển thị màn hình khóa bản quyền chủ động (HTTP 503)';
    } else if (hasWpDbError) {
      status = 'DOWN';
      errorDetail = 'Lỗi cơ sở dữ liệu WordPress (Database Connection Error)';
    } else if (hasWpCriticalError) {
      status = 'DOWN';
      errorDetail = 'Lỗi PHP nghiêm trọng trên WordPress (Critical / Fatal Error)';
    } else if (httpStatus >= 500) {
      status = 'DOWN';
      errorDetail = `Máy chủ trả về lỗi HTTP ${httpStatus} (Server Error)`;
    } else if (httpStatus === 403 || httpStatus === 404) {
      status = 'DOWN';
      errorDetail = `Không thể truy cập trang chủ (HTTP ${httpStatus})`;
    } else if (httpStatus >= 400) {
      status = 'DOWN';
      errorDetail = `Lỗi phản hồi HTTP ${httpStatus}`;
    } else if (latencyMs >= (settings.slowThresholdMs || 3500)) {
      status = 'SLOW';
      errorDetail = `Phản hồi chậm (${latencyMs}ms)`;
    } else {
      status = 'UP';
      errorDetail = null;
    }
  } catch (err) {
    latencyMs = Date.now() - startMs;
    status = 'DOWN';
    const rawMsg = (err as Error).message || 'Unknown error';
    if (rawMsg.includes('aborted') || rawMsg.includes('timeout')) {
      errorDetail = `Quá thời gian phản hồi (Timeout > 9s)`;
    } else if (rawMsg.includes('ENOTFOUND') || rawMsg.includes('getaddrinfo')) {
      errorDetail = 'Không phân giải được tên miền (Lỗi DNS)';
    } else if (rawMsg.includes('ECONNREFUSED')) {
      errorDetail = 'Máy chủ từ chối kết nối (Connection Refused)';
    } else if (rawMsg.includes('certificate') || rawMsg.includes('SSL') || rawMsg.includes('TLS')) {
      errorDetail = `Lỗi chứng chỉ bảo mật SSL (${rawMsg})`;
    } else {
      errorDetail = `Không thể kết nối tới Website (${rawMsg})`;
    }
  }

  const prevAlerted = prev?.lastAlertedState || 'UP';
  const stateChangedToDown = status === 'DOWN' && prevAlerted !== 'DOWN';
  const stateChangedToUp =
    (status === 'UP' || status === 'LOCKED') && prevAlerted === 'DOWN';

  const record: SiteHealthRecord = {
    domain,
    status,
    httpStatus,
    latencyMs,
    errorDetail,
    checkedAt: nowIso,
    lastIncidentAt: status === 'DOWN' ? nowIso : prev?.lastIncidentAt || null,
    lastAlertedState:
      status === 'DOWN'
        ? 'DOWN'
        : status === 'UP' || status === 'LOCKED'
          ? 'UP'
          : prevAlerted
  };

  healthMap[domain] = record;

  if (options?.sendNotifications !== false && settings.enabled) {
    const serverIp = lic?.allowedIp ? lic.allowedIp.split(',')[0].trim() : 'N/A';
    const timeStr = new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });
    if (stateChangedToDown) {
      const msg =
        `🚨 <b>CẢNH BÁO WEBSITE SẬP / LỖI TRUY CẬP!</b>\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `🌐 <b>Website:</b> <a href="https://${domain}">${domain}</a>\n` +
        `🖥 <b>Server IP:</b> <code>${serverIp}</code>\n` +
        `⚠️ <b>Tình trạng:</b> <b>${errorDetail || 'Không thể truy cập'}</b>\n` +
        `📡 <b>Mã HTTP:</b> <code>${httpStatus || 'ERR_CONNECTION_FAILED'}</code> (${latencyMs}ms)\n` +
        `🕒 <b>Thời gian phát hiện:</b> ${timeStr}\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `👉 <i>Vui lòng kiểm tra hosting hoặc mở CMS License Dashboard ngay!</i>`;
      await sendTelegramAlert(msg);
    } else if (stateChangedToUp && settings.notifyOnRecovery) {
      const msg =
        `✅ <b>WEBSITE ĐÃ KHÔI PHỤC HOẠT ĐỘNG!</b>\n` +
        `━━━━━━━━━━━━━━━━━━\n` +
        `🌐 <b>Website:</b> <a href="https://${domain}">${domain}</a>\n` +
        `🖥 <b>Server IP:</b> <code>${serverIp}</code>\n` +
        `🟢 <b>Trạng thái:</b> Hoạt động bình thường (HTTP ${httpStatus} • ${latencyMs}ms)\n` +
        `🕒 <b>Thời gian khôi phục:</b> ${timeStr}`;
      await sendTelegramAlert(msg);
    }
  }

  return { record, stateChangedToDown, stateChangedToUp };
}

// ==========================================================
// 15. THỐNG KÊ TỔNG QUAN & GIÁM SÁT SỨC KHỎE WEBSITE (DASHBOARD STATS PRO)
// ==========================================================
adminApiRouter.get('/dashboard/stats', requireAuth(), (_req, res) => {
  const nowMs = Date.now();
  const last24hMs = nowMs - 24 * 3600 * 1000;

  const licenses = dbService.state.licenses;
  // Đảm bảo toàn bộ license là vĩnh viễn (không bao giờ tự hết hạn)
  let migratedPermanent = false;
  for (const l of licenses) {
    if (!l.expiresAt || new Date(l.expiresAt).getFullYear() < 2090) {
      l.expiresAt = PERMANENT_EXPIRES_AT;
      if (l.status === 'EXPIRED') l.status = 'ACTIVE';
      migratedPermanent = true;
    }
  }
  if (migratedPermanent) {
    dbService.save();
  }

  const pendingTransfers = dbService.state.transferRequests.filter((t) => t.status === 'PENDING');

  // Group licenses by primary hosting Server IP
  const serverMap = new Map<string, { ip: string; total: number; active: number; suspended: number }>();
  for (const l of licenses) {
    const primaryIp = l.allowedIp ? l.allowedIp.split(',')[0].trim() : 'Chưa gán IP';
    const cur = serverMap.get(primaryIp) || { ip: primaryIp, total: 0, active: 0, suspended: 0 };
    cur.total += 1;
    if (l.status === 'ACTIVE') cur.active += 1;
    if (l.status === 'SUSPENDED') cur.suspended += 1;
    serverMap.set(primaryIp, cur);
  }

  // 24h validation telemetry
  const logs24h = dbService.state.validationLogs.filter(
    (v) => new Date(v.createdAt).getTime() >= last24hMs
  );
  const valid24h = logs24h.filter((v) => v.isValid).length;
  const invalid24h = logs24h.length - valid24h;

  // Enrich recent validation failures with licenseId & status for 1-click quick actions
  const recentValidationFailures = dbService.state.validationLogs
    .filter((v) => !v.isValid)
    .slice(-12)
    .reverse()
    .map((v) => {
      const lic =
        dbService.state.licenses.find((l) => l.id === v.licenseId) ||
        dbService.state.licenses.find((l) => l.allowedDomain === v.requestDomain);
      return {
        ...v,
        resolvedLicenseId: lic?.id || null,
        currentLicenseStatus: lic?.status || null,
        allowedIp: lic?.allowedIp || null
      };
    });

  // Tổng hợp sức khỏe website thời gian thực
  const settings = getMonitorSettings();
  const healthMap = getSiteHealthMap();
  let upCount = 0;
  let downCount = 0;
  let slowCount = 0;
  let lockedCount = 0;
  let uncheckedCount = 0;

  const monitoredSites = licenses
    .filter((l) => Boolean(l.allowedDomain))
    .map((l) => {
      const domain = l.allowedDomain!;
      const h = healthMap[domain] || null;
      const customer = dbService.state.customers.find((c) => c.id === l.customerId);
      if (!h) {
        uncheckedCount += 1;
      } else if (h.status === 'DOWN') {
        downCount += 1;
      } else if (h.status === 'SLOW') {
        slowCount += 1;
      } else if (h.status === 'LOCKED') {
        lockedCount += 1;
      } else {
        upCount += 1;
      }
      return {
        licenseId: l.id,
        licenseKey: l.licenseKey,
        licenseStatus: l.status,
        domain,
        allowedIp: l.allowedIp || '',
        customerName: customer?.name || 'N/A',
        health: h
      };
    });

  res.json({
    summary: {
      totalCustomers: dbService.state.customers.length,
      totalProducts: dbService.state.products.length,
      totalLicenses: licenses.length,
      activeLicenses: licenses.filter((l) => l.status === 'ACTIVE').length,
      inactiveLicenses: licenses.filter((l) => l.status === 'INACTIVE').length,
      suspendedLicenses: licenses.filter((l) => l.status === 'SUSPENDED').length,
      revokedLicenses: licenses.filter((l) => l.status === 'REVOKED').length,
      pendingTransferRequestsCount: pendingTransfers.length,
      totalRemoteFeatureCalls: dbService.state.remoteFeatureLogs.length,
      serverCount: serverMap.size,
      validations24hTotal: logs24h.length,
      validations24hValid: valid24h,
      validations24hInvalid: invalid24h,
      upCount,
      downCount,
      slowCount,
      lockedCount,
      uncheckedCount
    },
    monitorSettings: settings,
    monitoredSites,
    serverGroups: Array.from(serverMap.values()).sort((a, b) => b.total - a.total),
    cryptography: {
      algorithm: 'Ed25519 (RFC 8032)',
      keyId: ed25519Service.getKeyId(),
      publicKeyBase64: ed25519Service.getPublicKeyBase64()
    },
    recentValidationFailures
  });
});

// ==========================================================
// 1. QUẢN LÝ KHÁCH HÀNG (CUSTOMERS)
// ==========================================================
adminApiRouter.get('/customers', requireAuth(), (_req, res) => {
  const customers = dbService.state.customers.map((c) => ({
    ...c,
    licenseCount: dbService.state.licenses.filter((l) => l.customerId === c.id).length
  }));
  res.json({ customers });
});

adminApiRouter.post(
  '/customers',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const { name, email, phone, company, notes } = req.body || {};
    if (!name || !email) {
      res.status(400).json({ error: 'MISSING_FIELDS', message: 'Họ tên và Email là bắt buộc.' });
      return;
    }

    const now = new Date().toISOString();
    const customer = {
      id: crypto.randomUUID(),
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      phone: String(phone || '').trim(),
      company: String(company || '').trim(),
      notes: String(notes || '').trim(),
      createdAt: now,
      updatedAt: now
    };

    dbService.state.customers.push(customer);
    dbService.save();
    res.status(201).json({ customer });
  }
);

adminApiRouter.put(
  '/customers/:id',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const customer = dbService.state.customers.find((c) => c.id === req.params.id);
    if (!customer) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy khách hàng.' });
      return;
    }
    const { name, email, phone, company, notes } = req.body || {};
    if (name !== undefined) customer.name = String(name).trim();
    if (email !== undefined) customer.email = String(email).trim().toLowerCase();
    if (phone !== undefined) customer.phone = String(phone).trim();
    if (company !== undefined) customer.company = String(company).trim();
    if (notes !== undefined) customer.notes = String(notes).trim();
    customer.updatedAt = new Date().toISOString();
    dbService.save();
    res.json({ customer });
  }
);

adminApiRouter.delete(
  '/customers/:id',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const targetId = String(req.params.id || '');
    const index = dbService.state.customers.findIndex((c) => c.id === targetId);
    if (index === -1) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy khách hàng.' });
      return;
    }
    // Also remove licenses belonging to this customer
    dbService.state.licenses = dbService.state.licenses.filter((l) => l.customerId !== targetId);
    dbService.state.customers.splice(index, 1);
    dbService.save();
    res.json({ success: true, message: 'Đã xóa khách hàng.' });
  }
);

// ==========================================================
// 2. QUẢN LÝ SẢN PHẨM WORDPRESS (PRODUCTS)
// ==========================================================
adminApiRouter.get('/products', requireAuth(), (_req, res) => {
  res.json({ products: dbService.state.products });
});

adminApiRouter.post(
  '/products',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const {
      slug,
      name,
      currentVersion,
      commercialFeatures,
      defaultMaxActivations,
      defaultMaxTransfers,
      gracePeriodHours,
      downloadUrl
    } = req.body || {};

    if (!slug || !name) {
      res.status(400).json({ error: 'MISSING_FIELDS', message: 'Mã sản phẩm (slug) và tên là bắt buộc.' });
      return;
    }

    const now = new Date().toISOString();
    const product = {
      id: crypto.randomUUID(),
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

    dbService.state.products.push(product);
    dbService.save();
    res.status(201).json({ product });
  }
);

adminApiRouter.put(
  '/products/:id',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const product = dbService.state.products.find((p) => p.id === req.params.id);
    if (!product) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy sản phẩm.' });
      return;
    }
    const { slug, name, currentVersion, commercialFeatures } = req.body || {};
    if (slug !== undefined) product.slug = String(slug).trim().toLowerCase();
    if (name !== undefined) product.name = String(name).trim();
    if (currentVersion !== undefined) product.currentVersion = String(currentVersion).trim();
    if (commercialFeatures !== undefined) {
      product.commercialFeatures = Array.isArray(commercialFeatures)
        ? commercialFeatures.map(String)
        : String(commercialFeatures)
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
    }
    product.updatedAt = new Date().toISOString();
    dbService.save();
    res.json({ product });
  }
);

adminApiRouter.delete(
  '/products/:id',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const targetId = String(req.params.id || '');
    const index = dbService.state.products.findIndex((p) => p.id === targetId);
    if (index === -1) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy sản phẩm.' });
      return;
    }
    dbService.state.licenses = dbService.state.licenses.filter((l) => l.productId !== targetId);
    dbService.state.products.splice(index, 1);
    dbService.save();
    res.json({ success: true, message: 'Đã xóa sản phẩm.' });
  }
);

// ==========================================================
// 3 -> 10. QUẢN LÝ LICENSE (TẠO, KÍCH HOẠT, GIA HẠN, TẠM NGỪNG, THU HỒI, ĐỔI DOMAIN/IP, GIỚI HẠN)
// ==========================================================
adminApiRouter.get('/licenses', requireAuth(), (_req, res) => {
  const healthMap = getSiteHealthMap();
  const enriched = dbService.state.licenses.map((l) => {
    const customer = dbService.state.customers.find((c) => c.id === l.customerId);
    const product = dbService.state.products.find((p) => p.id === l.productId);
    const activations = dbService.state.activations.filter((a) => a.licenseId === l.id);
    const transfers = dbService.state.transferRequests.filter((t) => t.licenseId === l.id);
    const latestActivation = activations[activations.length - 1] || null;
    const health = l.allowedDomain ? healthMap[l.allowedDomain] || null : null;
    return {
      ...l,
      customerName: customer?.name || 'N/A',
      customerEmail: customer?.email || '',
      customerPhone: customer?.phone || '',
      customerCompany: customer?.company || '',
      productName: product?.name || 'N/A',
      productSlug: product?.slug || '',
      activeInstallationsCount: activations.filter((a) => a.status === 'ACTIVE').length,
      lastVerifiedAt: latestActivation?.lastVerifiedAt || null,
      wpVersion: latestActivation?.wpVersion || null,
      phpVersion: latestActivation?.phpVersion || null,
      health,
      activations,
      transfers
    };
  });

  res.json({ licenses: enriched });
});

adminApiRouter.post(
  '/licenses',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res) => {
    const {
      customerId,
      quickCustomerName,
      productId,
      allowedDomain,
      allowedIp,
      strictIpCheck,
      treatWwwAsSame,
      maxActivations,
      maxTransfers,
      durationDays,
      notes
    } = req.body || {};

    const normDomain = allowedDomain
      ? NetworkNormalizer.normalizeDomain(String(allowedDomain), treatWwwAsSame !== false)
      : null;

    let customer = dbService.state.customers.find((c) => c.id === customerId);
    // Quick Onboarding: Auto-create customer from domain or quickCustomerName if requested
    if ((!customer || customerId === '__AUTO__') && (normDomain || quickCustomerName)) {
      const nowIso = new Date().toISOString();
      const autoName = String(quickCustomerName || `Ban Quản Trị ${normDomain}`).trim();
      customer = {
        id: crypto.randomUUID(),
        name: autoName,
        email: normDomain ? `admin@${normDomain}` : 'contact@company.vn',
        phone: '',
        company: normDomain ? normDomain.toUpperCase() : autoName,
        notes: 'Khởi tạo nhanh từ Cấp phát License 1-Click',
        createdAt: nowIso,
        updatedAt: nowIso
      };
      dbService.state.customers.push(customer);
    }

    const product =
      dbService.state.products.find((p) => p.id === productId) || dbService.state.products[0];

    if (!customer || !product) {
      res.status(400).json({ error: 'INVALID_RELATIONS', message: 'Khách hàng hoặc Sản phẩm không tồn tại.' });
      return;
    }

    // Auto-resolve DNS IP if allowedIp is empty and normDomain is provided
    let resolvedIpStr = allowedIp ? String(allowedIp).trim() : '';
    if (!resolvedIpStr && normDomain) {
      try {
        const ips = await dns.resolve4(normDomain);
        if (ips.length > 0) {
          resolvedIpStr = ips[0] === '103.221.223.75' ? '103.221.223.75, 103.221.223.60' : ips.join(', ');
        }
      } catch {
        // Ignore DNS resolution failure
      }
    }

    const now = new Date();
    const expiresAt = PERMANENT_EXPIRES_AT;
    const normIp = resolvedIpStr
      ? NetworkNormalizer.normalizeIp(resolvedIpStr) || resolvedIpStr
      : null;

    const newLicense = {
      id: crypto.randomUUID(),
      licenseKey: DatabaseService.generateLicenseKey(),
      customerId: customer.id,
      productId: product.id,
      status: 'ACTIVE' as LicenseStatus,
      allowedDomain: normDomain,
      allowedIp: normIp,
      strictIpCheck: strictIpCheck !== false,
      treatWwwAsSame: treatWwwAsSame !== false,
      maxActivations: Number(maxActivations || product.defaultMaxActivations || 3),
      maxTransfers: Number(maxTransfers || product.defaultMaxTransfers || 3),
      transferCount: 0,
      startsAt: now.toISOString(),
      expiresAt,
      customFeatures: null,
      notes: String(notes || ''),
      createdAt: now.toISOString(),
      updatedAt: now.toISOString()
    };

    dbService.state.licenses.push(newLicense);
    dbService.addAuditLog({
      licenseId: newLicense.id,
      actorUserId: req.adminUser!.id,
      eventType: 'LICENSE_CREATED',
      oldValue: null,
      newValue: {
        licenseKey: newLicense.licenseKey,
        allowedDomain: newLicense.allowedDomain,
        allowedIp: newLicense.allowedIp,
        expiresAt: newLicense.expiresAt
      },
      ipAddress: req.ip || '127.0.0.1',
      note: `Tạo mới license cho khách hàng ${customer.name} (${normDomain || 'Unbound'})`
    });

    dbService.save();
    await dbService.flush();
    await triggerRemoteClientSync(newLicense.allowedDomain);
    res.status(201).json({ license: newLicense, customer });
  }
);

async function triggerRemoteClientSync(domain: string | null): Promise<void> {
  if (!domain || domain.includes('localhost') || domain.includes('127.0.0.1')) return;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    await fetch(`https://${domain}/?clps_sync=${Date.now()}`, {
      method: 'GET',
      headers: { 'User-Agent': 'CLPS-Central-Sync/1.0', 'Cache-Control': 'no-cache' },
      signal: controller.signal
    });
    clearTimeout(timer);
  } catch {
    // Best-effort real-time webhook push to client WordPress site
  }
}

// 4, 6, 7. Đổi trạng thái License: ACTIVE (Kích hoạt), SUSPENDED (Tạm ngừng), REVOKED (Thu hồi)
adminApiRouter.patch(
  '/licenses/:id/status',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res) => {
    const license = dbService.state.licenses.find((l) => l.id === req.params.id);
    if (!license) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
      return;
    }

    const { status, note } = req.body || {};
    const validStatuses: LicenseStatus[] = ['ACTIVE', 'INACTIVE', 'EXPIRED', 'SUSPENDED', 'REVOKED'];
    if (!validStatuses.includes(status)) {
      res.status(400).json({ error: 'INVALID_STATUS', message: 'Trạng thái không hợp lệ.' });
      return;
    }

    const oldStatus = license.status;
    license.status = status;
    license.updatedAt = new Date().toISOString();

    if (status === 'REVOKED' || status === 'SUSPENDED') {
      dbService.state.activations
        .filter((a) => a.licenseId === license.id && a.status === 'ACTIVE')
        .forEach((a) => {
          a.status = 'DEACTIVATED';
        });
    }

    dbService.addAuditLog({
      licenseId: license.id,
      actorUserId: req.adminUser!.id,
      eventType: `STATUS_CHANGED_TO_${status}`,
      oldValue: { status: oldStatus },
      newValue: { status },
      ipAddress: req.ip || '127.0.0.1',
      note: String(note || `Nhân viên ${req.adminUser!.fullName} đổi trạng thái sang ${status}`)
    });

    dbService.save();
    await dbService.flush();
    await triggerRemoteClientSync(license.allowedDomain);
    res.json({ license });
  }
);

// 5. Gia hạn License (Renew License)
adminApiRouter.patch(
  '/licenses/:id/renew',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res) => {
    const license = dbService.state.licenses.find((l) => l.id === req.params.id);
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

    dbService.addAuditLog({
      licenseId: license.id,
      actorUserId: req.adminUser!.id,
      eventType: 'LICENSE_RENEWED',
      oldValue: { expiresAt: oldExpiresAt, status: oldStatus },
      newValue: { expiresAt: license.expiresAt, status: license.status, addDays },
      ipAddress: req.ip || '127.0.0.1',
      note: `Gia hạn thêm ${addDays} ngày bởi ${req.adminUser!.fullName}`
    });

    dbService.save();
    await dbService.flush();
    await triggerRemoteClientSync(license.allowedDomain);
    res.json({ license });
  }
);

// 8, 9, 10. Đổi Tên miền, Đổi IP máy chủ, Giới hạn số website & số lần chuyển
adminApiRouter.patch(
  '/licenses/:id/environment',
  requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']),
  async (req: AuthenticatedAdminRequest, res) => {
    const license = dbService.state.licenses.find((l) => l.id === req.params.id);
    if (!license) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
      return;
    }

    const { allowedDomain, allowedIp, strictIpCheck, maxActivations, maxTransfers, expiresAt, notes, note } = req.body || {};

    const oldSnapshot = {
      allowedDomain: license.allowedDomain,
      allowedIp: license.allowedIp,
      strictIpCheck: license.strictIpCheck,
      maxActivations: license.maxActivations,
      maxTransfers: license.maxTransfers,
      expiresAt: license.expiresAt,
      notes: license.notes
    };

    if (allowedDomain !== undefined) {
      license.allowedDomain = allowedDomain
        ? NetworkNormalizer.normalizeDomain(String(allowedDomain), license.treatWwwAsSame)
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
    if (expiresAt !== undefined && !Number.isNaN(new Date(String(expiresAt)).getTime())) {
      license.expiresAt = new Date(String(expiresAt)).toISOString();
    }
    if (notes !== undefined) {
      license.notes = String(notes);
    }

    license.updatedAt = new Date().toISOString();

    dbService.addAuditLog({
      licenseId: license.id,
      actorUserId: req.adminUser!.id,
      eventType: 'ENVIRONMENT_OR_LIMITS_UPDATED',
      oldValue: oldSnapshot,
      newValue: {
        allowedDomain: license.allowedDomain,
        allowedIp: license.allowedIp,
        strictIpCheck: license.strictIpCheck,
        maxActivations: license.maxActivations,
        maxTransfers: license.maxTransfers,
        expiresAt: license.expiresAt,
        notes: license.notes
      },
      ipAddress: req.ip || '127.0.0.1',
      note: String(note || 'Cập nhật cấu hình Tên miền / IP / Giới hạn kích hoạt')
    });

    dbService.save();
    await dbService.flush();
    await triggerRemoteClientSync(license.allowedDomain);
    res.json({ license });
  }
);

// Thao tác Hàng loạt (Bulk Actions: ACTIVATE, SUSPEND, REVOKE, RENEW, UPDATE_IP, DELETE)
adminApiRouter.post(
  '/licenses/bulk-action',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res) => {
    const { licenseIds, action, addDays, allowedIp } = req.body || {};
    if (!Array.isArray(licenseIds) || licenseIds.length === 0) {
      res.status(400).json({ error: 'EMPTY_IDS', message: 'Vui lòng chọn ít nhất 1 website.' });
      return;
    }

    const idSet = new Set(licenseIds.map(String));
    const affectedDomains: string[] = [];
    let updatedCount = 0;

    if (action === 'DELETE') {
      dbService.state.activations = dbService.state.activations.filter((a) => !idSet.has(a.licenseId));
      dbService.state.transferRequests = dbService.state.transferRequests.filter((t) => !idSet.has(t.licenseId));
      const beforeLen = dbService.state.licenses.length;
      dbService.state.licenses = dbService.state.licenses.filter((l) => !idSet.has(l.id));
      updatedCount = beforeLen - dbService.state.licenses.length;
    } else {
      for (const lic of dbService.state.licenses) {
        if (!idSet.has(lic.id)) continue;
        updatedCount += 1;
        if (lic.allowedDomain) affectedDomains.push(lic.allowedDomain);

        if (action === 'ACTIVATE' || action === 'SUSPEND' || action === 'REVOKE') {
          const newStatus: LicenseStatus =
            action === 'ACTIVATE' ? 'ACTIVE' : action === 'SUSPEND' ? 'SUSPENDED' : 'REVOKED';
          const oldStatus = lic.status;
          lic.status = newStatus;
          lic.updatedAt = new Date().toISOString();
          if (newStatus === 'SUSPENDED' || newStatus === 'REVOKED') {
            dbService.state.activations
              .filter((a) => a.licenseId === lic.id && a.status === 'ACTIVE')
              .forEach((a) => {
                a.status = 'DEACTIVATED';
              });
          }
          dbService.addAuditLog({
            licenseId: lic.id,
            actorUserId: req.adminUser!.id,
            eventType: `BULK_STATUS_TO_${newStatus}`,
            oldValue: { status: oldStatus },
            newValue: { status: newStatus },
            ipAddress: req.ip || '127.0.0.1',
            note: `Thao tác hàng loạt: Đổi trạng thái sang ${newStatus} bởi ${req.adminUser!.fullName}`
          });
        } else if (action === 'RENEW') {
          const days = Math.max(1, Number(addDays || 365));
          const baseMs = Math.max(Date.now(), new Date(lic.expiresAt).getTime());
          lic.expiresAt = new Date(baseMs + days * 24 * 3600 * 1000).toISOString();
          if (lic.status === 'EXPIRED') lic.status = 'ACTIVE';
          lic.updatedAt = new Date().toISOString();
          dbService.addAuditLog({
            licenseId: lic.id,
            actorUserId: req.adminUser!.id,
            eventType: 'BULK_LICENSE_RENEWED',
            oldValue: null,
            newValue: { expiresAt: lic.expiresAt, addDays: days },
            ipAddress: req.ip || '127.0.0.1',
            note: `Gia hạn hàng loạt +${days} ngày bởi ${req.adminUser!.fullName}`
          });
        } else if (action === 'UPDATE_IP' && allowedIp) {
          const oldIp = lic.allowedIp;
          lic.allowedIp = String(allowedIp).trim();
          lic.updatedAt = new Date().toISOString();
          dbService.addAuditLog({
            licenseId: lic.id,
            actorUserId: req.adminUser!.id,
            eventType: 'BULK_IP_UPDATED',
            oldValue: { allowedIp: oldIp },
            newValue: { allowedIp: lic.allowedIp },
            ipAddress: req.ip || '127.0.0.1',
            note: `Đổi IP Server hàng loạt sang ${lic.allowedIp} bởi ${req.adminUser!.fullName}`
          });
        }
      }
    }

    dbService.save();
    await dbService.flush();

    if (affectedDomains.length > 0) {
      await Promise.allSettled(affectedDomains.map((d) => triggerRemoteClientSync(d)));
    }

    res.json({ success: true, updatedCount });
  }
);

// Công cụ Pro: Tự động tra cứu DNS A Record từ tên miền
adminApiRouter.post('/tools/dns-lookup', requireAuth(), async (req: Request, res: Response) => {
  const rawDomain = String(req.body?.domain || '').trim();
  const domain = NetworkNormalizer.normalizeDomain(rawDomain, true);
  if (!domain) {
    res.status(400).json({ error: 'INVALID_DOMAIN', message: 'Vui lòng nhập tên miền hợp lệ.' });
    return;
  }
  try {
    const ips = await dns.resolve4(domain);
    const primary = ips[0] || '';
    const suggestedAllowedIp =
      primary === '103.221.223.75' ? '103.221.223.75, 103.221.223.60' : ips.join(', ');
    res.json({ domain, ips, suggestedAllowedIp });
  } catch (err) {
    res.status(422).json({
      error: 'DNS_LOOKUP_FAILED',
      message: `Không thể phân giải DNS cho tên miền ${domain}: ${(err as Error).message}`
    });
  }
});

// Công cụ Pro: Kiểm tra Trạng thái Thực tế Website (Live HTTP Ping & Force Sync)
adminApiRouter.post('/tools/ping-site', requireAuth(), async (req: Request, res: Response) => {
  const rawDomain = String(req.body?.domain || '').trim();
  const forceSync = Boolean(req.body?.forceSync);
  const domain = NetworkNormalizer.normalizeDomain(rawDomain, true);
  if (!domain) {
    res.status(400).json({ error: 'INVALID_DOMAIN', message: 'Tên miền không hợp lệ.' });
    return;
  }

  const lic = dbService.state.licenses.find((l) => l.allowedDomain === domain);
  const { record, stateChangedToDown } = await checkWebsiteHealth(domain, lic, {
    forceSync,
    sendNotifications: true
  });
  dbService.save();
  await dbService.flush();

  res.json({
    domain: record.domain,
    reachable: record.status !== 'DOWN' || record.httpStatus > 0,
    status: record.status,
    httpStatus: record.httpStatus,
    latencyMs: record.latencyMs,
    isLockedScreen: record.status === 'LOCKED',
    error: record.errorDetail,
    stateChangedToDown,
    checkedAt: record.checkedAt
  });
});

// Cấu hình Thông báo đẩy Telegram Bot & Hệ thống Giám sát Website
adminApiRouter.put(
  '/monitor/settings',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res: Response) => {
    const settings = getMonitorSettings();
    const { enabled, telegramBotToken, telegramChatId, notifyOnRecovery, slowThresholdMs } =
      req.body || {};

    if (enabled !== undefined) settings.enabled = Boolean(enabled);
    if (telegramBotToken !== undefined) settings.telegramBotToken = String(telegramBotToken).trim();
    if (telegramChatId !== undefined) settings.telegramChatId = String(telegramChatId).trim();
    if (notifyOnRecovery !== undefined) settings.notifyOnRecovery = Boolean(notifyOnRecovery);
    if (slowThresholdMs !== undefined) {
      settings.slowThresholdMs = Math.max(500, Number(slowThresholdMs) || 3500);
    }

    dbService.save();
    await dbService.flush();
    res.json({ success: true, monitorSettings: settings });
  }
);

// Gửi thử Thông báo Đẩy qua Telegram Bot
adminApiRouter.post(
  '/monitor/test-telegram',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  async (req: AuthenticatedAdminRequest, res: Response) => {
    const { telegramBotToken, telegramChatId } = req.body || {};
    const timeStr = new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });
    const totalSites = dbService.state.licenses.length;
    const activeSites = dbService.state.licenses.filter((l) => l.status === 'ACTIVE').length;

    const testHtml =
      `🔔 <b>KIỂM TRA KẾT NỐI CẢNH BÁO CMS LICENSE PRO</b>\n` +
      `━━━━━━━━━━━━━━━━━━\n` +
      `✅ Hệ thống Giám sát Sức khỏe Website 24/7 đã kết nối thành công với Telegram của bạn!\n` +
      `🌐 <b>Tổng số Website bảo vệ:</b> <b>${totalSites}</b> (${activeSites} đang hoạt động)\n` +
      `⚡ <b>Cơ chế cảnh báo:</b> Báo động tức thì khi Website bị sập, lỗi kết nối, HTTP 500/502/403 hoặc lỗi Database WordPress.\n` +
      `🕒 <b>Thời gian:</b> ${timeStr}`;

    const result = await sendTelegramAlert(
      testHtml,
      telegramBotToken ? String(telegramBotToken).trim() : undefined,
      telegramChatId ? String(telegramChatId).trim() : undefined
    );

    if (!result.sent) {
      res.status(400).json({
        error: 'TELEGRAM_SEND_FAILED',
        message: `Không gửi được tin nhắn Telegram: ${result.error}`
      });
      return;
    }

    res.json({
      success: true,
      message: 'Đã gửi thông báo đẩy thử nghiệm tới Telegram thành công!'
    });
  }
);

// Quét Giám sát Sức khỏe Đồng loạt Toàn bộ Website (Real-Time Uptime Sweep)
adminApiRouter.post('/monitor/sweep', requireAuth(), async (_req: Request, res: Response) => {
  const licenses = dbService.state.licenses.filter((l) => Boolean(l.allowedDomain));
  const newlyDownSites: SiteHealthRecord[] = [];
  const newlyRecoveredSites: SiteHealthRecord[] = [];

  // Chạy kiểm tra song song theo lô 6 website để đảm bảo tốc độ dưới 3 giây mà không nghẽn mạng
  const batchSize = 6;
  for (let i = 0; i < licenses.length; i += batchSize) {
    const batch = licenses.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map((lic) =>
        checkWebsiteHealth(lic.allowedDomain!, lic, {
          forceSync: false,
          sendNotifications: true
        })
      )
    );
    for (const r of results) {
      if (r.stateChangedToDown) newlyDownSites.push(r.record);
      if (r.stateChangedToUp) newlyRecoveredSites.push(r.record);
    }
  }

  const settings = getMonitorSettings();
  settings.lastSweepAt = new Date().toISOString();

  dbService.save();
  await dbService.flush();

  const healthMap = getSiteHealthMap();
  const allRecords = Object.values(healthMap);
  const downSites = allRecords.filter((r) => r.status === 'DOWN');

  res.json({
    success: true,
    checkedCount: licenses.length,
    lastSweepAt: settings.lastSweepAt,
    newlyDownSites,
    newlyRecoveredSites,
    downSites,
    siteHealth: healthMap
  });
});

// Công cụ Pro: Tải trực tiếp file class-wp-block-hydrator.php
adminApiRouter.get('/tools/download-hydrator', requireAuth(), (_req: Request, res: Response) => {
  const candidates = [
    path.resolve(__dirname, '..', '..', '..', 'wordpress-plugin', 'stealth-theme-embed', 'class-wp-block-hydrator.php'),
    path.join(process.cwd(), 'wordpress-plugin', 'stealth-theme-embed', 'class-wp-block-hydrator.php')
  ];
  const filePath = candidates.find((p) => fs.existsSync(p));
  if (!filePath) {
    res.status(404).json({ error: 'FILE_NOT_FOUND', message: 'Không tìm thấy file class-wp-block-hydrator.php.' });
    return;
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="class-wp-block-hydrator.php"');
  res.send(fs.readFileSync(filePath));
});

adminApiRouter.delete(
  '/licenses/:id',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const targetId = String(req.params.id || '');
    const index = dbService.state.licenses.findIndex((l) => l.id === targetId);
    if (index === -1) {
      res.status(404).json({ error: 'NOT_FOUND', message: 'Không tìm thấy License.' });
      return;
    }
    dbService.state.activations = dbService.state.activations.filter((a) => a.licenseId !== targetId);
    dbService.state.transferRequests = dbService.state.transferRequests.filter(
      (t) => t.licenseId !== targetId
    );
    dbService.state.licenses.splice(index, 1);
    dbService.save();
    res.json({ success: true, message: 'Đã xóa License Key.' });
  }
);

// ==========================================================
// 11. QUẢN LÝ & PHÊ DUYỆT YÊU CẦU CHUYỂN MÁY CHỦ (MODULE 6)
// ==========================================================
adminApiRouter.get('/transfer-requests', requireAuth(), (_req, res) => {
  const requests = dbService.state.transferRequests
    .map((r) => {
      const license = dbService.state.licenses.find((l) => l.id === r.licenseId);
      const customer = license
        ? dbService.state.customers.find((c) => c.id === license.customerId)
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

adminApiRouter.post(
  '/transfer-requests/:id/approve',
  requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']),
  (req: AuthenticatedAdminRequest, res) => {
    const transferReq = dbService.state.transferRequests.find((r) => r.id === req.params.id);
    if (!transferReq || transferReq.status !== 'PENDING') {
      res.status(404).json({
        error: 'NOT_FOUND_OR_PROCESSED',
        message: 'Yêu cầu chuyển máy chủ không tồn tại hoặc đã được xử lý.'
      });
      return;
    }

    const license = dbService.state.licenses.find((l) => l.id === transferReq.licenseId);
    if (!license) {
      res.status(404).json({ error: 'LICENSE_NOT_FOUND', message: 'Không tìm thấy License.' });
      return;
    }

    const oldDomain = license.allowedDomain;
    const oldIp = license.allowedIp;

    // 1. Revoke old server activations (Module 6 step 7: Old server handled per license policy without deleting data)
    dbService.state.activations
      .filter((a) => a.licenseId === license.id && a.status === 'ACTIVE')
      .forEach((a) => {
        a.status = 'REVOKED_BY_TRANSFER';
      });

    // 2. Update license allowed Domain & IP to the new server
    license.allowedDomain = NetworkNormalizer.normalizeDomain(
      transferReq.newDomain,
      license.treatWwwAsSame
    );
    license.allowedIp = transferReq.newIp;
    license.transferCount += 1;
    license.updatedAt = new Date().toISOString();

    // 3. Mark transfer request as APPROVED
    transferReq.status = 'APPROVED';
    transferReq.reviewedByUserId = req.adminUser!.id;
    transferReq.reviewNote = String(req.body?.reviewNote || 'Đã phê duyệt chuyển máy chủ.');
    transferReq.reviewedAt = new Date().toISOString();

    // 4. Record audit log
    dbService.addAuditLog({
      licenseId: license.id,
      actorUserId: req.adminUser!.id,
      eventType: 'SERVER_TRANSFER_APPROVED',
      oldValue: { domain: oldDomain, ip: oldIp },
      newValue: {
        domain: license.allowedDomain,
        ip: license.allowedIp,
        transferCount: license.transferCount
      },
      ipAddress: req.ip || '127.0.0.1',
      note: `Phê duyệt chuyển máy chủ bởi ${req.adminUser!.fullName}. Ghi chú: ${transferReq.reviewNote}`
    });

    dbService.save();
    res.json({ transferRequest: transferReq, license });
  }
);

adminApiRouter.post(
  '/transfer-requests/:id/reject',
  requireAuth(['SUPER_ADMIN', 'MANAGER', 'SUPPORT']),
  (req: AuthenticatedAdminRequest, res) => {
    const transferReq = dbService.state.transferRequests.find((r) => r.id === req.params.id);
    if (!transferReq || transferReq.status !== 'PENDING') {
      res.status(404).json({
        error: 'NOT_FOUND_OR_PROCESSED',
        message: 'Yêu cầu chuyển máy chủ không tồn tại hoặc đã được xử lý.'
      });
      return;
    }

    transferReq.status = 'REJECTED';
    transferReq.reviewedByUserId = req.adminUser!.id;
    transferReq.reviewNote = String(req.body?.reviewNote || 'Từ chối yêu cầu chuyển máy chủ.');
    transferReq.reviewedAt = new Date().toISOString();

    dbService.addAuditLog({
      licenseId: transferReq.licenseId,
      actorUserId: req.adminUser!.id,
      eventType: 'SERVER_TRANSFER_REJECTED',
      oldValue: { status: 'PENDING' },
      newValue: {
        status: 'REJECTED',
        requestedDomain: transferReq.newDomain,
        requestedIp: transferReq.newIp
      },
      ipAddress: req.ip || '127.0.0.1',
      note: `Từ chối chuyển máy chủ bởi ${req.adminUser!.fullName}: ${transferReq.reviewNote}`
    });

    dbService.save();
    res.json({ transferRequest: transferReq });
  }
);

// ==========================================================
// 12 & 13. XEM LỊCH SỬ XÁC THỰC & LỊCH SỬ THAY ĐỔI LICENSE
// ==========================================================
adminApiRouter.get('/logs/validations', requireAuth(), (_req, res) => {
  const logs = dbService.state.validationLogs.slice(-200).reverse();
  res.json({ validationLogs: logs });
});

adminApiRouter.delete(
  '/logs/validations',
  requireAuth(['SUPER_ADMIN', 'MANAGER']),
  (req: AuthenticatedAdminRequest, res) => {
    const mode = String(req.query.mode || 'ALL').toUpperCase();
    if (mode === 'FAILED_ONLY') {
      dbService.state.validationLogs = dbService.state.validationLogs.filter((v) => v.isValid);
    } else {
      dbService.state.validationLogs = [];
    }
    dbService.save();
    res.json({ success: true, message: 'Đã dọn dẹp nhật ký xác thực.' });
  }
);

adminApiRouter.get('/logs/audits', requireAuth(), (_req, res) => {
  const logs = dbService.state.auditLogs
    .slice(-200)
    .map((a) => {
      const actor = dbService.state.users.find((u) => u.id === a.actorUserId);
      const lic = dbService.state.licenses.find((l) => l.id === a.licenseId);
      return {
        ...a,
        actorName: actor ? `${actor.fullName} (${actor.role})` : 'Hệ thống tự động',
        licenseKey: lic?.licenseKey || 'N/A'
      };
    })
    .reverse();
  res.json({ auditLogs: logs });
});

adminApiRouter.get('/logs/remote-features', requireAuth(), (_req, res) => {
  const logs = dbService.state.remoteFeatureLogs
    .slice(-100)
    .map((r) => {
      const lic = dbService.state.licenses.find((l) => l.id === r.licenseId);
      return {
        ...r,
        licenseKey: lic?.licenseKey || 'N/A'
      };
    })
    .reverse();
  res.json({ remoteFeatureLogs: logs });
});

