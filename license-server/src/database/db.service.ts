import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Pool } from 'pg';

export type StaffRole = 'SUPER_ADMIN' | 'MANAGER' | 'SUPPORT';
export type LicenseStatus = 'ACTIVE' | 'INACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
export type ActivationStatus = 'ACTIVE' | 'DEACTIVATED' | 'REVOKED_BY_TRANSFER';
export type TransferRequestStatus = 'PENDING' | 'APPROVED' | 'REJECTED';
export type ValidationAction =
  | 'ACTIVATE'
  | 'VERIFY'
  | 'DEACTIVATE'
  | 'REMOTE_FEATURE'
  | 'TRANSFER_REQ';

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  fullName: string;
  role: StaffRole;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CustomerRecord {
  id: string;
  name: string;
  email: string;
  phone: string;
  company: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProductRecord {
  id: string;
  slug: string;
  name: string;
  currentVersion: string;
  commercialFeatures: string[];
  defaultMaxActivations: number;
  defaultMaxTransfers: number;
  gracePeriodHours: number;
  downloadUrl: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LicenseRecord {
  id: string;
  licenseKey: string;
  customerId: string;
  productId: string;
  status: LicenseStatus;
  allowedDomain: string | null;
  allowedIp: string | null;
  strictIpCheck: boolean;
  treatWwwAsSame: boolean;
  maxActivations: number;
  maxTransfers: number;
  transferCount: number;
  startsAt: string;
  expiresAt: string;
  customFeatures: string[] | null;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface LicenseActivationRecord {
  id: string;
  licenseId: string;
  activationToken: string;
  domain: string;
  serverIp: string;
  wpVersion: string;
  phpVersion: string;
  pluginVersion: string;
  status: ActivationStatus;
  activatedAt: string;
  lastVerifiedAt: string;
}

export interface ServerTransferRequestRecord {
  id: string;
  licenseId: string;
  oldDomain: string | null;
  oldIp: string | null;
  newDomain: string;
  newIp: string;
  reason: string;
  status: TransferRequestStatus;
  reviewedByUserId: string | null;
  reviewNote: string | null;
  createdAt: string;
  reviewedAt: string | null;
}

export interface ValidationLogRecord {
  id: number;
  licenseId: string | null;
  licenseKeyAttempt: string;
  requestDomain: string;
  detectedOutboundIp: string;
  reportedServerIp: string | null;
  action: ValidationAction;
  isValid: boolean;
  failureReason: string | null;
  userAgent: string;
  createdAt: string;
}

export interface LicenseAuditLogRecord {
  id: number;
  licenseId: string;
  actorUserId: string | null;
  eventType: string;
  oldValue: Record<string, unknown> | null;
  newValue: Record<string, unknown> | null;
  ipAddress: string;
  note: string;
  createdAt: string;
}

export interface RemoteFeatureUsageLogRecord {
  id: number;
  licenseId: string;
  featureCode: string;
  executionMs: number;
  status: 'SUCCESS' | 'DENIED' | 'QUOTA_EXCEEDED';
  createdAt: string;
}

export interface MonitorSettingsRecord {
  enabled: boolean;
  telegramBotToken: string;
  telegramChatId: string;
  notifyOnRecovery: boolean;
  slowThresholdMs: number;
  lastSweepAt: string | null;
}

export interface SiteHealthRecord {
  domain: string;
  status: 'UP' | 'DOWN' | 'LOCKED' | 'SLOW';
  httpStatus: number;
  latencyMs: number;
  errorDetail: string | null;
  checkedAt: string;
  lastIncidentAt: string | null;
  lastAlertedState?: 'UP' | 'DOWN' | 'SLOW';
}

export interface DatabaseState {
  users: UserRecord[];
  customers: CustomerRecord[];
  products: ProductRecord[];
  licenses: LicenseRecord[];
  activations: LicenseActivationRecord[];
  transferRequests: ServerTransferRequestRecord[];
  validationLogs: ValidationLogRecord[];
  auditLogs: LicenseAuditLogRecord[];
  remoteFeatureLogs: RemoteFeatureUsageLogRecord[];
  monitorSettings?: MonitorSettingsRecord;
  siteHealth?: Record<string, SiteHealthRecord>;
}

export class DatabaseService {
  private dbFilePath: string;
  private pgPool: Pool | null = null;
  private pgInitialized = false;
  private pendingSyncPromise: Promise<void> | null = null;
  public state!: DatabaseState;

  constructor() {
    const dataCandidates = [
      path.resolve(__dirname, '..', '..', 'data'),
      path.join(process.cwd(), 'license-server', 'data'),
      path.join(process.cwd(), 'data')
    ];
    const dataDir = dataCandidates.find((d) => fs.existsSync(d)) || dataCandidates[0];
    this.dbFilePath = path.join(dataDir, 'license-db.json');
    this.loadOrSeed();
    this.initPostgresPoolIfNeeded();
  }

  private initPostgresPoolIfNeeded(): void {
    const rawUrl = (
      process.env.DATABASE_URL ||
      process.env.POSTGRES_URL ||
      process.env.POSTGRES_PRISMA_URL ||
      process.env.POSTGRES_URL_NON_POOLING ||
      process.env.SUPABASE_DB_URL ||
      ''
    ).trim();
    const isPlaceHolder = rawUrl.includes('postgres:postgres@localhost:5432');
    if (!rawUrl || (isPlaceHolder && process.env.USE_POSTGRES !== 'true')) {
      return;
    }

    const dbUrl = rawUrl
      .replace(/([?&])sslmode=require(&?)/gi, (_m, p1, p2) => (p2 ? p1 : ''))
      .replace(/[?&]$/, '');

    this.pgPool = new Pool({
      connectionString: dbUrl,
      ssl: dbUrl.includes('localhost') || dbUrl.includes('127.0.0.1')
        ? false
        : { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 8000
    });
  }

  public isCloudDatabaseEnabled(): boolean {
    return this.pgPool !== null;
  }

  /**
   * Ensures state is loaded from Supabase PostgreSQL before handling a request on Vercel Serverless.
   * Automatically creates table `clps_cloud_store` and seeds initial local data if empty.
   */
  public async ensureLoaded(): Promise<void> {
    if (!this.pgPool) {
      return;
    }

    try {
      if (!this.pgInitialized) {
        await this.pgPool.query(`
          CREATE TABLE IF NOT EXISTS clps_cloud_store (
            store_key VARCHAR(64) PRIMARY KEY,
            state_json JSONB NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          );
        `);
        this.pgInitialized = true;
      }

      // Wait for any in-flight save before reading
      if (this.pendingSyncPromise) {
        await this.pendingSyncPromise;
      }

      const res = await this.pgPool.query(
        `SELECT state_json FROM clps_cloud_store WHERE store_key = 'primary' LIMIT 1`
      );

      if (res.rows.length > 0 && res.rows[0].state_json) {
        this.state = res.rows[0].state_json as DatabaseState;
      } else {
        // First time connecting to Supabase: push current state (e.g. gofresh.vn) into Supabase
        await this.pgPool.query(
          `INSERT INTO clps_cloud_store (store_key, state_json, updated_at)
           VALUES ('primary', $1::jsonb, NOW())
           ON CONFLICT (store_key) DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = NOW()`,
          [JSON.stringify(this.state)]
        );
      }
    } catch (err) {
      console.error('[Supabase Sync Warning] Falling back to in-memory/local state:', (err as Error).message);
    }
  }

  /**
   * Flushes any pending asynchronous Supabase write before serverless function returns.
   */
  public async flush(): Promise<void> {
    if (this.pendingSyncPromise) {
      try {
        await this.pendingSyncPromise;
      } catch (err) {
        console.error('[Supabase Flush Error]:', (err as Error).message);
      }
    }
  }

  public static hashPassword(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derived}`;
  }

  public static verifyPassword(password: string, storedHash: string): boolean {
    if (!storedHash) return false;
    if (storedHash.includes(':')) {
      const [salt, keyHex] = storedHash.split(':');
      const computed = crypto.scryptSync(password, salt, 64).toString('hex');
      const a = Buffer.from(computed, 'utf8');
      const b = Buffer.from(keyHex || '', 'utf8');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    // Backward compatibility with legacy hash format
    const legacyComputed = crypto.scryptSync(password, 'clps_salt_v1', 32).toString('hex');
    const a = Buffer.from(legacyComputed, 'utf8');
    const b = Buffer.from(storedHash, 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  public static generateLicenseKey(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const segment = () =>
      Array.from({ length: 4 }, () => chars[crypto.randomInt(0, chars.length)]).join('');
    return `CLPS-${segment()}-${segment()}-${segment()}-${segment()}`;
  }

  private loadOrSeed(): void {
    try {
      if (fs.existsSync(this.dbFilePath)) {
        this.state = JSON.parse(fs.readFileSync(this.dbFilePath, 'utf8'));
        return;
      }
    } catch {
      // Fallback to empty state if corrupted or read-only
    }
    this.initEmptyState();
  }

  public initEmptyState(): void {
    this.state = {
      users: [],
      customers: [],
      products: [],
      licenses: [],
      activations: [],
      transferRequests: [],
      validationLogs: [],
      auditLogs: [],
      remoteFeatureLogs: []
    };
    this.save();
  }

  public save(): void {
    // 1. Write to local JSON if filesystem is writable (Local XAMPP development)
    try {
      fs.mkdirSync(path.dirname(this.dbFilePath), { recursive: true });
      fs.writeFileSync(this.dbFilePath, JSON.stringify(this.state, null, 2), 'utf8');
    } catch {
      // Ignore read-only filesystem errors on Vercel Serverless
    }

    // 2. Sync to Supabase PostgreSQL if configured
    if (this.pgPool) {
      const snapshot = JSON.stringify(this.state);
      this.pendingSyncPromise = this.pgPool
        .query(
          `INSERT INTO clps_cloud_store (store_key, state_json, updated_at)
           VALUES ('primary', $1::jsonb, NOW())
           ON CONFLICT (store_key) DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = NOW()`,
          [snapshot]
        )
        .then(() => {
          this.pendingSyncPromise = null;
        })
        .catch((err) => {
          console.error('[Supabase Save Error]:', (err as Error).message);
          this.pendingSyncPromise = null;
        });
    }
  }

  public seedInitialData(): void {
    const now = new Date();
    const oneYearLater = new Date(now.getTime() + 365 * 24 * 3600 * 1000).toISOString();
    const tenDaysLater = new Date(now.getTime() + 10 * 24 * 3600 * 1000).toISOString();
    const fiveDaysAgo = new Date(now.getTime() - 5 * 24 * 3600 * 1000).toISOString();

    const adminId = '11111111-1111-4111-8111-111111111111';
    const managerId = '22222222-2222-4222-8222-222222222222';
    const supportId = '33333333-3333-4333-8333-333333333333';

    const cust1Id = 'c1111111-1111-4111-8111-111111111111';
    const cust2Id = 'c2222222-2222-4222-8222-222222222222';
    const cust3Id = 'c3333333-3333-4333-8333-333333333333';

    const prod1Id = 'b1111111-1111-4111-8111-111111111111';
    const prod2Id = 'b2222222-2222-4222-8222-222222222222';

    const lic1Id = 'a1111111-1111-4111-8111-111111111111';
    const lic2Id = 'a2222222-2222-4222-8222-222222222222';
    const lic3Id = 'a3333333-3333-4333-8333-333333333333';

    this.state = {
      users: [],
      customers: [
        {
          id: cust1Id,
          name: 'Nguyễn Văn An',
          email: 'an.nguyen@noithathoangall.vn',
          phone: '0901234567',
          company: 'Công ty TNHH Nội Thất Hoàng Gia',
          notes: 'Khách hàng gói Enterprise E-Commerce bàn giao tháng 10',
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        },
        {
          id: cust2Id,
          name: 'Trần Thị Bích Ngọc',
          email: 'ngoc.tran@bdsdongnama.vn',
          phone: '0912345678',
          company: 'Tập đoàn BĐS Đông Nam Á',
          notes: 'Website Sàn Giao Dịch BĐS + Công cụ tính lãi suất vay',
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        },
        {
          id: cust3Id,
          name: 'Lê Minh Tuấn',
          email: 'tuan.le@fashionviet.vn',
          phone: '0987654321',
          company: 'Thương hiệu Thời trang FashionViet',
          notes: 'License đã hết hạn, đang chờ thanh toán gia hạn năm 2',
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        }
      ],
      products: [
        {
          id: prod1Id,
          slug: 'wp-commerce-pro-suite',
          name: 'WP Commerce Pro Suite (Website Bán Hàng Cao Cấp)',
          currentVersion: '2.4.0',
          commercialFeatures: [
            'dynamic_pricing_engine',
            'advanced_analytics_report',
            'smart_inventory_forecast',
            'vip_invoice_generator'
          ],
          defaultMaxActivations: 1,
          defaultMaxTransfers: 3,
          gracePeriodHours: 72,
          downloadUrl: 'https://releases.company.vn/wp-commerce-pro-suite-2.4.0.zip',
          isActive: true,
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        },
        {
          id: prod2Id,
          slug: 'wp-realestate-enterprise',
          name: 'WP RealEstate Enterprise (Hệ thống Sàn BĐS)',
          currentVersion: '1.8.2',
          commercialFeatures: [
            'mortgage_amortization_engine',
            'project_roi_valuation',
            'crm_lead_scoring'
          ],
          defaultMaxActivations: 1,
          defaultMaxTransfers: 2,
          gracePeriodHours: 72,
          downloadUrl: 'https://releases.company.vn/wp-realestate-enterprise-1.8.2.zip',
          isActive: true,
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        }
      ],
      licenses: [
        {
          id: lic1Id,
          licenseKey: 'CLPS-PRO1-2026-8888-9999',
          customerId: cust1Id,
          productId: prod1Id,
          status: 'ACTIVE',
          allowedDomain: 'noithathoanggia.vn',
          allowedIp: '103.56.158.10',
          strictIpCheck: true,
          treatWwwAsSame: true,
          maxActivations: 1,
          maxTransfers: 3,
          transferCount: 0,
          startsAt: now.toISOString(),
          expiresAt: oneYearLater,
          customFeatures: null,
          notes: 'License chính thức chạy trên VPS 103.56.158.10',
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        },
        {
          id: lic2Id,
          licenseKey: 'CLPS-RE26-7777-6666-5555',
          customerId: cust2Id,
          productId: prod2Id,
          status: 'ACTIVE',
          allowedDomain: 'bdsdongnama.vn',
          allowedIp: '127.0.0.1',
          strictIpCheck: true,
          treatWwwAsSame: true,
          maxActivations: 2,
          maxTransfers: 2,
          transferCount: 0,
          startsAt: now.toISOString(),
          expiresAt: tenDaysLater, // Sắp hết hạn trong 10 ngày (để hiển thị cảnh báo trên Dashboard)
          customFeatures: null,
          notes: 'License sắp hết hạn trong 10 ngày tới',
          createdAt: now.toISOString(),
          updatedAt: now.toISOString()
        },
        {
          id: lic3Id,
          licenseKey: 'CLPS-EXP0-2025-1111-2222',
          customerId: cust3Id,
          productId: prod1Id,
          status: 'EXPIRED',
          allowedDomain: 'fashionviet.vn',
          allowedIp: '203.113.152.20',
          strictIpCheck: true,
          treatWwwAsSame: true,
          maxActivations: 1,
          maxTransfers: 3,
          transferCount: 1,
          startsAt: fiveDaysAgo,
          expiresAt: fiveDaysAgo,
          customFeatures: null,
          notes: 'License đã quá hạn 5 ngày',
          createdAt: fiveDaysAgo,
          updatedAt: now.toISOString()
        }
      ],
      activations: [],
      transferRequests: [],
      validationLogs: [],
      auditLogs: [
        {
          id: 1,
          licenseId: lic1Id,
          actorUserId: adminId,
          eventType: 'LICENSE_CREATED',
          oldValue: null,
          newValue: {
            licenseKey: 'CLPS-PRO1-2026-8888-9999',
            domain: 'noithathoanggia.vn',
            ip: '103.56.158.10'
          },
          ipAddress: '127.0.0.1',
          note: 'Khởi tạo license bàn giao cho Công ty TNHH Nội Thất Hoàng Gia',
          createdAt: now.toISOString()
        }
      ],
      remoteFeatureLogs: []
    };

    this.save();
  }

  public addValidationLog(
    entry: Omit<ValidationLogRecord, 'id' | 'createdAt'>
  ): ValidationLogRecord {
    const nextId =
      this.state.validationLogs.length > 0
        ? this.state.validationLogs[this.state.validationLogs.length - 1].id + 1
        : 1;
    const record: ValidationLogRecord = {
      ...entry,
      id: nextId,
      createdAt: new Date().toISOString()
    };
    this.state.validationLogs.push(record);
    if (this.state.validationLogs.length > 2000) {
      this.state.validationLogs.shift();
    }
    this.save();
    return record;
  }

  public addAuditLog(entry: Omit<LicenseAuditLogRecord, 'id' | 'createdAt'>): LicenseAuditLogRecord {
    const nextId =
      this.state.auditLogs.length > 0
        ? this.state.auditLogs[this.state.auditLogs.length - 1].id + 1
        : 1;
    const record: LicenseAuditLogRecord = {
      ...entry,
      id: nextId,
      createdAt: new Date().toISOString()
    };
    this.state.auditLogs.push(record);
    this.save();
    return record;
  }

  public addRemoteFeatureLog(
    entry: Omit<RemoteFeatureUsageLogRecord, 'id' | 'createdAt'>
  ): RemoteFeatureUsageLogRecord {
    const nextId =
      this.state.remoteFeatureLogs.length > 0
        ? this.state.remoteFeatureLogs[this.state.remoteFeatureLogs.length - 1].id + 1
        : 1;
    const record: RemoteFeatureUsageLogRecord = {
      ...entry,
      id: nextId,
      createdAt: new Date().toISOString()
    };
    this.state.remoteFeatureLogs.push(record);
    this.save();
    return record;
  }
}

export const dbService = new DatabaseService();

