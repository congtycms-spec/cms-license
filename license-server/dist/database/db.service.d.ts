export type StaffRole = 'SUPER_ADMIN' | 'MANAGER' | 'SUPPORT';
export type LicenseStatus = 'ACTIVE' | 'INACTIVE' | 'EXPIRED' | 'SUSPENDED' | 'REVOKED';
export type ActivationStatus = 'ACTIVE' | 'DEACTIVATED' | 'REVOKED_BY_TRANSFER';
export type TransferRequestStatus = 'PENDING' | 'APPROVED' | 'REJECTED';
export type ValidationAction = 'ACTIVATE' | 'VERIFY' | 'DEACTIVATE' | 'REMOTE_FEATURE' | 'TRANSFER_REQ';
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
}
export declare class DatabaseService {
    private dbFilePath;
    private pgPool;
    private pgInitialized;
    private pendingSyncPromise;
    state: DatabaseState;
    constructor();
    private initPostgresPoolIfNeeded;
    isCloudDatabaseEnabled(): boolean;
    /**
     * Ensures state is loaded from Supabase PostgreSQL before handling a request on Vercel Serverless.
     * Automatically creates table `clps_cloud_store` and seeds initial local data if empty.
     */
    ensureLoaded(): Promise<void>;
    /**
     * Flushes any pending asynchronous Supabase write before serverless function returns.
     */
    flush(): Promise<void>;
    static hashPassword(password: string): string;
    static verifyPassword(password: string, storedHash: string): boolean;
    static generateLicenseKey(): string;
    private loadOrSeed;
    initEmptyState(): void;
    save(): void;
    seedInitialData(): void;
    addValidationLog(entry: Omit<ValidationLogRecord, 'id' | 'createdAt'>): ValidationLogRecord;
    addAuditLog(entry: Omit<LicenseAuditLogRecord, 'id' | 'createdAt'>): LicenseAuditLogRecord;
    addRemoteFeatureLog(entry: Omit<RemoteFeatureUsageLogRecord, 'id' | 'createdAt'>): RemoteFeatureUsageLogRecord;
}
export declare const dbService: DatabaseService;
