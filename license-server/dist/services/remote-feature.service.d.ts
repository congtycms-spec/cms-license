export interface RemoteFeatureRequest {
    licenseKey: string;
    activationToken: string;
    domain: string;
    detectedOutboundIp: string;
    reportedServerIp?: string;
    timestamp: string;
    hmacSignature: string;
    featureCode: string;
    rawBody: string;
    payload: Record<string, unknown>;
}
/**
 * MODULE 7: Remote Commercial Features Engine (Giữ các chức năng cốt lõi trên Server công ty).
 * - Protects proprietary algorithms and commercial features by executing them exclusively on Company Server.
 * - Enforces Data Minimization: Processes only anonymous numerical/structural inputs in-memory; never stores customer PII.
 */
export declare class RemoteFeatureService {
    static readonly DATA_PRIVACY_POLICY: {
        principle: string;
        allowedData: string[];
        prohibitedData: string[];
        retentionPolicy: string;
        customerControl: string;
    };
    executeFeature(req: RemoteFeatureRequest): {
        httpStatus: number;
        body: Record<string, unknown>;
    };
    private logUsage;
    private runProprietaryAlgorithm;
}
export declare const remoteFeatureService: RemoteFeatureService;
