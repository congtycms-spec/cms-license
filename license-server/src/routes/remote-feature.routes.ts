import { Router, Request, Response } from 'express';
import { remoteFeatureService, RemoteFeatureService } from '../services/remote-feature.service';
import { NetworkNormalizer } from '../utils/network-normalizer';

export const remoteFeatureRouter = Router();

/**
 * GET /api/v1/remote-features/catalog
 * Returns the catalog of Server-Side Commercial Features (Module 7) and Data Privacy Policy.
 */
remoteFeatureRouter.get('/catalog', (_req: Request, res: Response) => {
  res.json({
    module: 'MODULE_7_REMOTE_COMMERCIAL_CORE_ENGINE',
    data_privacy_policy: RemoteFeatureService.DATA_PRIVACY_POLICY,
    available_features: [
      {
        code: 'dynamic_pricing_engine',
        name: 'Thuật toán Định giá Động & Chiết khấu B2B (Dynamic Pricing Engine)',
        description:
          'Tính toán chiết khấu đa tầng theo hạng thành viên, số lượng sỉ và mùa cao điểm ngay trên máy chủ công ty.'
      },
      {
        code: 'advanced_analytics_report',
        name: 'Báo cáo Dự báo Doanh thu AI (Advanced Revenue Forecast)',
        description:
          'Phân tích tốc độ tăng trưởng trung bình và dự báo doanh thu 3 tháng tiếp theo từ chuỗi dữ liệu ẩn danh.'
      },
      {
        code: 'mortgage_amortization_engine',
        name: 'Engine Tính Lịch Trả Nợ & Lãi Suất BĐS (Mortgage Amortization Engine)',
        description:
          'Thuật toán tài chính tính lịch trả góp niên kim, tách gốc/lãi cho các sàn giao dịch bất động sản.'
      }
    ]
  });
});

/**
 * POST /api/v1/remote-features/:featureCode/execute
 * Executes a proprietary commercial feature on the Central License Server after full verification.
 * Headers required:
 *   X-License-Key: CLPS-XXXX-...
 *   X-Activation-Token: act_...
 *   X-Client-Domain: noithathoanggia.vn
 *   X-Request-Timestamp: 1761724200
 *   X-Request-Signature: <HMAC-SHA256(timestamp.featureCode.rawBody, activation_token)>
 */
remoteFeatureRouter.post('/:featureCode/execute', (req: Request, res: Response) => {
  const featureCode = String(req.params.featureCode || '');
  const licenseKey = String(req.headers['x-license-key'] || '');
  const activationToken = String(req.headers['x-activation-token'] || '');
  const domain = String(req.headers['x-client-domain'] || req.body?.domain || '');
  const timestamp = String(req.headers['x-request-timestamp'] || '');
  const hmacSignature = String(req.headers['x-request-signature'] || '');
  const reportedServerIp = String(req.headers['x-reported-server-ip'] || '');

  if (!licenseKey || !activationToken || !domain || !timestamp || !hmacSignature) {
    res.status(401).json({
      success: false,
      error_code: 'MISSING_AUTH_HEADERS',
      message:
        'Thiếu thông tin xác thực bắt buộc (X-License-Key, X-Activation-Token, X-Client-Domain, X-Request-Timestamp, X-Request-Signature).'
    });
    return;
  }

  const payload = (req.body && typeof req.body === 'object' ? req.body : {}) as Record<
    string,
    unknown
  >;
  const rawBody = JSON.stringify(payload);
  const detectedOutboundIp = NetworkNormalizer.extractTrustedClientServerIp(req);

  const result = remoteFeatureService.executeFeature({
    licenseKey,
    activationToken,
    domain,
    detectedOutboundIp,
    reportedServerIp: reportedServerIp || undefined,
    timestamp,
    hmacSignature,
    featureCode,
    rawBody,
    payload
  });

  res.status(result.httpStatus).json(result.body);
});

