import { dbService } from '../database/db.service';
import { ed25519Service } from '../crypto/ed25519.service';
import { NetworkNormalizer } from '../utils/network-normalizer';

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
export class RemoteFeatureService {
  public static readonly DATA_PRIVACY_POLICY = {
    principle: 'DATA_MINIMIZATION_AND_ZERO_PII_RETENTION',
    allowedData: [
      'Mã định danh phân loại sản phẩm / thông số đơn hàng ẩn danh (số lượng, đơn giá, nhóm khách)',
      'Chuỗi số liệu thống kê tổng hợp theo ngày/tháng để dự báo doanh thu',
      'Thông số khoản vay / giá trị bất động sản / lãi suất để tính lịch trả nợ & ROI'
    ],
    prohibitedData: [
      'Họ tên, số điện thoại, email, địa chỉ nhà riêng, CCCD của khách mua hàng cuối (End-User PII)',
      'Mật khẩu, thông tin thẻ tín dụng hoặc dữ liệu nhạy cảm của người dùng WordPress'
    ],
    retentionPolicy:
      'In-Memory Execution Only (0 giây lưu trữ payload nghiệp vụ trên ổ cứng). Chỉ ghi log metadata (license_id, feature_code, execution_ms, status) phục vụ kiểm toán.',
    customerControl:
      'Khách hàng có toàn quyền bật/tắt kết nối tính năng từ xa trong trang cấu hình WordPress Plugin.'
  };

  public executeFeature(req: RemoteFeatureRequest): {
    httpStatus: number;
    body: Record<string, unknown>;
  } {
    const startTime = Date.now();

    const license = dbService.state.licenses.find(
      (l) => l.licenseKey.toUpperCase() === req.licenseKey.trim().toUpperCase()
    );

    if (!license) {
      return {
        httpStatus: 404,
        body: {
          success: false,
          error_code: 'INVALID_LICENSE',
          message: 'License Key không tồn tại.'
        }
      };
    }

    // 1. Check License Status & Expiration
    if (new Date(license.expiresAt).getTime() < Date.now() && license.status === 'ACTIVE') {
      license.status = 'EXPIRED';
      dbService.save();
    }

    if (license.status !== 'ACTIVE') {
      this.logUsage(license.id, req.featureCode, startTime, 'DENIED');
      return {
        httpStatus: 403,
        body: {
          success: false,
          error_code: `LICENSE_${license.status}`,
          message: `Chức năng thương mại cốt lõi bị từ chối vì trạng thái License là ${license.status}.`
        }
      };
    }

    // 2. Verify Active Activation Token & Environment (Domain + IP)
    const activation = dbService.state.activations.find(
      (a) =>
        a.licenseId === license.id &&
        a.status === 'ACTIVE' &&
        a.activationToken === req.activationToken
    );

    if (!activation) {
      this.logUsage(license.id, req.featureCode, startTime, 'DENIED');
      return {
        httpStatus: 401,
        body: {
          success: false,
          error_code: 'INVALID_ACTIVATION_TOKEN',
          message: 'Phiên kích hoạt (Activation Token) không hợp lệ hoặc đã bị thu hồi.'
        }
      };
    }

    const domainMatched = NetworkNormalizer.isDomainMatch(
      req.domain,
      license.allowedDomain || activation.domain,
      license.treatWwwAsSame
    );
    const ipMatched = NetworkNormalizer.isIpMatch(
      req.detectedOutboundIp,
      req.reportedServerIp,
      license.allowedIp || activation.serverIp,
      license.strictIpCheck
    );

    if (!domainMatched || !ipMatched) {
      this.logUsage(license.id, req.featureCode, startTime, 'DENIED');
      return {
        httpStatus: 403,
        body: {
          success: false,
          error_code: 'ENV_MISMATCH',
          message: 'Môi trường gọi API (Tên miền/IP) không khớp với thông tin đã cấp phép.'
        }
      };
    }

    // 3. Verify Dynamic HMAC-SHA256 Signature (prevents static key spoofing)
    const hmacCheck = ed25519Service.verifyActivationHmac(
      activation.activationToken,
      req.timestamp,
      req.featureCode,
      req.rawBody,
      req.hmacSignature
    );

    if (!hmacCheck.valid) {
      this.logUsage(license.id, req.featureCode, startTime, 'DENIED');
      return {
        httpStatus: 401,
        body: {
          success: false,
          error_code: hmacCheck.reason || 'HMAC_VERIFICATION_FAILED',
          message: 'Chữ ký xác thực yêu cầu API (Request HMAC) không hợp lệ hoặc đã quá hạn 5 phút.'
        }
      };
    }

    // 4. Check Product & Feature Entitlement
    const product = dbService.state.products.find((p) => p.id === license.productId)!;
    const allowedFeatures =
      Array.isArray(license.customFeatures) && license.customFeatures.length > 0
        ? license.customFeatures
        : product.commercialFeatures;

    if (!allowedFeatures.includes(req.featureCode)) {
      this.logUsage(license.id, req.featureCode, startTime, 'DENIED');
      return {
        httpStatus: 403,
        body: {
          success: false,
          error_code: 'FEATURE_NOT_ENTITLED',
          message: `Gói bản quyền hiện tại không bao gồm quyền sử dụng chức năng '${req.featureCode}'.`
        }
      };
    }

    // 5. Privacy Sanitization Guard: Reject requests containing raw PII keys
    const piiBlockedKeys = ['customer_full_name', 'customer_phone', 'credit_card', 'cccd', 'cmnd'];
    const foundPiiKey = Object.keys(req.payload || {}).find((k) =>
      piiBlockedKeys.includes(k.toLowerCase())
    );
    if (foundPiiKey) {
      return {
        httpStatus: 400,
        body: {
          success: false,
          error_code: 'PII_DATA_REJECTED',
          message: `Chính sách bảo mật dữ liệu (Module 7): Không cho phép gửi trường dữ liệu cá nhân '${foundPiiKey}' lên máy chủ công ty.`
        }
      };
    }

    // 6. Execute Proprietary Commercial Algorithm on Company Server
    const resultData = this.runProprietaryAlgorithm(req.featureCode, req.payload);
    const executionMs = Math.max(1, Date.now() - startTime);
    this.logUsage(license.id, req.featureCode, startTime, 'SUCCESS');

    return {
      httpStatus: 200,
      body: {
        success: true,
        feature_code: req.featureCode,
        executed_on: 'COMPANY_CENTRAL_CORE_ENGINE',
        execution_ms: executionMs,
        data_retention: 'ZERO_STORAGE_IN_MEMORY_ONLY',
        result: resultData
      }
    };
  }

  private logUsage(
    licenseId: string,
    featureCode: string,
    startTime: number,
    status: 'SUCCESS' | 'DENIED' | 'QUOTA_EXCEEDED'
  ): void {
    dbService.addRemoteFeatureLog({
      licenseId,
      featureCode,
      executionMs: Math.max(1, Date.now() - startTime),
      status
    });
  }

  private runProprietaryAlgorithm(
    featureCode: string,
    input: Record<string, unknown>
  ): Record<string, unknown> {
    switch (featureCode) {
      case 'dynamic_pricing_engine': {
        const basePrice = Number(input.base_price || 1000000);
        const quantity = Math.max(1, Number(input.quantity || 1));
        const customerTier = String(input.customer_tier || 'GOLD').toUpperCase();
        const isPeakSeason = Boolean(input.is_peak_season);

        const tierRateMap: Record<string, number> = {
          STANDARD: 0,
          SILVER: 0.05,
          GOLD: 0.1,
          PLATINUM: 0.16,
          DIAMOND: 0.22
        };
        const tierDiscountRate = tierRateMap[customerTier] ?? 0.05;
        const volumeDiscountRate = quantity >= 50 ? 0.12 : quantity >= 10 ? 0.06 : 0;
        const seasonalAdjustment = isPeakSeason ? -0.02 : 0.03;

        const effectiveDiscountRate = Math.min(
          0.3,
          Math.max(0, tierDiscountRate + volumeDiscountRate + seasonalAdjustment)
        );
        const subtotal = basePrice * quantity;
        const discountAmount = Math.round(subtotal * effectiveDiscountRate);
        const finalTotal = subtotal - discountAmount;

        return {
          algorithm_version: 'PricingCore-v3.2',
          subtotal_vnd: subtotal,
          effective_discount_percent: Number((effectiveDiscountRate * 100).toFixed(2)),
          discount_amount_vnd: discountAmount,
          final_payable_vnd: finalTotal,
          loyalty_points_awarded: Math.floor(finalTotal / 100000),
          pricing_badge_html: `<div class="clps-vip-badge">Ưu đãi độc quyền ${customerTier}: Giảm ${(effectiveDiscountRate * 100).toFixed(1)}% (-${discountAmount.toLocaleString('vi-VN')} ₫)</div>`
        };
      }

      case 'advanced_analytics_report': {
        const monthlyRevenue = Array.isArray(input.monthly_revenue)
          ? (input.monthly_revenue as number[]).map(Number)
          : [120000000, 145000000, 162000000, 190000000];
        const avgGrowthRate =
          monthlyRevenue.length > 1
            ? (monthlyRevenue[monthlyRevenue.length - 1] - monthlyRevenue[0]) /
              monthlyRevenue[0] /
              (monthlyRevenue.length - 1)
            : 0.12;
        const lastMonth = monthlyRevenue[monthlyRevenue.length - 1] || 150000000;
        const nextQuarterForecast = [1, 2, 3].map((m) =>
          Math.round(lastMonth * Math.pow(1 + Math.max(0.02, avgGrowthRate), m))
        );

        return {
          algorithm_version: 'ForecastAI-v2.1',
          historical_months: monthlyRevenue.length,
          average_monthly_growth_percent: Number((avgGrowthRate * 100).toFixed(2)),
          next_3_months_forecast_vnd: nextQuarterForecast,
          health_score: avgGrowthRate >= 0.05 ? 'EXCELLENT (92/100)' : 'STABLE (76/100)'
        };
      }

      case 'mortgage_amortization_engine': {
        const loanPrincipal = Number(input.loan_principal || 2000000000);
        const annualRatePercent = Number(input.annual_rate_percent || 8.5);
        const termMonths = Math.max(1, Number(input.term_months || 180));
        const monthlyRate = annualRatePercent / 100 / 12;

        // Equal monthly installment (Annuity formula)
        const monthlyPayment =
          monthlyRate > 0
            ? Math.round(
                (loanPrincipal * (monthlyRate * Math.pow(1 + monthlyRate, termMonths))) /
                  (Math.pow(1 + monthlyRate, termMonths) - 1)
              )
            : Math.round(loanPrincipal / termMonths);

        const totalPayable = monthlyPayment * termMonths;
        const totalInterest = totalPayable - loanPrincipal;

        return {
          algorithm_version: 'RealEstateFin-v1.9',
          loan_principal_vnd: loanPrincipal,
          term_months: termMonths,
          monthly_installment_vnd: monthlyPayment,
          total_interest_vnd: totalInterest,
          total_payable_vnd: totalPayable,
          first_month_breakdown: {
            principal_vnd: Math.round(monthlyPayment - loanPrincipal * monthlyRate),
            interest_vnd: Math.round(loanPrincipal * monthlyRate)
          }
        };
      }

      default: {
        return {
          algorithm_version: 'GenericCore-v1.0',
          processed_at: new Date().toISOString(),
          summary: `Thực thi thành công chức năng thương mại '${featureCode}' trên máy chủ trung tâm.`
        };
      }
    }
  }
}

export const remoteFeatureService = new RemoteFeatureService();
