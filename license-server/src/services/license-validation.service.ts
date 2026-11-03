import crypto from 'node:crypto';
import { dbService, LicenseRecord, ProductRecord } from '../database/db.service';
import {
  ed25519Service,
  SignedEnvelope,
  SignedLicenseCertificatePayload
} from '../crypto/ed25519.service';
import { NetworkNormalizer } from '../utils/network-normalizer';

export interface PluginActivateInput {
  license_key: string;
  product_slug: string;
  domain: string;
  reported_server_ip?: string;
  detected_outbound_ip: string;
  nonce: string;
  wp_version?: string;
  php_version?: string;
  plugin_version?: string;
  user_agent?: string;
}

export interface PluginVerifyInput {
  license_key: string;
  activation_token: string;
  product_slug: string;
  domain: string;
  reported_server_ip?: string;
  detected_outbound_ip: string;
  nonce: string;
  user_agent?: string;
}

export interface PluginTransferRequestInput {
  license_key: string;
  product_slug?: string;
  current_domain: string;
  reported_server_ip?: string;
  detected_outbound_ip: string;
  reason: string;
  nonce: string;
  user_agent?: string;
}

export class LicenseValidationService {
  private buildSignedResponse(
    params: Partial<SignedLicenseCertificatePayload> & {
      nonce: string;
      license_key: string;
      product_slug: string;
      license_status: SignedLicenseCertificatePayload['license_status'];
      code: SignedLicenseCertificatePayload['code'];
      message: string;
      domain: string;
      server_ip: string;
    },
    gracePeriodHours = 72
  ): SignedEnvelope {
    const nowSec = Math.floor(Date.now() / 1000);
    const leaseHours = Number(process.env.DEFAULT_LEASE_HOURS || 24);

    const isActivatedOrValid =
      params.license_status === 'ACTIVE' &&
      (params.code === 'ACTIVATED' || params.code === 'VALID');

    const runtimeTokens = isActivatedOrValid
      ? {
          runtime_salt: crypto
            .createHash('sha256')
            .update(`clps_salt:${params.domain}:${params.product_slug}`)
            .digest('hex')
            .slice(0, 24),
          render_signature: crypto
            .createHash('sha256')
            .update(`clps_render:${params.license_key}:${params.domain}`)
            .digest('base64url')
            .slice(0, 32),
          css_scope_token: 'wp-hydrated-ready',
          hydrated_hooks: ['woocommerce_after_shop_loop_item', 'wp_head', 'the_content']
        }
      : null;

    const payload: SignedLicenseCertificatePayload = {
      ver: 1,
      nonce: params.nonce,
      iat: nowSec,
      exp: nowSec + leaseHours * 3600,
      grace_until: nowSec + gracePeriodHours * 3600,
      license_key: params.license_key,
      product_slug: params.product_slug,
      license_status: params.license_status,
      code: params.code,
      message: params.message,
      activation_token: params.activation_token ?? null,
      domain: params.domain,
      server_ip: params.server_ip,
      expires_at: params.expires_at ?? null,
      max_activations: params.max_activations ?? 1,
      features: params.features ?? [],
      runtime_tokens: runtimeTokens
    };

    return ed25519Service.signPayload(payload);
  }

  private resolveEffectiveFeatures(license: LicenseRecord, product: ProductRecord): string[] {
    if (Array.isArray(license.customFeatures) && license.customFeatures.length > 0) {
      return license.customFeatures;
    }
    return product.commercialFeatures || [];
  }

  private checkAndSyncExpiration(_license: LicenseRecord): void {
    // All licenses are permanent/unlimited — only controlled by ACTIVE, SUSPENDED, or REVOKED
  }

  /**
   * Resolves the effective server IP to bind/record.
   * When testing locally (detected_outbound_ip === 127.0.0.1) and reported_server_ip is provided,
   * we use reported_server_ip if it matches policy or for clear simulation.
   * In production internet connections, detected_outbound_ip from TCP/Trusted Proxy takes precedence.
   */
  private resolveEffectiveServerIp(detectedOutboundIp: string, reportedServerIp?: string): string {
    const normDetected = NetworkNormalizer.normalizeIp(detectedOutboundIp);
    const normReported = NetworkNormalizer.normalizeIp(reportedServerIp);
    if (normDetected === '127.0.0.1' && normReported) {
      return normReported;
    }
    return normDetected || normReported || '127.0.0.1';
  }

  /**
   * MODULE 2, 3, 4: Activate License on a WordPress site.
   */
  public activateLicense(input: PluginActivateInput): {
    httpStatus: number;
    envelope: SignedEnvelope;
  } {
    const license = dbService.state.licenses.find(
      (l) => l.licenseKey.toUpperCase() === input.license_key.trim().toUpperCase()
    );

    const effectiveIp = this.resolveEffectiveServerIp(
      input.detected_outbound_ip,
      input.reported_server_ip
    );
    const initialDomain = NetworkNormalizer.normalizeDomain(input.domain, true);

    if (!license) {
      dbService.addValidationLog({
        licenseId: null,
        licenseKeyAttempt: input.license_key,
        requestDomain: initialDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'ACTIVATE',
        isValid: false,
        failureReason: 'INVALID_KEY',
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 404,
        envelope: this.buildSignedResponse({
          nonce: input.nonce,
          license_key: input.license_key,
          product_slug: input.product_slug,
          license_status: 'INACTIVE',
          code: 'INVALID_KEY',
          message: 'Mã bản quyền (License Key) không tồn tại trên hệ thống.',
          domain: initialDomain,
          server_ip: effectiveIp
        })
      };
    }

    const product = dbService.state.products.find((p) => p.id === license.productId);
    if (!product || (input.product_slug && product.slug !== input.product_slug)) {
      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: initialDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'ACTIVATE',
        isValid: false,
        failureReason: 'PRODUCT_MISMATCH',
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse({
          nonce: input.nonce,
          license_key: license.licenseKey,
          product_slug: input.product_slug,
          license_status: license.status,
          code: 'PRODUCT_MISMATCH',
          message: 'License Key này không thuộc về sản phẩm WordPress hiện tại.',
          domain: initialDomain,
          server_ip: effectiveIp
        })
      };
    }

    const normalizedDomain = NetworkNormalizer.normalizeDomain(
      input.domain,
      license.treatWwwAsSame
    );

    this.checkAndSyncExpiration(license);

    if (license.status === 'EXPIRED' || license.status === 'SUSPENDED' || license.status === 'REVOKED') {
      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: normalizedDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'ACTIVATE',
        isValid: false,
        failureReason: `STATUS_${license.status}`,
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      const statusMessages: Record<string, string> = {
        EXPIRED: 'License đã hết hạn sử dụng. Vui lòng liên hệ đơn vị phát triển để gia hạn.',
        SUSPENDED: 'License đang bị tạm ngừng (SUSPENDED). Vui lòng liên hệ bộ phận quản lý bản quyền.',
        REVOKED: 'License đã bị thu hồi (REVOKED) do vi phạm chính sách bản quyền.'
      };

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse(
          {
            nonce: input.nonce,
            license_key: license.licenseKey,
            product_slug: product.slug,
            license_status: license.status,
            code: license.status,
            message: statusMessages[license.status],
            domain: normalizedDomain,
            server_ip: effectiveIp,
            expires_at: license.expiresAt,
            max_activations: license.maxActivations,
            features: []
          },
          product.gracePeriodHours
        )
      };
    }

    // Check Domain Policy (Module 3: Do NOT automatically authorize a new domain if allowedDomain is already set)
    if (license.allowedDomain) {
      const domainMatched = NetworkNormalizer.isDomainMatch(
        normalizedDomain,
        license.allowedDomain,
        license.treatWwwAsSame
      );
      if (!domainMatched) {
        dbService.addValidationLog({
          licenseId: license.id,
          licenseKeyAttempt: license.licenseKey,
          requestDomain: normalizedDomain,
          detectedOutboundIp: input.detected_outbound_ip,
          reportedServerIp: input.reported_server_ip || null,
          action: 'ACTIVATE',
          isValid: false,
          failureReason: `ENV_MISMATCH_DOMAIN (Expected: ${license.allowedDomain}, Got: ${normalizedDomain})`,
          userAgent: input.user_agent || 'WordPress-Plugin'
        });

        return {
          httpStatus: 403,
          envelope: this.buildSignedResponse(
            {
              nonce: input.nonce,
              license_key: license.licenseKey,
              product_slug: product.slug,
              license_status: license.status,
              code: 'ENV_MISMATCH',
              message: `Tên miền hiện tại (${normalizedDomain}) không khớp với tên miền được cấp phép (${license.allowedDomain}). Vui lòng gửi yêu cầu chuyển máy chủ/đổi tên miền.`,
              domain: license.allowedDomain,
              server_ip: license.allowedIp || effectiveIp,
              expires_at: license.expiresAt,
              max_activations: license.maxActivations,
              features: []
            },
            product.gracePeriodHours
          )
        };
      }
    }

    // Check IP Policy (Module 3: Do NOT automatically authorize a new server IP if allowedIp is already set)
    if (license.allowedIp && license.strictIpCheck) {
      const ipMatched = NetworkNormalizer.isIpMatch(
        input.detected_outbound_ip,
        input.reported_server_ip,
        license.allowedIp,
        license.strictIpCheck
      );
      if (!ipMatched) {
        dbService.addValidationLog({
          licenseId: license.id,
          licenseKeyAttempt: license.licenseKey,
          requestDomain: normalizedDomain,
          detectedOutboundIp: input.detected_outbound_ip,
          reportedServerIp: input.reported_server_ip || null,
          action: 'ACTIVATE',
          isValid: false,
          failureReason: `ENV_MISMATCH_IP (Expected: ${license.allowedIp}, Got: ${effectiveIp})`,
          userAgent: input.user_agent || 'WordPress-Plugin'
        });

        return {
          httpStatus: 403,
          envelope: this.buildSignedResponse(
            {
              nonce: input.nonce,
              license_key: license.licenseKey,
              product_slug: product.slug,
              license_status: license.status,
              code: 'ENV_MISMATCH',
              message: `IP máy chủ hiện tại (${effectiveIp}) không khớp với IP được cấp phép (${license.allowedIp}). Nếu bạn vừa chuyển hosting/VPS, vui lòng bấm "Yêu cầu chuyển máy chủ" để quản trị viên phê duyệt.`,
              domain: license.allowedDomain || normalizedDomain,
              server_ip: license.allowedIp,
              expires_at: license.expiresAt,
              max_activations: license.maxActivations,
              features: []
            },
            product.gracePeriodHours
          )
        };
      }
    }

    // Check existing active activations
    const activeList = dbService.state.activations.filter(
      (a) => a.licenseId === license.id && a.status === 'ACTIVE'
    );

    let existingActivation = activeList.find(
      (a) =>
        NetworkNormalizer.isDomainMatch(a.domain, normalizedDomain, license.treatWwwAsSame) &&
        (!license.strictIpCheck || a.serverIp === effectiveIp)
    );

    if (!existingActivation && activeList.length >= license.maxActivations) {
      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: normalizedDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'ACTIVATE',
        isValid: false,
        failureReason: `MAX_ACTIVATIONS_REACHED (${activeList.length}/${license.maxActivations})`,
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse(
          {
            nonce: input.nonce,
            license_key: license.licenseKey,
            product_slug: product.slug,
            license_status: license.status,
            code: 'MAX_ACTIVATIONS_REACHED',
            message: `License đã đạt giới hạn số lượng website kích hoạt tối đa (${license.maxActivations} website).`,
            domain: license.allowedDomain || normalizedDomain,
            server_ip: license.allowedIp || effectiveIp,
            expires_at: license.expiresAt,
            max_activations: license.maxActivations,
            features: []
          },
          product.gracePeriodHours
        )
      };
    }

    // Bind allowedDomain / allowedIp if license was created unbound for initial activation
    let licenseMutated = false;
    if (!license.allowedDomain) {
      license.allowedDomain = normalizedDomain;
      licenseMutated = true;
    }
    if (!license.allowedIp) {
      license.allowedIp = effectiveIp;
      licenseMutated = true;
    }
    if (license.status === 'INACTIVE') {
      license.status = 'ACTIVE';
      licenseMutated = true;
    }
    if (licenseMutated) {
      license.updatedAt = new Date().toISOString();
    }

    const nowIso = new Date().toISOString();
    if (existingActivation) {
      existingActivation.lastVerifiedAt = nowIso;
      existingActivation.wpVersion = input.wp_version || existingActivation.wpVersion;
      existingActivation.phpVersion = input.php_version || existingActivation.phpVersion;
      existingActivation.pluginVersion = input.plugin_version || existingActivation.pluginVersion;
    } else {
      existingActivation = {
        id: crypto.randomUUID(),
        licenseId: license.id,
        activationToken: `act_${crypto.randomBytes(24).toString('hex')}`,
        domain: normalizedDomain,
        serverIp: effectiveIp,
        wpVersion: input.wp_version || '6.7',
        phpVersion: input.php_version || '8.2',
        pluginVersion: input.plugin_version || '1.0.0',
        status: 'ACTIVE',
        activatedAt: nowIso,
        lastVerifiedAt: nowIso
      };
      dbService.state.activations.push(existingActivation);
    }

    dbService.addValidationLog({
      licenseId: license.id,
      licenseKeyAttempt: license.licenseKey,
      requestDomain: normalizedDomain,
      detectedOutboundIp: input.detected_outbound_ip,
      reportedServerIp: input.reported_server_ip || null,
      action: 'ACTIVATE',
      isValid: true,
      failureReason: null,
      userAgent: input.user_agent || 'WordPress-Plugin'
    });

    if (licenseMutated) {
      dbService.save();
    } else {
      dbService.saveTelemetryOnly();
    }

    const features = this.resolveEffectiveFeatures(license, product);

    return {
      httpStatus: 200,
      envelope: this.buildSignedResponse(
        {
          nonce: input.nonce,
          license_key: license.licenseKey,
          product_slug: product.slug,
          license_status: 'ACTIVE',
          code: 'ACTIVATED',
          message: 'Kích hoạt bản quyền WordPress thành công.',
          activation_token: existingActivation.activationToken,
          domain: normalizedDomain,
          server_ip: effectiveIp,
          expires_at: license.expiresAt,
          max_activations: license.maxActivations,
          features
        },
        product.gracePeriodHours
      )
    };
  }

  /**
   * MODULE 5: Periodic Heartbeat & Manual License Verification.
   */
  public verifyLicense(input: PluginVerifyInput): {
    httpStatus: number;
    envelope: SignedEnvelope;
  } {
    const license = dbService.state.licenses.find(
      (l) => l.licenseKey.toUpperCase() === input.license_key.trim().toUpperCase()
    );
    const effectiveIp = this.resolveEffectiveServerIp(
      input.detected_outbound_ip,
      input.reported_server_ip
    );
    const initialDomain = NetworkNormalizer.normalizeDomain(input.domain, true);

    if (!license) {
      dbService.addValidationLog({
        licenseId: null,
        licenseKeyAttempt: input.license_key,
        requestDomain: initialDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'VERIFY',
        isValid: false,
        failureReason: 'INVALID_KEY',
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 404,
        envelope: this.buildSignedResponse({
          nonce: input.nonce,
          license_key: input.license_key,
          product_slug: input.product_slug,
          license_status: 'INACTIVE',
          code: 'INVALID_KEY',
          message: 'License Key không hợp lệ.',
          domain: initialDomain,
          server_ip: effectiveIp
        })
      };
    }

    const product = dbService.state.products.find((p) => p.id === license.productId)!;
    const normalizedDomain = NetworkNormalizer.normalizeDomain(
      input.domain,
      license.treatWwwAsSame
    );

    this.checkAndSyncExpiration(license);

    if (license.status !== 'ACTIVE') {
      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: normalizedDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'VERIFY',
        isValid: false,
        failureReason: `STATUS_${license.status}`,
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      const codeMap: Record<string, SignedLicenseCertificatePayload['code']> = {
        EXPIRED: 'EXPIRED',
        SUSPENDED: 'SUSPENDED',
        REVOKED: 'REVOKED',
        INACTIVE: 'DEACTIVATED'
      };

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse(
          {
            nonce: input.nonce,
            license_key: license.licenseKey,
            product_slug: product.slug,
            license_status: license.status,
            code: codeMap[license.status] || 'EXPIRED',
            message: `License hiện đang ở trạng thái ${license.status}. Các chức năng thương mại đã bị tạm khóa.`,
            domain: license.allowedDomain || normalizedDomain,
            server_ip: license.allowedIp || effectiveIp,
            expires_at: license.expiresAt,
            max_activations: license.maxActivations,
            features: []
          },
          product.gracePeriodHours
        )
      };
    }

    // Verify Domain & IP match
    const domainMatched = license.allowedDomain
      ? NetworkNormalizer.isDomainMatch(
          normalizedDomain,
          license.allowedDomain,
          license.treatWwwAsSame
        )
      : true;

    const ipMatched =
      license.allowedIp && license.strictIpCheck
        ? NetworkNormalizer.isIpMatch(
            input.detected_outbound_ip,
            input.reported_server_ip,
            license.allowedIp,
            license.strictIpCheck
          )
        : true;

    if (!domainMatched || !ipMatched) {
      const reason = !domainMatched
        ? `ENV_MISMATCH_DOMAIN (Expected: ${license.allowedDomain}, Got: ${normalizedDomain})`
        : `ENV_MISMATCH_IP (Expected: ${license.allowedIp}, Got: ${effectiveIp})`;

      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: normalizedDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'VERIFY',
        isValid: false,
        failureReason: reason,
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse(
          {
            nonce: input.nonce,
            license_key: license.licenseKey,
            product_slug: product.slug,
            license_status: license.status,
            code: 'ENV_MISMATCH',
            message: !domainMatched
              ? `Phát hiện website đang chạy trên tên miền chưa cấp phép (${normalizedDomain}). Tên miền hợp lệ: ${license.allowedDomain}.`
              : `Phát hiện website đang chạy trên IP máy chủ mới (${effectiveIp}) khác với IP được cấp phép (${license.allowedIp}). Vui lòng gửi yêu cầu chuyển máy chủ.`,
            domain: license.allowedDomain || normalizedDomain,
            server_ip: license.allowedIp || effectiveIp,
            expires_at: license.expiresAt,
            max_activations: license.maxActivations,
            features: []
          },
          product.gracePeriodHours
        )
      };
    }

    // Find activation record (or auto-match active activation for approved transfer)
    let activation = dbService.state.activations.find(
      (a) =>
        a.licenseId === license.id &&
        a.status === 'ACTIVE' &&
        (a.activationToken === input.activation_token ||
          (NetworkNormalizer.isDomainMatch(a.domain, normalizedDomain, license.treatWwwAsSame) &&
            (!license.strictIpCheck || a.serverIp === effectiveIp)))
    );

    if (!activation) {
      // If admin just approved a server transfer to this new domain/IP, create or refresh activation
      const activeCount = dbService.state.activations.filter(
        (a) => a.licenseId === license.id && a.status === 'ACTIVE'
      ).length;
      if (activeCount < license.maxActivations) {
        const nowIso = new Date().toISOString();
        activation = {
          id: crypto.randomUUID(),
          licenseId: license.id,
          activationToken: `act_${crypto.randomBytes(24).toString('hex')}`,
          domain: normalizedDomain,
          serverIp: effectiveIp,
          wpVersion: '6.7',
          phpVersion: '8.2',
          pluginVersion: '1.0.0',
          status: 'ACTIVE',
          activatedAt: nowIso,
          lastVerifiedAt: nowIso
        };
        dbService.state.activations.push(activation);
      } else {
        return {
          httpStatus: 403,
          envelope: this.buildSignedResponse(
            {
              nonce: input.nonce,
              license_key: license.licenseKey,
              product_slug: product.slug,
              license_status: license.status,
              code: 'MAX_ACTIVATIONS_REACHED',
              message: 'Phiên kích hoạt không hợp lệ hoặc đã bị thu hồi.',
              domain: license.allowedDomain || normalizedDomain,
              server_ip: license.allowedIp || effectiveIp,
              expires_at: license.expiresAt,
              max_activations: license.maxActivations,
              features: []
            },
            product.gracePeriodHours
          )
        };
      }
    } else {
      activation.lastVerifiedAt = new Date().toISOString();
    }

    dbService.addValidationLog({
      licenseId: license.id,
      licenseKeyAttempt: license.licenseKey,
      requestDomain: normalizedDomain,
      detectedOutboundIp: input.detected_outbound_ip,
      reportedServerIp: input.reported_server_ip || null,
      action: 'VERIFY',
      isValid: true,
      failureReason: null,
      userAgent: input.user_agent || 'WordPress-Plugin'
    });

    dbService.saveTelemetryOnly();

    return {
      httpStatus: 200,
      envelope: this.buildSignedResponse(
        {
          nonce: input.nonce,
          license_key: license.licenseKey,
          product_slug: product.slug,
          license_status: 'ACTIVE',
          code: 'VALID',
          message: 'Bản quyền hợp lệ.',
          activation_token: activation.activationToken,
          domain: normalizedDomain,
          server_ip: effectiveIp,
          expires_at: license.expiresAt,
          max_activations: license.maxActivations,
          features: this.resolveEffectiveFeatures(license, product)
        },
        product.gracePeriodHours
      )
    };
  }

  /**
   * MODULE 6: Submit a Server / Domain Transfer Request for Admin Approval.
   */
  public requestServerTransfer(input: PluginTransferRequestInput): {
    httpStatus: number;
    envelope: SignedEnvelope;
    transferRequestId?: string;
  } {
    const license = dbService.state.licenses.find(
      (l) => l.licenseKey.toUpperCase() === input.license_key.trim().toUpperCase()
    );
    const effectiveIp = this.resolveEffectiveServerIp(
      input.detected_outbound_ip,
      input.reported_server_ip
    );
    const normalizedNewDomain = NetworkNormalizer.normalizeDomain(input.current_domain, true);

    if (!license) {
      return {
        httpStatus: 404,
        envelope: this.buildSignedResponse({
          nonce: input.nonce,
          license_key: input.license_key,
          product_slug: input.product_slug || 'unknown',
          license_status: 'INACTIVE',
          code: 'INVALID_KEY',
          message: 'License Key không tồn tại.',
          domain: normalizedNewDomain,
          server_ip: effectiveIp
        })
      };
    }

    const product = dbService.state.products.find((p) => p.id === license.productId)!;

    if (license.transferCount >= license.maxTransfers) {
      dbService.addValidationLog({
        licenseId: license.id,
        licenseKeyAttempt: license.licenseKey,
        requestDomain: normalizedNewDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'TRANSFER_REQ',
        isValid: false,
        failureReason: `TRANSFER_LIMIT_REACHED (${license.transferCount}/${license.maxTransfers})`,
        userAgent: input.user_agent || 'WordPress-Plugin'
      });

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse(
          {
            nonce: input.nonce,
            license_key: license.licenseKey,
            product_slug: product.slug,
            license_status: license.status,
            code: 'TRANSFER_LIMIT_REACHED',
            message: `License này đã sử dụng hết số lần chuyển máy chủ cho phép (${license.transferCount}/${license.maxTransfers}). Vui lòng liên hệ trực tiếp bộ phận hỗ trợ.`,
            domain: license.allowedDomain || normalizedNewDomain,
            server_ip: license.allowedIp || effectiveIp,
            expires_at: license.expiresAt,
            max_activations: license.maxActivations,
            features: []
          },
          product.gracePeriodHours
        )
      };
    }

    // Check if there is already a pending request for this license
    let pendingReq = dbService.state.transferRequests.find(
      (r) => r.licenseId === license.id && r.status === 'PENDING'
    );

    if (pendingReq) {
      pendingReq.newDomain = normalizedNewDomain;
      pendingReq.newIp = effectiveIp;
      pendingReq.reason = input.reason || pendingReq.reason;
    } else {
      pendingReq = {
        id: crypto.randomUUID(),
        licenseId: license.id,
        oldDomain: license.allowedDomain,
        oldIp: license.allowedIp,
        newDomain: normalizedNewDomain,
        newIp: effectiveIp,
        reason: input.reason || 'Khách hàng yêu cầu chuyển máy chủ / cập nhật IP-Domain từ WordPress Admin',
        status: 'PENDING',
        reviewedByUserId: null,
        reviewNote: null,
        createdAt: new Date().toISOString(),
        reviewedAt: null
      };
      dbService.state.transferRequests.push(pendingReq);
    }

    dbService.addValidationLog({
      licenseId: license.id,
      licenseKeyAttempt: license.licenseKey,
      requestDomain: normalizedNewDomain,
      detectedOutboundIp: input.detected_outbound_ip,
      reportedServerIp: input.reported_server_ip || null,
      action: 'TRANSFER_REQ',
      isValid: true,
      failureReason: `TRANSFER_REQUESTED_TO_${normalizedNewDomain}_${effectiveIp}`,
      userAgent: input.user_agent || 'WordPress-Plugin'
    });

    dbService.addAuditLog({
      licenseId: license.id,
      actorUserId: null,
      eventType: 'TRANSFER_REQUEST_SUBMITTED',
      oldValue: { domain: license.allowedDomain, ip: license.allowedIp },
      newValue: { newDomain: normalizedNewDomain, newIp: effectiveIp, reason: input.reason },
      ipAddress: effectiveIp,
      note: 'Yêu cầu chuyển máy chủ từ WordPress Plugin đang chờ Admin phê duyệt'
    });

    dbService.save();

    return {
      httpStatus: 202,
      transferRequestId: pendingReq.id,
      envelope: this.buildSignedResponse(
        {
          nonce: input.nonce,
          license_key: license.licenseKey,
          product_slug: product.slug,
          license_status: license.status,
          code: 'TRANSFER_PENDING',
          message: `Đã gửi yêu cầu chuyển máy chủ sang Tên miền: ${normalizedNewDomain} / IP: ${effectiveIp}. Yêu cầu đang chờ Quản trị viên phê duyệt trên Dashboard.`,
          domain: license.allowedDomain || normalizedNewDomain,
          server_ip: license.allowedIp || effectiveIp,
          expires_at: license.expiresAt,
          max_activations: license.maxActivations,
          features: []
        },
        product.gracePeriodHours
      )
    };
  }

  /**
   * STEALTH ZERO-UI MODE: Auto-bind & activate or verify solely by Domain + Server IP + Product Slug.
   * No License Key input required in WordPress Admin!
   * The agency registers the client's domain on the Central Dashboard, and the embedded theme core
   * automatically fetches its Ed25519 signed certificate & runtime hydration tokens.
   */
  public autoBindByDomain(input: {
    product_slug: string;
    domain: string;
    reported_server_ip?: string;
    detected_outbound_ip: string;
    nonce: string;
    wp_version?: string;
    php_version?: string;
    user_agent?: string;
  }): {
    httpStatus: number;
    envelope: SignedEnvelope;
  } {
    const normalizedDomain = NetworkNormalizer.normalizeDomain(input.domain, true);
    const effectiveIp = this.resolveEffectiveServerIp(
      input.detected_outbound_ip,
      input.reported_server_ip
    );

    const product = dbService.state.products.find((p) => p.slug === input.product_slug);

    // Find license matching this domain (prioritize exact product match, or match by domain directly)
    const matchedLicense =
      dbService.state.licenses.find((l) => {
        if (!l.allowedDomain) return false;
        if (product && l.productId !== product.id) return false;
        return NetworkNormalizer.isDomainMatch(
          normalizedDomain,
          l.allowedDomain,
          l.treatWwwAsSame
        );
      }) ||
      dbService.state.licenses.find((l) => {
        if (!l.allowedDomain) return false;
        return NetworkNormalizer.isDomainMatch(
          normalizedDomain,
          l.allowedDomain,
          l.treatWwwAsSame
        );
      });

    if (!matchedLicense) {
      dbService.addValidationLog({
        licenseId: null,
        licenseKeyAttempt: `AUTO_DOMAIN:${normalizedDomain}`,
        requestDomain: normalizedDomain,
        detectedOutboundIp: input.detected_outbound_ip,
        reportedServerIp: input.reported_server_ip || null,
        action: 'VERIFY',
        isValid: false,
        failureReason: `UNREGISTERED_DOMAIN (${normalizedDomain})`,
        userAgent: input.user_agent || 'WP-Core-Hydrator'
      });

      return {
        httpStatus: 403,
        envelope: this.buildSignedResponse({
          nonce: input.nonce,
          license_key: 'UNBOUND',
          product_slug: input.product_slug,
          license_status: 'INACTIVE',
          code: 'ENV_MISMATCH',
          message: `Tên miền (${normalizedDomain}) chưa được đăng ký trên hệ thống quản lý bản quyền trung tâm.`,
          domain: normalizedDomain,
          server_ip: effectiveIp,
          features: []
        })
      };
    }

    const matchedProduct = dbService.state.products.find((p) => p.id === matchedLicense.productId);

    // Delegate to activateLicense using the matched license key & product slug
    return this.activateLicense({
      license_key: matchedLicense.licenseKey,
      product_slug: matchedProduct ? matchedProduct.slug : input.product_slug,
      domain: input.domain,
      reported_server_ip: input.reported_server_ip,
      detected_outbound_ip: input.detected_outbound_ip,
      nonce: input.nonce,
      wp_version: input.wp_version,
      php_version: input.php_version,
      plugin_version: '1.0.0-stealth',
      user_agent: input.user_agent || 'WP-Core-Hydrator'
    });
  }
}

export const licenseValidationService = new LicenseValidationService();

