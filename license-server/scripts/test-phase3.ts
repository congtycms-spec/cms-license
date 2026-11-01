import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { dbService } from '../src/database/db.service';
import { licenseValidationService } from '../src/services/license-validation.service';
import { remoteFeatureService } from '../src/services/remote-feature.service';
import { ed25519Service } from '../src/crypto/ed25519.service';

console.log('🚀 BẮT ĐẦU KIỂM THỬ GIAI ĐOẠN 3: MODULE 7 (REMOTE CORE ENGINE) & QUY TRÌNH DUYỆT CHUYỂN SERVER\n');

dbService.seedInitialData();

// 1. Kích hoạt License hợp lệ để lấy Activation Token
const actRes = licenseValidationService.activateLicense({
  license_key: 'CLPS-PRO1-2026-8888-9999',
  product_slug: 'wp-commerce-pro-suite',
  domain: 'noithathoanggia.vn',
  reported_server_ip: '103.56.158.10',
  detected_outbound_ip: '127.0.0.1',
  nonce: crypto.randomBytes(16).toString('hex')
});

const activationToken = actRes.envelope.payload.activation_token!;
assert.ok(activationToken);

// 2. Test Module 7: Gọi Chức năng Thương mại Cốt lõi (Dynamic Pricing Engine) hợp lệ
console.log('1️⃣  Kiểm tra Thực thi Chức năng Thương mại Cốt lõi trên Server (Module 7)...');
const payloadObj = {
  base_price: 2500000,
  quantity: 12,
  customer_tier: 'PLATINUM',
  is_peak_season: false
};
const rawBody = JSON.stringify(payloadObj);
const ts = String(Math.floor(Date.now() / 1000));
const hmac = ed25519Service.computeActivationHmac(
  activationToken,
  ts,
  'dynamic_pricing_engine',
  rawBody
);

const execRes = remoteFeatureService.executeFeature({
  licenseKey: 'CLPS-PRO1-2026-8888-9999',
  activationToken,
  domain: 'noithathoanggia.vn',
  detectedOutboundIp: '127.0.0.1',
  reportedServerIp: '103.56.158.10',
  timestamp: ts,
  hmacSignature: hmac,
  featureCode: 'dynamic_pricing_engine',
  rawBody,
  payload: payloadObj
});

assert.equal(execRes.httpStatus, 200);
assert.equal(execRes.body.success, true);
const pricingResult = execRes.body.result as Record<string, unknown>;
assert.equal(pricingResult.subtotal_vnd, 30000000);
assert.ok(Number(pricingResult.final_payable_vnd) < 30000000);
console.log(
  `   ✅ Module 7 thực thi thành công! Giá gốc: 30,000,000đ -> Giá sau chiết khấu VIP: ${Number(pricingResult.final_payable_vnd).toLocaleString('vi-VN')}đ\n`
);

// 3. Test Module 7: Chặn gửi dữ liệu cá nhân nhạy cảm (Data Minimization Guard)
console.log('2️⃣  Kiểm tra Chặn Gửi Dữ liệu Cá nhân (PII Data Minimization Guard - Module 7)...');
const piiPayload = {
  base_price: 1000000,
  customer_phone: '0909123456' // Vi phạm chính sách bảo mật dữ liệu
};
const piiRaw = JSON.stringify(piiPayload);
const piiHmac = ed25519Service.computeActivationHmac(
  activationToken,
  ts,
  'dynamic_pricing_engine',
  piiRaw
);

const piiRes = remoteFeatureService.executeFeature({
  licenseKey: 'CLPS-PRO1-2026-8888-9999',
  activationToken,
  domain: 'noithathoanggia.vn',
  detectedOutboundIp: '127.0.0.1',
  reportedServerIp: '103.56.158.10',
  timestamp: ts,
  hmacSignature: piiHmac,
  featureCode: 'dynamic_pricing_engine',
  rawBody: piiRaw,
  payload: piiPayload
});
assert.equal(piiRes.httpStatus, 400);
assert.equal(piiRes.body.error_code, 'PII_DATA_REJECTED');
console.log('   ✅ Chặn thành công request chứa dữ liệu cá nhân (customer_phone)!\n');

// 4. Test Module 7: Chặn gọi tính năng không thuộc sản phẩm (Feature Entitlement Check)
console.log('3️⃣  Kiểm tra Chặn Gọi Chức năng Không Thuộc Sản phẩm (Feature Entitlement)...');
const unentitledHmac = ed25519Service.computeActivationHmac(
  activationToken,
  ts,
  'mortgage_amortization_engine', // Tính năng của BĐS, không thuộc gói E-commerce
  rawBody
);
const unentitledRes = remoteFeatureService.executeFeature({
  licenseKey: 'CLPS-PRO1-2026-8888-9999',
  activationToken,
  domain: 'noithathoanggia.vn',
  detectedOutboundIp: '127.0.0.1',
  reportedServerIp: '103.56.158.10',
  timestamp: ts,
  hmacSignature: unentitledHmac,
  featureCode: 'mortgage_amortization_engine',
  rawBody,
  payload: payloadObj
});
assert.equal(unentitledRes.httpStatus, 403);
assert.equal(unentitledRes.body.error_code, 'FEATURE_NOT_ENTITLED');
console.log('   ✅ Chặn thành công truy cập trái phép chức năng của gói sản phẩm khác!\n');

dbService.seedInitialData();
console.log('🎉 HOÀN TẤT KIỂM THỬ GIAI ĐOẠN 3: TẤT CẢ KỊCH BẢN MODULE 7 ĐỀU PASS 100%!');

