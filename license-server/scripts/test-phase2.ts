import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { ed25519Service } from '../src/crypto/ed25519.service';
import { NetworkNormalizer } from '../src/utils/network-normalizer';
import { dbService } from '../src/database/db.service';
import { licenseValidationService } from '../src/services/license-validation.service';

console.log('🚀 BẮT ĐẦU KIỂM THỬ GIAI ĐOẠN 2: CORE BACKEND, DATABASE, ED25519 & LUỒNG XÁC THỰC\n');

// Reset seed data for deterministic test
dbService.seedInitialData();

// 1. Test Chuẩn hóa Tên miền & IP (Module 3)
console.log('1️⃣  Kiểm tra Chuẩn hóa Tên miền & IP (Module 3)...');
assert.equal(
  NetworkNormalizer.normalizeDomain('HTTPS://WWW.NoiThatHoangGia.VN:8443/san-pham?id=1', true),
  'noithathoanggia.vn',
  'Phải loại bỏ giao thức, port, path, chữ hoa và www.'
);
assert.equal(
  NetworkNormalizer.isDomainMatch('https://www.noithathoanggia.vn', 'noithathoanggia.vn', true),
  true,
  'www và non-www phải khớp khi treatWwwAsSame = true'
);
assert.equal(
  NetworkNormalizer.isIpMatch('127.0.0.1', '103.56.158.10', '103.56.158.10', true),
  true,
  'IP khớp chính xác với chính sách'
);
assert.equal(
  NetworkNormalizer.isIpMatch('203.0.113.99', '203.0.113.99', '103.56.158.10', true),
  false,
  'IP lạ phải bị từ chối khi strictIpCheck = true'
);
console.log('   ✅ Chuẩn hóa Tên miền & Kiểm soát IP hoạt động chính xác!\n');

// 2. Test Kích hoạt License hợp lệ & Chữ ký số Ed25519 (Module 2 & Module 4)
console.log('2️⃣  Kiểm tra Kích hoạt License Hợp lệ & Chữ ký số Ed25519 (Module 2 & 4)...');
const nonce1 = crypto.randomBytes(16).toString('hex');
const actRes = licenseValidationService.activateLicense({
  license_key: 'CLPS-PRO1-2026-8888-9999',
  product_slug: 'wp-commerce-pro-suite',
  domain: 'https://www.noithathoanggia.vn/',
  reported_server_ip: '103.56.158.10',
  detected_outbound_ip: '127.0.0.1',
  nonce: nonce1
});

assert.equal(actRes.httpStatus, 200);
assert.equal(actRes.envelope.payload.code, 'ACTIVATED');
assert.equal(actRes.envelope.payload.license_status, 'ACTIVE');
assert.ok(actRes.envelope.payload.activation_token?.startsWith('act_'));

const verifySig = ed25519Service.verifyEnvelope(actRes.envelope, nonce1);
assert.equal(verifySig.valid, true, 'Chữ ký Ed25519 phải hợp lệ với Public Key');
console.log(`   ✅ Kích hoạt thành công! Activation Token: ${actRes.envelope.payload.activation_token}`);
console.log(`   ✅ Chữ ký số Ed25519 (KeyID: ${ed25519Service.getKeyId()}) xác thực thành công!\n`);

// 3. Test Chống giả mạo dữ liệu (Tampering Detection) & Chống Replay Nonce (Module 4)
console.log('3️⃣  Kiểm tra Chống sửa đổi Payload & Chống Replay Nonce (Module 4)...');
const tamperedEnvelope = {
  ...actRes.envelope,
  payload_raw: actRes.envelope.payload_raw.replace('noithathoanggia.vn', 'web-ăn-cắp.vn')
};
const tamperedCheck = ed25519Service.verifyEnvelope(tamperedEnvelope, nonce1);
assert.equal(tamperedCheck.valid, false);
assert.equal(tamperedCheck.reason, 'ED25519_SIGNATURE_MISMATCH');

const replayCheck = ed25519Service.verifyEnvelope(actRes.envelope, 'wrong_nonce_999');
assert.equal(replayCheck.valid, false);
assert.equal(replayCheck.reason, 'NONCE_MISMATCH_REPLAY_DETECTED');
console.log('   ✅ Mọi hành vi sửa đổi nội dung JSON hoặc phát lại Nonce cũ đều bị chặn đứng!\n');

// 4. Test Phát hiện Sao chép Source Code sang Tên miền khác / Máy chủ IP khác (Module 3)
console.log('4️⃣  Kiểm tra Chặn Sao chép Source sang Tên miền khác hoặc IP Máy chủ khác (Module 3)...');
const cloneDomainRes = licenseValidationService.verifyLicense({
  license_key: 'CLPS-PRO1-2026-8888-9999',
  activation_token: actRes.envelope.payload.activation_token!,
  product_slug: 'wp-commerce-pro-suite',
  domain: 'https://noithat-copy-lau.vn',
  reported_server_ip: '103.56.158.10',
  detected_outbound_ip: '127.0.0.1',
  nonce: 'nonce_clone_domain'
});
assert.equal(cloneDomainRes.httpStatus, 403);
assert.equal(cloneDomainRes.envelope.payload.code, 'ENV_MISMATCH');

const cloneIpRes = licenseValidationService.verifyLicense({
  license_key: 'CLPS-PRO1-2026-8888-9999',
  activation_token: actRes.envelope.payload.activation_token!,
  product_slug: 'wp-commerce-pro-suite',
  domain: 'noithathoanggia.vn',
  reported_server_ip: '45.112.99.88', // Máy chủ VPS mới chưa được duyệt
  detected_outbound_ip: '45.112.99.88',
  nonce: 'nonce_clone_ip'
});
assert.equal(cloneIpRes.httpStatus, 403);
assert.equal(cloneIpRes.envelope.payload.code, 'ENV_MISMATCH');
console.log('   ✅ Phát hiện & từ chối chính xác khi khách tự ý đổi Tên miền hoặc chuyển sang IP VPS mới!\n');

// 5. Test Yêu cầu Chuyển Máy chủ (Module 6)
console.log('5️⃣  Kiểm tra Luồng Gửi Yêu cầu Chuyển Máy chủ chờ Admin duyệt (Module 6)...');
const transferRes = licenseValidationService.requestServerTransfer({
  license_key: 'CLPS-PRO1-2026-8888-9999',
  product_slug: 'wp-commerce-pro-suite',
  current_domain: 'noithathoanggia.vn',
  reported_server_ip: '45.112.99.88',
  detected_outbound_ip: '45.112.99.88',
  reason: 'Nâng cấp từ VPS cũ 103.56.158.10 sang VPS mới 45.112.99.88',
  nonce: 'nonce_transfer_1'
});
assert.equal(transferRes.httpStatus, 202);
assert.equal(transferRes.envelope.payload.code, 'TRANSFER_PENDING');
assert.ok(transferRes.transferRequestId);
console.log(`   ✅ Yêu cầu chuyển máy chủ đã được ghi nhận (ID: ${transferRes.transferRequestId}) ở trạng thái PENDING!\n`);

// 6. Test License Hết hạn (EXPIRED)
console.log('6️⃣  Kiểm tra Chặn License Đã Hết Hạn (EXPIRED)...');
const expRes = licenseValidationService.activateLicense({
  license_key: 'CLPS-EXP0-2025-1111-2222',
  product_slug: 'wp-commerce-pro-suite',
  domain: 'fashionviet.vn',
  reported_server_ip: '203.113.152.20',
  detected_outbound_ip: '127.0.0.1',
  nonce: 'nonce_expired'
});
assert.equal(expRes.httpStatus, 403);
assert.equal(expRes.envelope.payload.code, 'EXPIRED');
assert.equal(expRes.envelope.payload.features.length, 0);
console.log('   ✅ License hết hạn bị chặn kích hoạt và thu hồi danh sách tính năng thương mại!\n');

// Reset seed data back to clean state after test
dbService.seedInitialData();
console.log('🎉 HOÀN TẤT KIỂM THỬ GIAI ĐOẠN 2: TẤT CẢ 6 KỊCH BẢN CỐT LÕI ĐỀU PASS 100%!');

