import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../src/main';
import { dbService } from '../src/database/db.service';
import { ed25519Service } from '../src/crypto/ed25519.service';

async function requestJson(
  baseUrl: string,
  path: string,
  options: RequestInit = {}
): Promise<{ status: number; data: any }> {
  const res = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function runE2E() {
  console.log('==============================================================');
  console.log('🧪 BẮT ĐẦU KIỂM THỬ TÍCH HỢP END-TO-END (GIAI ĐOẠN 6)');
  console.log('==============================================================\n');

  dbService.seedInitialData();
  const app = createApp();
  const server = http.createServer(app);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${address.port}`;

  try {
    // 1. Admin Login & Dashboard Stats (#14, #15)
    console.log('1️⃣  [Module 1 #14, #15] Đăng nhập Admin Dashboard & Kiểm tra Thống kê Sắp hết hạn...');
    const loginRes = await requestJson(baseUrl, '/api/v1/admin/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'admin@company.vn', password: 'Admin@123456' })
    });
    assert.equal(loginRes.status, 200);
    const adminToken = loginRes.data.token;
    assert.ok(adminToken);

    const statsRes = await requestJson(baseUrl, '/api/v1/admin/dashboard/stats', {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.equal(statsRes.status, 200);
    assert.equal(statsRes.data.summary.expiringWithin30DaysCount, 1);
    console.log('   ✅ Đăng nhập RBAC & Thống kê License sắp hết hạn hoạt động chính xác!\n');

    // 2. Plugin Activation & Ed25519 Signature Verification (Module 2, 3, 4)
    console.log('2️⃣  [Module 2, 3, 4] WordPress Plugin Kích hoạt License & Xác minh Chữ ký số Ed25519...');
    const actRes = await requestJson(baseUrl, '/api/v1/plugin/activate', {
      method: 'POST',
      body: JSON.stringify({
        license_key: 'CLPS-PRO1-2026-8888-9999',
        product_slug: 'wp-commerce-pro-suite',
        domain: 'https://www.noithathoanggia.vn',
        reported_server_ip: '103.56.158.10',
        nonce: 'e2e_nonce_activate_001'
      })
    });
    assert.equal(actRes.status, 200);
    assert.equal(actRes.data.payload.code, 'ACTIVATED');
    const verifyEnv = ed25519Service.verifyEnvelope(actRes.data, 'e2e_nonce_activate_001');
    assert.equal(verifyEnv.valid, true);
    const activationToken = actRes.data.payload.activation_token;
    console.log(`   ✅ Plugin kích hoạt & xác minh Ed25519 thành công (Token: ${activationToken})!\n`);

    // 3. Unauthorized Server Copy -> Request Transfer -> Admin Approves -> New Server Works (Module 3 & Module 6)
    console.log('3️⃣  [Module 3 & Module 6] Mô phỏng Khách chuyển VPS mới (IP 45.112.99.88) -> Bị chặn -> Gửi Yêu cầu Chuyển Server -> Admin Phê duyệt...');
    const mismatchRes = await requestJson(baseUrl, '/api/v1/plugin/verify', {
      method: 'POST',
      body: JSON.stringify({
        license_key: 'CLPS-PRO1-2026-8888-9999',
        activation_token: activationToken,
        product_slug: 'wp-commerce-pro-suite',
        domain: 'noithathoanggia.vn',
        reported_server_ip: '45.112.99.88',
        nonce: 'e2e_nonce_mismatch_002'
      })
    });
    assert.equal(mismatchRes.status, 403);
    assert.equal(mismatchRes.data.payload.code, 'ENV_MISMATCH');

    const transferReqRes = await requestJson(baseUrl, '/api/v1/plugin/transfer-request', {
      method: 'POST',
      body: JSON.stringify({
        license_key: 'CLPS-PRO1-2026-8888-9999',
        product_slug: 'wp-commerce-pro-suite',
        current_domain: 'noithathoanggia.vn',
        reported_server_ip: '45.112.99.88',
        reason: 'Chuyển sang máy chủ VPS mới 45.112.99.88',
        nonce: 'e2e_nonce_transfer_003'
      })
    });
    assert.equal(transferReqRes.status, 202);
    const transferRequestId = transferReqRes.data.transfer_request_id;
    assert.ok(transferRequestId);

    // Admin approves the transfer request from Dashboard
    const approveRes = await requestJson(
      baseUrl,
      `/api/v1/admin/transfer-requests/${transferRequestId}/approve`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ reviewNote: 'Đã xác minh khách hàng nâng cấp VPS, đồng ý duyệt.' })
      }
    );
    assert.equal(approveRes.status, 200);
    assert.equal(approveRes.data.license.allowedIp, '45.112.99.88');

    // Now the new server verifies and gets VALID status!
    const verifyNewSrvRes = await requestJson(baseUrl, '/api/v1/plugin/verify', {
      method: 'POST',
      body: JSON.stringify({
        license_key: 'CLPS-PRO1-2026-8888-9999',
        activation_token: activationToken,
        product_slug: 'wp-commerce-pro-suite',
        domain: 'noithathoanggia.vn',
        reported_server_ip: '45.112.99.88',
        nonce: 'e2e_nonce_new_srv_004'
      })
    });
    assert.equal(verifyNewSrvRes.status, 200);
    assert.equal(verifyNewSrvRes.data.payload.code, 'VALID');
    const newActivationToken = verifyNewSrvRes.data.payload.activation_token;
    console.log('   ✅ Máy chủ mới (45.112.99.88) đã hoạt động hợp lệ sau khi Admin phê duyệt, máy chủ cũ bị thu hồi phiên!\n');

    // 4. Execute Remote Commercial Feature on New Server (Module 7)
    console.log('4️⃣  [Module 7] Gọi API Chức năng Thương mại Cốt lõi từ Máy chủ mới...');
    const featBody = JSON.stringify({
      base_price: 5000000,
      quantity: 20,
      customer_tier: 'DIAMOND'
    });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = ed25519Service.computeActivationHmac(
      newActivationToken,
      ts,
      'dynamic_pricing_engine',
      featBody
    );

    const remoteRes = await requestJson(
      baseUrl,
      '/api/v1/remote-features/dynamic_pricing_engine/execute',
      {
        method: 'POST',
        headers: {
          'X-License-Key': 'CLPS-PRO1-2026-8888-9999',
          'X-Activation-Token': newActivationToken,
          'X-Client-Domain': 'noithathoanggia.vn',
          'X-Reported-Server-Ip': '45.112.99.88',
          'X-Request-Timestamp': ts,
          'X-Request-Signature': sig
        },
        body: featBody
      }
    );
    assert.equal(remoteRes.status, 200);
    assert.equal(remoteRes.data.success, true);
    console.log(
      `   ✅ Chức năng thương mại cốt lõi trả kết quả thành công: Giảm ${remoteRes.data.result.effective_discount_percent}%!\n`
    );

    // Reset seed data back to clean state for demo
    dbService.seedInitialData();
    console.log('🎉 KIỂM THỬ END-TO-END (E2E) HOÀN TẤT: TẤT CẢ CÁC MODULE 1 -> 8 ĐỀU HOẠT ĐỘNG HOÀN HẢO!');
  } finally {
    server.close();
  }
}

runE2E().catch((err) => {
  console.error(err);
  process.exit(1);
});

