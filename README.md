# HỆ THỐNG BẢO VỆ BẢN QUYỀN WEBSITE WORDPRESS (WORDPRESS LICENSE PROTECTION SYSTEM)

Hệ thống quản lý cấp phép bản quyền tập trung đa lớp dành cho đơn vị phát triển website WordPress, bao gồm đầy đủ **8 Module**:
1. **Module 1 — Central License Server & Admin Dashboard:** Quản lý khách hàng, sản phẩm, tạo/kích hoạt/gia hạn/tạm ngừng/thu hồi license, đổi tên miền/IP, giới hạn số website, duyệt chuyển máy chủ, lịch sử xác thực, audit log, phân quyền nhân viên RBAC (`SUPER_ADMIN`, `MANAGER`, `SUPPORT`) và cảnh báo license sắp hết hạn.
2. **Module 2 — WordPress License Plugin (`Company License Protection`):** Quản lý kích hoạt, hiển thị trạng thái, kiểm tra định kỳ, yêu cầu chuyển máy chủ, nhật ký lỗi quản trị và cập nhật plugin an toàn.
3. **Module 3 — Kiểm soát Tên miền & IP Máy chủ:** Chuẩn hóa tên miền (IDN/Punycode, `www`/non-`www`), phân biệt IP máy chủ (`SERVER_ADDR` / Outbound Socket IP) với IP người dùng truy cập, chống giả mạo header IP.
4. **Module 4 — Chữ ký số Bất đối xứng Ed25519:** `Private Key` chỉ nằm trên Central License Server; WordPress Plugin chỉ chứa `Public Key` (32-byte Base64, xác minh bằng `sodium_crypto_sign_verify_detached`). Chống giả mạo JSON và chống phát lại (Replay Attack) bằng `nonce` + `iat` + `exp`.
5. **Module 5 — Kiểm tra Định kỳ (WP-Cron 12h) & Grace Period (72h):** Không gọi License Server trong mỗi lượt tải trang. Khi Server bảo trì hoặc đứt mạng, website tự động duy trì hoạt động trong 72 giờ dự phòng (Grace Period).
6. **Module 6 — Quy trình Chuyển Máy chủ Có Phê duyệt:** Khách hàng gửi yêu cầu chuyển server từ WP Admin -> Dashboard thông báo -> Quản trị viên duyệt 1-click -> Tự động thu hồi phiên máy chủ cũ và kích hoạt máy chủ mới.
7. **Module 7 — Giữ Chức năng Thương mại Cốt lõi trên Server Công ty:** Các thuật toán thương mại (`dynamic_pricing_engine`, `advanced_analytics_report`, `mortgage_amortization_engine`) chạy trên máy chủ công ty, bảo vệ bằng chữ ký động `HMAC-SHA256` theo `activation_token`, tuân thủ nguyên tắc tối thiểu hóa dữ liệu (chặn PII, xử lý In-Memory 0 giây lưu trữ).
8. **Module 8 — Chính sách An toàn khi License Hết hạn / Vi phạm:** Không xóa dữ liệu, không tạo backdoor, không phá giao diện cơ bản; chỉ khóa các chức năng thương mại cốt lõi, chặn cập nhật và hiển thị hướng dẫn gia hạn/chuyển máy chủ.

---

## 1. CẤU TRÚC THƯ MỤC DỰ ÁN (`c:\xampp\htdocs\cms-license`)

```text
c:\xampp\htdocs\cms-license\
├── docker-compose.yml                         # Triển khai nhanh PostgreSQL + License Server trên VPS
├── README.md                                  # Tài liệu hướng dẫn vận hành & tích hợp
├── license-server\                            # MODULE 1, 3, 4, 6, 7: Central License Server & Dashboard
│   ├── Dockerfile
│   ├── package.json
│   ├── prisma\schema.prisma                   # Prisma Schema cho PostgreSQL (9 bảng)
│   ├── database\migrations\001_init_postgresql.sql
│   ├── public\                                # Giao diện Quản trị Tập trung (Central Dashboard SPA)
│   │   ├── index.html
│   │   └── app.js
│   ├── scripts\
│   │   ├── generate-keys.ts                   # Công cụ sinh cặp khóa Ed25519 mới
│   │   ├── test-phase2.ts                     # Kiểm thử Mật mã Ed25519 & Domain/IP
│   │   ├── test-phase3.ts                     # Kiểm thử Module 7 Remote Core Engine
│   │   └── test-e2e.ts                        # Kiểm thử Tích hợp Toàn diện (End-to-End)
│   └── src\
│       ├── main.ts                            # Điểm khởi chạy Server (Port 4000)
│       ├── crypto\ed25519.service.ts          # Ký & xác thực Ed25519 + HMAC-SHA256
│       ├── utils\network-normalizer.ts        # Chuẩn hóa Domain & Chống giả mạo IP
│       ├── database\db.service.ts             # Quản lý dữ liệu & Seed Data mẫu
│       ├── services\
│       │   ├── license-validation.service.ts  # Nghiệp vụ Kích hoạt, Xác thực, Chuyển Server
│       │   └── remote-feature.service.ts      # Nghiệp vụ Module 7 (Thực thi tính năng từ xa)
│       └── routes\
│           ├── plugin-api.routes.ts           # REST API cho WordPress Plugin
│           ├── remote-feature.routes.ts       # REST API cho Chức năng Thương mại Cốt lõi
│           └── admin-api.routes.ts            # REST API cho Dashboard Quản trị (RBAC)
└── wordpress-plugin\
    └── company-license-protection\            # MODULE 2, 3, 4, 5, 6, 7, 8: WordPress Plugin
        ├── company-license-protection.php     # File khởi chạy Plugin & Helper Functions
        └── includes\
            ├── class-clps-environment.php     # Chuẩn hóa Domain & lấy IP Máy chủ đáng tin cậy
            ├── class-clps-crypto-verifier.php # Xác minh chữ ký Ed25519 bằng PHP ext-sodium
            ├── class-clps-license-client.php  # Giao tiếp License Server, Grace Period & Log
            ├── class-clps-cron-updater.php    # WP-Cron 12h & Cập nhật Plugin an toàn
            ├── class-clps-remote-features.php # SDK gọi Module 7 & Shortcodes thương mại
            └── class-clps-admin-ui.php        # Giao diện Quản trị trong WordPress Admin
```

---

## 2. HƯỚNG DẪN CHẠY THỬ NGHIỆM TRỰC TIẾP (LOCAL / XAMPP)

### Bước 1: Khởi chạy Central License Server & Dashboard
Mở Terminal tại `c:\xampp\htdocs\cms-license\license-server`:
```powershell
cd c:\xampp\htdocs\cms-license\license-server
npm run dev
```
- **Central License Server & Dashboard UI** sẽ chạy tại: `http://localhost:4000`
- **Tài khoản đăng nhập Dashboard mẫu (RBAC):**
  - **Super Admin:** `admin@company.vn` / `Admin@123456`
  - **Manager:** `manager@company.vn` / `Manager@123`
  - **Support:** `support@company.vn` / `Support@123`
- **Mã License Key mẫu có sẵn:**
  - `CLPS-PRO1-2026-8888-9999` (Đang `ACTIVE`, tên miền `noithathoanggia.vn`, IP `103.56.158.10`)
  - `CLPS-RE26-7777-6666-5555` (Đang `ACTIVE`, sắp hết hạn trong 10 ngày, tên miền `bdsdongnama.vn`, IP `127.0.0.1`)
  - `CLPS-EXP0-2025-1111-2222` (Đã hết hạn `EXPIRED`)

### Bước 2: Cài đặt WordPress Plugin
1. Sao chép thư mục `c:\xampp\htdocs\cms-license\wordpress-plugin\company-license-protection` vào thư mục `wp-content/plugins/company-license-protection` của website WordPress.
2. Truy cập **WP Admin -> Plugins** và bấm **Activate (Kích hoạt)** plugin **Company License Protection**.
3. Truy cập menu **Bản quyền Website** trên thanh menu trái của WP Admin để nhập License Key, kiểm tra chữ ký số Ed25519, gửi yêu cầu chuyển máy chủ hoặc test gọi API Chức năng Thương mại Cốt lõi (Module 7).

### Bước 3: Sử dụng trong Source Code Thương mại bàn giao cho khách
Trong theme hoặc plugin thương mại của công ty bạn:
```php
// 1. Kiểm tra bản quyền trước khi cho phép chạy nghiệp vụ thương mại tại chỗ:
if ( function_exists( 'clps_is_commercial_feature_enabled' ) && clps_is_commercial_feature_enabled( 'dynamic_pricing_engine' ) ) {
    // Thực thi tính năng thương mại
}

// 2. Gọi thuật toán độc quyền đặt trên máy chủ công ty (Module 7):
$pricing = clps_execute_remote_feature( 'dynamic_pricing_engine', array(
    'base_price'    => 2500000,
    'quantity'      => 10,
    'customer_tier' => 'PLATINUM',
) );
if ( ! empty( $pricing['success'] ) ) {
    echo $pricing['result']['pricing_badge_html'];
}
```
Hoặc nhúng trực tiếp Shortcode thương mại vào bài viết/trang WordPress:
- `[clps_vip_pricing_calculator base_price="2500000" quantity="10" tier="PLATINUM"]`
- `[clps_mortgage_calculator principal="2000000000" rate="8.5" months="180"]`
*(Nếu license hết hạn hoặc bị thu hồi, shortcode sẽ tự động ẩn/hiển thị thông báo khóa an toàn cho Admin mà không làm lỗi trang).*

