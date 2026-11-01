-- ==========================================================
-- POSTGRESQL INITIAL MIGRATION (001_init_postgresql.sql)
-- Dự án: WordPress License Protection System
-- ==========================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

DO $$ BEGIN
    CREATE TYPE staff_role AS ENUM ('SUPER_ADMIN', 'MANAGER', 'SUPPORT');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE license_status AS ENUM ('ACTIVE', 'INACTIVE', 'EXPIRED', 'SUSPENDED', 'REVOKED');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE activation_status AS ENUM ('ACTIVE', 'DEACTIVATED', 'REVOKED_BY_TRANSFER');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE transfer_request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE validation_action AS ENUM ('ACTIVATE', 'VERIFY', 'DEACTIVATE', 'REMOTE_FEATURE', 'TRANSFER_REQ');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- 1. Bảng Nhân viên Quản trị (Users / Staff RBAC)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(191) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name VARCHAR(191) NOT NULL,
    role staff_role NOT NULL DEFAULT 'SUPPORT',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Bảng Khách hàng (Customers)
CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(191) NOT NULL,
    email VARCHAR(191) NOT NULL UNIQUE,
    phone VARCHAR(50),
    company VARCHAR(191),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Bảng Sản phẩm WordPress (Products)
CREATE TABLE IF NOT EXISTS products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(120) NOT NULL UNIQUE,
    name VARCHAR(191) NOT NULL,
    current_version VARCHAR(40) NOT NULL DEFAULT '1.0.0',
    commercial_features JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_max_activations INT NOT NULL DEFAULT 1,
    default_max_transfers INT NOT NULL DEFAULT 3,
    grace_period_hours INT NOT NULL DEFAULT 72,
    download_url TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Bảng Bản quyền (Licenses)
CREATE TABLE IF NOT EXISTS licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_key VARCHAR(64) NOT NULL UNIQUE,
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    status license_status NOT NULL DEFAULT 'INACTIVE',
    allowed_domain VARCHAR(255),
    allowed_ip VARCHAR(100),
    strict_ip_check BOOLEAN NOT NULL DEFAULT TRUE,
    treat_www_as_same BOOLEAN NOT NULL DEFAULT TRUE,
    max_activations INT NOT NULL DEFAULT 1,
    max_transfers INT NOT NULL DEFAULT 3,
    transfer_count INT NOT NULL DEFAULT 0,
    starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    custom_features JSONB,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_licenses_customer ON licenses(customer_id);
CREATE INDEX IF NOT EXISTS idx_licenses_product ON licenses(product_id);
CREATE INDEX IF NOT EXISTS idx_licenses_status_expires ON licenses(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_licenses_domain ON licenses(allowed_domain);

-- 5. Bảng Phiên Kích hoạt (License Activations)
CREATE TABLE IF NOT EXISTS license_activations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    activation_token VARCHAR(128) NOT NULL UNIQUE,
    domain VARCHAR(255) NOT NULL,
    server_ip VARCHAR(100) NOT NULL,
    wp_version VARCHAR(40),
    php_version VARCHAR(40),
    plugin_version VARCHAR(40),
    status activation_status NOT NULL DEFAULT 'ACTIVE',
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activations_license_status ON license_activations(license_id, status);

-- 6. Bảng Yêu cầu Chuyển Máy chủ (Server Transfer Requests)
CREATE TABLE IF NOT EXISTS server_transfer_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    old_domain VARCHAR(255),
    old_ip VARCHAR(100),
    new_domain VARCHAR(255) NOT NULL,
    new_ip VARCHAR(100) NOT NULL,
    reason TEXT NOT NULL,
    status transfer_request_status NOT NULL DEFAULT 'PENDING',
    reviewed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    review_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_transfer_requests_license_status ON server_transfer_requests(license_id, status);

-- 7. Bảng Nhật ký Xác thực từ Plugin (Validation Logs)
CREATE TABLE IF NOT EXISTS validation_logs (
    id BIGSERIAL PRIMARY KEY,
    license_id UUID REFERENCES licenses(id) ON DELETE SET NULL,
    license_key_attempt VARCHAR(64) NOT NULL,
    request_domain VARCHAR(255) NOT NULL,
    detected_outbound_ip VARCHAR(100) NOT NULL,
    reported_server_ip VARCHAR(100),
    action validation_action NOT NULL,
    is_valid BOOLEAN NOT NULL,
    failure_reason VARCHAR(120),
    user_agent VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_validation_logs_license_created ON validation_logs(license_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_validation_logs_valid_created ON validation_logs(is_valid, created_at DESC);

-- 8. Bảng Nhật ký Thay đổi License (License Audit Logs)
CREATE TABLE IF NOT EXISTS license_audit_logs (
    id BIGSERIAL PRIMARY KEY,
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(80) NOT NULL,
    old_value JSONB,
    new_value JSONB,
    ip_address VARCHAR(100),
    note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_license_created ON license_audit_logs(license_id, created_at DESC);

-- 9. Bảng Nhật ký Sử dụng Chức năng Thương mại Cốt lõi (Remote Feature Usage Logs - Module 7)
CREATE TABLE IF NOT EXISTS remote_feature_usage_logs (
    id BIGSERIAL PRIMARY KEY,
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    feature_code VARCHAR(100) NOT NULL,
    execution_ms INT NOT NULL,
    status VARCHAR(40) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_remote_feature_logs_license_created ON remote_feature_usage_logs(license_id, created_at DESC);

