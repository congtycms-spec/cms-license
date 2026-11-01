<?php
/**
 * Plugin Name:       Company License Protection
 * Plugin URI:        https://company.vn/license-protection
 * Description:       Hệ thống bảo vệ bản quyền website WordPress đa lớp: Xác thực chữ ký số bất đối xứng Ed25519, kiểm soát Tên miền & IP máy chủ, quản lý chuyển máy chủ có phê duyệt và thực thi chức năng thương mại cốt lõi từ xa.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            Company Software Architecture Team
 * Text Domain:       company-license-protection
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

define( 'CLPS_VERSION', '1.0.0' );
define( 'CLPS_PLUGIN_FILE', __FILE__ );
define( 'CLPS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'CLPS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * MODULE 4: Public Signing Key (Ed25519 32-byte raw Base64).
 * LƯU Ý BẢO MẬT: Chỉ nhúng PUBLIC KEY trong mã nguồn WordPress bàn giao.
 * Tuyệt đối KHÔNG BAO GIỜ lưu Private Key hoặc Master Secret tại đây.
 */
if ( ! defined( 'CLPS_ED25519_PUBLIC_KEY' ) ) {
	define( 'CLPS_ED25519_PUBLIC_KEY', '3QsaLZpyfFwjIztVPzRO1FOQtgn56FM/5qsbsg7avLg=' );
}

if ( ! defined( 'CLPS_DEFAULT_SERVER_URL' ) ) {
	define( 'CLPS_DEFAULT_SERVER_URL', 'http://localhost:4000' );
}

if ( ! defined( 'CLPS_DEFAULT_PRODUCT_SLUG' ) ) {
	define( 'CLPS_DEFAULT_PRODUCT_SLUG', 'wp-commerce-pro-suite' );
}

// Nạp các lớp thành phần cốt lõi
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-environment.php';
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-crypto-verifier.php';
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-license-client.php';
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-cron-updater.php';
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-remote-features.php';
require_once CLPS_PLUGIN_DIR . 'includes/class-clps-admin-ui.php';

/**
 * Khởi tạo hệ thống bảo vệ bản quyền.
 */
final class Company_License_Protection {
	private static ?Company_License_Protection $instance = null;

	public CLPS_License_Client $client;
	public CLPS_Cron_Updater $cron_updater;
	public CLPS_Remote_Features $remote_features;
	public CLPS_Admin_UI $admin_ui;

	public static function instance(): Company_License_Protection {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->client          = new CLPS_License_Client();
		$this->cron_updater    = new CLPS_Cron_Updater( $this->client );
		$this->remote_features = new CLPS_Remote_Features( $this->client );
		$this->admin_ui        = new CLPS_Admin_UI( $this->client, $this->remote_features );
	}
}

/**
 * Hook khi kích hoạt plugin: Lập lịch WP-Cron kiểm tra định kỳ 12 giờ.
 */
register_activation_hook(
	__FILE__,
	function () {
		CLPS_Cron_Updater::activate_schedule();
	}
);

/**
 * Hook khi hủy kích hoạt plugin: Hủy lịch WP-Cron.
 */
register_deactivation_hook(
	__FILE__,
	function () {
		CLPS_Cron_Updater::deactivate_schedule();
	}
);

add_action(
	'plugins_loaded',
	function () {
		Company_License_Protection::instance();
	}
);

/**
 * Helper toàn cục để các theme / plugin thương mại của công ty kiểm tra bản quyền.
 */
function clps_is_commercial_feature_enabled( ?string $feature_code = null ): bool {
	return Company_License_Protection::instance()->client->is_license_currently_valid( $feature_code );
}

/**
 * Helper toàn cục để gọi chức năng thương mại cốt lõi chạy trên máy chủ công ty (Module 7).
 */
function clps_execute_remote_feature( string $feature_code, array $payload = array() ): array {
	return Company_License_Protection::instance()->remote_features->execute_feature( $feature_code, $payload );
}

