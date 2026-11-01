<?php
/**
 * KIỂM THỬ TÍCH HỢP CHÉO PHP (WORDPRESS PLUGIN) <-> NODE.JS (LIVE CENTRAL SERVER PORT 4000)
 * Thực thi trực tiếp bằng c:\xampp\php\php.exe
 */

define( 'ABSPATH', 'C:/xampp/htdocs/andesec.vn/' );
define( 'WPINC', 'wp-includes' );
define( 'CLPS_VERSION', '1.0.0' );
define( 'CLPS_PLUGIN_FILE', __FILE__ );
define( 'CLPS_ED25519_PUBLIC_KEY', '3QsaLZpyfFwjIztVPzRO1FOQtgn56FM/5qsbsg7avLg=' );
define( 'CLPS_DEFAULT_SERVER_URL', 'http://localhost:4000' );
define( 'CLPS_DEFAULT_PRODUCT_SLUG', 'wp-commerce-pro-suite' );

// Mock WordPress core functions for standalone CLI verification
$GLOBALS['mock_wp_options'] = array();
$GLOBALS['mock_home_url']   = 'https://www.noithathoanggia.vn';
$_SERVER['SERVER_ADDR']     = '103.56.158.10';

function get_option( $key, $default = false ) {
	return array_key_exists( $key, $GLOBALS['mock_wp_options'] ) ? $GLOBALS['mock_wp_options'][ $key ] : $default;
}
function update_option( $key, $val, $autoload = true ) {
	$GLOBALS['mock_wp_options'][ $key ] = $val;
	return true;
}
function delete_option( $key ) {
	unset( $GLOBALS['mock_wp_options'][ $key ] );
	return true;
}
function home_url() {
	return $GLOBALS['mock_home_url'];
}
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component );
}
function sanitize_text_field( $str ) {
	return trim( strip_tags( (string) $str ) );
}
function sanitize_textarea_field( $str ) {
	return trim( strip_tags( (string) $str ) );
}
function sanitize_title( $str ) {
	return strtolower( trim( (string) $str ) );
}
function esc_url_raw( $url ) {
	return trim( (string) $url );
}
function wp_unslash( $val ) {
	return $val;
}
function current_time( $type ) {
	return date( 'Y-m-d H:i:s' );
}
function get_bloginfo( $show ) {
	return '6.7.2';
}
function wp_json_encode( $data, $options = 0 ) {
	return json_encode( $data, $options );
}
function add_shortcode( $tag, $callback ) {}
function is_wp_error( $thing ) {
	return is_array( $thing ) && ! empty( $thing['is_wp_error'] );
}
function wp_remote_post( $url, $args = array() ) {
	$ch = curl_init( $url );
	curl_setopt( $ch, CURLOPT_POST, true );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	curl_setopt( $ch, CURLOPT_TIMEOUT, $args['timeout'] ?? 15 );
	$headers = array();
	if ( ! empty( $args['headers'] ) ) {
		foreach ( $args['headers'] as $k => $v ) {
			$headers[] = "$k: $v";
		}
	}
	curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );
	curl_setopt( $ch, CURLOPT_POSTFIELDS, $args['body'] ?? '' );
	$body = curl_exec( $ch );
	$err  = curl_error( $ch );
	$code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	if ( false === $body ) {
		return array( 'is_wp_error' => true, 'error_message' => $err );
	}
	return array( 'body' => $body, 'response' => array( 'code' => $code ) );
}
function wp_remote_retrieve_body( $response ) {
	return $response['body'] ?? '';
}

// Load real WordPress Plugin classes
$plugin_dir = dirname( __DIR__, 2 ) . '/wordpress-plugin/company-license-protection/includes/';
require_once $plugin_dir . 'class-clps-environment.php';
require_once $plugin_dir . 'class-clps-crypto-verifier.php';
require_once $plugin_dir . 'class-clps-license-client.php';
require_once $plugin_dir . 'class-clps-remote-features.php';

echo "==============================================================\n";
echo "🐘 KIỂM THỬ THỰC TẾ WORDPRESS PLUGIN (PHP) <-> NODE.JS SERVER\n";
echo "==============================================================\n\n";

$client          = new CLPS_License_Client();
$remote_features = new CLPS_Remote_Features( $client );

// 1. Kích hoạt License từ PHP sang http://localhost:4000
echo "1. [PHP -> Node.js] Kích hoạt License CLPS-PRO1-2026-8888-9999 trên domain noithathoanggia.vn...\n";
$act_res = $client->activate_license(
	'CLPS-PRO1-2026-8888-9999',
	'http://localhost:4000',
	'wp-commerce-pro-suite'
);

if ( ! $act_res['success'] ) {
	fwrite( STDERR, "FAILED ACTIVATION: " . print_r( $act_res, true ) );
	exit( 1 );
}
echo "   ✅ PHP xác minh chữ ký Ed25519 thành công! Trạng thái: " . $act_res['code'] . " | Token: " . $act_res['payload']['activation_token'] . "\n\n";

// 2. Kiểm tra hàm kiểm tra quyền thương mại
echo "2. [PHP Local Check] Kiểm tra trạng thái tính năng thương mại từ chứng chỉ đã ký...\n";
if ( ! $client->is_license_currently_valid( 'dynamic_pricing_engine' ) ) {
	fwrite( STDERR, "FAILED FEATURE VALIDITY CHECK\n" );
	exit( 1 );
}
echo "   ✅ Tính năng 'dynamic_pricing_engine' được phép hoạt động!\n\n";

// 3. Gọi thực thi Module 7 từ PHP sang Node.js
echo "3. [PHP -> Node.js Module 7] Gọi thuật toán thương mại cốt lõi từ xa (kèm lọc bỏ PII)...\n";
$feat_res = $remote_features->execute_feature(
	'dynamic_pricing_engine',
	array(
		'base_price'         => 2000000,
		'quantity'           => 10,
		'customer_tier'      => 'PLATINUM',
		'customer_full_name' => 'Nguyễn Văn A (Dữ liệu PII nhạy cảm sẽ bị lọc tự động)',
	)
);
if ( empty( $feat_res['success'] ) ) {
	fwrite( STDERR, "FAILED REMOTE FEATURE: " . print_r( $feat_res, true ) );
	exit( 1 );
}
echo "   ✅ Module 7 trả kết quả về PHP thành công! Thành tiền sau chiết khấu: " . number_format( $feat_res['result']['final_payable_vnd'] ) . " VNĐ\n\n";

// 4. Mô phỏng khách hàng copy code sang tên miền lậu
echo "4. [Chống Sao Chép] Mô phỏng khách copy source code sang tên miền khác (web-copy-lau.vn)...\n";
$GLOBALS['mock_home_url'] = 'https://web-copy-lau.vn';
$status_after_clone       = $client->get_verified_status();
if ( false !== $status_after_clone['is_valid'] || 'ENV_MISMATCH' !== $status_after_clone['code'] ) {
	fwrite( STDERR, "FAILED CLONE DETECTION: " . print_r( $status_after_clone, true ) );
	exit( 1 );
}
echo "   ✅ Plugin phát hiện ngay lập tức: " . $status_after_clone['message'] . "\n";
echo "   ✅ Các chức năng thương mại lập tức bị khóa an toàn!\n\n";

echo "🎉 TẤT CẢ KIỂM THỬ THỰC TẾ GIỮA PHP WORDPRESS PLUGIN & NODE.JS SERVER ĐỀU PASS 100%!\n";
