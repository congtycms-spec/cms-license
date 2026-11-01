<?php
/**
 * KIỂM THỬ THỰC TẾ MODULE TÀNG HÌNH & CHỐNG GỠ BỎ (STEALTH & ZERO-UI AUTO-BIND)
 * Thực thi trực tiếp bằng c:\xampp\php\php.exe
 */

define( 'ABSPATH', 'C:/xampp/htdocs/andesec.vn/' );
define( 'WPINC', 'wp-includes' );

$GLOBALS['mock_wp_options'] = array();
$GLOBALS['mock_home_url']   = 'https://www.gofresh.vn';
$_SERVER['SERVER_ADDR']     = '103.221.223.75';

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
function get_bloginfo( $show ) {
	return '6.7.2';
}
function wp_json_encode( $data, $options = 0 ) {
	return json_encode( $data, $options );
}
function add_action( $tag, $callback, $priority = 10 ) {}
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

echo "==============================================================\n";
echo "🕵️ KIỂM THỬ MODULE TÀNG HÌNH (STEALTH & ZERO-UI AUTO-BIND)\n";
echo "==============================================================\n\n";

$stealth_file = dirname( __DIR__, 2 ) . '/wordpress-plugin/stealth-theme-embed/class-wp-block-hydrator.php';
$raw_source   = file_get_contents( $stealth_file );

// 1. Kiểm tra chống tìm kiếm từ khóa (Anti-Grep / Anti-Find-in-Files)
echo "1. [Anti-Search] Kiểm tra kỹ thuật viên tìm từ khóa 'license', 'clps', 'localhost:4000' trong file PHP...\n";
$forbidden_keywords = array( 'license', 'clps', 'localhost:4000', 'auto-bind', 'ed25519' );
foreach ( $forbidden_keywords as $kw ) {
	if ( false !== stripos( $raw_source, $kw ) ) {
		fwrite( STDERR, "FAILED STEALTH CHECK: Found keyword '$kw' in stealth file!\n" );
		exit( 1 );
	}
}
echo "   ✅ Hoàn toàn không có bất kỳ từ khóa 'license', 'clps', 'ed25519' hay URL Server nào trong mã nguồn!\n\n";

// 2. Nạp file tàng hình và tự động kích hoạt ngầm theo tên miền (Zero-UI)
require_once $stealth_file;

echo "2. [Zero-UI Auto-Bind] Tự động nhận diện tên miền gofresh.vn (IP: 103.221.223.75) mà không cần nhập License Key...\n";
if ( ! wp_theme_is_hydrated( 'dynamic_pricing_engine' ) ) {
	fwrite( STDERR, "FAILED ZERO-UI AUTO-BIND!\n" );
	exit( 1 );
}
$runtime_salt = wp_theme_runtime_token( 'runtime_salt' );
$render_sig   = wp_theme_runtime_token( 'render_signature' );
echo "   ✅ Tự động kích hoạt ngầm qua API thành công!\n";
echo "   ✅ Runtime Salt cấp cho Theme: " . $runtime_salt . " | Render Signature: " . $render_sig . "\n\n";

// 3. Gọi tính năng thương mại từ xa (Module 7) qua giao thức tàng hình
echo "3. [Remote Core API] Thực thi tính năng độc quyền trên Server trung tâm...\n";
$remote_res = wp_theme_remote_compute(
	'dynamic_pricing_engine',
	array(
		'base_price'    => 3000000,
		'quantity'      => 5,
		'customer_tier' => 'PLATINUM',
	)
);
if ( empty( $remote_res['success'] ) ) {
	fwrite( STDERR, "FAILED STEALTH REMOTE COMPUTE: " . print_r( $remote_res, true ) );
	exit( 1 );
}
echo "   ✅ Tính toán thành công từ Server! Giá sau chiết khấu: " . number_format( $remote_res['result']['final_payable_vnd'] ) . " VNĐ\n\n";

// 4. Mô phỏng copy sang tên miền chưa đăng ký trên Dashboard
echo "4. [Anti-Clone] Mô phỏng copy bộ Theme sang tên miền chưa cấp phép (web-chua-dang-ky.vn)...\n";
$GLOBALS['mock_home_url'] = 'https://web-chua-dang-ky.vn';
if ( false !== wp_theme_is_hydrated() || '' !== wp_theme_runtime_token( 'runtime_salt' ) ) {
	fwrite( STDERR, "FAILED CLONE BLOCKING IN STEALTH MODE!\n" );
	exit( 1 );
}
echo "   ✅ Token cấu hình lập tức bị thu hồi về rỗng ('') và các tính năng bị vô hiệu hóa ngầm!\n\n";

echo "🎉 KIỂM THỬ CHẾ ĐỘ TÀNG HÌNH & CHỐNG GỠ BỎ THÀNH CÔNG 100%!\n";
