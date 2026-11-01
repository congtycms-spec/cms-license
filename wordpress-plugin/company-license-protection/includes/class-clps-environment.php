<?php
/**
 * MODULE 3: Kiểm soát IP và Tên miền (Domain & Server IP Normalizer & Detector).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_Environment {

	/**
	 * Chuẩn hóa tên miền trước khi so sánh (Module 3):
	 * - Bỏ http://, https://, port, path
	 * - Chuyển về chữ thường
	 * - Hỗ trợ tên miền tiếng Việt (IDN Punycode)
	 * - Xử lý www và non-www theo cấu hình
	 */
	public static function get_normalized_domain( ?string $custom_url = null, bool $strip_www = true ): string {
		$raw_url = $custom_url ? $custom_url : home_url();
		$raw_url = trim( strtolower( $raw_url ) );

		if ( false === strpos( $raw_url, '://' ) ) {
			$raw_url = 'https://' . $raw_url;
		}

		$parsed_host = wp_parse_url( $raw_url, PHP_URL_HOST );
		if ( ! $parsed_host ) {
			$parsed_host = preg_replace( '#^https?://#', '', $raw_url );
			$parsed_host = explode( '/', $parsed_host )[0];
			$parsed_host = explode( ':', $parsed_host )[0];
		}

		$parsed_host = rtrim( $parsed_host, '.' );

		if ( function_exists( 'idn_to_ascii' ) ) {
			$ascii = idn_to_ascii( $parsed_host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46 );
			if ( $ascii ) {
				$parsed_host = strtolower( $ascii );
			}
		}

		if ( $strip_www && 0 === strpos( $parsed_host, 'www.' ) && substr_count( $parsed_host, '.' ) >= 2 ) {
			$parsed_host = substr( $parsed_host, 4 );
		}

		return $parsed_host;
	}

	/**
	 * Xác định IP của chính máy chủ WordPress (Module 3):
	 * - Phân biệt rõ IP máy chủ (SERVER_ADDR) với IP người truy cập (REMOTE_ADDR / HTTP_X_FORWARDED_FOR).
	 * - Tuyệt đối không lấy IP từ HTTP header do người truy cập có thể giả mạo.
	 */
	public static function get_reliable_server_ip(): string {
		// 1. Cho phép quản trị viên cấu hình cứng IP máy chủ trong wp-config.php nếu đứng sau NAT/Reverse Proxy đặc thù
		if ( defined( 'CLPS_TRUSTED_SERVER_IP' ) && filter_var( CLPS_TRUSTED_SERVER_IP, FILTER_VALIDATE_IP ) ) {
			return CLPS_TRUSTED_SERVER_IP;
		}

		// 2. Lấy trực tiếp từ biến môi trường của Web Server (Apache/Nginx/LiteSpeed)
		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			$srv_ip = trim( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) );
			if ( '::1' === $srv_ip ) {
				return '127.0.0.1';
			}
			if ( filter_var( $srv_ip, FILTER_VALIDATE_IP ) ) {
				return $srv_ip;
			}
		}

		// 3. Fallback qua hostname hệ điều hành của máy chủ
		$hostname = php_uname( 'n' );
		if ( $hostname ) {
			$resolved = gethostbyname( $hostname );
			if ( filter_var( $resolved, FILTER_VALIDATE_IP ) ) {
				return $resolved;
			}
		}

		return '127.0.0.1';
	}

	/**
	 * Tạo mã băm (Fingerprint) của môi trường hiện tại (Domain + Server IP)
	 * để phát hiện ngay lập tức khi khách hàng sao chép source code sang máy chủ khác hoặc đổi tên miền.
	 */
	public static function get_environment_fingerprint(): string {
		$domain = self::get_normalized_domain();
		$ip     = self::get_reliable_server_ip();
		return hash( 'sha256', $domain . '|' . $ip );
	}
}

