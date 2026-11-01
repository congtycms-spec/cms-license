<?php
/**
 * MODULE 2, 3, 5, 6: Quản lý kết nối Central License Server, Lưu trữ Chứng chỉ & Nhật ký Lỗi.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_License_Client {
	private const OPT_SERVER_URL      = 'clps_server_url';
	private const OPT_PRODUCT_SLUG    = 'clps_product_slug';
	private const OPT_LICENSE_KEY     = 'clps_license_key';
	private const OPT_SIGNED_ENVELOPE = 'clps_signed_envelope';
	private const OPT_ENV_FINGERPRINT = 'clps_env_fingerprint';
	private const OPT_ERROR_LOGS      = 'clps_admin_error_logs';
	private const OPT_LAST_CONN_ERROR = 'clps_last_connection_error';

	public function get_server_url(): string {
		$url = (string) get_option( self::OPT_SERVER_URL, CLPS_DEFAULT_SERVER_URL );
		return rtrim( $url ? $url : CLPS_DEFAULT_SERVER_URL, '/' );
	}

	public function get_product_slug(): string {
		$slug = (string) get_option( self::OPT_PRODUCT_SLUG, CLPS_DEFAULT_PRODUCT_SLUG );
		return $slug ? $slug : CLPS_DEFAULT_PRODUCT_SLUG;
	}

	public function get_license_key(): string {
		return (string) get_option( self::OPT_LICENSE_KEY, '' );
	}

	public function get_stored_envelope(): ?array {
		$env = get_option( self::OPT_SIGNED_ENVELOPE, null );
		return is_array( $env ) ? $env : null;
	}

	public function get_error_logs(): array {
		$logs = get_option( self::OPT_ERROR_LOGS, array() );
		return is_array( $logs ) ? $logs : array();
	}

	public function get_last_connection_error(): string {
		return (string) get_option( self::OPT_LAST_CONN_ERROR, '' );
	}

	/**
	 * Ghi nhật ký lỗi xác thực dành cho quản trị viên (Module 2 #8 & Module 4: Không để lộ secret trong log).
	 */
	public function log_admin_event( string $type, string $message ): void {
		$logs   = $this->get_error_logs();
		$logs[] = array(
			'time'    => current_time( 'mysql' ),
			'type'    => sanitize_text_field( $type ),
			'domain'  => CLPS_Environment::get_normalized_domain(),
			'ip'      => CLPS_Environment::get_reliable_server_ip(),
			'message' => sanitize_text_field( $message ),
		);

		if ( count( $logs ) > 50 ) {
			$logs = array_slice( $logs, -50 );
		}

		update_option( self::OPT_ERROR_LOGS, $logs, false );
	}

	/**
	 * Kích hoạt License trên Central License Server (Module 2).
	 */
	public function activate_license( string $license_key, ?string $server_url = null, ?string $product_slug = null ): array {
		if ( $server_url ) {
			update_option( self::OPT_SERVER_URL, esc_url_raw( rtrim( $server_url, '/' ) ) );
		}
		if ( $product_slug ) {
			update_option( self::OPT_PRODUCT_SLUG, sanitize_title( $product_slug ) );
		}

		$clean_key = strtoupper( trim( sanitize_text_field( $license_key ) ) );
		update_option( self::OPT_LICENSE_KEY, $clean_key );

		$nonce    = bin2hex( random_bytes( 16 ) );
		$endpoint = $this->get_server_url() . '/api/v1/plugin/activate';

		$body = array(
			'license_key'        => $clean_key,
			'product_slug'       => $this->get_product_slug(),
			'domain'             => CLPS_Environment::get_normalized_domain(),
			'reported_server_ip' => CLPS_Environment::get_reliable_server_ip(),
			'nonce'              => $nonce,
			'wp_version'         => get_bloginfo( 'version' ),
			'php_version'        => PHP_VERSION,
			'plugin_version'     => CLPS_VERSION,
		);

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			$err_msg = $response->get_error_message();
			update_option( self::OPT_LAST_CONN_ERROR, $err_msg );
			$this->log_admin_event( 'NETWORK_ERROR', 'Không thể kết nối License Server khi kích hoạt: ' . $err_msg );
			return array(
				'success' => false,
				'code'    => 'NETWORK_ERROR',
				'message' => 'Lỗi kết nối đến Central License Server: ' . $err_msg,
			);
		}

		delete_option( self::OPT_LAST_CONN_ERROR );
		$raw_body = wp_remote_retrieve_body( $response );
		$envelope = json_decode( $raw_body, true );

		if ( ! is_array( $envelope ) ) {
			$this->log_admin_event( 'INVALID_RESPONSE', 'Phản hồi từ Server không đúng định dạng JSON.' );
			return array(
				'success' => false,
				'code'    => 'INVALID_RESPONSE',
				'message' => 'Phản hồi từ License Server không hợp lệ.',
			);
		}

		$verified = CLPS_Crypto_Verifier::verify_signed_envelope( $envelope, $nonce, false );
		if ( ! $verified['valid'] ) {
			$this->log_admin_event( 'CRYPTO_VERIFY_FAILED', 'Xác minh chữ ký số Ed25519 thất bại: ' . $verified['reason'] );
			return array(
				'success' => false,
				'code'    => $verified['reason'],
				'message' => 'Cảnh báo bảo mật: Chữ ký số phản hồi không hợp lệ (' . $verified['reason'] . ').',
			);
		}

		$payload = $verified['payload'];
		update_option( self::OPT_SIGNED_ENVELOPE, $envelope, false );
		update_option( self::OPT_ENV_FINGERPRINT, CLPS_Environment::get_environment_fingerprint(), false );

		$is_activated = ( 'ACTIVE' === ( $payload['license_status'] ?? '' ) && in_array( $payload['code'] ?? '', array( 'ACTIVATED', 'VALID' ), true ) );
		if ( ! $is_activated ) {
			$this->log_admin_event(
				$payload['code'] ?? 'ACTIVATE_REJECTED',
				'Kích hoạt bị từ chối cho mã ' . CLPS_Crypto_Verifier::mask_secret( $clean_key ) . ': ' . ( $payload['message'] ?? '' )
			);
		} else {
			$this->log_admin_event( 'ACTIVATED', 'Kích hoạt thành công License ' . CLPS_Crypto_Verifier::mask_secret( $clean_key ) );
		}

		return array(
			'success' => $is_activated,
			'code'    => $payload['code'] ?? 'UNKNOWN',
			'message' => $payload['message'] ?? '',
			'payload' => $payload,
		);
	}

	/**
	 * Kiểm tra định kỳ hoặc kiểm tra thủ công (Module 5).
	 * Khi License Server gặp sự cố mạng: Không khóa website ngay lập tức mà áp dụng Grace Period 72h.
	 */
	public function verify_license(): array {
		$license_key = $this->get_license_key();
		if ( empty( $license_key ) ) {
			return array(
				'success' => false,
				'code'    => 'NO_LICENSE_KEY',
				'message' => 'Chưa nhập License Key.',
			);
		}

		$stored_env       = $this->get_stored_envelope();
		$activation_token = 'unactivated';
		if ( $stored_env && ! empty( $stored_env['payload']['activation_token'] ) ) {
			$activation_token = (string) $stored_env['payload']['activation_token'];
		}

		$nonce    = bin2hex( random_bytes( 16 ) );
		$endpoint = $this->get_server_url() . '/api/v1/plugin/verify';

		$body = array(
			'license_key'        => $license_key,
			'activation_token'   => $activation_token,
			'product_slug'       => $this->get_product_slug(),
			'domain'             => CLPS_Environment::get_normalized_domain(),
			'reported_server_ip' => CLPS_Environment::get_reliable_server_ip(),
			'nonce'              => $nonce,
		);

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			// MODULE 5: Phân biệt lỗi kết nối mạng với license hết hạn/thu hồi; kích hoạt chế độ dự phòng (Grace Period)
			$err_msg = $response->get_error_message();
			update_option( self::OPT_LAST_CONN_ERROR, $err_msg );
			$this->log_admin_event( 'SERVER_UNREACHABLE_GRACE_MODE', 'Mất kết nối License Server (' . $err_msg . '). Đang áp dụng thời gian dự phòng (Grace Period).' );

			return array(
				'success' => $this->is_license_currently_valid(),
				'code'    => 'GRACE_PERIOD_ACTIVE',
				'message' => 'Không thể kết nối License Server (' . $err_msg . '). Website đang hoạt động trong thời gian dự phòng an toàn (Grace Period).',
			);
		}

		delete_option( self::OPT_LAST_CONN_ERROR );
		$envelope = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $envelope ) ) {
			return array(
				'success' => $this->is_license_currently_valid(),
				'code'    => 'INVALID_SERVER_JSON',
				'message' => 'Phản hồi từ License Server không hợp lệ.',
			);
		}

		$verified = CLPS_Crypto_Verifier::verify_signed_envelope( $envelope, $nonce, false );
		if ( ! $verified['valid'] ) {
			$this->log_admin_event( 'VERIFY_SIGNATURE_FAILED', 'Chữ ký số không hợp lệ khi kiểm tra định kỳ: ' . $verified['reason'] );
			return array(
				'success' => false,
				'code'    => $verified['reason'],
				'message' => 'Không thể xác minh chữ ký số từ Server.',
			);
		}

		$payload = $verified['payload'];
		update_option( self::OPT_SIGNED_ENVELOPE, $envelope, false );
		update_option( self::OPT_ENV_FINGERPRINT, CLPS_Environment::get_environment_fingerprint(), false );

		$is_valid = ( 'ACTIVE' === ( $payload['license_status'] ?? '' ) && 'VALID' === ( $payload['code'] ?? '' ) );
		if ( ! $is_valid ) {
			$this->log_admin_event( $payload['code'] ?? 'VERIFY_FAILED', $payload['message'] ?? 'License không hợp lệ.' );
		}

		return array(
			'success' => $is_valid,
			'code'    => $payload['code'] ?? 'UNKNOWN',
			'message' => $payload['message'] ?? '',
			'payload' => $payload,
		);
	}

	/**
	 * Gửi yêu cầu chuyển máy chủ / đổi tên miền chờ Admin duyệt (Module 6).
	 */
	public function request_server_transfer( string $reason ): array {
		$license_key = $this->get_license_key();
		if ( empty( $license_key ) ) {
			return array(
				'success' => false,
				'message' => 'Vui lòng nhập License Key trước khi gửi yêu cầu chuyển máy chủ.',
			);
		}

		$nonce    = bin2hex( random_bytes( 16 ) );
		$endpoint = $this->get_server_url() . '/api/v1/plugin/transfer-request';

		$body = array(
			'license_key'        => $license_key,
			'product_slug'       => $this->get_product_slug(),
			'current_domain'     => CLPS_Environment::get_normalized_domain(),
			'reported_server_ip' => CLPS_Environment::get_reliable_server_ip(),
			'reason'             => sanitize_textarea_field( $reason ),
			'nonce'              => $nonce,
		);

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode( $body ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => 'Lỗi kết nối Server: ' . $response->get_error_message(),
			);
		}

		$envelope = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $envelope ) ) {
			return array(
				'success' => false,
				'message' => 'Phản hồi không hợp lệ từ Server.',
			);
		}

		$verified = CLPS_Crypto_Verifier::verify_signed_envelope( $envelope, $nonce, false );
		if ( ! $verified['valid'] ) {
			return array(
				'success' => false,
				'message' => 'Chữ ký số phản hồi không hợp lệ.',
			);
		}

		$payload = $verified['payload'];
		update_option( self::OPT_SIGNED_ENVELOPE, $envelope, false );
		$this->log_admin_event( 'TRANSFER_REQUEST_SENT', $payload['message'] ?? 'Đã gửi yêu cầu chuyển máy chủ.' );

		return array(
			'success' => ( 'TRANSFER_PENDING' === ( $payload['code'] ?? '' ) ),
			'code'    => $payload['code'] ?? '',
			'message' => $payload['message'] ?? '',
		);
	}

	/**
	 * Kiểm tra trạng thái hợp lệ hiện tại từ chứng chỉ đã ký (không gọi HTTP trên mỗi lượt tải trang - Module 5).
	 */
	public function get_verified_status(): array {
		$stored_env = $this->get_stored_envelope();
		if ( ! $stored_env ) {
			return array(
				'is_valid'        => false,
				'status'          => 'INACTIVE',
				'code'            => 'NOT_ACTIVATED',
				'message'         => 'Plugin chưa được kích hoạt bản quyền.',
				'in_grace_period' => false,
				'payload'         => null,
			);
		}

		// Cho phép dùng Grace Period nếu đang có lỗi kết nối mạng gần nhất
		$has_conn_error = ! empty( $this->get_last_connection_error() );
		$verified       = CLPS_Crypto_Verifier::verify_signed_envelope( $stored_env, null, $has_conn_error );

		if ( ! $verified['valid'] ) {
			return array(
				'is_valid'        => false,
				'status'          => 'INACTIVE',
				'code'            => $verified['reason'],
				'message'         => 'Chứng chỉ bản quyền đã hết phiên hoặc chữ ký không hợp lệ (' . $verified['reason'] . ').',
				'in_grace_period' => false,
				'payload'         => $verified['payload'],
			);
		}

		$payload        = $verified['payload'];
		$current_domain = CLPS_Environment::get_normalized_domain();
		$licensed_dom   = CLPS_Environment::get_normalized_domain( $payload['domain'] ?? '' );

		// Kiểm tra nhanh xem domain hiện tại có khớp với domain được ký trong chứng chỉ hay không
		if ( $licensed_dom && $current_domain !== $licensed_dom ) {
			return array(
				'is_valid'        => false,
				'status'          => $payload['license_status'] ?? 'ACTIVE',
				'code'            => 'ENV_MISMATCH',
				'message'         => sprintf(
					'Phát hiện thay đổi tên miền! Website đang chạy tại (%s) nhưng chứng chỉ cấp cho (%s).',
					$current_domain,
					$licensed_dom
				),
				'in_grace_period' => false,
				'payload'         => $payload,
			);
		}

		$is_active = ( 'ACTIVE' === ( $payload['license_status'] ?? '' ) && in_array( $payload['code'] ?? '', array( 'ACTIVATED', 'VALID' ), true ) );

		return array(
			'is_valid'        => $is_active,
			'status'          => $payload['license_status'] ?? 'INACTIVE',
			'code'            => $payload['code'] ?? 'UNKNOWN',
			'message'         => $payload['message'] ?? '',
			'in_grace_period' => $verified['in_grace_period'],
			'payload'         => $payload,
		);
	}

	/**
	 * Kiểm tra xem chức năng thương mại có được phép chạy hay không.
	 */
	public function is_license_currently_valid( ?string $feature_code = null ): bool {
		$state = $this->get_verified_status();
		if ( ! $state['is_valid'] ) {
			return false;
		}

		if ( $feature_code && ! empty( $state['payload']['features'] ) && is_array( $state['payload']['features'] ) ) {
			return in_array( $feature_code, $state['payload']['features'], true );
		}

		return true;
	}
}

