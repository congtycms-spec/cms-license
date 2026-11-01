<?php
/**
 * MODULE 7 & MODULE 8: Thực thi Chức năng Thương mại Cốt lõi từ xa trên Server Công ty
 * và Chính sách Xử lý An toàn khi License Không Hợp lệ (Graceful Degradation).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_Remote_Features {
	private CLPS_License_Client $client;

	/**
	 * Danh sách các trường dữ liệu cá nhân (PII) bị cấm gửi lên máy chủ công ty theo Module 7.
	 */
	private const BLOCKED_PII_FIELDS = array(
		'customer_full_name',
		'customer_phone',
		'customer_email',
		'credit_card',
		'cccd',
		'cmnd',
		'password',
		'user_pass',
	);

	public function __construct( CLPS_License_Client $client ) {
		$this->client = $client;

		// Đăng ký các Shortcode Thương mại được bảo vệ bởi Module 7 & Module 8
		add_shortcode( 'clps_vip_pricing_calculator', array( $this, 'render_vip_pricing_shortcode' ) );
		add_shortcode( 'clps_mortgage_calculator', array( $this, 'render_mortgage_shortcode' ) );
	}

	/**
	 * Lọc bỏ mọi trường dữ liệu cá nhân (PII) trước khi gửi lên Server Công ty (Data Minimization - Module 7).
	 */
	public function sanitize_payload_for_privacy( array $payload ): array {
		$clean = array();
		foreach ( $payload as $key => $value ) {
			$lower_key = strtolower( (string) $key );
			if ( in_array( $lower_key, self::BLOCKED_PII_FIELDS, true ) ) {
				continue; // Tuyệt đối không gửi dữ liệu cá nhân của khách hàng
			}
			$clean[ $key ] = $value;
		}
		return $clean;
	}

	/**
	 * Gọi API thực thi chức năng thương mại cốt lõi trên Central License Server (Module 7).
	 */
	public function execute_feature( string $feature_code, array $payload = array() ): array {
		$status = $this->client->get_verified_status();

		if ( ! $status['is_valid'] ) {
			return array(
				'success'    => false,
				'error_code' => 'LICENSE_NOT_VALID',
				'message'    => 'Chức năng thương mại tạm khóa do bản quyền chưa hợp lệ (' . $status['code'] . ').',
			);
		}

		$activation_token = $status['payload']['activation_token'] ?? '';
		if ( empty( $activation_token ) ) {
			return array(
				'success'    => false,
				'error_code' => 'MISSING_ACTIVATION_TOKEN',
				'message'    => 'Không tìm thấy Activation Token hợp lệ. Vui lòng bấm Kiểm tra License.',
			);
		}

		$clean_payload = $this->sanitize_payload_for_privacy( $payload );
		$raw_body      = wp_json_encode( $clean_payload );
		$timestamp     = (string) time();
		$hmac_sig      = CLPS_Crypto_Verifier::sign_remote_feature_request(
			$activation_token,
			$timestamp,
			$feature_code,
			$raw_body
		);

		$endpoint = $this->client->get_server_url() . '/api/v1/remote-features/' . rawurlencode( $feature_code ) . '/execute';

		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 15,
				'headers' => array(
					'Content-Type'         => 'application/json',
					'X-License-Key'        => $this->client->get_license_key(),
					'X-Activation-Token'   => $activation_token,
					'X-Client-Domain'      => CLPS_Environment::get_normalized_domain(),
					'X-Reported-Server-Ip' => CLPS_Environment::get_reliable_server_ip(),
					'X-Request-Timestamp'  => $timestamp,
					'X-Request-Signature'  => $hmac_sig,
				),
				'body'    => $raw_body,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->client->log_admin_event( 'REMOTE_FEATURE_ERROR', 'Lỗi kết nối Module 7 (' . $feature_code . '): ' . $response->get_error_message() );
			return array(
				'success'    => false,
				'error_code' => 'REMOTE_CONNECTION_ERROR',
				'message'    => 'Không thể kết nối máy chủ xử lý tính năng thương mại: ' . $response->get_error_message(),
			);
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return array(
				'success'    => false,
				'error_code' => 'INVALID_REMOTE_RESPONSE',
				'message'    => 'Phản hồi không hợp lệ từ máy chủ tính năng.',
			);
		}

		return $data;
	}

	/**
	 * MODULE 8: Hiển thị thông báo an toàn khi tính năng thương mại bị tạm khóa (Không làm hỏng giao diện website).
	 */
	private function render_locked_feature_notice( string $feature_title ): string {
		if ( current_user_can( 'manage_options' ) ) {
			return sprintf(
				'<div style="padding:14px;border:1px solid #f59e0b;background:#fffbeb;color:#92400e;border-radius:8px;font-size:14px;">
					<strong>[Quản trị viên] Chức năng thương mại "%s" đang tạm khóa.</strong><br/>
					Vui lòng kiểm tra trạng thái bản quyền hoặc gia hạn tại trang <a href="%s">Cấu hình Bản quyền WordPress</a>.
				</div>',
				esc_html( $feature_title ),
				esc_url( admin_url( 'admin.php?page=company-license-protection' ) )
			);
		}
		return '<!-- Commercial feature temporarily unavailable -->';
	}

	public function render_vip_pricing_shortcode( $atts ): string {
		if ( ! $this->client->is_license_currently_valid( 'dynamic_pricing_engine' ) ) {
			return $this->render_locked_feature_notice( 'Dynamic VIP Pricing Engine' );
		}

		$atts = shortcode_atts(
			array(
				'base_price' => 1500000,
				'quantity'   => 10,
				'tier'       => 'GOLD',
			),
			$atts
		);

		$res = $this->execute_feature(
			'dynamic_pricing_engine',
			array(
				'base_price'    => (float) $atts['base_price'],
				'quantity'      => (int) $atts['quantity'],
				'customer_tier' => sanitize_text_field( $atts['tier'] ),
			)
		);

		if ( empty( $res['success'] ) || empty( $res['result'] ) ) {
			return $this->render_locked_feature_notice( 'Dynamic VIP Pricing Engine' );
		}

		return wp_kses_post( $res['result']['pricing_badge_html'] ?? '' );
	}

	public function render_mortgage_shortcode( $atts ): string {
		if ( ! $this->client->is_license_currently_valid( 'mortgage_amortization_engine' ) ) {
			return $this->render_locked_feature_notice( 'Mortgage Amortization Engine' );
		}

		$atts = shortcode_atts(
			array(
				'principal' => 2000000000,
				'rate'      => 8.5,
				'months'    => 180,
			),
			$atts
		);

		$res = $this->execute_feature(
			'mortgage_amortization_engine',
			array(
				'loan_principal'      => (float) $atts['principal'],
				'annual_rate_percent' => (float) $atts['rate'],
				'term_months'         => (int) $atts['months'],
			)
		);

		if ( empty( $res['success'] ) || empty( $res['result'] ) ) {
			return $this->render_locked_feature_notice( 'Mortgage Amortization Engine' );
		}

		$r = $res['result'];
		return sprintf(
			'<div class="clps-mortgage-box" style="padding:16px;border:1px solid #cbd5e1;border-radius:10px;background:#f8fafc;">
				<strong>Bảng tính trả góp BĐS (Xử lý từ Server trung tâm):</strong><br/>
				Khoản vay: %s ₫ | Kỳ hạn: %d tháng | Trả hàng tháng: <strong>%s ₫</strong>
			</div>',
			number_format_i18n( (float) $r['loan_principal_vnd'] ),
			(int) $r['term_months'],
			number_format_i18n( (float) $r['monthly_installment_vnd'] )
		);
	}
}

