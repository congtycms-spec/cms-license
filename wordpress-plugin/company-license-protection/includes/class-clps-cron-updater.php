<?php
/**
 * MODULE 5 & MODULE 2 (#9, #10): Kiểm tra License định kỳ (WP-Cron 12h),
 * Phát hiện thay đổi môi trường & Cập nhật Plugin an toàn.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_Cron_Updater {
	public const CRON_HOOK = 'clps_periodic_license_verify_event';

	private CLPS_License_Client $client;

	public function __construct( CLPS_License_Client $client ) {
		$this->client = $client;

		add_action( self::CRON_HOOK, array( $this, 'handle_periodic_verification' ) );
		add_action( 'admin_init', array( $this, 'detect_environment_change_on_admin' ) );
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_for_plugin_updates' ) );
	}

	public static function activate_schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			// Thêm jitter ngẫu nhiên 0-15 phút để tránh hàng loạt site gọi về Server cùng 1 giây
			$first_run = time() + wp_rand( 60, 900 );
			wp_schedule_event( $first_run, 'twicedaily', self::CRON_HOOK );
		}
	}

	public static function deactivate_schedule(): void {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	/**
	 * Thực thi kiểm tra định kỳ mỗi 12 giờ qua WP-Cron.
	 */
	public function handle_periodic_verification(): void {
		$this->client->verify_license();
	}

	/**
	 * MODULE 3 & 5: Tự động kiểm tra lại ngay khi phát hiện thay đổi môi trường (đổi Domain hoặc đổi IP máy chủ)
	 * khi quản trị viên truy cập trang Admin (không làm chậm request của người dùng cuối).
	 */
	public function detect_environment_change_on_admin(): void {
		$stored_fp  = (string) get_option( 'clps_env_fingerprint', '' );
		$current_fp = CLPS_Environment::get_environment_fingerprint();

		if ( ! empty( $stored_fp ) && $stored_fp !== $current_fp && ! empty( $this->client->get_license_key() ) ) {
			$this->client->log_admin_event(
				'ENVIRONMENT_CHANGE_DETECTED',
				'Phát hiện thay đổi cấu hình Tên miền hoặc IP máy chủ. Hệ thống tự động gửi yêu cầu xác thực lại.'
			);
			$this->client->verify_license();
		}
	}

	/**
	 * MODULE 2 (#10): Cơ chế cập nhật plugin an toàn — Chỉ nhận gói cập nhật khi License đang ACTIVE.
	 */
	public function check_for_plugin_updates( $transient ) {
		if ( empty( $transient->checked ) || ! $this->client->is_license_currently_valid() ) {
			return $transient;
		}

		$endpoint = $this->client->get_server_url() . '/api/v1/plugin/update-check';
		$response = wp_remote_post(
			$endpoint,
			array(
				'timeout' => 10,
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => wp_json_encode(
					array(
						'license_key'     => $this->client->get_license_key(),
						'product_slug'    => $this->client->get_product_slug(),
						'current_version' => CLPS_VERSION,
						'domain'          => CLPS_Environment::get_normalized_domain(),
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $transient;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! empty( $data['update_available'] ) && ! empty( $data['package_url'] ) ) {
			$plugin_basename                               = plugin_basename( CLPS_PLUGIN_FILE );
			$transient->response[ $plugin_basename ]       = (object) array(
				'slug'        => 'company-license-protection',
				'plugin'      => $plugin_basename,
				'new_version' => sanitize_text_field( $data['latest_version'] ),
				'package'     => esc_url_raw( $data['package_url'] ),
				'tested'      => sanitize_text_field( $data['tested_wp'] ?? '6.7' ),
			);
		}

		return $transient;
	}
}

