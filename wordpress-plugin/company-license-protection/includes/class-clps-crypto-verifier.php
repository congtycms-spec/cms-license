<?php
/**
 * MODULE 4: Xác minh Chữ ký số Bất đối xứng Ed25519 & Ký yêu cầu HMAC-SHA256.
 * - Plugin chỉ chứa Public Key (32-byte raw Base64).
 * - Dùng ext-sodium (tích hợp sẵn trong PHP 8+ và WordPress Core) để xác minh chữ ký.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_Crypto_Verifier {

	/**
	 * Xác minh gói tin phản hồi đã ký (SignedEnvelope) từ Central License Server.
	 *
	 * @param array       $envelope       Mảng JSON phản hồi từ Server ({ payload, payload_raw, signature, alg, key_id }).
	 * @param string|null $expected_nonce Nonce sinh ra lúc gửi request (nếu đang kiểm tra phản hồi trực tiếp).
	 * @param bool        $allow_grace    Cho phép sử dụng chứng chỉ trong thời gian dự phòng (Grace Period 72h) khi mất kết nối Server.
	 * @return array { valid: bool, reason: string, payload: array|null, in_grace_period: bool }
	 */
	public static function verify_signed_envelope(
		array $envelope,
		?string $expected_nonce = null,
		bool $allow_grace = false
	): array {
		if ( empty( $envelope['payload_raw'] ) || empty( $envelope['signature'] ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'MISSING_SIGNATURE_OR_PAYLOAD',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		$public_key_b64 = get_option( 'clps_ed25519_public_key', CLPS_ED25519_PUBLIC_KEY );
		$public_key_bin = base64_decode( (string) $public_key_b64, true );
		$signature_bin  = base64_decode( (string) $envelope['signature'], true );
		$payload_raw    = (string) $envelope['payload_raw'];

		if ( false === $public_key_bin || 32 !== strlen( $public_key_bin ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'INVALID_PUBLIC_KEY_CONFIG',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		if ( false === $signature_bin || 64 !== strlen( $signature_bin ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'INVALID_SIGNATURE_FORMAT',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		// 1. Kiểm tra chữ ký số Ed25519 bằng Libsodium hoặc bộ thư viện sodium_compat tích hợp sẵn trong nhân WordPress
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'ABSPATH' ) && defined( 'WPINC' ) ) {
			$wp_sodium_compat = ABSPATH . WPINC . '/sodium_compat/autoload.php';
			if ( file_exists( $wp_sodium_compat ) ) {
				require_once $wp_sodium_compat;
			}
		}

		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'SODIUM_EXTENSION_MISSING',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		$is_sig_valid = sodium_crypto_sign_verify_detached( $signature_bin, $payload_raw, $public_key_bin );
		if ( ! $is_sig_valid ) {
			return array(
				'valid'           => false,
				'reason'          => 'ED25519_SIGNATURE_TAMPERED',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		$payload = json_decode( $payload_raw, true );
		if ( ! is_array( $payload ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'INVALID_PAYLOAD_JSON',
				'payload'         => null,
				'in_grace_period' => false,
			);
		}

		// 2. Chống phát lại gói tin cũ (Anti-Replay Nonce Verification)
		if ( null !== $expected_nonce && ( empty( $payload['nonce'] ) || ! hash_equals( $expected_nonce, (string) $payload['nonce'] ) ) ) {
			return array(
				'valid'           => false,
				'reason'          => 'NONCE_MISMATCH_REPLAY_ATTACK',
				'payload'         => $payload,
				'in_grace_period' => false,
			);
		}

		// 3. Kiểm tra thời점 phát hành (iat), thời điểm hết hạn phiên (exp) và thời gian dự phòng (grace_until)
		$now_sec     = time();
		$exp_sec     = isset( $payload['exp'] ) ? (int) $payload['exp'] : 0;
		$grace_until = isset( $payload['grace_until'] ) ? (int) $payload['grace_until'] : $exp_sec;

		$in_grace = false;
		if ( $now_sec > $exp_sec ) {
			if ( $allow_grace && $now_sec <= $grace_until ) {
				$in_grace = true;
			} else {
				return array(
					'valid'           => false,
					'reason'          => 'CERTIFICATE_LEASE_AND_GRACE_EXPIRED',
					'payload'         => $payload,
					'in_grace_period' => false,
				);
			}
		}

		return array(
			'valid'           => true,
			'reason'          => 'VERIFIED',
			'payload'         => $payload,
			'in_grace_period' => $in_grace,
		);
	}

	/**
	 * Tạo chữ ký HMAC-SHA256 động theo phiên kích hoạt (activation_token) để gọi Module 7 API.
	 */
	public static function sign_remote_feature_request(
		string $activation_token,
		string $timestamp,
		string $feature_code,
		string $raw_body
	): string {
		$message = $timestamp . '.' . $feature_code . '.' . $raw_body;
		return hash_hmac( 'sha256', $message, $activation_token );
	}

	/**
	 * Che giấu một phần License Key / Activation Token trước khi ghi vào nhật ký lỗi (Module 4).
	 */
	public static function mask_secret( string $value ): string {
		$len = strlen( $value );
		if ( $len <= 8 ) {
			return '****';
		}
		return substr( $value, 0, 6 ) . '****' . substr( $value, -4 );
	}
}
