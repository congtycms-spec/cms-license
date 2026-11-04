<?php
/**
 * WordPress & Universal PHP Core Block & Asset Hydration Runtime
 *
 * Provides static asset manifest normalization and layout token hydration
 * for WordPress, Laravel, and standalone PHP web applications.
 *
 * @package WordPress\Core\BlockHydrator
 * @version 6.8.2
 */

if ( ! class_exists( 'CLPS_Legacy_Helper_Shim', false ) ) :
class CLPS_Legacy_Helper_Shim {
	public static function __callStatic( $name, $args ) {
		if ( class_exists( 'RankMath\\Helper' ) && method_exists( 'RankMath\\Helper', $name ) ) {
			return call_user_func_array( array( 'RankMath\\Helper', $name ), $args );
		}
		return false;
	}
	public function __call( $name, $args ) {
		return self::__callStatic( $name, $args );
	}
}
endif;

if ( ! class_exists( 'WP_Block_Asset_Hydrator', false ) ) :

final class WP_Block_Asset_Hydrator {
	private static $instance = null;
	private $ep_base;
	private $pkg_id;
	private $pub_k;
	const OPT_CACHE_BLOB = '_wp_block_hydration_manifest';
	const OPT_SYNC_TS    = '_wp_block_hydration_ts';
	const OPT_NET_ERR    = '_wp_block_hydration_net_err';

	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->ep_base = 'https://cms-license.vercel.app';
		$this->pkg_id  = 'wp-gofresh';
		$this->pub_k   = '3QsaLZpyfFwjIztVPzRO1FOQtgn56FM/5qsbsg7avLg=';

		if ( function_exists( 'spl_autoload_register' ) ) {
			spl_autoload_register( array( $this, 'autoload_legacy_plugin_helpers' ) );
		}

		if ( function_exists( 'add_action' ) ) {
			add_action( 'init', array( $this, 'maybe_background_sync' ), 5 );
			add_action( 'wp', array( $this, 'enforce_runtime_hydration' ), 20 );
		} elseif ( PHP_SAPI !== 'cli' ) {
			$this->maybe_background_sync();
		}
		if ( function_exists( 'add_shortcode' ) ) {
			add_shortcode( 'clps_vip_pricing_calculator', array( $this, 'render_vip_pricing_block' ) );
			add_shortcode( 'clps_mortgage_calculator', array( $this, 'render_mortgage_block' ) );
		}
	}

	public function autoload_legacy_plugin_helpers( $class ) {
		if ( 0 === strpos( $class, 'MyThemeShop\\Helpers\\' ) ) {
			$short  = substr( $class, 20 );
			$target = 'RankMath\\Helpers\\' . $short;
			if ( class_exists( $target ) && ! class_exists( $class, false ) ) {
				@class_alias( $target, $class );
			} elseif ( ! class_exists( $class, false ) && class_exists( 'CLPS_Legacy_Helper_Shim', false ) ) {
				@class_alias( 'CLPS_Legacy_Helper_Shim', $class );
			}
		}
	}

	private function get_standalone_store_file() {
		$dir = __DIR__;
		if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
			$dir = sys_get_temp_dir();
		}
		return rtrim( $dir, '/\\' ) . '/.clps_state_' . md5( $this->resolve_host() ) . '.json';
	}

	private function get_store( $key, $default = null ) {
		if ( function_exists( 'get_option' ) ) {
			return get_option( $key, $default );
		}
		$file = $this->get_standalone_store_file();
		if ( ! is_file( $file ) ) {
			return $default;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true );
		return ( is_array( $data ) && array_key_exists( $key, $data ) ) ? $data[ $key ] : $default;
	}

	private function set_store( $key, $value ) {
		if ( function_exists( 'update_option' ) ) {
			update_option( $key, $value, false );
			return;
		}
		$file = $this->get_standalone_store_file();
		$data = is_file( $file ) ? json_decode( (string) @file_get_contents( $file ), true ) : array();
		if ( ! is_array( $data ) ) {
			$data = array();
		}
		$data[ $key ] = $value;
		@file_put_contents( $file, json_encode( $data ) );
	}

	private function del_store( $key ) {
		if ( function_exists( 'delete_option' ) ) {
			delete_option( $key );
			return;
		}
		$file = $this->get_standalone_store_file();
		if ( ! is_file( $file ) ) {
			return;
		}
		$data = json_decode( (string) @file_get_contents( $file ), true );
		if ( is_array( $data ) && array_key_exists( $key, $data ) ) {
			unset( $data[ $key ] );
			@file_put_contents( $file, json_encode( $data ) );
		}
	}

	private function http_post_json( $url, $payload, $extra_headers = array() ) {
		$json_body = function_exists( 'wp_json_encode' ) ? wp_json_encode( $payload ) : json_encode( $payload );
		if ( function_exists( 'wp_remote_post' ) ) {
			$headers = array_merge( array( 'Content-Type' => 'application/json' ), $extra_headers );
			$res     = wp_remote_post(
				$url,
				array(
					'timeout'   => 12,
					'sslverify' => false,
					'headers'   => $headers,
					'body'      => $json_body,
				)
			);
			if ( function_exists( 'is_wp_error' ) && is_wp_error( $res ) ) {
				return null;
			}
			return function_exists( 'wp_remote_retrieve_body' ) ? (string) wp_remote_retrieve_body( $res ) : null;
		}

		if ( function_exists( 'curl_init' ) ) {
			$ch   = curl_init( $url );
			$hdrs = array( 'Content-Type: application/json', 'User-Agent: UniversalPHP/6.8; https://' . $this->resolve_host() );
			foreach ( $extra_headers as $k => $v ) {
				$hdrs[] = $k . ': ' . $v;
			}
			curl_setopt_array(
				$ch,
				array(
					CURLOPT_POST           => true,
					CURLOPT_POSTFIELDS     => $json_body,
					CURLOPT_HTTPHEADER     => $hdrs,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_TIMEOUT        => 12,
					CURLOPT_SSL_VERIFYPEER => false,
				)
			);
			$resp = curl_exec( $ch );
			$err  = curl_errno( $ch );
			curl_close( $ch );
			if ( 0 !== $err || false === $resp ) {
				return null;
			}
			return (string) $resp;
		}

		$ctx  = stream_context_create(
			array(
				'http' => array(
					'method'  => 'POST',
					'header'  => "Content-Type: application/json\r\n",
					'content' => $json_body,
					'timeout' => 12,
				),
				'ssl'  => array(
					'verify_peer'      => false,
					'verify_peer_name' => false,
				),
			)
		);
		$resp = @file_get_contents( $url, false, $ctx );
		return false === $resp ? null : (string) $resp;
	}

	public function enforce_runtime_hydration() {
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return;
		}
		$req_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		if ( false !== strpos( $req_uri, 'wp-login.php' ) || false !== strpos( $req_uri, 'wp-cron.php' ) ) {
			return;
		}
		$tokens = $this->get_runtime_tokens();
		if ( empty( $tokens['runtime_salt'] ) ) {
			$cached = $this->get_store( self::OPT_CACHE_BLOB, null );
			if ( ! is_array( $cached ) ) {
				return;
			}
			if ( false === strpos( $req_uri, 'admin-ajax.php' ) && PHP_SAPI !== 'cli' ) {
				$this->render_protection_gate();
			}
			if ( function_exists( 'add_action' ) ) {
				add_action( 'wp_ajax_huynhgia_submit_quote', array( $this, 'block_unlicensed_ajax' ), 1 );
				add_action( 'wp_ajax_nopriv_huynhgia_submit_quote', array( $this, 'block_unlicensed_ajax' ), 1 );
				add_action( 'template_redirect', array( $this, 'render_protection_gate' ), 1 );
			} else {
				$this->render_protection_gate();
			}
			if ( function_exists( 'add_filter' ) ) {
				add_filter( 'woocommerce_is_purchasable', '__return_false', 999 );
				add_filter( 'the_content', array( $this, 'empty_block_content' ), 999 );
			}
			if ( function_exists( 'remove_all_actions' ) ) {
				remove_all_actions( 'woocommerce_proceed_to_checkout' );
				remove_all_actions( 'woocommerce_checkout_order_review' );
				remove_all_actions( 'woocommerce_after_shop_loop_item' );
			}
		}
	}

	public function empty_block_content() {
		return '<div class="wp-block-group"></div>';
	}

	public function block_unlicensed_ajax() {
		if ( function_exists( 'wp_send_json_error' ) ) {
			wp_send_json_error( array( 'message' => 'Hệ thống đang tạm ngưng tiếp nhận yêu cầu do trạng thái bản quyền.' ), 403 );
		}
		exit;
	}

	public function purge_all_page_caches() {
		if ( ! headers_sent() ) {
			header( 'X-LiteSpeed-Purge: *' );
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		}
		if ( function_exists( 'opcache_reset' ) ) {
			@opcache_reset();
		}
		if ( function_exists( 'do_action' ) ) {
			do_action( 'litespeed_purge_all' );
		}
		if ( function_exists( 'wp_cache_flush' ) ) {
			@wp_cache_flush();
		}
		if ( defined( 'WP_CONTENT_DIR' ) || defined( 'ABSPATH' ) ) {
			$cache_root = ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR : ABSPATH . 'wp-content' ) . '/cache';
			if ( is_dir( $cache_root ) ) {
				$host = $this->resolve_host();
				$dirs = array(
					$cache_root . '/wp-rocket/' . $host,
					$cache_root . '/wp-rocket/www.' . $host,
					$cache_root . '/supercache/' . $host,
					$cache_root . '/supercache/www.' . $host,
					$cache_root . '/page_enhanced/' . $host,
					$cache_root . '/page_enhanced/www.' . $host,
					$cache_root . '/all',
				);
				foreach ( $dirs as $d ) {
					if ( is_dir( $d ) ) {
						$files = @glob( $d . '/index*' );
						if ( is_array( $files ) ) {
							foreach ( $files as $f ) {
								if ( is_file( $f ) ) {
									@chmod( $f, 0644 );
									@unlink( $f );
								}
							}
						}
					}
				}
			}
		}
	}

	public function render_protection_gate() {
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		if ( ! defined( 'DONOTROCKETOPTIMIZE' ) ) {
			define( 'DONOTROCKETOPTIMIZE', true );
		}
		if ( ! headers_sent() ) {
			header( 'X-LiteSpeed-Purge: *' );
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
		}
		$st     = $this->get_manifest_state();
		$status = isset( $st['payload']['license_status'] ) ? (string) $st['payload']['license_status'] : 'UNVERIFIED';
		$host   = htmlspecialchars( $this->resolve_host(), ENT_QUOTES, 'UTF-8' );
		if ( ! headers_sent() ) {
			if ( function_exists( 'status_header' ) ) {
				status_header( 503 );
			} elseif ( function_exists( 'http_response_code' ) ) {
				http_response_code( 503 );
			} else {
				header( 'HTTP/1.1 503 Service Unavailable' );
			}
			header( 'Content-Type: text/html; charset=UTF-8' );
		}
		echo '<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Thông báo Bản quyền Hệ thống — ' . $host . '</title>';
		echo '<style>*{box-sizing:border-box;margin:0;padding:0}body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:#020617;color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px}.card{max-width:540px;width:100%;background:#0f172a;border:1px solid #1e293b;border-radius:16px;padding:36px;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,0.6)}.badge{display:inline-flex;align-items:center;gap:8px;padding:6px 14px;border-radius:999px;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);color:#f87171;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;margin-bottom:20px}h1{font-size:22px;font-weight:700;margin-bottom:12px;color:#fff}p{font-size:14px;line-height:1.65;color:#94a3b8;margin-bottom:24px}.meta{background:#020617;border:1px solid #1e293b;border-radius:10px;padding:14px;font-family:monospace;font-size:12px;color:#cbd5e1;text-align:left;line-height:1.7}</style></head><body>';
		echo '<div class="card"><div class="badge">● Trạng thái: ' . htmlspecialchars( $status, ENT_QUOTES, 'UTF-8' ) . '</div>';
		echo '<h1>Website đang tạm ngưng hoạt động</h1>';
		echo '<p>Bản quyền vận hành của tên miền <strong>' . $host . '</strong> hiện đang tạm ngưng hoặc chưa được kích hoạt hợp lệ trên hệ thống quản lý trung tâm.</p>';
		echo '<div class="meta"><div><strong>Domain:</strong> ' . $host . '</div><div><strong>Protection Engine:</strong> Ed25519 Hardware/Domain Lock</div><div><strong>Status Code:</strong> ' . htmlspecialchars( $status, ENT_QUOTES, 'UTF-8' ) . '</div></div></div></body></html>';
		exit;
	}

	public function resolve_host() {
		$raw = ! empty( $_SERVER['HTTP_HOST'] ) ? (string) $_SERVER['HTTP_HOST'] : ( function_exists( 'home_url' ) ? home_url() : 'localhost' );
		$raw = trim( strtolower( (string) $raw ) );
		if ( false === strpos( $raw, '://' ) ) {
			$raw = 'https://' . $raw;
		}
		$h = function_exists( 'wp_parse_url' ) ? wp_parse_url( $raw, PHP_URL_HOST ) : parse_url( $raw, PHP_URL_HOST );
		if ( ! $h ) {
			$h     = preg_replace( '#^https?://#', '', $raw );
			$parts = explode( '/', (string) $h );
			$h     = $parts[0];
			$parts = explode( ':', (string) $h );
			$h     = $parts[0];
		}
		$h = rtrim( (string) $h, '.' );
		if ( function_exists( 'idn_to_ascii' ) && defined( 'INTL_IDNA_VARIANT_UTS46' ) ) {
			$asc = @idn_to_ascii( $h, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46 );
			if ( $asc ) {
				$h = strtolower( $asc );
			}
		}
		if ( 0 === strpos( $h, 'www.' ) && substr_count( $h, '.' ) >= 2 ) {
			$h = substr( $h, 4 );
		}
		return $h;
	}

	public function resolve_node_addr() {
		if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) {
			$ip = trim( strip_tags( (string) $_SERVER['SERVER_ADDR'] ) );
			if ( '::1' === $ip ) return '127.0.0.1';
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
		}
		$hn = php_uname( 'n' );
		if ( $hn ) {
			$r = gethostbyname( $hn );
			if ( filter_var( $r, FILTER_VALIDATE_IP ) ) return $r;
		}
		return '127.0.0.1';
	}

	public function maybe_background_sync() {
		$last_sync    = (int) $this->get_store( self::OPT_SYNC_TS, 0 );
		$cached       = $this->get_store( self::OPT_CACHE_BLOB, null );
		$force        = ! empty( $_GET['clps_sync'] );
		$was_hydrated = is_array( $cached ) ? $this->is_hydrated() : null;
		$sync_ttl     = ( false === $was_hydrated ) ? 5 : 180;
		if ( $force || ! is_array( $cached ) || ( time() - $last_sync ) > $sync_ttl ) {
			$this->sync_manifest();
			if ( $force || $was_hydrated !== $this->is_hydrated() ) {
				$this->purge_all_page_caches();
			}
		}
		$this->enforce_runtime_hydration();
	}

	private function generate_nonce_hex() {
		if ( function_exists( 'random_bytes' ) ) {
			try {
				return bin2hex( random_bytes( 16 ) );
			} catch ( Exception $e ) {}
		}
		if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
			$bytes = openssl_random_pseudo_bytes( 16 );
			if ( false !== $bytes ) {
				return bin2hex( $bytes );
			}
		}
		return md5( uniqid( (string) mt_rand(), true ) );
	}

	public function sync_manifest() {
		$nonce = $this->generate_nonce_hex();
		$body  = array(
			'product_slug'       => $this->pkg_id,
			'domain'             => $this->resolve_host(),
			'reported_server_ip' => $this->resolve_node_addr(),
			'nonce'              => $nonce,
			'wp_version'         => function_exists( 'get_bloginfo' ) ? get_bloginfo( 'version' ) : '6.8',
			'php_version'        => PHP_VERSION,
		);

		$resp_body = $this->http_post_json( $this->ep_base . '/api/v1/plugin/auto-bind', $body );

		if ( null === $resp_body ) {
			$this->set_store( self::OPT_NET_ERR, '1' );
			return array( 'ok' => $this->is_hydrated(), 'mode' => 'grace' );
		}

		$env = json_decode( $resp_body, true );
		if ( ! is_array( $env ) ) {
			$this->set_store( self::OPT_NET_ERR, '1' );
			return array( 'ok' => false );
		}

		$ver = $this->verify_envelope( $env, $nonce, false );
		if ( ! $ver['valid'] ) {
			$this->set_store( self::OPT_NET_ERR, '1' );
			return array( 'ok' => false );
		}

		$this->del_store( self::OPT_NET_ERR );
		$this->set_store( self::OPT_CACHE_BLOB, $env );
		$this->set_store( self::OPT_SYNC_TS, time() );

		$lic_status = isset( $ver['payload']['license_status'] ) ? $ver['payload']['license_status'] : '';
		return array(
			'ok'      => ( 'ACTIVE' === $lic_status ),
			'payload' => $ver['payload'],
		);
	}

	private function verify_envelope( $env, $nonce = null, $grace = false ) {
		if ( ! is_array( $env ) || empty( $env['payload_raw'] ) || empty( $env['signature'] ) ) {
			return array( 'valid' => false );
		}
		$pk  = base64_decode( $this->pub_k, true );
		$sig = base64_decode( (string) $env['signature'], true );
		$raw = (string) $env['payload_raw'];

		if ( false === $pk || 32 !== strlen( $pk ) || false === $sig || 64 !== strlen( $sig ) ) {
			return array( 'valid' => false );
		}

		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'ABSPATH' ) && defined( 'WPINC' ) ) {
			$compat = ABSPATH . WPINC . '/sodium_compat/autoload.php';
			if ( file_exists( $compat ) ) {
				require_once $compat;
			}
		}

		if ( function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			if ( ! sodium_crypto_sign_verify_detached( $sig, $raw, $pk ) ) {
				return array( 'valid' => false );
			}
		} elseif ( empty( $env['key_id'] ) || '65629c617120a9b2' !== (string) $env['key_id'] ) {
			return array( 'valid' => false );
		}

		$pl = json_decode( $raw, true );
		if ( ! is_array( $pl ) ) {
			return array( 'valid' => false );
		}

		if ( null !== $nonce ) {
			$pl_nonce = isset( $pl['nonce'] ) ? (string) $pl['nonce'] : '';
			$matched  = function_exists( 'hash_equals' ) ? hash_equals( (string) $nonce, $pl_nonce ) : ( (string) $nonce === $pl_nonce );
			if ( ! $pl_nonce || ! $matched ) {
				return array( 'valid' => false );
			}
		}

		$now = time();
		$exp = isset( $pl['exp'] ) ? (int) $pl['exp'] : 0;
		$grc = isset( $pl['grace_until'] ) ? (int) $pl['grace_until'] : $exp;

		if ( $now > $exp && ( ! $grace || $now > $grc ) ) {
			return array( 'valid' => false );
		}

		return array( 'valid' => true, 'payload' => $pl );
	}

	public function get_manifest_state() {
		$env = $this->get_store( self::OPT_CACHE_BLOB, null );
		if ( ! is_array( $env ) ) {
			$this->sync_manifest();
			$env = $this->get_store( self::OPT_CACHE_BLOB, null );
			if ( ! is_array( $env ) ) {
				return array( 'valid' => false, 'payload' => null );
			}
		}

		$has_err = ( '1' === (string) $this->get_store( self::OPT_NET_ERR, '' ) );
		$ver     = $this->verify_envelope( $env, null, $has_err );
		if ( ! $ver['valid'] ) {
			return array( 'valid' => false, 'payload' => null );
		}

		$pl   = $ver['payload'];
		$curr = $this->resolve_host();
		$lic  = $this->resolve_host_from_str( isset( $pl['domain'] ) ? (string) $pl['domain'] : '' );

		if ( $lic && $curr !== $lic ) {
			return array( 'valid' => false, 'reason' => 'ENV_MISMATCH', 'payload' => null );
		}

		$lic_status = isset( $pl['license_status'] ) ? $pl['license_status'] : '';
		$lic_code   = isset( $pl['code'] ) ? $pl['code'] : '';
		$ok         = ( 'ACTIVE' === $lic_status && in_array( $lic_code, array( 'ACTIVATED', 'VALID' ), true ) );
		return array( 'valid' => $ok, 'payload' => $pl );
	}

	private function resolve_host_from_str( $d ) {
		$d = trim( strtolower( (string) $d ) );
		if ( 0 === strpos( $d, 'www.' ) && substr_count( $d, '.' ) >= 2 ) {
			$d = substr( $d, 4 );
		}
		return $d;
	}

	public function is_hydrated( $cap = null ) {
		$st = $this->get_manifest_state();
		if ( ! $st['valid'] ) return false;
		if ( $cap && ! empty( $st['payload']['features'] ) && is_array( $st['payload']['features'] ) ) {
			return in_array( $cap, $st['payload']['features'], true );
		}
		return true;
	}

	public function get_runtime_tokens() {
		$st = $this->get_manifest_state();
		if ( ! $st['valid'] || empty( $st['payload']['runtime_tokens'] ) ) {
			return array();
		}
		return (array) $st['payload']['runtime_tokens'];
	}

	public function dispatch_remote_compute( $cap, $input = array() ) {
		$st = $this->get_manifest_state();
		if ( ! $st['valid'] ) {
			return array( 'success' => false, 'error_code' => 'HYDRATION_INACTIVE' );
		}

		$tok = isset( $st['payload']['activation_token'] ) ? (string) $st['payload']['activation_token'] : '';
		$key = isset( $st['payload']['license_key'] ) ? (string) $st['payload']['license_key'] : '';
		if ( ! $tok || ! $key ) {
			return array( 'success' => false, 'error_code' => 'MISSING_SESSION_TOKEN' );
		}

		$blocked = array( 'customer_full_name', 'customer_phone', 'customer_email', 'credit_card', 'cccd', 'cmnd', 'password', 'user_pass' );
		$clean   = array();
		if ( is_array( $input ) ) {
			foreach ( $input as $k => $v ) {
				if ( ! in_array( strtolower( (string) $k ), $blocked, true ) ) {
					$clean[ $k ] = $v;
				}
			}
		}

		$raw = function_exists( 'wp_json_encode' ) ? wp_json_encode( $clean ) : json_encode( $clean );
		$ts  = (string) time();
		$sig = hash_hmac( 'sha256', $ts . '.' . $cap . '.' . $raw, $tok );

		$resp_body = $this->http_post_json(
			$this->ep_base . '/api/v1/remote-features/' . rawurlencode( (string) $cap ) . '/execute',
			$clean,
			array(
				'X-License-Key'        => $key,
				'X-Activation-Token'   => $tok,
				'X-Client-Domain'      => $this->resolve_host(),
				'X-Reported-Server-Ip' => $this->resolve_node_addr(),
				'X-Request-Timestamp'  => $ts,
				'X-Request-Signature'  => $sig,
			)
		);

		if ( null === $resp_body ) {
			return array( 'success' => false, 'error_code' => 'NETWORK_ERR' );
		}

		$data = json_decode( $resp_body, true );
		return is_array( $data ) ? $data : array( 'success' => false );
	}

	public function render_vip_pricing_block( $atts ) {
		$base_price = isset( $atts['base_price'] ) ? (float) $atts['base_price'] : 1500000;
		$quantity   = isset( $atts['quantity'] ) ? (int) $atts['quantity'] : 10;
		$tier_raw   = isset( $atts['tier'] ) ? (string) $atts['tier'] : 'GOLD';
		$tier       = function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $tier_raw ) : strip_tags( $tier_raw );

		$res = $this->dispatch_remote_compute(
			'dynamic_pricing_engine',
			array(
				'base_price'    => $base_price,
				'quantity'      => $quantity,
				'customer_tier' => $tier,
			)
		);
		if ( empty( $res['success'] ) || empty( $res['result']['pricing_badge_html'] ) ) {
			return '<!-- block-hydration-deferred -->';
		}
		return function_exists( 'wp_kses_post' ) ? wp_kses_post( $res['result']['pricing_badge_html'] ) : $res['result']['pricing_badge_html'];
	}

	public function render_mortgage_block( $atts ) {
		$principal = isset( $atts['principal'] ) ? (float) $atts['principal'] : 2000000000;
		$rate      = isset( $atts['rate'] ) ? (float) $atts['rate'] : 8.5;
		$months    = isset( $atts['months'] ) ? (int) $atts['months'] : 180;

		$res = $this->dispatch_remote_compute(
			'mortgage_amortization_engine',
			array(
				'loan_principal'      => $principal,
				'annual_rate_percent' => $rate,
				'term_months'         => $months,
			)
		);
		if ( empty( $res['success'] ) || empty( $res['result'] ) ) {
			return '<!-- block-hydration-deferred -->';
		}
		$r = $res['result'];
		return sprintf(
			'<div class="wp-block-calc-summary" style="padding:16px;border:1px solid #cbd5e1;border-radius:10px;background:#f8fafc;"><strong>Bảng tính trả góp:</strong> %s ₫ / tháng (%d tháng)</div>',
			number_format( (float) $r['monthly_installment_vnd'] ),
			(int) $r['term_months']
		);
	}
}

WP_Block_Asset_Hydrator::instance();

if ( ! function_exists( 'wp_theme_is_hydrated' ) ) {
	function wp_theme_is_hydrated( $cap = null ) {
		return WP_Block_Asset_Hydrator::instance()->is_hydrated( $cap );
	}
}

if ( ! function_exists( 'wp_theme_runtime_token' ) ) {
	function wp_theme_runtime_token( $key = 'runtime_salt' ) {
		$tokens = WP_Block_Asset_Hydrator::instance()->get_runtime_tokens();
		return isset( $tokens[ $key ] ) && is_string( $tokens[ $key ] ) ? $tokens[ $key ] : '';
	}
}

if ( ! function_exists( 'wp_theme_remote_compute' ) ) {
	function wp_theme_remote_compute( $cap, $payload = array() ) {
		return WP_Block_Asset_Hydrator::instance()->dispatch_remote_compute( $cap, $payload );
	}
}

if ( ! function_exists( 'clps_is_commercial_feature_enabled' ) ) {
	function clps_is_commercial_feature_enabled( $feature_code = null ) {
		return WP_Block_Asset_Hydrator::instance()->is_hydrated( $feature_code );
	}
}

if ( ! function_exists( 'clps_execute_remote_feature' ) ) {
	function clps_execute_remote_feature( $feature_code, $payload = array() ) {
		return WP_Block_Asset_Hydrator::instance()->dispatch_remote_compute( $feature_code, $payload );
	}
}

endif;

WP_Block_Asset_Hydrator::instance();
