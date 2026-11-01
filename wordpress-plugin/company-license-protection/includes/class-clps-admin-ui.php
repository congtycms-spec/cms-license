<?php
/**
 * MODULE 2 (#1 -> #8): Giao diện Quản trị WordPress cho Plugin "Company License Protection".
 * Bao gồm:
 * 1. Trang nhập license key
 * 2. Trang hiển thị trạng thái license
 * 3. Hiển thị tên miền đã đăng ký
 * 4. Hiển thị trạng thái xác thực (Chữ ký số Ed25519 + Grace Period)
 * 5. Hiển thị ngày hết hạn
 * 6. Nút kiểm tra license thủ công
 * 7. Nút & Form yêu cầu chuyển máy chủ
 * 8. Nhật ký lỗi xác thực dành cho quản trị viên
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class CLPS_Admin_UI {
	private CLPS_License_Client $client;
	private CLPS_Remote_Features $remote_features;
	private ?array $action_feedback = null;
	private ?array $remote_test_result = null;

	public function __construct( CLPS_License_Client $client, CLPS_Remote_Features $remote_features ) {
		$this->client          = $client;
		$this->remote_features = $remote_features;

		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_form_submissions' ) );
		add_action( 'admin_notices', array( $this, 'render_global_admin_notices' ) );
	}

	public function register_admin_menu(): void {
		add_menu_page(
			'Company License Protection',
			'Bản quyền Website',
			'manage_options',
			'company-license-protection',
			array( $this, 'render_admin_page' ),
			'dashicons-shield-alt',
			80
		);
	}

	public function handle_form_submissions(): void {
		if ( ! isset( $_POST['clps_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		check_admin_referer( 'clps_admin_action_nonce', 'clps_nonce_field' );

		$action = sanitize_text_field( wp_unslash( $_POST['clps_action'] ) );

		if ( 'activate_license' === $action ) {
			$license_key  = isset( $_POST['license_key'] ) ? sanitize_text_field( wp_unslash( $_POST['license_key'] ) ) : '';
			$server_url   = isset( $_POST['server_url'] ) ? esc_url_raw( wp_unslash( $_POST['server_url'] ) ) : '';
			$product_slug = isset( $_POST['product_slug'] ) ? sanitize_title( wp_unslash( $_POST['product_slug'] ) ) : '';

			$res                   = $this->client->activate_license( $license_key, $server_url, $product_slug );
			$this->action_feedback = array(
				'type'    => $res['success'] ? 'success' : 'error',
				'message' => $res['message'],
			);
		} elseif ( 'verify_license' === $action ) {
			$res                   = $this->client->verify_license();
			$this->action_feedback = array(
				'type'    => $res['success'] ? 'success' : 'error',
				'message' => $res['message'],
			);
		} elseif ( 'request_transfer' === $action ) {
			$reason                = isset( $_POST['transfer_reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['transfer_reason'] ) ) : '';
			$res                   = $this->client->request_server_transfer( $reason );
			$this->action_feedback = array(
				'type'    => $res['success'] ? 'success' : 'error',
				'message' => $res['message'],
			);
		} elseif ( 'test_remote_feature' === $action ) {
			$feature_code             = isset( $_POST['feature_code'] ) ? sanitize_text_field( wp_unslash( $_POST['feature_code'] ) ) : 'dynamic_pricing_engine';
			$this->remote_test_result = $this->remote_features->execute_feature(
				$feature_code,
				array(
					'base_price'    => 2500000,
					'quantity'      => 15,
					'customer_tier' => 'PLATINUM',
				)
			);
		} elseif ( 'clear_logs' === $action ) {
			delete_option( 'clps_admin_error_logs' );
			$this->action_feedback = array(
				'type'    => 'success',
				'message' => 'Đã xóa lịch sử nhật ký lỗi xác thực.',
			);
		}
	}

	/**
	 * Hiển thị cảnh báo trên toàn bộ trang WP Admin nếu License không hợp lệ hoặc đang trong thời gian dự phòng (Module 5 & Module 8).
	 */
	public function render_global_admin_notices(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$state      = $this->client->get_verified_status();
		$conn_error = $this->client->get_last_connection_error();

		if ( ! empty( $conn_error ) && $state['is_valid'] ) {
			printf(
				'<div class="notice notice-warning"><p><strong>[Company License Protection - Chế độ Dự phòng]</strong> Không thể kết nối đến máy chủ bản quyền (%s). Website vẫn hoạt động bình thường trong thời gian dự phòng (Grace Period 72h). Hệ thống sẽ tự động kết nối lại.</p></div>',
				esc_html( $conn_error )
			);
			return;
		}

		if ( ! $state['is_valid'] ) {
			printf(
				'<div class="notice notice-error"><p><strong>[Cảnh báo Bản quyền Website WordPress]</strong> %s — Các chức năng thương mại cao cấp đang tạm khóa. <a href="%s" class="button button-small" style="margin-left:8px;">Quản lý Bản quyền & Chuyển Máy chủ</a></p></div>',
				esc_html( $state['message'] ),
				esc_url( admin_url( 'admin.php?page=company-license-protection' ) )
			);
		}
	}

	public function render_admin_page(): void {
		$state          = $this->client->get_verified_status();
		$payload        = $state['payload'] ?? array();
		$license_key    = $this->client->get_license_key();
		$server_url     = $this->client->get_server_url();
		$product_slug   = $this->client->get_product_slug();
		$current_domain = CLPS_Environment::get_normalized_domain();
		$current_ip     = CLPS_Environment::get_reliable_server_ip();
		$error_logs     = array_reverse( $this->client->get_error_logs() );
		$next_cron      = wp_next_scheduled( CLPS_Cron_Updater::CRON_HOOK );
		?>
		<style>
			@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Fira+Sans:wght@400;500;600;700&display=swap');
			.clps-wrap {
				font-family: 'Fira Sans', -apple-system, BlinkMacSystemFont, sans-serif;
				color: #0F172A;
				max-width: 1280px;
				margin: 20px 20px 40px 0;
			}
			.clps-mono {
				font-family: 'Fira Code', monospace;
			}
			.clps-header {
				background: linear-gradient(135deg, #020617 0%, #0F172A 100%);
				color: #F8FAFC;
				border: 1px solid #1E293B;
				border-radius: 14px;
				padding: 22px 26px;
				display: flex;
				flex-wrap: wrap;
				align-items: center;
				justify-content: space-between;
				gap: 16px;
				margin-bottom: 22px;
				box-shadow: 0 10px 25px -5px rgba(2, 6, 23, 0.25);
			}
			.clps-header-left {
				display: flex;
				align-items: center;
				gap: 16px;
			}
			.clps-brand-icon {
				width: 48px;
				height: 48px;
				border-radius: 12px;
				background: rgba(14, 165, 233, 0.15);
				border: 1px solid rgba(56, 189, 248, 0.35);
				display: flex;
				align-items: center;
				justify-content: center;
				color: #38BDF8;
				flex-shrink: 0;
			}
			.clps-header h1 {
				color: #F8FAFC;
				font-size: 20px;
				font-weight: 700;
				margin: 0 0 4px 0;
				padding: 0;
				line-height: 1.3;
			}
			.clps-header p {
				color: #94A3B8;
				font-size: 13px;
				margin: 0;
			}
			.clps-grid {
				display: grid;
				grid-template-columns: repeat(auto-fit, minmax(460px, 1fr));
				gap: 22px;
			}
			.clps-card {
				background: #FFFFFF;
				border: 1px solid #E2E8F0;
				border-radius: 14px;
				padding: 24px;
				box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
			}
			.clps-card-title {
				display: flex;
				align-items: center;
				gap: 10px;
				font-size: 15px;
				font-weight: 700;
				color: #0F172A;
				margin: 0 0 16px 0;
				padding-bottom: 12px;
				border-bottom: 1px solid #E2E8F0;
			}
			.clps-badge-valid {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				background: #DCFCE7;
				color: #166534;
				border: 1px solid #86EFAC;
				padding: 5px 12px;
				border-radius: 999px;
				font-size: 12px;
				font-weight: 700;
			}
			.clps-badge-invalid {
				display: inline-flex;
				align-items: center;
				gap: 6px;
				background: #FEE2E2;
				color: #991B1B;
				border: 1px solid #FCA5A5;
				padding: 5px 12px;
				border-radius: 999px;
				font-size: 12px;
				font-weight: 700;
			}
			.clps-table {
				width: 100%;
				border-collapse: collapse;
			}
			.clps-table tr {
				border-bottom: 1px solid #F1F5F9;
			}
			.clps-table tr:last-child {
				border-bottom: none;
			}
			.clps-table td {
				padding: 11px 8px;
				font-size: 13px;
				vertical-align: top;
			}
			.clps-table td:first-child {
				color: #475569;
				font-weight: 600;
				width: 42%;
			}
			.clps-code {
				font-family: 'Fira Code', monospace;
				background: #F1F5F9;
				color: #0F172A;
				border: 1px solid #CBD5E1;
				padding: 2px 7px;
				border-radius: 6px;
				font-size: 12px;
			}
			.clps-feature-tag {
				display: inline-flex;
				align-items: center;
				background: #E0F2FE;
				color: #0369A1;
				border: 1px solid #BAE6FD;
				padding: 3px 9px;
				border-radius: 6px;
				font-size: 11px;
				font-family: 'Fira Code', monospace;
				font-weight: 500;
				margin: 2px 4px 2px 0;
			}
			.clps-label {
				display: block;
				font-size: 12px;
				font-weight: 600;
				color: #334155;
				margin-bottom: 6px;
			}
			.clps-input {
				width: 100%;
				padding: 9px 12px;
				border: 1px solid #CBD5E1;
				border-radius: 8px;
				font-size: 13px;
				color: #0F172A;
				background: #FFFFFF;
				transition: border-color 0.2s, box-shadow 0.2s;
			}
			.clps-input:focus {
				border-color: #0284C7;
				box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15);
				outline: none;
			}
			.clps-btn-primary {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				gap: 8px;
				background: #0284C7;
				color: #FFFFFF;
				border: 1px solid #0369A1;
				padding: 9px 16px;
				border-radius: 8px;
				font-size: 13px;
				font-weight: 600;
				cursor: pointer;
				transition: background-color 0.2s;
			}
			.clps-btn-primary:hover {
				background: #0369A1;
				color: #FFFFFF;
			}
			.clps-btn-secondary {
				display: inline-flex;
				align-items: center;
				justify-content: center;
				gap: 8px;
				background: #F8FAFC;
				color: #0F172A;
				border: 1px solid #CBD5E1;
				padding: 8px 14px;
				border-radius: 8px;
				font-size: 13px;
				font-weight: 600;
				cursor: pointer;
				transition: background-color 0.2s, border-color 0.2s;
			}
			.clps-btn-secondary:hover {
				background: #F1F5F9;
				border-color: #94A3B8;
			}
		</style>

		<div class="clps-wrap">
			<div class="clps-header">
				<div class="clps-header-left">
					<div class="clps-brand-icon">
						<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
							<path d="m9 12 2 2 4-4"/>
						</svg>
					</div>
					<div>
						<h1>Company License Protection — Quản lý Bản quyền Website</h1>
						<p>Bảo vệ bản quyền bằng Chữ ký số Bất đối xứng Ed25519 (ext-sodium) &amp; Xác thực Cốt lõi HMAC-SHA256</p>
					</div>
				</div>
				<div>
					<?php if ( $state['is_valid'] ) : ?>
						<span class="clps-badge-valid clps-mono">● ACTIVE &amp; VERIFIED</span>
					<?php else : ?>
						<span class="clps-badge-invalid clps-mono">✕ <?php echo esc_html( $state['status'] . ' / ' . $state['code'] ); ?></span>
					<?php endif; ?>
				</div>
			</div>

			<?php if ( $this->action_feedback ) : ?>
				<div class="notice notice-<?php echo esc_attr( $this->action_feedback['type'] ); ?> is-dismissible" style="margin:0 0 20px 0;border-radius:8px;">
					<p><strong><?php echo esc_html( $this->action_feedback['message'] ); ?></strong></p>
				</div>
			<?php endif; ?>

			<div class="clps-grid">

				<!-- CỘT 1: TRẠNG THÁI LICENSE & XÁC THỰC CHỮ KÝ SỐ (#2, #3, #4, #5, #6) -->
				<div class="clps-card">
					<h2 class="clps-card-title">
						<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg>
						<span>Trạng thái Bản quyền &amp; Môi trường Máy chủ</span>
					</h2>

					<table class="clps-table">
						<tbody>
							<tr>
								<td>Trạng thái License:</td>
								<td>
									<?php if ( $state['is_valid'] ) : ?>
										<span class="clps-badge-valid">
											● ACTIVE (Đang hoạt động hợp lệ)
										</span>
									<?php else : ?>
										<span class="clps-badge-invalid">
											✕ <?php echo esc_html( $state['status'] . ' / ' . $state['code'] ); ?>
										</span>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<td>Xác thực Chữ ký số (Ed25519):</td>
								<td>
									<?php if ( ! empty( $payload ) ) : ?>
										<span style="color:#0369A1;font-weight:600;">✓ Đã xác minh bằng Ed25519 Public Key (ext-sodium)</span>
									<?php else : ?>
										<span style="color:#475569;">Chưa có chứng chỉ số</span>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<td>Tên miền đã đăng ký (#3):</td>
								<td>
									<code class="clps-code"><?php echo esc_html( $payload['domain'] ?? 'Chưa đăng ký' ); ?></code>
									<div style="font-size:12px;color:#475569;margin-top:4px;">Tên miền hiện tại: <code class="clps-code"><?php echo esc_html( $current_domain ); ?></code></div>
								</td>
							</tr>
							<tr>
								<td>IP Máy chủ đã đăng ký:</td>
								<td>
									<code class="clps-code"><?php echo esc_html( $payload['server_ip'] ?? 'Chưa đăng ký' ); ?></code>
									<div style="font-size:12px;color:#475569;margin-top:4px;">IP Máy chủ hiện tại: <code class="clps-code"><?php echo esc_html( $current_ip ); ?></code></div>
								</td>
							</tr>
							<tr>
								<td>Ngày hết hạn License (#5):</td>
								<td>
									<strong class="clps-mono">
										<?php
										echo ! empty( $payload['expires_at'] )
											? esc_html( wp_date( 'd/m/Y H:i', strtotime( $payload['expires_at'] ) ) )
											: 'Chưa xác định';
										?>
									</strong>
								</td>
							</tr>
							<tr>
								<td>Thời hạn phiên &amp; Dự phòng (Grace Period):</td>
								<td>
									<?php if ( ! empty( $payload['grace_until'] ) ) : ?>
										Hiệu lực dự phòng đến: <code class="clps-code"><?php echo esc_html( wp_date( 'd/m/Y H:i', (int) $payload['grace_until'] ) ); ?></code>
									<?php else : ?>
										<span style="color:#475569;">72 giờ khi mất kết nối mạng</span>
									<?php endif; ?>
								</td>
							</tr>
							<tr>
								<td>Lịch kiểm tra định kỳ (WP-Cron #9):</td>
								<td>
									<?php
									echo $next_cron
										? 'Lần kiểm tra tự động tiếp theo: <code class="clps-code">' . esc_html( wp_date( 'd/m/Y H:i:s', $next_cron ) ) . '</code>'
										: '<span style="color:#475569;">Đang chờ kích hoạt</span>';
									?>
								</td>
							</tr>
							<tr>
								<td>Chức năng Thương mại Mở khóa (Module 7):</td>
								<td>
									<?php
									if ( ! empty( $payload['features'] ) && is_array( $payload['features'] ) ) {
										foreach ( $payload['features'] as $feat ) {
											echo '<span class="clps-feature-tag">' . esc_html( $feat ) . '</span>';
										}
									} else {
										echo '<span style="color:#991B1B;font-weight:600;">Đang khóa (Cần kích hoạt License hợp lệ)</span>';
									}
									?>
								</td>
							</tr>
						</tbody>
					</table>

					<!-- NÚT KIỂM TRA LICENSE THỦ CÔNG (#6) -->
					<form method="post" style="margin-top:18px;padding-top:14px;border-top:1px solid #E2E8F0;display:flex;gap:10px;align-items:center;">
						<?php wp_nonce_field( 'clps_admin_action_nonce', 'clps_nonce_field' ); ?>
						<input type="hidden" name="clps_action" value="verify_license" />
						<button type="submit" class="clps-btn-secondary">
							<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg>
							<span>Kiểm tra License ngay (Manual Check)</span>
						</button>
					</form>
				</div>

				<!-- CỘT 2: NHẬP LICENSE KEY & YÊU CẦU CHUYỂN MÁY CHỦ (#1 & #7) -->
				<div style="display:flex;flex-direction:column;gap:22px;">
					<!-- Form Nhập & Kích hoạt License Key (#1) -->
					<div class="clps-card">
						<h2 class="clps-card-title">
							<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>
							<span>Nhập &amp; Kích hoạt License Key (#1)</span>
						</h2>
						<form method="post">
							<?php wp_nonce_field( 'clps_admin_action_nonce', 'clps_nonce_field' ); ?>
							<input type="hidden" name="clps_action" value="activate_license" />

							<div style="margin-bottom:14px;">
								<label for="clps-input-key" class="clps-label">Mã Bản quyền (License Key)</label>
								<input id="clps-input-key" type="text" name="license_key" value="<?php echo esc_attr( $license_key ); ?>"
									placeholder="VD: CLPS-PRO1-2026-8888-9999" required
									class="clps-input clps-mono" style="font-size:14px;font-weight:600;" />
							</div>
							<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
								<div>
									<label for="clps-input-server" class="clps-label">Central License Server URL</label>
									<input id="clps-input-server" type="url" name="server_url" value="<?php echo esc_attr( $server_url ); ?>"
										required class="clps-input" />
								</div>
								<div>
									<label for="clps-input-slug" class="clps-label">Mã Sản phẩm (Product Slug)</label>
									<input id="clps-input-slug" type="text" name="product_slug" value="<?php echo esc_attr( $product_slug ); ?>"
										required class="clps-input clps-mono" />
								</div>
							</div>
							<button type="submit" class="clps-btn-primary">
								<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
								<span>Lưu &amp; Kích hoạt Bản quyền trên Máy chủ này</span>
							</button>
						</form>
					</div>

					<!-- Form Yêu cầu Chuyển Máy chủ / Đổi Tên miền (#7 - Module 6) -->
					<div class="clps-card">
						<h2 class="clps-card-title">
							<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 2.1l4 4-4 4"/><path d="M3 12.2v-2a4 4 0 0 1 4-4h12.8M7 21.9l-4-4 4-4"/><path d="M21 11.8v2a4 4 0 0 1-4 4H4.2"/></svg>
							<span>Yêu cầu Chuyển Máy chủ / Đổi Tên miền (#7 - Module 6)</span>
						</h2>
						<p style="font-size:13px;color:#475569;margin-top:0;line-height:1.5;">
							Nếu bạn vừa chuyển website sang VPS/Hosting mới (IP mới: <code class="clps-code"><?php echo esc_html( $current_ip ); ?></code>) hoặc đổi tên miền (<code class="clps-code"><?php echo esc_html( $current_domain ); ?></code>), hãy gửi yêu cầu để Quản trị viên phê duyệt trên Dashboard.
						</p>
						<form method="post">
							<?php wp_nonce_field( 'clps_admin_action_nonce', 'clps_nonce_field' ); ?>
							<input type="hidden" name="clps_action" value="request_transfer" />
							<label for="clps-transfer-reason" class="clps-label">Lý do chuyển máy chủ / đổi tên miền</label>
							<textarea id="clps-transfer-reason" name="transfer_reason" rows="2" required
								placeholder="Nhập lý do chuyển máy chủ / nâng cấp VPS để Quản trị viên phê duyệt..."
								class="clps-input" style="margin-bottom:12px;"></textarea>
							<button type="submit" class="clps-btn-secondary">
								<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" x2="11" y1="2" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
								<span>Gửi Yêu cầu Chuyển Máy chủ đến Central Server</span>
							</button>
						</form>
					</div>
				</div>
			</div>

			<!-- MODULE 7: KIỂM THỬ TRỰC TIẾP CHỨC NĂNG THƯƠNG MẠI CỐT LÕI CHẠY TRÊN SERVER CÔNG TY -->
			<div class="clps-card" style="margin-top:22px;">
				<h2 class="clps-card-title">
					<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
					<span>Thực thi Chức năng Thương mại Cốt lõi từ Máy chủ Công ty (Module 7)</span>
				</h2>
				<p style="font-size:13px;color:#475569;margin-top:0;">
					Các thuật toán thương mại độc quyền được thực thi trên Central License Server (xác thực bằng chữ ký động <code class="clps-code">HMAC-SHA256</code> theo phiên kích hoạt và tuân thủ nguyên tắc không gửi dữ liệu cá nhân PII).
				</p>
				<form method="post" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;">
					<?php wp_nonce_field( 'clps_admin_action_nonce', 'clps_nonce_field' ); ?>
					<input type="hidden" name="clps_action" value="test_remote_feature" />
					<label for="clps-feature-code" class="screen-reader-text">Chọn thuật toán thương mại</label>
					<select id="clps-feature-code" name="feature_code" class="clps-input" style="width:auto;min-width:340px;">
						<option value="dynamic_pricing_engine">Thuật toán Định giá &amp; Chiết khấu VIP (dynamic_pricing_engine)</option>
						<option value="advanced_analytics_report">Dự báo Tăng trưởng Doanh thu AI (advanced_analytics_report)</option>
						<option value="mortgage_amortization_engine">Tính Lịch Trả Góp BĐS (mortgage_amortization_engine)</option>
					</select>
					<button type="submit" class="clps-btn-primary">
						<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
						<span>Gọi Thực thi API Chức năng Cốt lõi</span>
					</button>
				</form>

				<?php if ( $this->remote_test_result ) : ?>
					<pre class="clps-mono" style="background:#020617;color:#38BDF8;border:1px solid #1E293B;padding:16px;border-radius:10px;margin-top:14px;overflow-x:auto;font-size:12px;line-height:1.5;"><?php echo esc_html( wp_json_encode( $this->remote_test_result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE ) ); ?></pre>
				<?php endif; ?>
			</div>

			<!-- MODULE 2 (#8): NHẬT KÝ LỖI XÁC THỰC DÀNH CHO QUẢN TRỊ VIÊN -->
			<div class="clps-card" style="margin-top:22px;">
				<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #E2E8F0;padding-bottom:12px;margin-bottom:14px;">
					<h2 style="margin:0;font-size:15px;font-weight:700;color:#0F172A;display:flex;align-items:center;gap:10px;">
						<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#0284C7" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" x2="8" y1="13" y2="13"/><line x1="16" x2="8" y1="17" y2="17"/><line x1="10" x2="8" y1="9" y2="9"/></svg>
						<span>Nhật ký Xác thực &amp; Sự kiện Bảo mật dành cho Quản trị viên (#8)</span>
					</h2>
					<form method="post">
						<?php wp_nonce_field( 'clps_admin_action_nonce', 'clps_nonce_field' ); ?>
						<input type="hidden" name="clps_action" value="clear_logs" />
						<button type="submit" class="clps-btn-secondary" style="padding:5px 12px;font-size:12px;">Xóa nhật ký</button>
					</form>
				</div>

				<table class="widefat striped" style="border-radius:8px;overflow:hidden;border:1px solid #E2E8F0;">
					<thead>
						<tr>
							<th>Thời gian</th>
							<th>Loại sự kiện</th>
							<th>Tên miền &amp; IP Máy chủ</th>
							<th>Chi tiết (Đã che giấu thông tin nhạy cảm)</th>
						</tr>
					</thead>
					<tbody>
						<?php if ( empty( $error_logs ) ) : ?>
							<tr>
								<td colspan="4" style="text-align:center;color:#475569;padding:18px;">Chưa có sự kiện nào được ghi nhận.</td>
							</tr>
						<?php else : ?>
							<?php foreach ( $error_logs as $log ) : ?>
								<tr>
									<td><code class="clps-code"><?php echo esc_html( $log['time'] ?? '' ); ?></code></td>
									<td><strong class="clps-mono"><?php echo esc_html( $log['type'] ?? '' ); ?></strong></td>
									<td><code class="clps-code"><?php echo esc_html( ( $log['domain'] ?? '' ) . ' / ' . ( $log['ip'] ?? '' ) ); ?></code></td>
									<td><?php echo esc_html( $log['message'] ?? '' ); ?></td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}
}
