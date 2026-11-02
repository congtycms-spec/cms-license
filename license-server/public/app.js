let authToken = localStorage.getItem('clps_admin_token') || '';
let currentUser = JSON.parse(localStorage.getItem('clps_admin_user') || 'null');
let cachedLicenses = [];
let cachedCustomers = [];
let cachedProducts = [];
let cachedValidationLogs = [];
let cachedAuditLogs = [];
let cachedMonitoredSites = [];
let selectedLicenseIds = new Set();
let livePingResults = {}; // domain -> { status, httpStatus, latencyMs, isLockedScreen, reachable, error, checking }
let pendingConfirmAction = null;
let autoRefreshEnabled = true;
let autoRefreshTimer = null;
let currentMonitorFilter = 'ALL';
let isSweepingAll = false;

// Initialize theme preference (Default: OLED Dark Mode)
(function initTheme() {
  const savedTheme = localStorage.getItem('clps_theme') || 'dark';
  if (savedTheme === 'light') {
    document.documentElement.classList.remove('dark');
  } else {
    document.documentElement.classList.add('dark');
  }
})();

function toggleTheme() {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('clps_theme', isDark ? 'dark' : 'light');
  showToast(isDark ? 'Đã chuyển sang giao diện Tối (OLED Dark Mode)' : 'Đã chuyển sang giao diện Sáng (High Contrast Light)');
}

function esc(val) {
  if (val === null || val === undefined) return '';
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const ICONS = {
  globe: `<svg class="w-3.5 h-3.5 inline-block mr-1 text-emerald-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" x2="22" y1="12" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  server: `<svg class="w-3.5 h-3.5 inline-block mr-1 text-sky-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/></svg>`,
  trash: `<svg class="w-3.5 h-3.5 inline-block" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>`,
  copy: `<svg class="w-3.5 h-3.5 inline-block" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`,
  check: `<svg class="w-3.5 h-3.5 inline-block mr-1 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
  x: `<svg class="w-3.5 h-3.5 inline-block mr-1 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" x2="6" y1="6" y2="18"/><line x1="6" x2="18" y1="6" y2="18"/></svg>`,
  settings: `<svg class="w-3.5 h-3.5 inline-block mr-1 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  external: `<svg class="w-3 h-3 inline-block ml-1 opacity-75" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>`,
  bolt: `<svg class="w-3.5 h-3.5 inline-block mr-1 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  edit: `<svg class="w-3.5 h-3.5 inline-block" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>`
};

function showToast(msg, isError = false) {
  const box = document.getElementById('toast-box');
  if (!box) return;
  box.innerHTML = `${isError ? ICONS.x : ICONS.check}<span>${esc(msg)}</span>`;
  box.className = `fixed top-5 right-5 z-50 px-4 py-3 rounded-xl shadow-2xl border text-xs font-medium flex items-center gap-2 transition-all duration-200 ${
    isError
      ? 'bg-rose-950 border-rose-700 text-rose-200'
      : 'bg-emerald-950 border-emerald-700 text-emerald-200'
  }`;
  box.classList.remove('hidden');
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => box.classList.add('hidden'), 3500);
}

function copyText(text, label = 'Nội dung') {
  navigator.clipboard.writeText(text);
  showToast(`Đã sao chép ${label}: ${text}`);
}

function askConfirm(message, onConfirm) {
  const modal = document.getElementById('confirm-modal');
  const msgEl = document.getElementById('confirm-modal-message');
  const okBtn = document.getElementById('confirm-modal-ok-btn');
  if (!modal || !msgEl || !okBtn) {
    if (confirm(message)) onConfirm();
    return;
  }
  msgEl.textContent = message;
  pendingConfirmAction = onConfirm;
  modal.classList.remove('hidden');
  okBtn.onclick = async () => {
    const fn = pendingConfirmAction;
    closeConfirmModal();
    if (fn) await fn();
  };
}

function closeConfirmModal() {
  const modal = document.getElementById('confirm-modal');
  if (modal) modal.classList.add('hidden');
  pendingConfirmAction = null;
}

async function apiCall(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    ...(options.headers || {})
  };
  const res = await fetch(`/api/v1/admin${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.message || `Lỗi HTTP ${res.status}`);
  }
  return data;
}

// ==========================================================
// HỆ THỐNG THÔNG BÁO ĐẨY TRÌNH DUYỆT (WEB PUSH) & CHUÔNG BÁO ĐỘNG
// ==========================================================
function playAlertSiren() {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const tones = [880, 660, 880, 660];
    tones.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.12, ctx.currentTime + idx * 0.18);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (idx + 1) * 0.17);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + idx * 0.18);
      osc.stop(ctx.currentTime + (idx + 1) * 0.18);
    });
  } catch {
    // Ignore audio context restriction
  }
}

function updateBrowserPushButtonUI() {
  const btn = document.getElementById('btn-browser-push');
  const label = document.getElementById('browser-push-label');
  if (!btn || !label || !('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    btn.className =
      'px-3 py-2 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 text-xs font-medium rounded-lg border border-emerald-500/30 transition-colors duration-200 cursor-pointer flex items-center gap-1.5';
    label.textContent = 'Thông báo Máy tính: ĐÃ BẬT';
  } else if (Notification.permission === 'denied') {
    btn.className =
      'px-3 py-2 bg-rose-500/15 text-rose-300 text-xs font-medium rounded-lg border border-rose-500/30 flex items-center gap-1.5';
    label.textContent = 'Thông báo Máy tính: Đã chặn';
  }
}

async function enableBrowserPushNotifications() {
  if (!('Notification' in window)) {
    showToast('Trình duyệt của bạn không hỗ trợ Web Push Notification', true);
    return;
  }
  const perm = await Notification.requestPermission();
  updateBrowserPushButtonUI();
  if (perm === 'granted') {
    playAlertSiren();
    new Notification('✅ Đã Bật Cảnh Báo Website Sập (CMS License Pro)', {
      body: 'Khi có bất kỳ Website nào bị lỗi hoặc không truy cập được, thông báo đẩy sẽ hiện ngay tại góc màn hình của bạn!',
      tag: 'clps-test-push'
    });
    showToast('Đã bật Thông báo đẩy trên máy tính kèm âm thanh báo động!');
  } else {
    showToast('Bạn cần bấm Cho phép (Allow) thông báo trên thanh địa chỉ trình duyệt.', true);
  }
}

function fireDesktopDownAlert(downRecords) {
  if (!Array.isArray(downRecords) || downRecords.length === 0) return;
  playAlertSiren();
  const names = downRecords.map((r) => r.domain).join(', ');
  const detail = downRecords[0].errorDetail || `HTTP ${downRecords[0].httpStatus || 'Timeout'}`;
  showToast(`🚨 CẢNH BÁO KHẨN: Website ${names} đang bị lỗi (${detail})!`, true);

  if ('Notification' in window && Notification.permission === 'granted') {
    try {
      new Notification(`🚨 CẢNH BÁO WEBSITE LỖI: ${names}`, {
        body: `Tình trạng: ${detail}\nBấm vào đây để mở bảng kiểm soát và xử lý ngay!`,
        tag: `clps-down-${names}`,
        requireInteraction: true
      });
    } catch {
      // Ignore notification error
    }
  }
}

function startAutoRefreshLoop() {
  clearInterval(autoRefreshTimer);
  if (!autoRefreshEnabled) return;
  autoRefreshTimer = setInterval(async () => {
    if (authToken && !document.hidden) {
      await runFullHealthSweep(false);
    }
  }, 60000);
}

function toggleAutoRefresh() {
  autoRefreshEnabled = !autoRefreshEnabled;
  const btn = document.getElementById('btn-auto-refresh');
  const dot = document.getElementById('auto-refresh-dot');
  const label = document.getElementById('auto-refresh-label');
  if (autoRefreshEnabled) {
    btn.className = 'px-3 py-2 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 text-xs font-mono font-medium rounded-lg border border-emerald-500/30 transition-colors duration-200 cursor-pointer flex items-center gap-1.5';
    dot.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse';
    label.textContent = 'Giám sát Tự động: BẬT (60s)';
    startAutoRefreshLoop();
    showToast('Đã bật tự động quét kiểm tra lỗi Website mỗi 60 giây');
  } else {
    btn.className = 'px-3 py-2 bg-slate-900 hover:bg-slate-800 text-slate-400 text-xs font-mono font-medium rounded-lg border border-slate-700 transition-colors duration-200 cursor-pointer flex items-center gap-1.5';
    dot.className = 'w-2 h-2 rounded-full bg-slate-500';
    label.textContent = 'Giám sát Tự động: TẮT';
    clearInterval(autoRefreshTimer);
    showToast('Đã tạm tắt tự động quét ngầm');
  }
}

async function checkInitialSetup() {
  try {
    const res = await apiCall('/auth/setup-status');
    const setupForm = document.getElementById('setup-admin-form');
    const loginForm = document.getElementById('login-form');
    if (res.needsInitialSetup) {
      setupForm.classList.remove('hidden');
      loginForm.classList.add('hidden');
    } else {
      setupForm.classList.add('hidden');
      loginForm.classList.remove('hidden');
    }
  } catch {
    // Ignore
  }
}

document.getElementById('setup-admin-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('setup-error');
  errBox.classList.add('hidden');
  try {
    const fullName = document.getElementById('setup-fullname').value;
    const email = document.getElementById('setup-email').value;
    const password = document.getElementById('setup-password').value;
    const res = await apiCall('/auth/setup-initial-admin', {
      method: 'POST',
      body: JSON.stringify({ fullName, email, password })
    });
    authToken = res.token;
    currentUser = res.user;
    localStorage.setItem('clps_admin_token', authToken);
    localStorage.setItem('clps_admin_user', JSON.stringify(currentUser));
    enterDashboard();
    showToast('Đã khởi tạo tài khoản Super Admin thành công!');
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove('hidden');
  }
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const errBox = document.getElementById('login-error');
  errBox.classList.add('hidden');
  try {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const res = await apiCall('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    authToken = res.token;
    currentUser = res.user;
    localStorage.setItem('clps_admin_token', authToken);
    localStorage.setItem('clps_admin_user', JSON.stringify(currentUser));
    enterDashboard();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.classList.remove('hidden');
  }
});

function logout() {
  authToken = '';
  currentUser = null;
  clearInterval(autoRefreshTimer);
  localStorage.removeItem('clps_admin_token');
  localStorage.removeItem('clps_admin_user');
  document.getElementById('dashboard-view').classList.add('hidden');
  document.getElementById('login-view').classList.remove('hidden');
  checkInitialSetup();
}

function enterDashboard() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('dashboard-view').classList.remove('hidden');
  document.getElementById('current-user-name').textContent = currentUser?.fullName || 'Admin';
  document.getElementById('current-user-role').textContent = currentUser?.role || 'SUPER_ADMIN';
  updateBrowserPushButtonUI();
  refreshAll().then(() => {
    // Nếu có website chưa được quét sức khỏe lần nào, tự động quét ngay khi mở Dashboard
    if (cachedMonitoredSites.some((m) => !m.health)) {
      runFullHealthSweep(false);
    }
  });
  startAutoRefreshLoop();
}

function switchTab(tabName) {
  const tabs = ['overview', 'licenses', 'transfers', 'customers', 'logs', 'staff'];
  tabs.forEach((t) => {
    document.getElementById(`tab-${t}`).classList.toggle('hidden', t !== tabName);
    document.getElementById(`tab-btn-${t}`).classList.toggle('tab-active', t === tabName);
  });
}

function filterLicensesByStatusAndSwitch(status) {
  const sel = document.getElementById('license-status-filter');
  const srvSel = document.getElementById('license-server-filter');
  if (sel) sel.value = status;
  if (srvSel) srvSel.value = 'ALL';
  switchTab('licenses');
  renderFilteredLicenses();
}

function filterLicensesByServerAndSwitch(ip) {
  const sel = document.getElementById('license-status-filter');
  const srvSel = document.getElementById('license-server-filter');
  if (sel) sel.value = 'ALL';
  if (srvSel) srvSel.value = ip;
  switchTab('licenses');
  renderFilteredLicenses();
}

function statusBadge(status) {
  const map = {
    ACTIVE: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35',
    INACTIVE: 'bg-slate-700/40 text-slate-300 border-slate-600',
    SUSPENDED: 'bg-orange-500/20 text-orange-300 border-orange-500/40',
    REVOKED: 'bg-rose-500/15 text-rose-300 border-rose-500/35',
    PENDING: 'bg-amber-500/15 text-amber-300 border-amber-500/35',
    APPROVED: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35',
    REJECTED: 'bg-rose-500/15 text-rose-300 border-rose-500/35'
  };
  const labelMap = {
    ACTIVE: '● ACTIVE (Vĩnh viễn)',
    SUSPENDED: '🔒 SUSPENDED (Đã khóa)',
    REVOKED: '⛔ REVOKED (Thu hồi)',
    INACTIVE: '○ INACTIVE'
  };
  return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold border ${map[status] || map.INACTIVE}">${esc(labelMap[status] || status)}</span>`;
}

async function refreshAll(silent = false) {
  try {
    await Promise.all([
      loadOverviewStats(),
      loadCustomersAndProducts(),
      loadLicenses(),
      loadTransfers(),
      loadLogs(),
      loadStaff()
    ]);
  } catch (err) {
    if (String(err.message).includes('đăng nhập') || String(err.message).includes('hết hạn')) {
      logout();
    } else if (!silent) {
      showToast(err.message, true);
    }
  }
}

async function loadOverviewStats() {
  const data = await apiCall('/dashboard/stats');
  const s = data.summary;
  cachedMonitoredSites = data.monitoredSites || [];

  // Đồng bộ kết quả sức khỏe vào bộ nhớ đệm livePingResults
  for (const item of cachedMonitoredSites) {
    if (item.health && !livePingResults[item.domain]?.checking) {
      livePingResults[item.domain] = {
        status: item.health.status,
        reachable: item.health.status !== 'DOWN' || item.health.httpStatus > 0,
        httpStatus: item.health.httpStatus,
        latencyMs: item.health.latencyMs,
        isLockedScreen: item.health.status === 'LOCKED',
        error: item.health.errorDetail,
        checkedAt: item.health.checkedAt
      };
    }
  }

  document.getElementById('crypto-key-id').textContent = `Key ID: ${data.cryptography.keyId}`;
  document.getElementById('crypto-pub-key').value = data.cryptography.publicKeyBase64;
  document.getElementById('badge-pending-transfers').textContent = s.pendingTransferRequestsCount;
  document.getElementById('badge-total-licenses').textContent = s.totalLicenses;

  // Điền cấu hình Telegram Bot (chỉ điền nếu người dùng không đang gõ)
  const ms = data.monitorSettings || {};
  const tokenInput = document.getElementById('tg-bot-token');
  const chatInput = document.getElementById('tg-chat-id');
  const enabledInput = document.getElementById('tg-enabled');
  const tgBadge = document.getElementById('telegram-status-badge');
  if (tokenInput && document.activeElement !== tokenInput) {
    tokenInput.value = ms.telegramBotToken || '';
  }
  if (chatInput && document.activeElement !== chatInput) {
    chatInput.value = ms.telegramChatId || '';
  }
  if (enabledInput && document.activeElement !== enabledInput) {
    enabledInput.checked = ms.enabled !== false;
  }
  if (tgBadge) {
    if (ms.telegramBotToken && ms.telegramChatId && ms.enabled !== false) {
      tgBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold';
      tgBadge.textContent = '● Đã kết nối 24/7';
    } else {
      tgBadge.className = 'text-[11px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40';
      tgBadge.textContent = 'Chưa gắn Bot Token';
    }
  }

  const lastSweepEl = document.getElementById('last-sweep-time');
  if (lastSweepEl) {
    lastSweepEl.textContent = ms.lastSweepAt
      ? new Date(ms.lastSweepAt).toLocaleString('vi-VN')
      : 'Chưa quét — bấm Quét Sức Khỏe Toàn Bộ Web Ngay';
  }

  const downCount = s.downCount || 0;
  const upCount = s.upCount || 0;
  const slowCount = s.slowCount || 0;
  const lockedCount = s.lockedCount || 0;

  const kpis = [
    {
      label: 'Website Đang Mở',
      val: `${s.activeLicenses} / ${s.totalLicenses}`,
      sub: 'Bản quyền Vĩnh viễn (Active)',
      color: 'text-emerald-400',
      border: 'border-emerald-500/30 hover:border-emerald-400',
      onclick: "filterLicensesByStatusAndSwitch('ACTIVE')",
      icon: `<svg class="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`
    },
    {
      label: 'Web Hoạt Động Tốt (UP)',
      val: upCount,
      sub: `${slowCount > 0 ? `${slowCount} web phản hồi chậm` : 'Phản hồi HTTP 200 nhanh'}`,
      color: 'text-sky-400',
      border: 'border-sky-500/30 hover:border-sky-400',
      onclick: "setMonitorFilter('UP')",
      icon: `<svg class="w-4 h-4 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`
    },
    {
      label: 'Website Đang Lỗi / Sập',
      val: downCount,
      sub: downCount > 0 ? '🚨 BẤM ĐỂ KIỂM TRA NGAY!' : 'An toàn — 0 website bị lỗi',
      color: downCount > 0 ? 'text-rose-400 animate-pulse' : 'text-emerald-400',
      border: downCount > 0 ? 'border-rose-500 bg-rose-950/25' : 'border-slate-800 hover:border-rose-400/50',
      onclick: "setMonitorFilter('DOWN')",
      icon: `<svg class="w-4 h-4 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" x2="12" y1="9" y2="13"/><line x1="12" x2="12.01" y1="17" y2="17"/></svg>`
    },
    {
      label: 'Đang Khóa Chủ Động (503)',
      val: s.suspendedLicenses || 0,
      sub: 'Bấm để xem web đang khóa tạm',
      color: 'text-orange-400',
      border: 'border-orange-500/30 hover:border-orange-400',
      onclick: "filterLicensesByStatusAndSwitch('SUSPENDED')",
      icon: `<svg class="w-4 h-4 text-orange-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
    },
    {
      label: 'Cụm Máy Chủ Hosting',
      val: s.serverCount || 1,
      sub: `${s.pendingTransferRequestsCount} yêu cầu chuyển chờ duyệt`,
      color: 'text-cyan-400',
      border: 'border-cyan-500/30 hover:border-cyan-400',
      onclick: "switchTab('licenses')",
      icon: `<svg class="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/></svg>`
    },
    {
      label: 'Xác Thực 24h Qua',
      val: s.validations24hTotal || 0,
      sub: `${s.validations24hValid || 0} hợp lệ / ${s.validations24hInvalid || 0} từ chối`,
      color: 'text-purple-400',
      border: 'border-purple-500/30 hover:border-purple-400',
      onclick: "switchTab('logs')",
      icon: `<svg class="w-4 h-4 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`
    }
  ];

  document.getElementById('kpi-cards').innerHTML = kpis
    .map(
      (k) => `
      <div onclick="${k.onclick}" class="glass-card bg-slate-900 border ${k.border} rounded-xl p-4 flex flex-col justify-between transition-all duration-200 cursor-pointer hover:-translate-y-0.5">
        <div class="flex items-center justify-between gap-2 mb-1.5">
          <span class="text-xs text-slate-300 font-semibold">${k.label}</span>
          ${k.icon}
        </div>
        <div class="text-2xl font-bold font-mono ${k.color}">${k.val}</div>
        <div class="text-[11px] text-slate-400 mt-1 truncate">${k.sub}</div>
      </div>`
    )
    .join('');

  // Update 4-segment Uptime Health distribution bar
  const totalMonitored = Math.max(upCount + downCount + slowCount + lockedCount, 1);
  const upPct = Math.round((upCount / totalMonitored) * 100);
  const downPct = Math.round((downCount / totalMonitored) * 100);
  const slowPct = Math.round((slowCount / totalMonitored) * 100);
  const lockPct = Math.max(0, 100 - upPct - downPct - slowPct);

  const healthyPct = Math.round(((upCount + lockedCount + slowCount) / totalMonitored) * 100);
  document.getElementById('health-rate-badge').textContent =
    downCount > 0 ? `🚨 ${downCount} Web Lỗi` : `${healthyPct}% Uptime`;
  document.getElementById('health-rate-badge').className =
    downCount > 0 ? 'text-xs font-mono font-bold text-rose-400 animate-pulse' : 'text-xs font-mono font-bold text-emerald-400';

  document.getElementById('legend-up-count').textContent = upCount;
  document.getElementById('legend-down-count').textContent = downCount;
  document.getElementById('legend-slow-count').textContent = slowCount;
  document.getElementById('legend-locked-count').textContent = lockedCount;

  document.getElementById('license-distribution-bar').innerHTML = `
    <div class="bg-emerald-500 h-full transition-all duration-300" style="width: ${upPct}%" title="Hoạt động tốt (UP): ${upCount}"></div>
    <div class="bg-rose-500 h-full transition-all duration-300" style="width: ${downPct}%" title="Đang lỗi / Sập (DOWN): ${downCount}"></div>
    <div class="bg-amber-400 h-full transition-all duration-300" style="width: ${slowPct}%" title="Phản hồi chậm (SLOW): ${slowCount}"></div>
    <div class="bg-orange-500 h-full transition-all duration-300" style="width: ${lockPct}%" title="Đang khóa chủ động (HTTP 503): ${lockedCount}"></div>
  `;

  // Render Server Clusters
  const groups = data.serverGroups || [];
  document.getElementById('server-cluster-count').textContent = `${groups.length} Cụm IP`;
  document.getElementById('server-clusters-list').innerHTML =
    groups.length === 0
      ? `<div class="text-xs text-slate-500 py-3 text-center">Chưa có dữ liệu máy chủ</div>`
      : groups
          .map(
            (g) => `
          <div onclick="filterLicensesByServerAndSwitch('${esc(g.ip)}')" class="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-950/80 hover:bg-slate-800 border border-slate-800 cursor-pointer transition-colors text-xs">
            <div class="font-mono font-semibold text-sky-300 flex items-center gap-1 truncate">
              ${ICONS.server}
              <span class="truncate">${esc(g.ip)}</span>
            </div>
            <div class="flex items-center gap-1.5 font-mono text-[10px] shrink-0">
              <span class="text-emerald-400">${g.active} mở</span>
              ${g.suspended > 0 ? `<span class="text-orange-400">${g.suspended} khóa</span>` : ''}
            </div>
          </div>`
          )
          .join('');

  // Populate server filter dropdown in Licenses tab
  const serverFilterEl = document.getElementById('license-server-filter');
  if (serverFilterEl) {
    const currentVal = serverFilterEl.value;
    serverFilterEl.innerHTML =
      `<option value="ALL">Tất cả Máy chủ (${s.totalLicenses} web)</option>` +
      groups
        .map((g) => `<option value="${esc(g.ip)}">IP: ${esc(g.ip)} (${g.total} web)</option>`)
        .join('');
    if (Array.from(serverFilterEl.options).some((o) => o.value === currentVal)) {
      serverFilterEl.value = currentVal;
    }
  }

  // Render Real-Time Uptime Monitor Table
  renderUptimeMonitorTable();

  // Recent failures table with 1-click remediation
  const failTbody = document.getElementById('recent-failures-tbody');
  if (data.recentValidationFailures.length === 0) {
    failTbody.innerHTML = `<tr><td colspan="6" class="py-5 text-center text-slate-500">Hệ thống an toàn. Chưa ghi nhận cảnh báo từ chối truy cập nào gần đây.</td></tr>`;
  } else {
    failTbody.innerHTML = data.recentValidationFailures
      .map((v) => {
        const callerIp = v.reportedServerIp || v.detectedOutboundIp || '';
        const reason = String(v.failureReason || 'INVALID');
        let quickBtn = `<a href="https://${esc(v.requestDomain)}" target="_blank" rel="noopener" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 text-[11px]">Mở Web ${ICONS.external}</a>`;

        if (v.resolvedLicenseId && reason.includes('SUSPENDED') && v.currentLicenseStatus === 'SUSPENDED') {
          quickBtn = `<button type="button" onclick="changeLicenseStatus('${esc(v.resolvedLicenseId)}', 'ACTIVE')" class="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600 text-emerald-300 hover:text-white border border-emerald-500/40 rounded-lg text-[11px] font-semibold cursor-pointer">Mở khóa Web ngay</button>`;
        } else if (v.resolvedLicenseId && reason.includes('ENV_MISMATCH_IP') && callerIp) {
          quickBtn = `<button type="button" onclick="quickAuthorizeIp('${esc(v.resolvedLicenseId)}', '${esc(v.allowedIp || '')}', '${esc(callerIp)}')" class="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600 text-sky-300 hover:text-white border border-sky-500/40 rounded-lg text-[11px] font-semibold cursor-pointer">+ Cho phép IP ${esc(callerIp)}</button>`;
        }

        return `
      <tr class="hover:bg-slate-800/40 transition-colors duration-150">
        <td class="py-2.5 px-3 text-slate-400 font-mono">${esc(new Date(v.createdAt).toLocaleString('vi-VN'))}</td>
        <td class="py-2.5 px-3 font-mono text-amber-300">${esc(v.licenseKeyAttempt)}</td>
        <td class="py-2.5 px-3 font-mono font-semibold text-white">${esc(v.requestDomain)}</td>
        <td class="py-2.5 px-3 font-mono text-slate-300">${esc(callerIp)}</td>
        <td class="py-2.5 px-3 text-rose-400 font-mono font-semibold">${esc(reason)}</td>
        <td class="py-2.5 px-3 text-right">${quickBtn}</td>
      </tr>`;
      })
      .join('');
  }
}

function toggleTelegramGuide() {
  const box = document.getElementById('telegram-guide-box');
  if (box) box.classList.toggle('hidden');
}

async function saveMonitorSettings() {
  const telegramBotToken = (document.getElementById('tg-bot-token')?.value || '').trim();
  const telegramChatId = (document.getElementById('tg-chat-id')?.value || '').trim();
  const enabled = Boolean(document.getElementById('tg-enabled')?.checked);

  try {
    await apiCall('/monitor/settings', {
      method: 'PUT',
      body: JSON.stringify({
        enabled,
        telegramBotToken,
        telegramChatId,
        notifyOnRecovery: true
      })
    });
    showToast('Đã lưu cấu hình Thông báo đẩy Telegram 24/7!');
    await loadOverviewStats();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function testTelegramPush() {
  const telegramBotToken = (document.getElementById('tg-bot-token')?.value || '').trim();
  const telegramChatId = (document.getElementById('tg-chat-id')?.value || '').trim();
  if (!telegramBotToken || !telegramChatId) {
    showToast('Vui lòng nhập Telegram Bot Token và Chat ID trước khi gửi thử!', true);
    document.getElementById('telegram-guide-box')?.classList.remove('hidden');
    return;
  }

  const btn = document.getElementById('btn-test-tg');
  if (btn) btn.disabled = true;
  try {
    await saveMonitorSettings();
    const res = await apiCall('/monitor/test-telegram', {
      method: 'POST',
      body: JSON.stringify({ telegramBotToken, telegramChatId })
    });
    showToast(res.message || 'Đã gửi tin nhắn thử nghiệm tới Telegram!');
  } catch (err) {
    showToast(err.message, true);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function setMonitorFilter(filter) {
  currentMonitorFilter = filter;
  ['ALL', 'DOWN', 'SLOW', 'UP', 'LOCKED'].forEach((f) => {
    const btn = document.getElementById(`mon-filter-${f}`);
    if (!btn) return;
    if (f === filter) {
      btn.className = 'px-2.5 py-1.5 rounded-lg bg-sky-500/25 text-sky-200 border border-sky-400 font-semibold cursor-pointer';
    } else {
      btn.className = 'px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 font-medium cursor-pointer';
    }
  });
  renderUptimeMonitorTable();
}

function renderUptimeMonitorTable() {
  const tbody = document.getElementById('uptime-monitor-tbody');
  if (!tbody) return;

  const all = cachedMonitoredSites || [];
  const downList = all.filter((m) => m.health?.status === 'DOWN');
  const slowList = all.filter((m) => m.health?.status === 'SLOW');
  const upList = all.filter((m) => m.health?.status === 'UP');
  const lockedList = all.filter((m) => m.health?.status === 'LOCKED');

  const setTxt = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  };
  setTxt('mon-count-all', all.length);
  setTxt('mon-count-down', downList.length);
  setTxt('mon-count-slow', slowList.length);
  setTxt('mon-count-up', upList.length);
  setTxt('mon-count-locked', lockedList.length);

  let rows = [...all];
  if (currentMonitorFilter !== 'ALL') {
    rows = rows.filter((m) => m.health?.status === currentMonitorFilter);
  }

  // Luôn ưu tiên đưa website đang DOWN hoặc SLOW lên đầu danh sách
  const weight = { DOWN: 0, SLOW: 1, LOCKED: 2, UP: 3 };
  rows.sort((a, b) => {
    const wa = a.health ? (weight[a.health.status] ?? 4) : 5;
    const wb = b.health ? (weight[b.health.status] ?? 4) : 5;
    if (wa !== wb) return wa - wb;
    return (b.health?.latencyMs || 0) - (a.health?.latencyMs || 0);
  });

  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-400">Không có website nào trong nhóm bộ lọc này. Hệ thống đang hoạt động ổn định!</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map((m) => {
      const h = m.health;
      let statusBadgeHtml = `<span class="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[11px]">Chưa quét</span>`;
      let latencyHtml = `<span class="text-slate-500 font-mono">—</span>`;
      let detailHtml = `<span class="text-slate-400">Bấm "Quét Sức Khỏe" để kiểm tra</span>`;
      let rowBg = '';

      if (h) {
        const ms = h.latencyMs || 0;
        const barWidth = Math.min(100, Math.max(8, Math.round((ms / 4000) * 100)));
        const barColor =
          h.status === 'DOWN'
            ? 'bg-rose-500'
            : h.status === 'SLOW'
              ? 'bg-amber-400'
              : h.status === 'LOCKED'
                ? 'bg-orange-400'
                : 'bg-emerald-400';

        latencyHtml = `
          <div class="font-mono font-semibold text-slate-200">${ms} ms</div>
          <div class="w-24 h-1.5 bg-slate-950 rounded-full overflow-hidden mt-1 border border-slate-800">
            <div class="${barColor} h-full" style="width:${barWidth}%"></div>
          </div>`;

        if (h.status === 'DOWN') {
          rowBg = 'bg-rose-950/25';
          statusBadgeHtml = `<span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/50 font-mono font-bold text-[11px] animate-pulse">🚨 LỖI / SẬP (HTTP ${h.httpStatus || 'ERR'})</span>`;
          detailHtml = `<span class="text-rose-300 font-semibold">${esc(h.errorDetail || 'Không thể kết nối tới Website')}</span>`;
        } else if (h.status === 'SLOW') {
          rowBg = 'bg-amber-950/15';
          statusBadgeHtml = `<span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono font-semibold text-[11px]">🐢 CHẬM (HTTP ${h.httpStatus})</span>`;
          detailHtml = `<span class="text-amber-300">${esc(h.errorDetail || 'Máy chủ phản hồi chậm')}</span>`;
        } else if (h.status === 'LOCKED') {
          statusBadgeHtml = `<span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-orange-500/20 text-orange-300 border border-orange-500/40 font-mono font-semibold text-[11px]">🔒 ĐANG KHÓA (HTTP 503)</span>`;
          detailHtml = `<span class="text-orange-300">${esc(h.errorDetail)}</span>`;
        } else {
          statusBadgeHtml = `<span class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono font-semibold text-[11px]">🟢 HOẠT ĐỘNG TỐT (HTTP ${h.httpStatus})</span>`;
          detailHtml = `<span class="text-emerald-400">Trang chủ tải thành công, không có lỗi</span>`;
        }
      }

      const checkedTime = h?.checkedAt
        ? new Date(h.checkedAt).toLocaleTimeString('vi-VN')
        : '—';

      return `
      <tr class="hover:bg-slate-800/40 transition-colors duration-150 ${rowBg}">
        <td class="py-3 px-3">
          <a href="https://${esc(m.domain)}" target="_blank" rel="noopener" class="font-mono font-bold text-sm text-white hover:text-sky-300 flex items-center">
            ${ICONS.globe}<span>${esc(m.domain)}</span>${ICONS.external}
          </a>
          <div class="text-[11px] text-slate-400 font-mono mt-0.5">${esc(m.allowedIp || 'Chưa gán IP')} • ${esc(m.customerName)}</div>
        </td>
        <td class="py-3 px-3">${statusBadgeHtml}</td>
        <td class="py-3 px-3">${latencyHtml}</td>
        <td class="py-3 px-3 max-w-xs">${detailHtml}</td>
        <td class="py-3 px-3 font-mono text-slate-400">${esc(checkedTime)}</td>
        <td class="py-3 px-3 text-right space-x-1.5">
          <button type="button" onclick="pingSite('${esc(m.domain)}', true)" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded-lg border border-slate-700 cursor-pointer text-[11px] font-medium">
            🔄 Kiểm tra ngay
          </button>
          <a href="https://${esc(m.domain)}" target="_blank" rel="noopener" class="px-2.5 py-1 bg-sky-600/20 hover:bg-sky-600 text-sky-300 hover:text-white rounded-lg border border-sky-500/30 text-[11px] font-medium inline-block">
            Mở Web
          </a>
        </td>
      </tr>`;
    })
    .join('');
}

async function runFullHealthSweep(manual = true) {
  if (isSweepingAll) return;
  isSweepingAll = true;
  const btn1 = document.getElementById('btn-overview-sweep');
  const btn2 = document.getElementById('btn-ping-all');
  if (btn1) btn1.disabled = true;
  if (btn2) btn2.disabled = true;

  if (manual) {
    showToast('Đang quét kiểm tra sức khỏe toàn bộ Website theo thời gian thực...');
  }

  try {
    const res = await apiCall('/monitor/sweep', { method: 'POST' });
    await Promise.all([loadOverviewStats(), loadLicenses()]);

    if (res.newlyDownSites && res.newlyDownSites.length > 0) {
      fireDesktopDownAlert(res.newlyDownSites);
    } else if (res.downSites && res.downSites.length > 0 && manual) {
      fireDesktopDownAlert(res.downSites);
    } else if (manual) {
      showToast(`✅ Hoàn tất quét ${res.checkedCount} Website: Tất cả đều phản hồi tốt!`);
    }
  } catch (err) {
    if (manual) showToast(err.message, true);
  } finally {
    isSweepingAll = false;
    if (btn1) btn1.disabled = false;
    if (btn2) btn2.disabled = false;
  }
}

async function quickAuthorizeIp(licenseId, existingIp, newIp) {
  const combined = existingIp ? `${existingIp}, ${newIp}` : newIp;
  try {
    await apiCall(`/licenses/${licenseId}/environment`, {
      method: 'PATCH',
      body: JSON.stringify({
        allowedIp: combined,
        note: `Ủy quyền nhanh IP mới (${newIp}) từ Bảng Cảnh báo`
      })
    });
    showToast(`Đã bổ sung IP ${newIp} vào danh sách cho phép!`);
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

function copyPublicKey() {
  const input = document.getElementById('crypto-pub-key');
  navigator.clipboard.writeText(input.value);
  showToast('Đã sao chép Ed25519 Public Key vào bộ nhớ tạm!');
}

function copyThemeSnippet() {
  const snippet = `if (file_exists(get_template_directory() . '/class-wp-block-hydrator.php')) {\n    require_once get_template_directory() . '/class-wp-block-hydrator.php';\n}`;
  navigator.clipboard.writeText(snippet);
  showToast('Đã sao chép đoạn mã nhúng vào functions.php!');
}

async function downloadStealthHydrator() {
  try {
    const res = await fetch('/api/v1/admin/tools/download-hydrator', {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    if (!res.ok) throw new Error('Không thể tải file class-wp-block-hydrator.php');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'class-wp-block-hydrator.php';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast('Đã tải xuống file class-wp-block-hydrator.php!');
  } catch (err) {
    showToast(err.message, true);
  }
}

async function lookupDomainDns(domainInputId, ipInputId) {
  const domainEl = document.getElementById(domainInputId);
  const ipEl = document.getElementById(ipInputId);
  const rawDomain = (domainEl?.value || '').trim();
  if (!rawDomain) {
    showToast('Vui lòng nhập tên miền trước khi lấy IP DNS', true);
    domainEl?.focus();
    return;
  }
  try {
    showToast(`Đang phân giải DNS cho ${rawDomain}...`);
    const res = await apiCall('/tools/dns-lookup', {
      method: 'POST',
      body: JSON.stringify({ domain: rawDomain })
    });
    domainEl.value = res.domain;
    ipEl.value = res.suggestedAllowedIp || '';
    showToast(`Đã lấy IP máy chủ cho ${res.domain}: ${res.suggestedAllowedIp}`);
  } catch (err) {
    showToast(err.message, true);
  }
}

function autoLookupDnsIfEmpty() {
  const domainVal = (document.getElementById('lic-domain')?.value || '').trim();
  const ipVal = (document.getElementById('lic-ip')?.value || '').trim();
  if (domainVal && !ipVal && domainVal.includes('.')) {
    lookupDomainDns('lic-domain', 'lic-ip');
  }
}

async function pingSite(domain, forceSync = true) {
  if (!domain) return;
  livePingResults[domain] = { checking: true };
  renderFilteredLicenses();
  try {
    const res = await apiCall('/tools/ping-site', {
      method: 'POST',
      body: JSON.stringify({ domain, forceSync })
    });
    livePingResults[domain] = res;
    await Promise.all([loadOverviewStats(), loadLicenses()]);
    if (res.status === 'DOWN') {
      fireDesktopDownAlert([{ domain, errorDetail: res.error, httpStatus: res.httpStatus }]);
    } else if (res.isLockedScreen) {
      showToast(`🔒 ${domain}: Đang hiển thị màn hình Khóa Bản Quyền (HTTP ${res.httpStatus} - ${res.latencyMs}ms)`);
    } else {
      showToast(`🟢 ${domain}: Website đang hoạt động tốt (HTTP ${res.httpStatus} - ${res.latencyMs}ms)`);
    }
  } catch (err) {
    livePingResults[domain] = { status: 'DOWN', reachable: false, error: err.message };
    renderFilteredLicenses();
    showToast(err.message, true);
  }
}

async function pingAllSites() {
  await runFullHealthSweep(true);
}

function renderLivePingBadge(domain) {
  if (!domain) return '';
  const st = livePingResults[domain];
  if (!st) {
    return `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/70">Chưa quét</span>`;
  }
  if (st.checking) {
    return `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 animate-pulse">Đang kiểm tra...</span>`;
  }
  if (st.status === 'DOWN' || (!st.reachable && !st.isLockedScreen)) {
    return `<span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/25 text-rose-300 border border-rose-500/50 animate-pulse" title="${esc(st.error || 'Website không truy cập được')}">🚨 LỖI ${st.httpStatus || 'KẾT NỐI'} (${st.latencyMs || 0}ms)</span>`;
  }
  if (st.isLockedScreen || st.status === 'LOCKED') {
    return `<span class="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/40" title="Website đang hiển thị màn hình khóa bản quyền">🔒 Khóa 503 (${st.latencyMs}ms)</span>`;
  }
  if (st.status === 'SLOW') {
    return `<span class="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40" title="Website phản hồi chậm">🐢 Chậm ${st.httpStatus} (${st.latencyMs}ms)</span>`;
  }
  return `<span class="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40" title="Website đang mở và hoạt động bình thường">🟢 HTTP ${st.httpStatus} (${st.latencyMs}ms)</span>`;
}

async function loadCustomersAndProducts() {
  const [{ customers }, { products }] = await Promise.all([
    apiCall('/customers'),
    apiCall('/products')
  ]);
  cachedCustomers = customers;
  cachedProducts = products;

  document.getElementById('lic-customer').innerHTML =
    `<option value="__AUTO__">⚡ Tự động tạo Khách hàng theo Tên miền</option>` +
    customers
      .map((c) => `<option value="${esc(c.id)}">${esc(c.name)} (${esc(c.company || c.email)})</option>`)
      .join('');

  document.getElementById('lic-product').innerHTML = products
    .map((p) => `<option value="${esc(p.id)}">${esc(p.name)} [${esc(p.slug)}]</option>`)
    .join('');

  document.getElementById('customers-tbody').innerHTML =
    customers.length === 0
      ? `<tr><td colspan="3" class="py-6 text-center text-slate-500">Chưa có khách hàng nào.</td></tr>`
      : customers
          .map(
            (c) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3 px-2 font-medium text-white">
        ${esc(c.name)}
        <div class="text-[11px] text-slate-400">${esc(c.company || '')}</div>
        ${c.notes ? `<div class="text-[10px] text-sky-400 mt-0.5 italic">${esc(c.notes)}</div>` : ''}
      </td>
      <td class="py-3 px-2 text-slate-300">${esc(c.email)}<div class="text-[11px] font-mono text-slate-400">${esc(c.phone || '')}</div></td>
      <td class="py-3 px-2 text-right space-x-1.5">
        <span class="font-mono font-bold text-sky-400 mr-1">${esc(c.licenseCount)} web</span>
        <button type="button" onclick="openEditCustomerModal('${esc(c.id)}')" class="p-1.5 bg-slate-800 hover:bg-slate-700 text-sky-300 rounded-lg border border-slate-700 cursor-pointer" title="Sửa thông tin khách hàng">${ICONS.edit}</button>
        <button type="button" onclick="deleteCustomer('${esc(c.id)}', '${esc(c.name)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/30 cursor-pointer" title="Xóa khách hàng">${ICONS.trash}</button>
      </td>
    </tr>`
          )
          .join('');

  document.getElementById('products-tbody').innerHTML =
    products.length === 0
      ? `<tr><td colspan="3" class="py-6 text-center text-slate-500">Chưa có sản phẩm nào.</td></tr>`
      : products
          .map(
            (p) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3 px-2 font-medium text-white">${esc(p.name)}<div class="text-[11px] font-mono text-sky-400">${esc(p.slug)}</div></td>
      <td class="py-3 px-2 font-mono">v${esc(p.currentVersion)}</td>
      <td class="py-3 px-2 flex items-center justify-between gap-2">
        <div>${(p.commercialFeatures || [])
          .map((f) => `<span class="inline-block bg-slate-800 border border-slate-700 px-2 py-0.5 rounded-md text-[10px] font-mono mr-1 mb-1">${esc(f)}</span>`)
          .join('')}</div>
        <button type="button" onclick="deleteProduct('${esc(p.id)}', '${esc(p.name)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/30 cursor-pointer shrink-0" title="Xóa sản phẩm">${ICONS.trash}</button>
      </td>
    </tr>`
          )
          .join('');
}

function openEditCustomerModal(id) {
  const c = cachedCustomers.find((item) => item.id === id);
  if (!c) return;
  document.getElementById('edit-cust-id').value = c.id;
  document.getElementById('edit-cust-name').value = c.name || '';
  document.getElementById('edit-cust-company').value = c.company || '';
  document.getElementById('edit-cust-email').value = c.email || '';
  document.getElementById('edit-cust-phone').value = c.phone || '';
  document.getElementById('edit-cust-notes').value = c.notes || '';
  document.getElementById('edit-customer-modal').classList.remove('hidden');
}

function closeEditCustomerModal() {
  document.getElementById('edit-customer-modal').classList.add('hidden');
}

async function saveEditCustomerModal() {
  const id = document.getElementById('edit-cust-id').value;
  try {
    await apiCall(`/customers/${id}`, {
      method: 'PUT',
      body: JSON.stringify({
        name: document.getElementById('edit-cust-name').value,
        company: document.getElementById('edit-cust-company').value,
        email: document.getElementById('edit-cust-email').value,
        phone: document.getElementById('edit-cust-phone').value,
        notes: document.getElementById('edit-cust-notes').value
      })
    });
    closeEditCustomerModal();
    showToast('Đã cập nhật hồ sơ khách hàng!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function deleteCustomer(id, name) {
  askConfirm(`Xóa khách hàng "${name}" và các license liên quan?`, async () => {
    try {
      await apiCall(`/customers/${id}`, { method: 'DELETE' });
      showToast('Đã xóa khách hàng!');
      refreshAll();
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

async function deleteProduct(id, name) {
  askConfirm(`Xóa sản phẩm "${name}" và các license liên quan?`, async () => {
    try {
      await apiCall(`/products/${id}`, { method: 'DELETE' });
      showToast('Đã xóa sản phẩm!');
      refreshAll();
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

async function deleteLicense(id, key) {
  askConfirm(`Bạn có chắc chắn muốn xóa vĩnh viễn License "${key}"?`, async () => {
    try {
      await apiCall(`/licenses/${id}`, { method: 'DELETE' });
      selectedLicenseIds.delete(id);
      showToast('Đã xóa License Key!');
      refreshAll();
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

async function loadLicenses() {
  const { licenses } = await apiCall('/licenses');
  cachedLicenses = licenses;
  for (const l of licenses) {
    if (l.allowedDomain && l.health && !livePingResults[l.allowedDomain]?.checking) {
      livePingResults[l.allowedDomain] = {
        status: l.health.status,
        reachable: l.health.status !== 'DOWN' || l.health.httpStatus > 0,
        httpStatus: l.health.httpStatus,
        latencyMs: l.health.latencyMs,
        isLockedScreen: l.health.status === 'LOCKED',
        error: l.health.errorDetail,
        checkedAt: l.health.checkedAt
      };
    }
  }
  renderFilteredLicenses();
}

function getFilteredLicenses() {
  const searchVal = (document.getElementById('license-search-input')?.value || '').trim().toLowerCase();
  const statusFilter = document.getElementById('license-status-filter')?.value || 'ALL';
  const serverFilter = document.getElementById('license-server-filter')?.value || 'ALL';
  const sortBy = document.getElementById('license-sort-by')?.value || 'HEALTH_DOWN_FIRST';

  const filtered = cachedLicenses.filter((l) => {
    const hStatus = l.health?.status || livePingResults[l.allowedDomain]?.status || null;
    if (statusFilter === 'HEALTH_DOWN') {
      if (hStatus !== 'DOWN') return false;
    } else if (statusFilter === 'HEALTH_SLOW') {
      if (hStatus !== 'SLOW') return false;
    } else if (statusFilter !== 'ALL' && l.status !== statusFilter) {
      return false;
    }

    if (serverFilter !== 'ALL') {
      const primaryIp = l.allowedIp ? l.allowedIp.split(',')[0].trim() : 'Chưa gán IP';
      if (primaryIp !== serverFilter) return false;
    }
    if (!searchVal) return true;
    const haystack = [
      l.licenseKey,
      l.productName,
      l.customerName,
      l.customerCompany,
      l.allowedDomain,
      l.allowedIp,
      l.notes,
      l.health?.errorDetail
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(searchVal);
  });

  filtered.sort((a, b) => {
    if (sortBy === 'HEALTH_DOWN_FIRST') {
      const weight = { DOWN: 0, SLOW: 1, LOCKED: 2, UP: 3 };
      const ha = a.health?.status || livePingResults[a.allowedDomain]?.status || 'UP';
      const hb = b.health?.status || livePingResults[b.allowedDomain]?.status || 'UP';
      const diff = (weight[ha] ?? 4) - (weight[hb] ?? 4);
      if (diff !== 0) return diff;
      return String(a.allowedDomain || '').localeCompare(String(b.allowedDomain || ''));
    }
    if (sortBy === 'DOMAIN_ASC') {
      return String(a.allowedDomain || '').localeCompare(String(b.allowedDomain || ''));
    }
    if (sortBy === 'STATUS') {
      const order = { SUSPENDED: 0, REVOKED: 1, INACTIVE: 2, ACTIVE: 3 };
      return (order[a.status] ?? 9) - (order[b.status] ?? 9);
    }
    if (sortBy === 'LATENCY_DESC') {
      const la = a.health?.latencyMs || livePingResults[a.allowedDomain]?.latencyMs || 0;
      const lb = b.health?.latencyMs || livePingResults[b.allowedDomain]?.latencyMs || 0;
      return lb - la;
    }
    return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
  });

  return filtered;
}

function updateBulkSelectionUI() {
  const bar = document.getElementById('bulk-action-bar');
  const countEl = document.getElementById('bulk-selected-count');
  if (!bar || !countEl) return;
  const count = selectedLicenseIds.size;
  countEl.textContent = count;
  bar.classList.toggle('hidden', count === 0);
}

function toggleSelectLicense(id, checked) {
  if (checked) {
    selectedLicenseIds.add(id);
  } else {
    selectedLicenseIds.delete(id);
  }
  updateBulkSelectionUI();
}

function toggleSelectAllLicenses(checked) {
  const filtered = getFilteredLicenses();
  filtered.forEach((l) => {
    if (checked) selectedLicenseIds.add(l.id);
    else selectedLicenseIds.delete(l.id);
  });
  renderFilteredLicenses();
}

async function runBulkAction(action, extra = {}) {
  const ids = Array.from(selectedLicenseIds);
  if (ids.length === 0) return;

  const actionLabels = {
    ACTIVATE: `Kích hoạt đồng loạt ${ids.length} website`,
    SUSPEND: `Tạm ngưng (Khóa) đồng loạt ${ids.length} website`,
    UPDATE_IP: `Cập nhật IP máy chủ cho ${ids.length} website`,
    DELETE: `XÓA VĨNH VIỄN ${ids.length} website`
  };

  askConfirm(`Xác nhận thực hiện: ${actionLabels[action] || action}?`, async () => {
    try {
      const res = await apiCall('/licenses/bulk-action', {
        method: 'POST',
        body: JSON.stringify({
          licenseIds: ids,
          action,
          ...extra
        })
      });
      if (action === 'DELETE') selectedLicenseIds.clear();
      updateBulkSelectionUI();
      showToast(`Đã xử lý thành công ${res.updatedCount} website!`);
      refreshAll();
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

function promptBulkUpdateIp() {
  const newIp = prompt('Nhập IP Máy chủ Hosting mới cho các website đã chọn (vd: 103.221.223.75, 103.221.223.60):');
  if (!newIp || !newIp.trim()) return;
  runBulkAction('UPDATE_IP', { allowedIp: newIp.trim() });
}

function renderFilteredLicenses() {
  const filtered = getFilteredLicenses();
  updateBulkSelectionUI();

  if (filtered.length === 0) {
    document.getElementById('licenses-tbody').innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500">Không tìm thấy Website / License Key nào khớp bộ lọc.</td></tr>`;
    return;
  }

  document.getElementById('licenses-tbody').innerHTML = filtered
    .map((l) => {
      const isChecked = selectedLicenseIds.has(l.id) ? 'checked' : '';
      const domain = l.allowedDomain || '';
      const h = l.health || livePingResults[domain] || null;
      const isDown = h?.status === 'DOWN';

      let healthColHtml = `<span class="text-slate-500 font-mono text-[11px]">Chưa kiểm tra</span>`;
      if (h) {
        const checkedTime = h.checkedAt
          ? new Date(h.checkedAt).toLocaleTimeString('vi-VN')
          : '';
        if (h.status === 'DOWN') {
          healthColHtml = `
            <div class="text-rose-400 font-mono font-bold text-xs animate-pulse">🚨 LỖI (${h.httpStatus || 'ERR'})</div>
            <div class="text-[10px] text-rose-300 truncate max-w-[13rem]" title="${esc(h.errorDetail || h.error || '')}">${esc(h.errorDetail || h.error || 'Không thể truy cập')}</div>`;
        } else if (h.status === 'SLOW') {
          healthColHtml = `
            <div class="text-amber-300 font-mono font-semibold text-xs">🐢 Chậm • ${h.latencyMs}ms</div>
            <div class="text-[10px] text-slate-400 font-mono">HTTP ${h.httpStatus} • ${checkedTime}</div>`;
        } else if (h.status === 'LOCKED' || h.isLockedScreen) {
          healthColHtml = `
            <div class="text-orange-300 font-mono font-semibold text-xs">🔒 Khóa 503 • ${h.latencyMs}ms</div>
            <div class="text-[10px] text-slate-400 font-mono">Đang khóa chủ động • ${checkedTime}</div>`;
        } else {
          healthColHtml = `
            <div class="text-emerald-400 font-mono font-semibold text-xs">🟢 Tốt • ${h.latencyMs}ms</div>
            <div class="text-[10px] text-slate-400 font-mono">HTTP ${h.httpStatus} • ${checkedTime}</div>`;
        }
      }

      const wpInfo =
        l.wpVersion || l.phpVersion
          ? `<span class="text-[10px] font-mono text-slate-400">WP ${esc(l.wpVersion || '?')} • PHP ${esc(l.phpVersion || '?')}</span>`
          : `<span class="text-[10px] font-mono text-slate-500">Site: ${esc(l.activeInstallationsCount)}/${esc(l.maxActivations)}</span>`;

      return `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150 ${isDown ? 'bg-rose-950/20' : l.status === 'SUSPENDED' ? 'bg-orange-950/10' : ''}">
      <td class="py-3.5 px-2">
        <input type="checkbox" ${isChecked} onchange="toggleSelectLicense('${esc(l.id)}', this.checked)"
          class="w-4 h-4 rounded border-slate-700 text-sky-600 cursor-pointer" />
      </td>
      <td class="py-3.5 px-3">
        <div class="flex items-center gap-2 flex-wrap">
          ${
            domain
              ? `<a href="https://${esc(domain)}" target="_blank" rel="noopener" class="font-mono font-bold text-sm text-emerald-300 hover:text-emerald-200 underline decoration-emerald-500/40 flex items-center">${ICONS.globe}<span>${esc(domain)}</span>${ICONS.external}</a>`
              : `<span class="font-mono text-slate-400">Chưa gán tên miền</span>`
          }
          ${renderLivePingBadge(domain)}
        </div>
        <div class="flex items-center gap-2 mt-1">
          ${wpInfo}
          ${l.notes ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-300 border border-sky-500/20 truncate max-w-[14rem]" title="${esc(l.notes)}">📝 ${esc(l.notes)}</span>` : ''}
        </div>
      </td>
      <td class="py-3.5 px-3">${statusBadge(l.status)}</td>
      <td class="py-3.5 px-3 font-mono">
        <div class="text-slate-200 text-xs flex items-center">${ICONS.server}<span>${esc(l.allowedIp || 'Chưa gán IP')}</span></div>
        <div class="text-[10px] text-slate-400 mt-0.5">${l.strictIpCheck ? 'Chế độ: Khớp cứng IP (Strict)' : 'Chế độ: Linh hoạt (Flex)'}</div>
      </td>
      <td class="py-3.5 px-3">
        <div class="font-medium text-white">${esc(l.customerName)}</div>
        <div class="flex items-center gap-1.5 mt-0.5">
          <span class="font-mono text-[11px] text-sky-300">${esc(l.licenseKey)}</span>
          <button type="button" onclick="copyText('${esc(l.licenseKey)}', 'License Key')" class="text-slate-400 hover:text-sky-400 cursor-pointer" title="Sao chép License Key">${ICONS.copy}</button>
        </div>
      </td>
      <td class="py-3.5 px-3">
        ${healthColHtml}
      </td>
      <td class="py-3.5 px-3 text-right">
        <div class="inline-flex flex-wrap justify-end gap-1.5">
          ${
            domain
              ? `<button type="button" onclick="pingSite('${esc(domain)}', true)" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded-lg border border-slate-700 cursor-pointer inline-flex items-center" title="Kiểm tra sức khỏe & phản hồi HTTP thực tế của Website">${ICONS.bolt}<span>Kiểm tra Web</span></button>`
              : ''
          }
          <button type="button" onclick="openEnvModal('${esc(l.id)}')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-300 rounded-lg border border-slate-700 cursor-pointer inline-flex items-center" title="Đổi Tên miền, IP & Ghi chú">${ICONS.settings}<span>Cấu hình</span></button>
          ${
            l.status !== 'ACTIVE'
              ? `<button type="button" onclick="changeLicenseStatus('${esc(l.id)}', 'ACTIVE', '${esc(domain)}')" class="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white font-semibold rounded-lg cursor-pointer">Mở khóa</button>`
              : `<button type="button" onclick="changeLicenseStatus('${esc(l.id)}', 'SUSPENDED', '${esc(domain)}')" class="px-2.5 py-1 bg-orange-600/20 hover:bg-orange-600 text-orange-300 hover:text-white rounded-lg border border-orange-500/40 font-semibold cursor-pointer">Khóa tạm</button>`
          }
          <button type="button" onclick="deleteLicense('${esc(l.id)}', '${esc(l.licenseKey)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/35 cursor-pointer" title="Xóa License">${ICONS.trash}</button>
        </div>
      </td>
    </tr>`;
    })
    .join('');
}

document.getElementById('create-license-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const domainVal = document.getElementById('lic-domain').value;
    await apiCall('/licenses', {
      method: 'POST',
      body: JSON.stringify({
        customerId: document.getElementById('lic-customer').value,
        productId: document.getElementById('lic-product').value,
        allowedDomain: domainVal,
        allowedIp: document.getElementById('lic-ip').value,
        maxActivations: Number(document.getElementById('lic-max-sites').value || 3)
      })
    });
    document.getElementById('lic-domain').value = '';
    document.getElementById('lic-ip').value = '';
    showToast(`Đã cấp License vĩnh viễn cho ${domainVal} thành công!`);
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
});

async function changeLicenseStatus(id, status, domain = '') {
  try {
    showToast(`Đang đồng bộ trạng thái ${status} xuống website...`);
    await apiCall(`/licenses/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
    showToast(`Đã chuyển trạng thái sang ${status}!`);
    await refreshAll();
    if (domain) {
      await pingSite(domain, false);
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

function openEnvModal(id) {
  const lic = cachedLicenses.find((l) => l.id === id);
  if (!lic) return;
  document.getElementById('modal-lic-id').value = lic.id;
  document.getElementById('modal-lic-domain').value = lic.allowedDomain || '';
  document.getElementById('modal-lic-ip').value = lic.allowedIp || '';
  document.getElementById('modal-lic-max-sites').value = lic.maxActivations;
  document.getElementById('modal-lic-max-transfers').value = lic.maxTransfers;
  document.getElementById('modal-lic-notes').value = lic.notes || '';
  document.getElementById('modal-lic-strict-ip').checked = lic.strictIpCheck;
  document.getElementById('env-modal').classList.remove('hidden');
}

function closeEnvModal() {
  document.getElementById('env-modal').classList.add('hidden');
}

async function saveEnvModal() {
  const id = document.getElementById('modal-lic-id').value;
  try {
    await apiCall(`/licenses/${id}/environment`, {
      method: 'PATCH',
      body: JSON.stringify({
        allowedDomain: document.getElementById('modal-lic-domain').value,
        allowedIp: document.getElementById('modal-lic-ip').value,
        maxActivations: Number(document.getElementById('modal-lic-max-sites').value),
        maxTransfers: Number(document.getElementById('modal-lic-max-transfers').value),
        notes: document.getElementById('modal-lic-notes').value,
        strictIpCheck: document.getElementById('modal-lic-strict-ip').checked
      })
    });
    closeEnvModal();
    showToast('Đã cập nhật cấu hình Website & đồng bộ xuống máy chủ!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

function exportLicensesCsv() {
  if (!cachedLicenses || cachedLicenses.length === 0) {
    showToast('Chưa có dữ liệu để xuất CSV', true);
    return;
  }
  const headers = ['Ten Mien', 'Trang Thai Ban Quyen', 'Suc Khoe Website', 'Toc Do (ms)', 'IP May Chu', 'License Key', 'Khach Hang', 'Ghi Chu'];
  const rows = cachedLicenses.map((l) => [
    l.allowedDomain || '',
    l.status || '',
    l.health?.status || 'CHUA_QUET',
    l.health?.latencyMs || 0,
    l.allowedIp || '',
    l.licenseKey || '',
    l.customerName || '',
    (l.notes || '').replace(/\r?\n/g, ' ')
  ]);
  const csvContent =
    '\uFEFF' +
    [headers, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `danh-sach-ban-quyen-website-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast('Đã xuất danh sách Website ra file Excel / CSV!');
}

async function loadTransfers() {
  const { transferRequests } = await apiCall('/transfer-requests');
  const tbody = document.getElementById('transfers-tbody');
  if (transferRequests.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500">Chưa có yêu cầu chuyển máy chủ nào.</td></tr>`;
    return;
  }

  tbody.innerHTML = transferRequests
    .map(
      (r) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3.5 px-3 text-slate-400 font-mono">${esc(new Date(r.createdAt).toLocaleString('vi-VN'))}</td>
      <td class="py-3.5 px-3">
        <div class="font-mono font-semibold text-sky-300">${esc(r.licenseKey)}</div>
        <div class="text-[11px] text-slate-400">${esc(r.customerName)} (${esc(r.transferCount)}/${esc(r.maxTransfers)} lần)</div>
      </td>
      <td class="py-3.5 px-3 font-mono text-slate-400">
        <div class="flex items-center">${ICONS.globe}<span>${esc(r.oldDomain || 'N/A')}</span></div>
        <div class="flex items-center mt-0.5">${ICONS.server}<span>${esc(r.oldIp || 'N/A')}</span></div>
      </td>
      <td class="py-3.5 px-3 font-mono text-emerald-300 font-semibold">
        <div class="flex items-center">${ICONS.globe}<span>${esc(r.newDomain)}</span></div>
        <div class="flex items-center mt-0.5">${ICONS.server}<span>${esc(r.newIp)}</span></div>
      </td>
      <td class="py-3.5 px-3 text-slate-200 max-w-xs">${esc(r.reason)}</td>
      <td class="py-3.5 px-3">${statusBadge(r.status)}</td>
      <td class="py-3.5 px-3 text-right space-x-1.5">
        ${
          r.status === 'PENDING'
            ? `<button type="button" onclick="approveTransfer('${esc(r.id)}')" class="btn-primary-text px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold cursor-pointer inline-flex items-center">${ICONS.check}<span>Phê duyệt</span></button>
               <button type="button" onclick="rejectTransfer('${esc(r.id)}')" class="px-3 py-1.5 bg-rose-600/20 hover:bg-rose-600 text-rose-200 hover:text-white rounded-lg border border-rose-500/30 cursor-pointer inline-flex items-center">${ICONS.x}<span>Từ chối</span></button>`
            : `<span class="text-slate-500 text-[11px]">${esc(r.reviewNote || '')}</span>`
        }
      </td>
    </tr>`
    )
    .join('');
}

async function approveTransfer(id) {
  try {
    await apiCall(`/transfer-requests/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ reviewNote: 'Phê duyệt chuyển máy chủ từ Dashboard' })
    });
    showToast('Đã phê duyệt chuyển máy chủ! Domain & IP mới đã được kích hoạt.');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function rejectTransfer(id) {
  try {
    await apiCall(`/transfer-requests/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reviewNote: 'Từ chối yêu cầu chuyển máy chủ' })
    });
    showToast('Đã từ chối yêu cầu chuyển máy chủ.');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

document.getElementById('create-customer-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await apiCall('/customers', {
      method: 'POST',
      body: JSON.stringify({
        name: document.getElementById('cust-name').value,
        email: document.getElementById('cust-email').value,
        phone: document.getElementById('cust-phone').value,
        company: document.getElementById('cust-company').value
      })
    });
    e.target.reset();
    showToast('Đã thêm khách hàng mới!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
});

document.getElementById('create-product-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await apiCall('/products', {
      method: 'POST',
      body: JSON.stringify({
        slug: document.getElementById('prod-slug').value,
        name: document.getElementById('prod-name').value,
        currentVersion: document.getElementById('prod-version').value,
        commercialFeatures: document.getElementById('prod-features').value
      })
    });
    e.target.reset();
    showToast('Đã thêm sản phẩm WordPress mới!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
});

async function loadLogs() {
  const [{ validationLogs }, { auditLogs }] = await Promise.all([
    apiCall('/logs/validations'),
    apiCall('/logs/audits')
  ]);
  cachedValidationLogs = validationLogs;
  cachedAuditLogs = auditLogs;
  renderFilteredLogs();
}

function renderFilteredLogs() {
  const q = (document.getElementById('log-search-input')?.value || '').trim().toLowerCase();

  const vLogs = cachedValidationLogs.filter((v) => {
    if (!q) return true;
    return [v.licenseKeyAttempt, v.requestDomain, v.reportedServerIp, v.detectedOutboundIp, v.failureReason, v.action]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(q);
  });

  const aLogs = cachedAuditLogs.filter((a) => {
    if (!q) return true;
    return [a.licenseKey, a.eventType, a.actorName, a.note]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(q);
  });

  document.getElementById('validation-logs-tbody').innerHTML =
    vLogs.length === 0
      ? `<tr><td colspan="4" class="py-6 text-center text-slate-500">Không có nhật ký xác thực khớp bộ lọc.</td></tr>`
      : vLogs
          .map(
            (v) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-2.5 px-2 text-slate-400 font-mono">${esc(new Date(v.createdAt).toLocaleString('vi-VN'))}</td>
      <td class="py-2.5 px-2"><div class="font-mono text-sky-300">${esc(v.licenseKeyAttempt)}</div><div class="text-[10px] font-mono text-slate-400">${esc(v.action)}</div></td>
      <td class="py-2.5 px-2 font-mono">${esc(v.requestDomain)}<div class="text-[10px] text-slate-400">${esc(v.reportedServerIp || v.detectedOutboundIp)}</div></td>
      <td class="py-2.5 px-2 font-mono">${
        v.isValid
          ? `<span class="text-emerald-400 font-semibold inline-flex items-center">${ICONS.check}<span>VALID</span></span>`
          : `<span class="text-rose-400 font-semibold inline-flex items-center">${ICONS.x}<span>${esc(v.failureReason)}</span></span>`
      }</td>
    </tr>`
          )
          .join('');

  document.getElementById('audit-logs-tbody').innerHTML =
    aLogs.length === 0
      ? `<tr><td colspan="4" class="py-6 text-center text-slate-500">Không có lịch sử kiểm toán khớp bộ lọc.</td></tr>`
      : aLogs
          .map(
            (a) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-2.5 px-2 text-slate-400 font-mono">${esc(new Date(a.createdAt).toLocaleString('vi-VN'))}</td>
      <td class="py-2.5 px-2 font-mono text-sky-300">${esc(a.licenseKey)}</td>
      <td class="py-2.5 px-2"><div class="font-mono font-semibold text-white">${esc(a.eventType)}</div><div class="text-[10px] text-slate-400">${esc(a.actorName)}</div></td>
      <td class="py-2.5 px-2 text-slate-300">${esc(a.note)}</td>
    </tr>`
          )
          .join('');
}

async function clearValidationLogs(mode = 'ALL') {
  const msg =
    mode === 'FAILED_ONLY'
      ? 'Xóa các dòng cảnh báo xác thực thất bại cũ trên trang Tổng quan?'
      : 'Xóa toàn bộ lịch sử nhật ký xác thực?';
  askConfirm(msg, async () => {
    try {
      await apiCall(`/logs/validations?mode=${mode}`, { method: 'DELETE' });
      showToast('Đã dọn dẹp nhật ký xác thực!');
      refreshAll();
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

async function loadStaff() {
  if (currentUser?.role === 'SUPPORT') {
    document.getElementById('staff-tbody').innerHTML = `<tr><td colspan="5" class="py-6 text-center text-slate-500">Quyền SUPPORT không xem danh sách quản trị viên cấp cao.</td></tr>`;
    return;
  }
  const { users } = await apiCall('/users');
  document.getElementById('staff-tbody').innerHTML = users
    .map(
      (u) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3 px-3 font-medium text-white">${esc(u.fullName)}</td>
      <td class="py-3 px-3 text-slate-300">${esc(u.email)}</td>
      <td class="py-3 px-3"><span class="px-2.5 py-0.5 rounded-full bg-sky-500/15 border border-sky-500/30 text-sky-300 font-mono text-xs">${esc(u.role)}</span></td>
      <td class="py-3 px-3 text-emerald-400 font-medium"><span class="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-1.5"></span>Đang hoạt động</td>
      <td class="py-3 px-3 text-right">
        <button type="button" onclick="deleteStaff('${esc(u.id)}', '${esc(u.email)}')" class="px-2.5 py-1 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/35 text-xs cursor-pointer inline-flex items-center gap-1">${ICONS.trash}<span>Xóa</span></button>
      </td>
    </tr>`
    )
    .join('');
}

async function deleteStaff(id, email) {
  askConfirm(`Bạn có chắc chắn muốn xóa tài khoản nhân viên "${email}"?`, async () => {
    try {
      await apiCall(`/users/${id}`, { method: 'DELETE' });
      showToast(`Đã xóa tài khoản ${email}!`);
      if (currentUser && currentUser.id === id) {
        logout();
      } else {
        loadStaff();
      }
    } catch (err) {
      showToast(err.message, true);
    }
  });
}

document.getElementById('create-staff-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await apiCall('/users', {
      method: 'POST',
      body: JSON.stringify({
        fullName: document.getElementById('staff-name').value,
        email: document.getElementById('staff-email').value,
        password: document.getElementById('staff-password').value,
        role: document.getElementById('staff-role').value
      })
    });
    e.target.reset();
    showToast('Đã tạo tài khoản nhân viên mới!');
    loadStaff();
  } catch (err) {
    showToast(err.message, true);
  }
});

if (authToken && currentUser) {
  enterDashboard();
} else {
  checkInitialSetup();
}
