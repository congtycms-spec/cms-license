let authToken = localStorage.getItem('clps_admin_token') || '';
let currentUser = JSON.parse(localStorage.getItem('clps_admin_user') || 'null');
let cachedLicenses = [];
let pendingConfirmAction = null;

// Initialize theme preference (Default: OLED Dark Mode per Design System)
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

/**
 * HTML-escapes user/external strings to prevent Stored & Reflected XSS on Dashboard.
 */
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
  settings: `<svg class="w-3.5 h-3.5 inline-block mr-1 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`
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
  refreshAll();
}

function switchTab(tabName) {
  const tabs = ['overview', 'licenses', 'transfers', 'customers', 'logs', 'staff'];
  tabs.forEach((t) => {
    document.getElementById(`tab-${t}`).classList.toggle('hidden', t !== tabName);
    document.getElementById(`tab-btn-${t}`).classList.toggle('tab-active', t === tabName);
  });
}

function statusBadge(status) {
  const map = {
    ACTIVE: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35',
    INACTIVE: 'bg-slate-700/40 text-slate-300 border-slate-600',
    EXPIRED: 'bg-amber-500/15 text-amber-300 border-amber-500/35',
    SUSPENDED: 'bg-orange-500/15 text-orange-300 border-orange-500/35',
    REVOKED: 'bg-rose-500/15 text-rose-300 border-rose-500/35',
    PENDING: 'bg-amber-500/15 text-amber-300 border-amber-500/35',
    APPROVED: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/35',
    REJECTED: 'bg-rose-500/15 text-rose-300 border-rose-500/35'
  };
  return `<span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold border ${map[status] || map.INACTIVE}">${esc(status)}</span>`;
}

async function refreshAll() {
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
    } else {
      showToast(err.message, true);
    }
  }
}

async function loadOverviewStats() {
  const data = await apiCall('/dashboard/stats');
  const s = data.summary;

  document.getElementById('crypto-key-id').textContent = `Key ID: ${data.cryptography.keyId}`;
  document.getElementById('crypto-pub-key').value = data.cryptography.publicKeyBase64;
  document.getElementById('badge-pending-transfers').textContent = s.pendingTransferRequestsCount;

  const kpis = [
    {
      label: 'License Đang Hoạt Động',
      val: `${s.activeLicenses} / ${s.totalLicenses}`,
      color: 'text-emerald-400',
      border: 'border-emerald-500/25',
      icon: `<svg class="w-4 h-4 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`
    },
    {
      label: 'Sắp Hết Hạn (<30 ngày)',
      val: s.expiringWithin30DaysCount,
      color: 'text-amber-400',
      border: 'border-amber-500/25',
      icon: `<svg class="w-4 h-4 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`
    },
    {
      label: 'Chờ Duyệt Chuyển Server',
      val: s.pendingTransferRequestsCount,
      color: 'text-sky-400',
      border: 'border-sky-500/25',
      icon: `<svg class="w-4 h-4 text-sky-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 2.1l4 4-4 4"/><path d="M3 12.2v-2a4 4 0 0 1 4-4h12.8M7 21.9l-4-4 4-4"/><path d="M21 11.8v2a4 4 0 0 1-4 4H4.2"/></svg>`
    },
    {
      label: 'Đã Hết Hạn / Thu Hồi',
      val: s.expiredLicenses + s.revokedLicenses,
      color: 'text-rose-400',
      border: 'border-rose-500/25',
      icon: `<svg class="w-4 h-4 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" x2="9" y1="9" y2="15"/><line x1="9" x2="15" y1="9" y2="15"/></svg>`
    },
    {
      label: 'Lượt Gọi Module 7 (Core API)',
      val: s.totalRemoteFeatureCalls,
      color: 'text-purple-400',
      border: 'border-purple-500/25',
      icon: `<svg class="w-4 h-4 text-purple-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`
    }
  ];

  document.getElementById('kpi-cards').innerHTML = kpis
    .map(
      (k) => `
      <div class="glass-card bg-slate-900 border ${k.border} rounded-xl p-4 flex flex-col justify-between transition-colors duration-200">
        <div class="flex items-center justify-between gap-2 mb-2">
          <span class="text-xs text-slate-400 font-medium">${k.label}</span>
          ${k.icon}
        </div>
        <div class="text-2xl font-bold font-mono ${k.color}">${k.val}</div>
      </div>`
    )
    .join('');

  // Update visual distribution bar
  const total = Math.max(s.totalLicenses, 1);
  const activePct = Math.round((s.activeLicenses / total) * 100);
  const expSoonPct = Math.min(100 - activePct, Math.round((s.expiringWithin30DaysCount / total) * 100));
  const inactiveOrRevokedPct = Math.max(0, 100 - activePct - expSoonPct);
  const distBar = document.getElementById('license-distribution-bar');
  const healthBadge = document.getElementById('health-rate-badge');
  if (distBar && healthBadge) {
    healthBadge.textContent = `${s.totalLicenses > 0 ? activePct : 100}% Active`;
    distBar.innerHTML = `
      <div class="bg-emerald-500 h-full transition-all duration-300" style="width: ${s.totalLicenses > 0 ? activePct : 100}%"></div>
      <div class="bg-amber-500 h-full transition-all duration-300" style="width: ${expSoonPct}%"></div>
      <div class="bg-rose-500 h-full transition-all duration-300" style="width: ${inactiveOrRevokedPct}%"></div>
    `;
  }

  const expTbody = document.getElementById('expiring-soon-tbody');
  if (data.expiringSoonLicenses.length === 0) {
    expTbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500">Không có license nào sắp hết hạn trong 30 ngày tới.</td></tr>`;
  } else {
    expTbody.innerHTML = data.expiringSoonLicenses
      .map(
        (l) => `
      <tr class="hover:bg-slate-800/40 transition-colors duration-150">
        <td class="py-3 px-3 font-mono font-semibold text-sky-300">${esc(l.licenseKey)}</td>
        <td class="py-3 px-3"><div class="font-medium text-white">${esc(l.customerName)}</div><div class="text-[11px] text-slate-400">${esc(l.customerCompany)}</div></td>
        <td class="py-3 px-3">${esc(l.productName)}</td>
        <td class="py-3 px-3 font-mono">${esc(l.allowedDomain || '*')} / ${esc(l.allowedIp || '*')}</td>
        <td class="py-3 px-3"><span class="text-amber-400 font-mono font-bold">Còn ${esc(l.daysLeft)} ngày</span></td>
        <td class="py-3 px-3 text-right">
          <button type="button" onclick="renewLicense('${esc(l.id)}', 365)" class="btn-primary-text px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition-colors duration-200 cursor-pointer">+ Gia hạn 1 năm</button>
        </td>
      </tr>`
      )
      .join('');
  }

  const failTbody = document.getElementById('recent-failures-tbody');
  if (data.recentValidationFailures.length === 0) {
    failTbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500">Chưa ghi nhận cảnh báo vi phạm môi trường nào.</td></tr>`;
  } else {
    failTbody.innerHTML = data.recentValidationFailures
      .map(
        (v) => `
      <tr class="hover:bg-slate-800/40 transition-colors duration-150">
        <td class="py-2.5 px-3 text-slate-400 font-mono">${esc(new Date(v.createdAt).toLocaleString('vi-VN'))}</td>
        <td class="py-2.5 px-3 font-mono text-amber-300">${esc(v.licenseKeyAttempt)}</td>
        <td class="py-2.5 px-3 font-mono">${esc(v.requestDomain)}</td>
        <td class="py-2.5 px-3 font-mono">${esc(v.reportedServerIp || v.detectedOutboundIp)}</td>
        <td class="py-2.5 px-3 font-mono text-[11px]">${esc(v.action)}</td>
        <td class="py-2.5 px-3 text-rose-400 font-mono font-semibold">${esc(v.failureReason || 'INVALID')}</td>
      </tr>`
      )
      .join('');
  }
}

function copyPublicKey() {
  const input = document.getElementById('crypto-pub-key');
  navigator.clipboard.writeText(input.value);
  showToast('Đã sao chép Ed25519 Public Key vào bộ nhớ tạm!');
}

async function loadCustomersAndProducts() {
  const [{ customers }, { products }] = await Promise.all([
    apiCall('/customers'),
    apiCall('/products')
  ]);

  document.getElementById('lic-customer').innerHTML = customers
    .map((c) => `<option value="${esc(c.id)}">${esc(c.name)} (${esc(c.company || c.email)})</option>`)
    .join('');

  document.getElementById('lic-product').innerHTML = products
    .map((p) => `<option value="${esc(p.id)}">${esc(p.name)} [${esc(p.slug)}]</option>`)
    .join('');

  document.getElementById('customers-tbody').innerHTML =
    customers.length === 0
      ? `<tr><td colspan="3" class="py-6 text-center text-slate-500">Chưa có khách hàng nào. Hãy thêm khách hàng mới ở trên.</td></tr>`
      : customers
          .map(
            (c) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3 px-2 font-medium text-white">${esc(c.name)}<div class="text-[11px] text-slate-400">${esc(c.company || '')}</div></td>
      <td class="py-3 px-2 text-slate-300">${esc(c.email)}<div class="text-[11px] font-mono text-slate-400">${esc(c.phone || '')}</div></td>
      <td class="py-3 px-2 text-right space-x-2">
        <span class="font-mono font-bold text-sky-400">${esc(c.licenseCount)}</span>
        <button type="button" onclick="deleteCustomer('${esc(c.id)}', '${esc(c.name)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/30 transition-colors duration-200 cursor-pointer" title="Xóa khách hàng" aria-label="Xóa khách hàng">${ICONS.trash}</button>
      </td>
    </tr>`
          )
          .join('');

  document.getElementById('products-tbody').innerHTML =
    products.length === 0
      ? `<tr><td colspan="3" class="py-6 text-center text-slate-500">Chưa có sản phẩm nào. Hãy thêm sản phẩm WordPress mới ở trên.</td></tr>`
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
        <button type="button" onclick="deleteProduct('${esc(p.id)}', '${esc(p.name)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/30 transition-colors duration-200 cursor-pointer shrink-0" title="Xóa sản phẩm" aria-label="Xóa sản phẩm">${ICONS.trash}</button>
      </td>
    </tr>`
          )
          .join('');
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
  renderFilteredLicenses();
}

function renderFilteredLicenses() {
  const searchVal = (document.getElementById('license-search-input')?.value || '').trim().toLowerCase();
  const statusFilter = document.getElementById('license-status-filter')?.value || 'ALL';

  const filtered = cachedLicenses.filter((l) => {
    if (statusFilter !== 'ALL' && l.status !== statusFilter) return false;
    if (!searchVal) return true;
    const haystack = [
      l.licenseKey,
      l.productName,
      l.customerName,
      l.customerCompany,
      l.allowedDomain,
      l.allowedIp
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(searchVal);
  });

  if (filtered.length === 0) {
    document.getElementById('licenses-tbody').innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500">Không tìm thấy License Key nào khớp bộ lọc.</td></tr>`;
    return;
  }

  document.getElementById('licenses-tbody').innerHTML = filtered
    .map(
      (l) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-3.5 px-3">
        <div class="flex items-center gap-2">
          <span class="font-mono font-bold text-sky-300">${esc(l.licenseKey)}</span>
          <button type="button" onclick="copyText('${esc(l.licenseKey)}', 'License Key')" class="text-slate-400 hover:text-sky-400 transition-colors duration-150 cursor-pointer" title="Sao chép License Key" aria-label="Sao chép License Key">${ICONS.copy}</button>
        </div>
        <div class="text-[11px] text-slate-400 mt-0.5">${esc(l.productName)}</div>
      </td>
      <td class="py-3.5 px-3">
        <div class="font-medium text-white">${esc(l.customerName)}</div>
        <div class="text-[11px] text-slate-400">${esc(l.customerCompany)}</div>
      </td>
      <td class="py-3.5 px-3">${statusBadge(l.status)}</td>
      <td class="py-3.5 px-3 font-mono">
        <div class="text-emerald-300 flex items-center">${ICONS.globe}<span>${esc(l.allowedDomain || 'Chưa gán')}</span></div>
        <div class="text-slate-400 text-[11px] flex items-center mt-0.5">${ICONS.server}<span>IP: ${esc(l.allowedIp || 'Chưa gán')} ${l.strictIpCheck ? '(Strict)' : '(Flex)'}</span></div>
      </td>
      <td class="py-3.5 px-3">
        <div>Site: <span class="font-mono font-semibold text-white">${esc(l.activeInstallationsCount)}/${esc(l.maxActivations)}</span></div>
        <div class="text-[11px] text-slate-400 font-mono">Chuyển Server: ${esc(l.transferCount)}/${esc(l.maxTransfers)}</div>
      </td>
      <td class="py-3.5 px-3 font-mono text-slate-300">${esc(new Date(l.expiresAt).toLocaleDateString('vi-VN'))}</td>
      <td class="py-3.5 px-3 text-right">
        <div class="inline-flex flex-wrap justify-end gap-1.5">
          <button type="button" onclick="openEnvModal('${esc(l.id)}')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-sky-300 rounded-lg border border-slate-700 transition-colors duration-200 cursor-pointer inline-flex items-center" title="Đổi Domain / IP">${ICONS.settings}<span>Domain/IP</span></button>
          <button type="button" onclick="renewLicense('${esc(l.id)}', 365)" class="px-2.5 py-1 bg-emerald-600/15 hover:bg-emerald-600/35 text-emerald-300 rounded-lg border border-emerald-500/35 transition-colors duration-200 cursor-pointer" title="Gia hạn +1 năm">+Gia hạn</button>
          ${
            l.status !== 'ACTIVE'
              ? `<button type="button" onclick="changeLicenseStatus('${esc(l.id)}', 'ACTIVE')" class="px-2.5 py-1 bg-sky-600/15 hover:bg-sky-600/35 text-sky-300 rounded-lg border border-sky-500/35 transition-colors duration-200 cursor-pointer">Kích hoạt</button>`
              : `<button type="button" onclick="changeLicenseStatus('${esc(l.id)}', 'SUSPENDED')" class="px-2.5 py-1 bg-amber-600/15 hover:bg-amber-600/35 text-amber-300 rounded-lg border border-amber-500/35 transition-colors duration-200 cursor-pointer">Tạm ngừng</button>`
          }
          ${
            l.status !== 'REVOKED'
              ? `<button type="button" onclick="changeLicenseStatus('${esc(l.id)}', 'REVOKED')" class="px-2.5 py-1 bg-rose-600/15 hover:bg-rose-600/35 text-rose-300 rounded-lg border border-rose-500/35 transition-colors duration-200 cursor-pointer">Thu hồi</button>`
              : ''
          }
          <button type="button" onclick="deleteLicense('${esc(l.id)}', '${esc(l.licenseKey)}')" class="p-1.5 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/35 transition-colors duration-200 cursor-pointer" title="Xóa License" aria-label="Xóa License">${ICONS.trash}</button>
        </div>
      </td>
    </tr>`
    )
    .join('');
}

document.getElementById('create-license-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await apiCall('/licenses', {
      method: 'POST',
      body: JSON.stringify({
        customerId: document.getElementById('lic-customer').value,
        productId: document.getElementById('lic-product').value,
        allowedDomain: document.getElementById('lic-domain').value,
        allowedIp: document.getElementById('lic-ip').value,
        maxActivations: Number(document.getElementById('lic-max-sites').value || 1),
        durationDays: Number(document.getElementById('lic-days').value || 365)
      })
    });
    document.getElementById('lic-domain').value = '';
    document.getElementById('lic-ip').value = '';
    showToast('Đã tạo License Key mới thành công!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
});

async function renewLicense(id, addDays) {
  try {
    await apiCall(`/licenses/${id}/renew`, {
      method: 'PATCH',
      body: JSON.stringify({ addDays })
    });
    showToast(`Đã gia hạn License thêm ${addDays} ngày!`);
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function changeLicenseStatus(id, status) {
  try {
    await apiCall(`/licenses/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status })
    });
    showToast(`Đã chuyển trạng thái License sang ${status}!`);
    refreshAll();
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
        strictIpCheck: document.getElementById('modal-lic-strict-ip').checked
      })
    });
    closeEnvModal();
    showToast('Đã cập nhật Tên miền, IP máy chủ & Giới hạn kích hoạt!');
    refreshAll();
  } catch (err) {
    showToast(err.message, true);
  }
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
            ? `<button type="button" onclick="approveTransfer('${esc(r.id)}')" class="btn-primary-text px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-semibold transition-colors duration-200 cursor-pointer inline-flex items-center">${ICONS.check}<span>Phê duyệt</span></button>
               <button type="button" onclick="rejectTransfer('${esc(r.id)}')" class="px-3 py-1.5 bg-rose-600/20 hover:bg-rose-600 text-rose-200 hover:text-white rounded-lg border border-rose-500/30 transition-colors duration-200 cursor-pointer inline-flex items-center">${ICONS.x}<span>Từ chối</span></button>`
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

  document.getElementById('validation-logs-tbody').innerHTML = validationLogs
    .map(
      (v) => `
    <tr class="hover:bg-slate-800/40 transition-colors duration-150">
      <td class="py-2.5 px-2 text-slate-400 font-mono">${esc(new Date(v.createdAt).toLocaleTimeString('vi-VN'))}</td>
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

  document.getElementById('audit-logs-tbody').innerHTML = auditLogs
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
        <button type="button" onclick="deleteStaff('${esc(u.id)}', '${esc(u.email)}')" class="px-2.5 py-1 bg-rose-600/15 hover:bg-rose-600 text-rose-300 hover:text-white rounded-lg border border-rose-500/35 text-xs transition-colors duration-200 cursor-pointer inline-flex items-center gap-1">${ICONS.trash}<span>Xóa</span></button>
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
