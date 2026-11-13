(function () {
  'use strict';

  const panel = document.querySelector('[data-mfa-supported]');
  if (!panel) return;

  const supported = panel.dataset.mfaSupported === 'true';
  const statusEl = document.getElementById('mfaStatus');
  const enabledView = document.getElementById('mfaEnabledView');
  const disabledView = document.getElementById('mfaDisabledView');
  const pendingView = document.getElementById('pendingView');
  let recoveryCodes = [];

  function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.content || '';
  }

  function setStatus(tone, message) {
    if (!statusEl) return;
    statusEl.dataset.tone = tone;
    statusEl.textContent = message;
  }

  function clearStatus() {
    if (!statusEl) return;
    statusEl.removeAttribute('data-tone');
    statusEl.textContent = '';
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body) headers.set('Content-Type', 'application/json');
    if (!['GET', 'HEAD', 'OPTIONS'].includes((options.method || 'GET').toUpperCase())) {
      headers.set('X-CSRF-Token', csrfToken());
    }
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : `Request failed (${response.status})`;
      throw new Error(message);
    }
    return payload || {};
  }

  function show(el, visible) {
    if (!el) return;
    el.classList.toggle('hidden', !visible);
  }

  function render(data) {
    const enabled = Boolean(data.enabled);
    panel.dataset.mfaEnabled = enabled ? 'true' : 'false';
    show(enabledView, enabled);
    show(disabledView, !enabled);
    if (enabled) {
      show(pendingView, false);
      const confirmed = document.getElementById('mfaConfirmedAt');
      if (confirmed) confirmed.textContent = data.confirmed_at || '—';
      const remaining = document.getElementById('mfaRecoveryRemaining');
      if (remaining) {
        remaining.textContent = `${data.recovery_codes_remaining} unused`;
      }
    }
  }

  async function refresh() {
    if (!supported) return;
    try {
      const data = await api('/api/me/mfa');
      render(data);
    } catch (error) {
      setStatus('error', error.message);
    }
  }

  async function copyText(text, label) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setStatus('ok', `${label} copied to the clipboard.`);
    } catch (error) {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const copied = document.execCommand('copy');
      document.body.removeChild(area);
      setStatus(copied ? 'ok' : 'error', copied ? `${label} copied.` : 'Copy failed. Select the value manually.');
    }
  }

  if (supported) {
    refresh();

    const enrollForm = document.getElementById('enrollForm');
    enrollForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearStatus();
      const button = enrollForm.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        const data = await api('/api/me/mfa/enroll', {
          method: 'POST',
          body: JSON.stringify({ password: document.getElementById('enrollPassword').value }),
        });
        recoveryCodes = Array.isArray(data.recovery_codes) ? data.recovery_codes : [];
        document.getElementById('mfaSecret').textContent = data.secret || '—';
        document.getElementById('mfaUri').textContent = data.provisioning_uri || '—';
        const list = document.getElementById('recoveryCodes');
        list.innerHTML = '';
        recoveryCodes.forEach((code) => {
          const item = document.createElement('li');
          item.textContent = code;
          list.appendChild(item);
        });
        show(disabledView, false);
        show(enabledView, false);
        show(pendingView, true);
        setStatus('info', 'Enrollment started. Save the recovery codes before continuing; they will not be shown again.');
        document.getElementById('confirmCode')?.focus();
      } catch (error) {
        setStatus('error', error.message);
      } finally {
        button.disabled = false;
        enrollForm.reset();
      }
    });

    const confirmForm = document.getElementById('confirmForm');
    confirmForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearStatus();
      const button = confirmForm.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        await api('/api/me/mfa/confirm', {
          method: 'POST',
          body: JSON.stringify({ code: document.getElementById('confirmCode').value.trim() }),
        });
        recoveryCodes = [];
        confirmForm.reset();
        show(pendingView, false);
        await refresh();
        setStatus('ok', 'Multi-factor authentication is enabled. The next sign-in will require a code.');
      } catch (error) {
        setStatus('error', error.message);
      } finally {
        button.disabled = false;
      }
    });

    const disableForm = document.getElementById('disableForm');
    disableForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearStatus();
      const button = disableForm.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        await api('/api/me/mfa/disable', {
          method: 'POST',
          body: JSON.stringify({
            password: document.getElementById('disablePassword').value,
            code: document.getElementById('disableCode').value.trim(),
          }),
        });
        disableForm.reset();
        await refresh();
        setStatus('info', 'Multi-factor authentication is disabled for this account.');
      } catch (error) {
        setStatus('error', error.message);
      } finally {
        button.disabled = false;
      }
    });

    document.getElementById('copySecret')?.addEventListener('click', () => {
      copyText(document.getElementById('mfaSecret').textContent, 'Secret');
    });
    document.getElementById('copyUri')?.addEventListener('click', () => {
      copyText(document.getElementById('mfaUri').textContent, 'Provisioning URI');
    });
    document.getElementById('copyCodes')?.addEventListener('click', () => {
      copyText(recoveryCodes.join('\n'), 'Recovery codes');
    });
    document.getElementById('downloadCodes')?.addEventListener('click', () => {
      if (!recoveryCodes.length) return;
      const body = [
        'NetShield MFA recovery codes',
        'Each code works once. Store this file offline, not in the repository.',
        '',
        ...recoveryCodes,
        '',
      ].join('\n');
      const blob = new Blob([body], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'netshield-recovery-codes.txt';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    });
  }
})();
