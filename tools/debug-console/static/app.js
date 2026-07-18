const fallbackStatus = {
  ok: false,
  summary: 'daemon is reachable, SDK is not initialized',
  next_action: 'Run: ipadctl sdk init',
  checks: [
    {
      name: 'platform.check',
      ok: true,
      severity: 'info',
      message: 'platform is supported',
      suggestion: 'Run: ipadctl doctor'
    },
    {
      name: 'config.check',
      ok: true,
      severity: 'info',
      message: 'config loaded',
      suggestion: ''
    },
    {
      name: 'sdk.status',
      ok: false,
      severity: 'warning',
      message: 'SDK is not initialized',
      suggestion: 'Run: ipadctl sdk init'
    }
  ]
};

async function fetchStatus() {
  try {
    const response = await fetch('/api/status', {cache: 'no-store'});
    if (!response.ok) {
      throw new Error(`status ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    return fallbackStatus;
  }
}

function severityFor(data) {
  if (!data.ok && (data.checks || []).some((check) => check.severity === 'error')) {
    return 'error';
  }
  if (!data.ok) {
    return 'warning';
  }
  return 'info';
}

function renderStatus(data) {
  const severity = severityFor(data);
  const health = document.getElementById('health');
  const checks = document.getElementById('checks');

  health.className = `health ${severity}`;
  health.textContent = data.ok ? 'Ready' : severity === 'error' ? 'Error' : 'Attention';
  document.getElementById('summary').textContent = data.summary || 'No summary available';
  document.getElementById('next-action').textContent = data.next_action || '';

  checks.innerHTML = '';
  for (const check of data.checks || []) {
    const item = document.createElement('article');
    item.className = `check ${check.severity || 'info'}`;
    item.innerHTML = `<strong>${check.name}</strong><p>${check.message || ''}</p><small>${check.suggestion || ''}</small>`;
    checks.appendChild(item);
  }
}

async function loadStatus() {
  renderStatus(await fetchStatus());
}

document.getElementById('refresh').addEventListener('click', loadStatus);
document.getElementById('bundle').addEventListener('click', async () => {
  try {
    const response = await fetch('/api/support-bundle', {method: 'POST'});
    const data = await response.json();
    window.alert(data.bundle_dir ? `Support bundle: ${data.bundle_dir}` : 'Run: ipadctl support bundle --output /tmp/ipad-support');
  } catch (error) {
    window.alert('Run: ipadctl support bundle --output /tmp/ipad-support');
  }
});

loadStatus();
