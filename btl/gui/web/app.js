/* The browser side of the BTL interface.
 *
 * Every server call goes through api(), which posts a JSON body to
 * /api/<action> and resolves with the "result" field of the answer.  A
 * failed call rejects with an Error carrying the message the server sent,
 * so the caller can show it without knowing the transport.
 */
'use strict';

// ---------------------------------------------------------------- utils

const $ = (id) => document.getElementById(id);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function log(message, kind) {
  const box = $('lOutput');
  const stamp = new Date().toLocaleTimeString('vi-VN');
  const line = document.createElement('div');
  line.textContent = '[' + stamp + '] ' + message;
  if (kind) line.style.color = kind === 'bad' ? '#f2545b' : kind === 'ok' ? '#35c48b' : '#93a1bd';
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

let toastTimer = null;
function toast(message, kind) {
  const box = $('toast');
  box.textContent = message;
  box.className = 'toast' + (kind ? ' ' + kind : '');
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, 4500);
  log(message, kind);
}

function setStatus(id, message, kind) {
  const el = $(id);
  if (!el) return;
  el.textContent = message;
  el.className = 'status' + (kind ? ' ' + kind : '');
}

// ------------------------------------------------------------ transport

async function api(action, payload) {
  let response;
  try {
    response = await fetch('/api/' + action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });
  } catch (err) {
    throw new Error('Không kết nối được tới máy chủ giao diện: ' + err.message);
  }

  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new Error('Máy chủ giao diện trả về dữ liệu không hợp lệ (HTTP ' + response.status + ')');
  }

  if (!body.ok) {
    throw new Error(body.error || 'Thao tác thất bại');
  }
  return body.result;
}

/** Run an action, showing any error as a toast. */
async function guard(label, fn) {
  try {
    const value = await fn();
    if (label) log(label + ' thành công', 'ok');
    return value;
  } catch (err) {
    toast(err.message, 'bad');
    return null;
  }
}

// ----------------------------------------------------------------- tabs

function setupTabs() {
  $$('.tabs > .tab:not(.sub-tabs .tab)').forEach((tab) => {
    tab.addEventListener('click', () => {
      const group = tab.parentElement;
      group.querySelectorAll(':scope > .tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      const name = tab.dataset.tab;
      $$('.panel').forEach((p) => p.classList.remove('active'));
      const panel = $('panel-' + name);
      if (panel) panel.classList.add('active');
    });
  });

  $$('.sub-tabs .tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      tab.parentElement.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.subpanel').forEach((p) => p.classList.remove('active'));
      const panel = $('sub-' + tab.dataset.subtab);
      if (panel) panel.classList.add('active');
    });
  });
}

// -------------------------------------------------------------- session

function applySession(state) {
  const dot = $('sessionDot');
  const text = $('sessionText');
  const button = $('btnDisconnect');

  if (state && state.connected) {
    dot.classList.add('online');
    text.textContent = state.username + '@' + state.host + ':' + state.port;
    button.hidden = false;
  } else {
    dot.classList.remove('online');
    text.textContent = 'Chưa kết nối';
    button.hidden = true;
  }
}

async function refreshState() {
  try {
    const state = await api('state', {});
    applySession(state);
    applyDefaults(state.defaults);
  } catch (err) {
    /* the server may still be starting */
  }
}

/** Pre-fill the form with the usual OpenSSH paths, without overwriting
 *  anything the user has already typed. */
function applyDefaults(defaults) {
  if (!defaults) return;

  if (!$('cKeyPath').value && defaults.key_path) {
    $('cKeyPath').value = defaults.key_path;
  }
  if (!$('hKnownHosts').value && defaults.known_hosts) {
    $('hKnownHosts').value = defaults.known_hosts;
  }
}

// -------------------------------------------------------------- connect

function setupConnection() {
  const method = $('cAuthMethod');
  const sync = () => {
    const value = method.value;
    $('authKey').hidden = value !== 'key';
    $('authPassword').hidden = value !== 'password';
  };
  method.addEventListener('change', sync);
  sync();

  $('btnConnect').addEventListener('click', async () => {
    const button = $('btnConnect');
    button.disabled = true;
    button.textContent = 'Đang kết nối...';

    const result = await guard('Kết nối', () => api('connect', {
      host: $('cHost').value.trim(),
      port: Number($('cPort').value) || 22,
      username: $('cUser').value.trim(),
      auth_method: method.value,
      key_path: $('cKeyPath').value.trim(),
      passphrase: $('cPassphrase').value,
      password: $('cPassword').value,
      sudo_password: $('cSudoPassword').value,
      known_hosts: $('cKnownHosts').value.trim(),
      auto_accept_host_key: $('cAutoAccept').checked,
      timeout: Number($('cTimeout').value) || 15,
    }));

    button.disabled = false;
    button.textContent = 'Kết nối';

    if (result) {
      applySession(result);
      toast('Đã kết nối tới ' + result.username + '@' + result.host, 'ok');
    }
  });

  $('btnDisconnect').addEventListener('click', async () => {
    const result = await guard('Ngắt kết nối', () => api('disconnect', {}));
    if (result) {
      applySession(result);
      toast('Đã ngắt kết nối', 'ok');
    }
  });
}

// ------------------------------------------------------------- terminal

function setupTerminal() {
  const output = $('tOutput');

  const run = async () => {
    const command = $('tCommand').value.trim();
    if (!command) return;

    setStatus('tStatus', 'Đang chạy...', 'busy');
    output.textContent = '$ ' + command + '\n';

    const result = await guard(null, () => api('run', { command }));
    if (!result) {
      setStatus('tStatus', 'Thất bại', 'bad');
      return;
    }

    const parts = [];
    if (result.stdout) parts.push(result.stdout.replace(/\n$/, ''));
    if (result.stderr) parts.push('[stderr]\n' + result.stderr.replace(/\n$/, ''));
    parts.push('\n[exit ' + result.exit_status + ']');
    output.textContent = '$ ' + command + '\n' + parts.join('\n');

    setStatus(
      'tStatus',
      result.exit_status === 0 ? 'Thành công' : 'Mã thoát ' + result.exit_status,
      result.exit_status === 0 ? 'ok' : 'bad'
    );
  };

  $('btnRun').addEventListener('click', run);
  $('tCommand').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') run();
  });

  $$('.chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      $('tCommand').value = chip.dataset.cmd;
      run();
    });
  });

  $('btnInfo').addEventListener('click', async () => {
    setStatus('tStatus', 'Đang lấy thông tin...', 'busy');
    const info = await guard(null, () => api('server_info', {}));
    if (!info) {
      setStatus('tStatus', 'Thất bại', 'bad');
      return;
    }
    output.textContent = JSON.stringify(info, null, 2);
    setStatus('tStatus', 'Thông tin máy chủ', 'ok');
  });
}

// ---------------------------------------------------------------- files

function setupFiles() {
  const body = $('fSftpBody');

  const list = async () => {
    const path = $('fSftpPath').value.trim() || '/';
    const root = $('fSftpRoot').value.trim();

    const result = await guard(null, () => api('sftp_list', { path, root }));
    if (!result) return;

    body.innerHTML = '';
    if (!result.entries.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 5;
      cell.textContent = '(thư mục trống)';
      cell.style.color = '#93a1bd';
      return;
    }

    result.entries.forEach((entry) => {
      const row = body.insertRow();
      const name = row.insertCell();
      name.textContent = entry.name;
      if (entry.is_dir) {
        name.style.color = '#4c8dff';
        name.style.cursor = 'pointer';
        name.addEventListener('click', () => {
          $('fSftpPath').value = entry.path;
          list();
        });
      }

      row.insertCell().textContent = entry.permissions;
      row.insertCell().textContent = entry.size_human;
      row.insertCell().textContent = entry.is_link ? 'symlink' : (entry.is_dir ? 'thư mục' : 'tệp');

      const actions = row.insertCell();
      const download = document.createElement('button');
      download.className = 'btn btn-ghost';
      download.style.padding = '3px 10px';
      download.textContent = 'Tải về';
      download.addEventListener('click', async () => {
        const local = window.prompt('Lưu tệp tại đường dẫn cục bộ nào?', entry.name);
        if (!local) return;
        await guard('Tải xuống', () => api('sftp_download', {
          remote_path: entry.path,
          local_path: local,
          root: $('fSftpRoot').value.trim(),
        }));
      });
      actions.appendChild(download);
    });
  };

  $('btnSftpList').addEventListener('click', list);
  $('btnSftpRefresh').addEventListener('click', list);
  $('btnSftpUp').addEventListener('click', () => {
    const current = $('fSftpPath').value.trim() || '/';
    const parts = current.split('/').filter(Boolean);
    parts.pop();
    $('fSftpPath').value = '/' + parts.join('/');
    list();
  });

  $('btnSftpUpload').addEventListener('click', async () => {
    const input = $('fUpLocal');
    if (!input.files || !input.files.length) {
      toast('Hãy chọn một tệp cần tải lên', 'bad');
      return;
    }
    const remote = $('fUpRemote').value.trim();
    if (!remote) {
      toast('Hãy nhập đường dẫn đích trên máy chủ', 'bad');
      return;
    }

    const file = input.files[0];
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }

    await guard('Tải lên', () => api('sftp_upload_inline', {
      remote_path: remote,
      root: $('fSftpRoot').value.trim(),
      content_b64: btoa(binary),
    }));
  });

  $('btnSftpDownload').addEventListener('click', async () => {
    const remote = $('fDownRemote').value.trim();
    const local = $('fDownLocal').value.trim();
    if (!remote || !local) {
      toast('Cần cả đường dẫn nguồn và đường dẫn lưu', 'bad');
      return;
    }
    await guard('Tải xuống', () => api('sftp_download', {
      remote_path: remote,
      local_path: local,
      root: $('fSftpRoot').value.trim(),
      resume: $('fDownResume').checked,
    }));
  });

  $('btnScpUpload').addEventListener('click', async () => {
    await guard('Tải lên qua SCP', () => api('scp_upload', {
      local_path: $('fScpUpLocal').value.trim(),
      remote_path: $('fScpUpRemote').value.trim(),
      recursive: $('fScpUpRec').checked,
      preserve_times: $('fScpUpTime').checked,
    }));
  });

  $('btnScpDownload').addEventListener('click', async () => {
    await guard('Tải xuống qua SCP', () => api('scp_download', {
      remote_path: $('fScpDownRemote').value.trim(),
      local_path: $('fScpDownLocal').value.trim(),
      recursive: $('fScpDownRec').checked,
      preserve_times: $('fScpDownTime').checked,
    }));
  });
}

// ---------------------------------------------------------------- audit

function setupAudit() {
  const body = $('aBody');

  const show = (result) => {
    const summary = $('aSummary');
    summary.hidden = false;
    summary.innerHTML = '';

    const counts = result.summary || {};
    const items = [
      ['Tuân thủ', counts.ok || 0, '#35c48b'],
      ['Yếu', counts.weak || 0, '#f0b23c'],
      ['Thiếu', counts.missing || 0, '#f2545b'],
    ];
    items.forEach(([label, value, color]) => {
      const pill = document.createElement('div');
      pill.className = 'pill';
      pill.innerHTML = '<b style="color:' + color + '">' + value + '</b> ' + label;
      summary.appendChild(pill);
    });

    body.innerHTML = '';
    result.findings.forEach((finding) => {
      const row = body.insertRow();
      row.insertCell().textContent = finding.directive;
      row.insertCell().textContent = finding.expected;
      row.insertCell().textContent = finding.actual;

      const status = row.insertCell();
      const badge = document.createElement('span');
      badge.className = 'badge ' + finding.status;
      badge.textContent = {
        ok: 'Đạt',
        weak: 'Yếu',
        missing: 'Thiếu',
        unexpected: 'Ngoài dự kiến',
      }[finding.status] || finding.status;
      status.appendChild(badge);
    });

    setStatus(
      'aStatus',
      result.compliant ? 'Toàn bộ chỉ thị đều tuân thủ' : 'Có chỉ thị chưa tuân thủ',
      result.compliant ? 'ok' : 'bad'
    );
  };

  const run = async (scope) => {
    setStatus('aStatus', 'Đang kiểm tra...', 'busy');
    const result = await guard(null, () => api('audit', { scope }));
    if (!result) {
      setStatus('aStatus', 'Thất bại', 'bad');
      return;
    }
    show(result);
  };

  $('btnAuditRemote').addEventListener('click', () => run('remote'));
  $('btnAuditLocal').addEventListener('click', () => run('local'));
}

// ------------------------------------------------------------- hostkeys

function setupHostKeys() {
  const body = $('hBody');

  const list = async () => {
    const result = await guard(null, () => api('hostkey_list', {
      known_hosts: $('hKnownHosts').value.trim(),
    }));
    if (!result) return;

    body.innerHTML = '';
    if (!result.entries.length) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = 4;
      cell.textContent = '(chưa có host key nào được tin cậy)';
      cell.style.color = '#93a1bd';
      return;
    }

    result.entries.forEach((entry) => {
      const row = body.insertRow();
      row.insertCell().textContent = entry.hostname;
      row.insertCell().textContent = entry.key_type;

      const fingerprint = row.insertCell();
      fingerprint.className = 'mono';
      fingerprint.textContent = entry.fingerprint;

      row.insertCell().textContent = entry.comment;
    });
  };

  $('btnHostkeyList').addEventListener('click', list);
  $('btnHostkeyAdd').addEventListener('click', async () => {
    const result = await guard('Thêm host key', () => api('hostkey_add', {
      hostname: $('hHostname').value.trim(),
      key_file: $('hKeyFile').value.trim(),
      known_hosts: $('hKnownHosts').value.trim(),
    }));
    if (result) {
      toast('Đã tin cậy ' + result.key_type + ' ' + result.fingerprint, 'ok');
      list();
    }
  });

  $('btnHostkeyRemove').addEventListener('click', async () => {
    const result = await guard('Xóa host key', () => api('hostkey_remove', {
      hostname: $('hRemoveHost').value.trim(),
      known_hosts: $('hKnownHosts').value.trim(),
    }));
    if (result) {
      toast('Đã xóa ' + result.removed + ' host key', 'ok');
      list();
    }
  });
}

// -------------------------------------------------------------- config

function setupConfig() {
  $('btnRender').addEventListener('click', async () => {
    const result = await guard(null, () => api('render', {
      what: $('cfWhat').value,
      port: Number($('cfPort').value) || 22,
      groups: $('cfGroups').value.trim(),
      sftp_users: $('cfSftpUsers').value.trim(),
    }));
    if (result) $('cfOutput').textContent = result.content;
  });

  $('btnCopy').addEventListener('click', async () => {
    const text = $('cfOutput').textContent;
    if (!text) {
      toast('Chưa có nội dung để sao chép', 'bad');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      toast('Đã sao chép vào bộ nhớ tạm', 'ok');
    } catch (err) {
      toast('Trình duyệt không cho phép sao chép tự động', 'bad');
    }
  });
}

// ----------------------------------------------------------- provisioning

function setupProvisioning() {
  const output = $('pOutput');

  const payload = () => ({
    group: $('pGroup').value.trim(),
    admin_users: $('pAdminUsers').value.trim(),
    sftp_users: $('pSftpUsers').value.trim(),
    admin_public_key: $('pAdminKey').value.trim(),
    sftp_public_key: $('pSftpKey').value.trim(),
    fail2ban_ignore: $('pIgnore').value.trim(),
    ufw_limit_ssh: $('pLimit').checked,
    no_firewall: $('pNoFirewall').checked,
  });

  $('btnProvisionPreview').addEventListener('click', async () => {
    const result = await guard(null, () => api('provision_preview', payload()));
    if (!result) return;

    output.innerHTML = '';
    const files = result.files || {};
    Object.keys(files).forEach((path) => {
      const details = document.createElement('details');
      details.className = 'prov-file';
      const summary = document.createElement('summary');
      summary.textContent = path;
      const pre = document.createElement('pre');
      pre.textContent = files[path];
      details.appendChild(summary);
      details.appendChild(pre);
      output.appendChild(details);
    });

    ['admin_script', 'sftp_script', 'install_script', 'apply_script'].forEach((key) => {
      if (!result[key]) return;
      const details = document.createElement('details');
      details.className = 'prov-file';
      const summary = document.createElement('summary');
      summary.textContent = key.replace('_', ' ');
      const pre = document.createElement('pre');
      pre.textContent = result[key];
      details.appendChild(summary);
      details.appendChild(pre);
      output.appendChild(details);
    });

    toast('Đã dựng kế hoạch, chưa thay đổi gì trên máy chủ', 'ok');
  });

  $('btnProvisionApply').addEventListener('click', async () => {
    if (!window.confirm('Áp dụng cấu hình lên máy chủ? Thao tác này sẽ thay đổi sshd, fail2ban và tường lửa.')) {
      return;
    }
    const result = await guard(null, () => api('provision_apply', payload()));
    if (!result) return;

    output.innerHTML = '';
    const list = document.createElement('ol');
    list.className = 'steps';
    (result.steps || []).forEach((step) => {
      const item = document.createElement('li');
      item.textContent = step.label + (step.output ? ' — ' + step.output.trim().split('\n').pop() : '');
      list.appendChild(item);
    });
    output.appendChild(list);
    toast('Đã triển khai xong, hãy kiểm tra bằng tab "Kiểm tra bảo mật"', 'ok');
  });
}

// ----------------------------------------------------------------- logs

function setupLogs() {
  $('btnClearLog').addEventListener('click', () => {
    $('lOutput').innerHTML = '';
    setStatus('lStatus', 'Đã xóa', 'ok');
  });
}

// ----------------------------------------------------------------- init

document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupConnection();
  setupTerminal();
  setupFiles();
  setupAudit();
  setupHostKeys();
  setupConfig();
  setupProvisioning();
  setupLogs();

  refreshState();
  log('Giao diện đã sẵn sàng');
});
