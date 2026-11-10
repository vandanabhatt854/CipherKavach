(() => {
  const maxBytes = Number(document.body.dataset.maxBytes);
  const input = document.getElementById('file-input');
  const dropZone = document.getElementById('drop-zone');
  const selected = document.getElementById('selected-file');
  const form = document.getElementById('file-form');
  const submit = document.getElementById('submit-button');
  const message = document.getElementById('message');
  const password = document.getElementById('password');
  const confirmation = document.getElementById('confirm-password');
  let action = 'encrypt';

  const formatSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };
  const showMessage = (text, type) => {
    message.textContent = text;
    message.className = `message ${type}`;
    message.hidden = false;
  };
  const clearMessage = () => { message.hidden = true; message.textContent = ''; };
  const showFile = (file) => {
    clearMessage();
    if (!file) return;
    if (file.size > maxBytes) {
      input.value = '';
      selected.hidden = true;
      dropZone.hidden = false;
      showMessage(`This file is larger than the ${Math.floor(maxBytes / (1024 * 1024))} MB limit.`, 'error');
      return;
    }
    document.getElementById('file-name').textContent = file.name;
    document.getElementById('file-size').textContent = formatSize(file.size);
    selected.hidden = false;
    dropZone.hidden = true;
  };
  const setAction = (next) => {
    action = next;
    document.querySelectorAll('.tab').forEach((tab) => {
      const active = tab.dataset.action === next;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
    });
    const encrypting = next === 'encrypt';
    document.getElementById('password-label').textContent = encrypting ? 'Create a password' : 'Enter your password';
    document.getElementById('password-note').textContent = encrypting
      ? 'Choose a password you can remember. It cannot be recovered if lost.'
      : 'Use the same password that was used to encrypt this file.';
    document.getElementById('confirm-group').hidden = !encrypting;
    confirmation.required = encrypting;
    submit.querySelector('.button-label').textContent = encrypting ? 'Encrypt & Download' : 'Decrypt & Download';
    password.autocomplete = encrypting ? 'new-password' : 'current-password';
    clearMessage();
  };

  document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => setAction(tab.dataset.action)));
  document.getElementById('browse-button').addEventListener('click', () => input.click());
  dropZone.addEventListener('click', (event) => {
    if (event.target.closest('.browse-button')) return;
    input.click();
  });
  dropZone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => showFile(input.files[0]));
  document.getElementById('remove-file').addEventListener('click', () => {
    input.value = '';
    selected.hidden = true;
    dropZone.hidden = false;
    clearMessage();
  });
  ['dragenter', 'dragover'].forEach((type) => dropZone.addEventListener(type, (event) => {
    event.preventDefault(); dropZone.classList.add('dragover');
  }));
  ['dragleave', 'drop'].forEach((type) => dropZone.addEventListener(type, (event) => {
    event.preventDefault(); dropZone.classList.remove('dragover');
  }));
  dropZone.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    try { input.files = event.dataTransfer.files; } catch (_) { /* File display still works */ }
    showFile(file);
  });
  document.querySelectorAll('.show-password').forEach((button) => button.addEventListener('click', () => {
    const field = document.getElementById(button.dataset.toggle);
    const reveal = field.type === 'password';
    field.type = reveal ? 'text' : 'password';
    button.textContent = reveal ? 'Hide' : 'Show';
    button.setAttribute('aria-label', `${reveal ? 'Hide' : 'Show'} ${button.dataset.toggle === 'password' ? 'password' : 'password confirmation'}`);
  }));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearMessage();
    const file = input.files[0];
    if (!file) { showMessage('Choose a file to continue.', 'error'); return; }
    if (!password.value) { showMessage('Enter your password to continue.', 'error'); password.focus(); return; }
    if (action === 'encrypt' && password.value !== confirmation.value) {
      showMessage('The password confirmation does not match.', 'error'); confirmation.focus(); return;
    }
    if (file.size > maxBytes) { showMessage(`This file is larger than the ${Math.floor(maxBytes / (1024 * 1024))} MB limit.`, 'error'); return; }

    submit.disabled = true;
    submit.classList.add('loading');
    const label = submit.querySelector('.button-label');
    const previousLabel = label.textContent;
    label.textContent = action === 'encrypt' ? 'Encrypting file…' : 'Decrypting file…';
    try {
      const body = new FormData();
      body.append('file', file, file.name);
      body.append('password', password.value);
      if (action === 'encrypt') body.append('confirm_password', confirmation.value);
      const response = await fetch(`/api/${action}`, { method: 'POST', body });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.error || 'The file could not be processed. Please try again.');
      }
      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const encodedName = disposition.match(/filename\*=UTF-8''([^;]+)/i);
      const plainName = disposition.match(/filename="?([^";]+)"?/i);
      const filename = encodedName ? decodeURIComponent(encodedName[1]) : (plainName ? plainName[1] : (action === 'encrypt' ? `${file.name}.ckv` : `${file.name}.decrypted`));
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showMessage(action === 'encrypt' ? 'Your encrypted file is ready to download.' : 'Your decrypted file is ready to download.', 'success');
    } catch (error) {
      showMessage(error.message || 'The file could not be processed. Please try again.', 'error');
    } finally {
      submit.disabled = false;
      submit.classList.remove('loading');
      label.textContent = previousLabel;
    }
  });
})();
