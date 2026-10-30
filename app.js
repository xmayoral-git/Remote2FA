const $ = sel => document.querySelector(sel);

function setMsg(el, text, type = '') {
  el.textContent = text;
  el.className = 'msg ' + type;
}

const wordsOf = form => ['w1', 'w2', 'w3'].map(n => form.elements[n].value);

// Refresc periòdic dels codis visibles
const tickers = new Set();
setInterval(() => tickers.forEach(fn => fn()), 1000);

// ---------- Opció 1: accedir amb 3 paraules ----------
let session = null; // { vault, entry }

$('#form-access').addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target, msg = $('#access-msg'), btn = form.querySelector('button');
  btn.disabled = true;
  setMsg(msg, 'Comprovant…');
  try {
    const vault = await Vault.open(wordsOf(form));
    const entry = await Vault.load(vault);
    if (!entry) throw new Error('No hi ha cap 2FA associat a aquestes paraules');
    session = { vault, entry };
    form.reset();
    setMsg(msg, '');
    form.classList.add('hidden');
    $('#codes').classList.remove('hidden');
    refreshCode();
    tickers.add(refreshCode);
  } catch (err) {
    setMsg(msg, err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

$('#btn-lock').addEventListener('click', lock);
$('#code').addEventListener('click', ev => copyCode(ev.target));
$('#btn-delete').addEventListener('click', removeEntry);

function lock() {
  session = null;
  tickers.delete(refreshCode);
  $('#code').textContent = '------';
  $('#code-ttl').textContent = '';
  $('#codes').classList.add('hidden');
  $('#form-access').classList.remove('hidden');
}

async function refreshCode() {
  if (!session) return;
  try {
    $('#code').textContent = await TOTP.generate(session.entry);
    $('#code-ttl').textContent = TOTP.remaining(session.entry) + 's';
  } catch {
    $('#code').textContent = 'error';
  }
}

async function copyCode(el) {
  try {
    await navigator.clipboard.writeText(el.textContent);
    const old = el.title;
    el.title = 'Copiat!';
    el.style.opacity = .5;
    setTimeout(() => { el.style.opacity = ''; el.title = old; }, 400);
  } catch { /* el portapapers pot no estar disponible */ }
}

async function removeEntry() {
  if (!confirm('Eliminar aquest 2FA? Aquesta acció no es pot desfer i les paraules quedaran lliures.')) return;
  try {
    await Vault.remove(session.vault);
    lock();
    setMsg($('#access-msg'), '2FA eliminat.', 'ok');
  } catch (err) {
    alert(err.message);
  }
}

// ---------- Opció 2: llegir QR de configuració ----------
let pending = null; // entrada llegida del QR pendent de desar
let stream = null;
const video = $('#video'), canvas = $('#canvas');
const detector = 'BarcodeDetector' in window ? new BarcodeDetector({ formats: ['qr_code'] }) : null;

async function decodeQR(source, width, height) {
  if (detector) {
    const codes = await detector.detect(source);
    if (codes.length) return codes[0].rawValue;
  }
  if (window.jsQR) {
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(source, 0, 0, width, height);
    const img = ctx.getImageData(0, 0, width, height);
    const code = jsQR(img.data, width, height);
    if (code) return code.data;
  }
  return null;
}

$('#btn-camera').addEventListener('click', async () => {
  if (stream) return stopCamera();
  const msg = $('#scan-msg');
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  } catch (err) {
    return setMsg(msg, 'No s\'ha pogut obrir la càmera: ' + err.message, 'error');
  }
  video.srcObject = stream;
  video.classList.remove('hidden');
  await video.play();
  $('#btn-camera').textContent = 'Aturar càmera';
  setMsg(msg, 'Apunta la càmera al QR…');
  scanLoop();
});

async function scanLoop() {
  if (!stream) return;
  if (video.readyState >= 2) {
    const text = await decodeQR(video, video.videoWidth, video.videoHeight).catch(() => null);
    if (text) {
      stopCamera();
      return handleQRText(text);
    }
  }
  requestAnimationFrame(scanLoop);
}

function stopCamera() {
  if (stream) stream.getTracks().forEach(t => t.stop());
  stream = null;
  video.srcObject = null;
  video.classList.add('hidden');
  $('#btn-camera').textContent = 'Obrir càmera';
}

$('#file-qr').addEventListener('change', async e => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  const msg = $('#scan-msg');
  try {
    const bmp = await createImageBitmap(file);
    const text = await decodeQR(bmp, bmp.width, bmp.height);
    if (!text) throw new Error('No s\'ha trobat cap QR a la imatge');
    handleQRText(text);
  } catch (err) {
    setMsg(msg, err.message, 'error');
  }
});

$('#btn-manual').addEventListener('click', () => handleQRText($('#manual-uri').value));

// Codis llegits del darrer QR. Un QR d'exportació de Google Authenticator en pot
// contenir diversos; com que no es mostra l'emissor ni el compte, l'usuari els
// identifica comparant el codi actual amb el que veu a Google Authenticator.
let choices = [];

function handleQRText(text) {
  const msg = $('#scan-msg');
  let parsed;
  try {
    parsed = TOTP.parse(text);
  } catch (err) {
    choices = [];
    selectChoice(-1);
    $('#pick').classList.add('hidden');
    return setMsg(msg, err.message, 'error');
  }
  $('#manual-uri').value = '';
  choices = parsed.entries;
  const note = parsed.skipped === 1 ? ' (1 no compatible, ignorat)'
    : parsed.skipped ? ` (${parsed.skipped} no compatibles, ignorats)` : '';

  if (choices.length === 1) {
    setMsg(msg, 'QR llegit correctament.' + note, 'ok');
    $('#pick').classList.add('hidden');
    selectChoice(0);
  } else {
    setMsg(msg, `QR d'exportació llegit: ${choices.length} codis${note}.`, 'ok');
    selectChoice(-1);
    renderChoices();
  }
}

function renderChoices() {
  const list = $('#pick-list');
  list.innerHTML = '';
  choices.forEach((entry, i) => {
    const li = document.createElement('li');
    li.innerHTML = `<button type="button" class="secondary"><span class="code">------</span> <span class="ttl"></span></button>`;
    const btn = li.querySelector('button');
    btn.disabled = !!entry.saved;
    btn.classList.toggle('selected', entry === pending);
    if (entry.saved) btn.insertAdjacentHTML('beforeend', ' <small>desat</small>');
    btn.addEventListener('click', () => { selectChoice(i); renderChoices(); });
    list.appendChild(li);
  });
  $('#pick').classList.remove('hidden');
  refreshChoices();
  tickers.add(refreshChoices);
}

async function refreshChoices() {
  const items = $('#pick-list').children;
  await Promise.all(choices.map(async (entry, i) => {
    if (!items[i]) return;
    items[i].querySelector('.code').textContent = await TOTP.generate(entry);
    items[i].querySelector('.ttl').textContent = TOTP.remaining(entry) + 's';
  }));
}

function selectChoice(i) {
  pending = choices[i] || null;
  const form = $('#form-setup');
  setMsg($('#setup-msg'), '');
  if (!pending) {
    tickers.delete(refreshPreview);
    return form.classList.add('hidden');
  }
  form.classList.remove('hidden');
  refreshPreview();
  tickers.add(refreshPreview);
}

async function refreshPreview() {
  if (!pending) return;
  $('#preview-code').textContent = await TOTP.generate(pending);
  $('#preview-ttl').textContent = TOTP.remaining(pending) + 's';
}

$('#preview-code').addEventListener('click', ev => copyCode(ev.target));

$('#form-setup').addEventListener('submit', async e => {
  e.preventDefault();
  const form = e.target, msg = $('#setup-msg'), btn = form.querySelector('button[type=submit]');
  btn.disabled = true;
  setMsg(msg, 'Desant…');
  try {
    const vault = await Vault.open(wordsOf(form));
    // Sense consulta prèvia: el servidor rebutja (409) les combinacions ja en ús,
    // i així una alta legítima no gasta cap intent fallit del rate limiting.
    const { saved, ...entry } = pending;
    await Vault.create(vault, { ...entry, added: new Date().toISOString() });
    pending.saved = true;
    form.reset();
    selectChoice(-1);
    const left = choices.filter(c => !c.saved).length;
    if (choices.length > 1) {
      renderChoices();
      setMsg($('#scan-msg'), left === 1 ? '2FA desat. En queda 1 per desar (amb unes altres 3 paraules).'
        : left ? `2FA desat. En queden ${left} per desar (cadascun amb 3 paraules diferents).` : 'Tots els codis desats.', 'ok');
    } else {
      setMsg($('#scan-msg'), '2FA desat.', 'ok');
    }
  } catch (err) {
    setMsg(msg, err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});
