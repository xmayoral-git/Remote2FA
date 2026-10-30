// Magatzem xifrat. Les 3 paraules es transformen (PBKDF2) en:
//  - un identificador del magatzem (l'únic que veu el servidor)
//  - una clau AES-GCM per xifrar/desxifrar els secrets al navegador.
// El servidor només desa blobs xifrats; mai rep les paraules ni els secrets.
const Vault = (() => {
  const API = 'api.php';
  const SALT = new TextEncoder().encode('Remote2FA/v1');
  const ITERATIONS = 600000;

  const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  // Minúscules, sense accents ni espais sobrants, perquè "Càmera" == "camera".
  function normalize(words) {
    return words
      .map(w => w.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim())
      .join(' ');
  }

  async function open(words) {
    if (words.length !== 3 || words.some(w => !w.trim())) throw new Error('Calen 3 paraules');
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(normalize(words)), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: SALT, iterations: ITERATIONS, hash: 'SHA-256' }, base, 512));
    const id = toHex(await crypto.subtle.digest('SHA-256', bits.slice(0, 32)));
    const key = await crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { id, key };
  }

  // fetch() que converteix el 429 del rate limiting en un missatge llegible.
  async function request(id, options = {}) {
    const res = await fetch(`${API}?id=${id}`, { cache: 'no-store', ...options });
    if (res.status === 429) {
      const secs = parseInt(res.headers.get('Retry-After'), 10) || 60;
      const wait = secs < 60 ? secs + ' segons' : Math.ceil(secs / 60) + ' minuts';
      throw new Error(`Massa intents. Torna-ho a provar d'aquí ${wait}.`);
    }
    return res;
  }

  // Retorna el codi associat a les paraules, o null si no n'hi ha cap.
  async function load({ id, key }) {
    const res = await request(id);
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('Error del servidor (' + res.status + ')');
    const blob = await res.json();
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(blob.iv) }, key, unb64(blob.ct));
      return JSON.parse(new TextDecoder().decode(plain));
    } catch {
      throw new Error('No s\'ha pogut desxifrar el magatzem');
    }
  }

  // Només crea: si la combinació de paraules ja té un codi, el servidor respon 409.
  async function create({ id, key }, entry) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(entry)));
    const res = await request(id, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) }),
    });
    if (res.status === 409) throw new Error('Aquesta combinació de paraules ja està en ús. Tria\'n una altra.');
    if (!res.ok) throw new Error('No s\'ha pogut desar (' + res.status + ')');
  }

  async function remove({ id }) {
    const res = await request(id, { method: 'DELETE' });
    if (!res.ok && res.status !== 404) throw new Error('No s\'ha pogut eliminar (' + res.status + ')');
  }

  return { open, load, create, remove };
})();
