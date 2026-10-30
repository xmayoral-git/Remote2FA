// TOTP (RFC 6238) i parseig d'URIs otpauth:// amb WebCrypto.
const TOTP = (() => {
  const ALGOS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

  function base32Decode(str) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = str.toUpperCase().replace(/[\s=-]/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (const ch of clean) {
      const idx = alphabet.indexOf(ch);
      if (idx < 0) throw new Error('Clau Base32 no vàlida');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    if (!out.length) throw new Error('Clau buida');
    return new Uint8Array(out);
  }

  async function generate(entry, time = Date.now()) {
    const period = entry.period || 30;
    const digits = entry.digits || 6;
    const hash = ALGOS[(entry.algorithm || 'SHA1').toUpperCase()] || 'SHA-1';
    const counter = Math.floor(time / 1000 / period);

    const msg = new ArrayBuffer(8);
    const view = new DataView(msg);
    view.setUint32(0, Math.floor(counter / 2 ** 32));
    view.setUint32(4, counter >>> 0);

    const key = await crypto.subtle.importKey('raw', base32Decode(entry.secret), { name: 'HMAC', hash }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
    const off = mac[mac.length - 1] & 0x0f;
    const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  function remaining(entry, time = Date.now()) {
    const period = entry.period || 30;
    return period - Math.floor(time / 1000) % period;
  }

  function base32Encode(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
    return out;
  }

  // Lector mínim de protobuf: retorna [[número de camp, valor], ...].
  // Només calen els tipus varint (0) i longitud prefixada (2); la resta se salta.
  function protoFields(buf) {
    let i = 0;
    const varint = () => {
      let v = 0, mul = 1, b;
      do {
        if (i >= buf.length) throw new Error('QR d\'exportació malmès');
        b = buf[i++];
        v += (b & 0x7f) * mul;
        mul *= 128;
      } while (b & 0x80);
      return v;
    };
    const out = [];
    while (i < buf.length) {
      const key = varint(), wire = key & 7;
      if (wire === 0) out.push([Math.floor(key / 8), varint()]);
      else if (wire === 2) {
        const len = varint();
        if (i + len > buf.length) throw new Error('QR d\'exportació malmès');
        out.push([Math.floor(key / 8), buf.subarray(i, i + len)]);
        i += len;
      }
      else if (wire === 1) i += 8;
      else if (wire === 5) i += 4;
      else throw new Error('QR d\'exportació malmès');
    }
    return out;
  }

  // QR d'exportació de Google Authenticator: "otpauth-migration://offline?data=<base64>".
  // El contingut és un MigrationPayload (protobuf) amb un OtpParameters per compte:
  //   1 secret (bytes), 2 nom, 3 emissor, 4 algorisme, 5 dígits, 6 tipus, 7 comptador
  function parseMigration(url) {
    // URLSearchParams converteix els "+" del base64 en espais
    const data = (url.searchParams.get('data') || '').replace(/ /g, '+');
    let bytes;
    try {
      bytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));
    } catch {
      throw new Error('QR d\'exportació malmès');
    }

    const ALGO = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' }; // 4 = MD5, no suportat
    const entries = [];
    let skipped = 0;
    for (const [num, value] of protoFields(bytes)) {
      if (num !== 1 || !(value instanceof Uint8Array)) continue;
      const p = Object.fromEntries(protoFields(value));
      const type = p[6] ?? 2; // 1 = HOTP, 2 = TOTP
      if (type === 1 || !(p[1] instanceof Uint8Array) || !p[1].length || !((p[4] ?? 0) in ALGO)) {
        skipped++;
        continue;
      }
      entries.push({ secret: base32Encode(p[1]), algorithm: ALGO[p[4] ?? 0], digits: p[5] === 2 ? 8 : 6, period: 30 });
    }
    if (!entries.length) throw new Error('El QR d\'exportació no conté cap codi TOTP compatible');
    return { entries, skipped };
  }

  // Accepta:
  //  - "otpauth://totp/Emissor:compte?secret=..." o una clau Base32 sola (un codi)
  //  - "otpauth-migration://offline?data=..." de Google Authenticator (un o més codis)
  // Retorna { entries, skipped }. L'emissor i el compte s'ignoren expressament:
  // no es mostren ni es desen.
  function parse(text) {
    text = text.trim();
    if (/^otpauth-migration:/i.test(text)) return parseMigration(new URL(text));
    if (!/^otpauth:/i.test(text)) {
      base32Decode(text);
      return { entries: [{ secret: text.toUpperCase().replace(/[\s=-]/g, ''), algorithm: 'SHA1', digits: 6, period: 30 }], skipped: 0 };
    }

    const url = new URL(text);
    if (url.host.toLowerCase() !== 'totp') throw new Error('Només es suporta TOTP (no ' + url.host + ')');
    const p = url.searchParams;
    const secret = (p.get('secret') || '').toUpperCase().replace(/[\s=-]/g, '');
    base32Decode(secret);

    return {
      entries: [{
        secret,
        algorithm: (p.get('algorithm') || 'SHA1').toUpperCase(),
        digits: parseInt(p.get('digits'), 10) || 6,
        period: parseInt(p.get('period'), 10) || 30,
      }],
      skipped: 0,
    };
  }

  return { generate, remaining, parse };
})();
