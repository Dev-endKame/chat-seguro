// ===== Web Crypto API: ECDH (P-256) + AES-GCM =====

function bufParaBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64ParaBuf(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function gerarParDeChaves() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveKey']
  );
}

async function exportarPublica(par) {
  const spki = await crypto.subtle.exportKey('spki', par.publicKey);
  return bufParaBase64(spki);
}

async function importarPublica(b64) {
  return crypto.subtle.importKey(
    'spki',
    base64ParaBuf(b64),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
}

// Cada par de pessoas deriva um segredo ÚNICO entre elas
async function derivarChave(par, publicaDeles) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicaDeles },
    par.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function criptografar(chave, texto) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    chave,
    new TextEncoder().encode(texto)
  );
  return { iv: bufParaBase64(iv), ct: bufParaBase64(ct) };
}

async function descriptografar(chave, ivB64, ctB64) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ParaBuf(ivB64) },
    chave,
    base64ParaBuf(ctB64)
  );
  return new TextDecoder().decode(pt);
}