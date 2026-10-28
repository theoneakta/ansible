// Sentry Lens: a Vaultwarden account made in this browser - Bitwarden's
// client side, so the master password never leaves it: PBKDF2-SHA256 (600000)
// of it salted with the email -> the master key; HKDF-Expand of that -> an
// AES + HMAC key that encrypts a new random account key ("2." strings); an
// RSA-OAEP pair whose private half that account key encrypts. Only the
// password's hash and those encrypted keys go to the server.
//
// WebCrypto where the page is secure (HTTPS, localhost); on a plain-HTTP page
// browsers don't offer it, so node-forge (pure JavaScript, loaded then) does
// the same - slower, same result. Used by the app (Assets > Credentials) and
// the installer (its last step); the same file in both.
"use strict";
const VaultSignup = (() => {
  const te = new TextEncoder();
  const ITERATIONS = 600000;
  const FORGE = "https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js";
  const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; a.forEach(x => { o.set(x, i); i += x.length; }); return o; };
  const b64 = u8 => { let s = ""; u8.forEach(b => { s += String.fromCharCode(b); }); return btoa(s); };
  const rand = n => crypto.getRandomValues(new Uint8Array(n));  // offered on HTTP pages too
  const bin = u8 => { let s = ""; u8.forEach(b => { s += String.fromCharCode(b); }); return s; };  // forge's byte strings
  const unbin = s => Uint8Array.from(s, ch => ch.charCodeAt(0));

  const web = {
    async pbkdf2(pass, salt, iterations) {
      const k = await crypto.subtle.importKey("raw", pass, "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await crypto.subtle.deriveBits({name: "PBKDF2", salt, iterations, hash: "SHA-256"}, k, 256));
    },
    async hmac(key, data) {
      const k = await crypto.subtle.importKey("raw", key, {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
      return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
    },
    async aes(key32, iv, data) {
      const k = await crypto.subtle.importKey("raw", key32, "AES-CBC", false, ["encrypt"]);
      return new Uint8Array(await crypto.subtle.encrypt({name: "AES-CBC", iv}, k, data));
    },
    async rsa() {
      const p = await crypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1"},
                                                true, ["encrypt", "decrypt"]);
      return {spki: new Uint8Array(await crypto.subtle.exportKey("spki", p.publicKey)),
              pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", p.privateKey))};
    },
  };

  let forgeReady = null;
  const loadForge = () => forgeReady || (forgeReady = new Promise((ok, fail) => {
    if (window.forge) return ok(window.forge);
    const s = document.createElement("script");
    s.src = FORGE; s.onload = () => ok(window.forge); s.onerror = () => fail(new Error("couldn't load the encryption library (no internet?) - open this page over HTTPS instead"));
    document.head.appendChild(s);
  }));
  const forgeImpl = f => ({
    async pbkdf2(pass, salt, iterations) {
      await new Promise(r => setTimeout(r, 30));  // let the page say "encrypting" first
      return unbin(f.pkcs5.pbkdf2(bin(pass), bin(salt), iterations, 32, f.md.sha256.create()));
    },
    async hmac(key, data) { const h = f.hmac.create(); h.start("sha256", bin(key)); h.update(bin(data)); return unbin(h.digest().getBytes()); },
    async aes(key32, iv, data) {
      const c = f.cipher.createCipher("AES-CBC", bin(key32)); c.start({iv: bin(iv)}); c.update(f.util.createBuffer(bin(data))); c.finish();
      return unbin(c.output.getBytes());
    },
    rsa: () => new Promise((ok, fail) => f.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001, workers: 0}, (err, p) => {
      if (err) return fail(err);
      ok({spki: unbin(f.asn1.toDer(f.pki.publicKeyToAsn1(p.publicKey)).getBytes()),
          pkcs8: unbin(f.asn1.toDer(f.pki.wrapRsaPrivateKey(f.pki.privateKeyToAsn1(p.privateKey))).getBytes())});
    })),
  });

  const secure = () => !!(window.isSecureContext && window.crypto && crypto.subtle);
  async function impl() { return secure() ? web : forgeImpl(await loadForge()); }

  async function enc(c, data, key64) {  // "2." AES-256-CBC + HMAC-SHA256
    const iv = rand(16), ct = await c.aes(key64.slice(0, 32), iv, data);
    return `2.${b64(iv)}|${b64(ct)}|${b64(await c.hmac(key64.slice(32), cat(iv, ct)))}`;
  }

  // {masterPasswordHash, kdfIterations, key, keys: {publicKey, encryptedPrivateKey}} - what Vaultwarden's register takes.
  async function account(email, password, c) {
    c = c || await impl();
    const pw = te.encode(password);
    const mk = await c.pbkdf2(pw, te.encode(email.trim().toLowerCase()), ITERATIONS);
    const stretched = cat(await c.hmac(mk, cat(te.encode("enc"), new Uint8Array([1]))),   // HKDF-Expand, 32 bytes = T(1)
                          await c.hmac(mk, cat(te.encode("mac"), new Uint8Array([1]))));
    const userKey = rand(64), pair = await c.rsa();
    return {masterPasswordHash: b64(await c.pbkdf2(mk, pw, 1)), kdfIterations: ITERATIONS, key: await enc(c, userKey, stretched),
            keys: {publicKey: b64(pair.spki), encryptedPrivateKey: await enc(c, pair.pkcs8, userKey)}};
  }
  return {account, secure, web, forgeImpl, loadForge};
})();
