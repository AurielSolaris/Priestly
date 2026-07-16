// Priestly Covenant + sealed-message crypto for the browser.
//
// A faithful port of crypto/covenant.py and protocol/session.py. Kept in its
// own file so the exact same code runs in the browser and under Node in the
// test suite (tests/test_ui_covenant.py cross-checks every primitive against
// the Python implementation). Uses only BigInt + WebCrypto (SubtleCrypto),
// both available in browsers on a secure context (localhost) and in Node 20+.
//
// The browser only ever sends "stored" (uncompressed) sealed payloads, so no
// Huffman codec is needed here; the server seals to browser clients the same
// way (see SessionState.compress).

(function (root) {
    "use strict";

    // RFC 3526 Group 14 (2048-bit MODP) -- identical to crypto/covenant.py.
    const P = BigInt("0x" +
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374" +
        "fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee" +
        "386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598d" +
        "a48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed5" +
        "29077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e7" +
        "72c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497" +
        "cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff");
    const G = 2n;
    const ELEMENT_BYTES = 256;
    const subtle = (root.crypto || globalThis.crypto).subtle;
    const enc = (s) => new TextEncoder().encode(s);

    // --- BigInt / byte helpers ---
    function modPow(base, exp, mod) {
        base %= mod; let r = 1n;
        while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; exp >>= 1n; base = (base * base) % mod; }
        return r;
    }
    function egcd(a, b) {
        let [or, r] = [a, b], [os, s] = [1n, 0n], [ot, t] = [0n, 1n];
        while (r !== 0n) { const q = or / r;[or, r] = [r, or - q * r];[os, s] = [s, os - q * s];[ot, t] = [t, ot - q * t]; }
        return [or, os, ot];
    }
    function modinv(a, m) { const [g, x] = egcd(((a % m) + m) % m, m); if (g !== 1n) throw new Error("no inverse"); return ((x % m) + m) % m; }
    function bytesToBig(b) { let x = 0n; for (const v of b) x = (x << 8n) | BigInt(v); return x; }
    function bigToBytes(x, len) { const o = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }
    function hexToBytes(h) { const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; }
    function bytesToHex(b) { return Array.from(b).map((v) => v.toString(16).padStart(2, "0")).join(""); }
    function concat(...arrs) { const n = arrs.reduce((s, a) => s + a.length, 0); const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; }
    function u64be(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; }
    function b64encode(bytes) { let s = ""; for (const v of bytes) s += String.fromCharCode(v); return btoa(s); }
    function b64decode(str) { const s = atob(str); const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i); return o; }

    // --- hashing ---
    async function sha1(bytes) { return new Uint8Array(await subtle.digest("SHA-1", bytes)); }
    async function hmac(keyBytes, dataBytes) {
        const k = await subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        return new Uint8Array(await subtle.sign("HMAC", k, dataBytes));
    }

    // --- Covenant primitives ---
    async function secretToElement(pwBytes) {
        const h = await hmac(pwBytes, enc("Priestly-Covenant-Map"));
        let val = bytesToBig(h) % P; if (val === 0n) val = 1n;
        return modPow(val, 2n, P);
    }
    function randomExponent() {
        const r = new Uint8Array(ELEMENT_BYTES); (root.crypto || globalThis.crypto).getRandomValues(r);
        return (bytesToBig(r) % (P - 2n)) + 1n;
    }
    async function confirmMac(shared, commit, role, pub) {
        return hmac(bigToBytes(shared, ELEMENT_BYTES), concat(commit, enc(role), bigToBytes(pub, ELEMENT_BYTES)));
    }
    async function hkdfExpand(prk, info, length) {
        const t = await hmac(prk, concat(info, new Uint8Array([1]))); // length <= 32
        return t.slice(0, length);
    }
    async function deriveKeys(shared) {
        const prk = bigToBytes(shared, ELEMENT_BYTES);
        return {
            client_mac: await hkdfExpand(prk, enc("Priestly-v1-client-mac"), 32),
            server_mac: await hkdfExpand(prk, enc("Priestly-v1-server-mac"), 32),
        };
    }

    // --- sealed frames (mirror protocol/session.py, "stored" marker only) ---
    async function seal(keys, seq, obj) {
        const plaintext = enc(JSON.stringify(obj));
        const body = concat(new Uint8Array([0x00]), plaintext); // 0x00 = stored
        const header = concat(u64be(0), u64be(seq), enc("C"));
        const tag = bytesToHex(await hmac(keys.client_mac, concat(header, body)));
        return { type: "sealed", epoch: 0, seq, direction: "client", payload: b64encode(body), tag };
    }
    async function open_(keys, rxSeq, frame) {
        if (frame.direction !== "server") throw new Error("bad direction");
        const body = b64decode(frame.payload);
        const header = concat(u64be(frame.epoch), u64be(frame.seq), enc("S"));
        const expect = bytesToHex(await hmac(keys.server_mac, concat(header, body)));
        if (expect !== frame.tag) throw new Error("bad tag");
        if (frame.seq <= rxSeq) throw new Error("replay");
        if (body[0] !== 0x00) throw new Error("unexpected compression");
        return JSON.parse(new TextDecoder().decode(body.slice(1)));
    }

    const api = {
        P, G, ELEMENT_BYTES,
        modPow, modinv, egcd, bytesToBig, bigToBytes, hexToBytes, bytesToHex,
        concat, u64be, b64encode, b64decode, enc,
        sha1, hmac, secretToElement, randomExponent, confirmMac, hkdfExpand,
        deriveKeys, seal, open_,
    };

    root.PriestlyCovenant = api;
    if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
