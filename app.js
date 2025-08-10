(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();

  // Streaming renderer for large logs
  function renderBytesStreaming(u8, preEl){
    const decoder = new TextDecoder('utf-8');
    const textNode = document.createTextNode('');
    preEl.textContent = '';
    preEl.appendChild(textNode);

    const CHUNK = 256 * 1024;
    const FLUSH_THRESHOLD = 200_000;
    let i = 0;
    let acc = '';

    function pump(){
      const end = Math.min(i + CHUNK, u8.length);
      const slice = u8.subarray(i, end);
      acc += decoder.decode(slice, { stream: true });

      if (acc.length >= FLUSH_THRESHOLD){
        textNode.appendData(acc);
        acc = '';
      }

      i = end;
      if (i < u8.length){
        requestAnimationFrame(pump);
      } else {
        acc += decoder.decode();
        if (acc) textNode.appendData(acc);
      }
    }
    pump();
  }

  function concatBytes(a, b){ const out = new Uint8Array(a.length + b.length); out.set(a, 0); out.set(b, a.length); return out; }
  function u16(n){ const b=new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, false); return b; }
  function be32(view, off){ return (view.getUint32(off, false))>>>0; }
  function eqMagic(view, arr){ for (let i=0;i<4;i++) if (view.getUint8(i)!==arr[i]) return false; return true; }

  async function buildPasswordBytes(phrase, fileBytes){
    const p = enc.encode(phrase);
    const h = await crypto.subtle.digest('SHA-256', fileBytes);
    const fhash = new Uint8Array(h);
    return concatBytes(concatBytes(u16(p.length), p), concatBytes(u16(fhash.length), fhash));
  }

  async function deriveKeyArgon2id(pwd, salt, mKiB, t, p){
    if (!(window.argon2 && window.argon2.hash)) throw new Error('argon2 runtime');
    const h = await window.argon2.hash({
      pass: pwd,
      salt: salt,
      time: t,
      mem: mKiB,
      hashLen: 32,
      parallelism: p,
      type: window.argon2.ArgonType.Argon2id,
      distPath: 'libs'
    });
    const raw = (h && h.hash && h.hash instanceof Uint8Array) ? h.hash : new Uint8Array(h.hash);
    return crypto.subtle.importKey('raw', raw, { name:'AES-GCM' }, false, ['decrypt']);
  }

  async function decryptEMS2(fullBuf, phrase, fileBytes){
    const HDR = { len: 48, magic: [0x45,0x4d,0x53,0x32] }; // 'EMS2'
    const view = new DataView(fullBuf);
    if (!eqMagic(view, HDR.magic) || view.getUint8(4)!==1) throw new Error('hdr');
    const kdfId  = view.getUint8(5);
    const aeadId = view.getUint8(6);
    if (kdfId!==2 || aeadId!==1) throw new Error('kdf/aead');

    const mKiB = be32(view, 8);
    const t    = be32(view, 12);
    const par  = view.getUint8(16);
    const salt = new Uint8Array(fullBuf.slice(20, 36));
    const nonce= new Uint8Array(fullBuf.slice(36, 48));
    const ct   = new Uint8Array(fullBuf.slice(HDR.len));

    const pwd = await buildPasswordBytes(phrase, fileBytes);
    const key = await deriveKeyArgon2id(pwd, salt, mKiB, t, par);
    const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv: nonce, tagLength: 128 }, key, ct);
    return new Uint8Array(pt);
  }

  async function run(){
    const path = $('deviceSelect').value;
    const fileInput = $('dataInput').files[0];
    const phrase = $('refCode').value.trim();
    const out = $('result');

    if (!path || !fileInput || !phrase) { out.textContent = 'Protokol nelze zobrazit.'; return; }

    out.textContent = 'Zpracovávám…';
    try{
      const resp = await fetch(path, { cache:'no-store' });
      if (!resp.ok) throw new Error('fetch');
      const fullBuf = await resp.arrayBuffer();
      const fileBuf = await fileInput.arrayBuffer();
      const pt = await decryptEMS2(fullBuf, phrase, new Uint8Array(fileBuf));
      renderBytesStreaming(pt, out);
    } catch(e){
      out.textContent = 'Protokol nelze zobrazit.';
    }
  }

  window.addEventListener('DOMContentLoaded', () => {
    const btn = $('runBtn'); if (btn) btn.addEventListener('click', run);
  });
})();