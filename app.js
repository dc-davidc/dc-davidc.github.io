(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();

  // Progress overlay helpers
  const overlay = document.getElementById('overlay');
  const pfill = document.getElementById('pfill');
  const plabel = document.getElementById('plabel');
  const progress = overlay ? overlay.querySelector('.progress') : null;

  function showOverlay(){ if(!overlay) return; overlay.classList.add('show'); document.body.style.overflow='hidden'; setProgress(1, 'Připravuji…'); }
  function hideOverlay(){ if(!overlay) return; overlay.classList.remove('show'); document.body.style.overflow=''; }
  function setProgress(pct, label){
    if(!progress) return;
    const v = Math.max(0, Math.min(100, Math.floor(pct)));
    if (pfill) pfill.style.width = v + '%';
    progress.setAttribute('aria-valuenow', String(v));
    if (label && plabel) plabel.textContent = label;
  }

  // Streaming renderer
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
      try { acc += decoder.decode(slice, { stream: true }); } catch(e) { acc += decoder.decode(slice); }

      if (acc.length >= FLUSH_THRESHOLD){
        textNode.appendData(acc);
        acc = '';
      }

      i = end;
      if (i < u8.length){
        requestAnimationFrame(pump);
      } else {
        try { acc += decoder.decode(); } catch(e) {}
        if (acc) textNode.appendData(acc);
      }
    }
    requestAnimationFrame(pump);
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
      distPath: 'libs',
      onProgress: (x) => { setProgress(35 + Math.round((x||0)*50), 'Odvozování klíče…'); }
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
    const header = new Uint8Array(fullBuf.slice(0, HDR.len));
    const salt = new Uint8Array(fullBuf.slice(20, 36));
    const nonce= new Uint8Array(fullBuf.slice(36, 48));
    const ct   = new Uint8Array(fullBuf.slice(HDR.len));

    setProgress(35, 'Odvozování klíče…');
    const pwd = await buildPasswordBytes(phrase, fileBytes);
    const key = await deriveKeyArgon2id(pwd, salt, mKiB, t, par);
    setProgress(86, 'Dešifrování…');
    const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv: nonce, tagLength: 128, additionalData: header }, key, ct);
    return new Uint8Array(pt);
  }

  async function fetchWithProgress(url){
    setProgress(5, 'Stahuji…');
    const resp = await fetch(url, { cache:'no-store' });
    if (!resp.ok) throw new Error('fetch');
    const len = Number(resp.headers.get('Content-Length')) || 0;
    if (resp.body && resp.body.getReader){
      const reader = resp.body.getReader();
      const chunks = [];
      let received = 0;
      while(true){
        const {value, done} = await reader.read();
        if (done) break;
        chunks.push(value);
        received += value.byteLength;
        if (len) {
          const pct = Math.min(30, 5 + (received/len)*25);
          setProgress(pct, 'Stahuji…');
        }
      }
      let size = 0; for (const c of chunks) size += c.byteLength;
      const out = new Uint8Array(size);
      let off = 0;
      for (const c of chunks){ out.set(c, off); off += c.byteLength; }
      return out.buffer;
    } else {
      const buf = await resp.arrayBuffer();
      setProgress(30, 'Stahuji…');
      return buf;
    }
  }

  async function run(){
    const path = $('deviceSelect').value;
    const fileInput = $('dataInput').files[0];
    const phrase = $('refCode').value.trim();
    const out = $('result');

    if (!path || !fileInput || !phrase) { out.textContent = 'Protokol nelze zobrazit.'; return; }

    showOverlay();
    try{
      const fullBuf = await fetchWithProgress(path);
      const fileBuf = await fileInput.arrayBuffer();
      setProgress(92, 'Vykreslování…');
      const pt = await decryptEMS2(fullBuf, phrase, new Uint8Array(fileBuf));
      hideOverlay();
      renderBytesStreaming(pt, out);
    } catch(e){
      hideOverlay();
      out.textContent = 'Protokol nelze zobrazit.';
    }
  }

  window.addEventListener('DOMContentLoaded', () => {
    const btn = $('runBtn'); if (btn) btn.addEventListener('click', run);
  });
})();