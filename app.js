(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();

  // Progress overlay helpers (camouflaged texts)
  const overlay = $('overlay');
  const pfill = $('pfill');
  const plabel = $('plabel');
  const actlabel = $('actlabel');
  const progress = overlay ? overlay.querySelector('.progress') : null;

  function showOverlay(){ if(!overlay) return; overlay.classList.add('show'); document.body.style.overflow='hidden'; setProgress(1, 'Načítám balíček…', 'Inicializace…'); }
  function hideOverlay(){ if(!overlay) return; overlay.classList.remove('show'); document.body.style.overflow=''; }
  function setProgress(pct, label, act){
    if(!progress) return;
    const v = Math.max(0, Math.min(100, Math.floor(pct)));
    if (pfill) pfill.style.width = v + '%';
    progress.setAttribute('aria-valuenow', String(v));
    if (label && plabel) plabel.textContent = label;
    if (actlabel && typeof act === 'string') actlabel.textContent = act;
  }

  // Secure wipe state
  let lastPlain = null;
  let lastCipher = null;
  let lastFileBytes = null;

  function secureWipe(){
    try {
      if (lastPlain && lastPlain.fill) lastPlain.fill(0);
      if (lastCipher && lastCipher.fill) lastCipher.fill(0);
      if (lastFileBytes && lastFileBytes.fill) lastFileBytes.fill(0);
    } catch(e){}
    lastPlain = lastCipher = lastFileBytes = null;
    const res = $('result');
    if (res){
      while (res.firstChild) {
        res.removeChild(res.firstChild);
      }
    }
    try { if (window.gc) window.gc(); } catch(e){}
  }

  // Segmented renderer (mobile Firefox-proof)
  function renderSegmented(u8, container){
    const decoder = new TextDecoder('utf-8');
    const MAX_SEG_CHARS = 200000;
    const CHUNK = 256 * 1024;
    let i = 0;
    let acc = '';

    while (container.firstChild) container.removeChild(container.firstChild);
    const frag = document.createDocumentFragment();

    function flushSegment() {
      if (!acc) return;
      const pre = document.createElement('pre');
      pre.className = 'seg';
      pre.textContent = acc;
      frag.appendChild(pre);
      acc = '';
    }

    function pump(){
      const end = Math.min(i + CHUNK, u8.length);
      const slice = u8.subarray(i, end);
      try { acc += decoder.decode(slice, { stream: true }); } catch(e) { acc += decoder.decode(slice); }

      if (acc.length >= MAX_SEG_CHARS){
        flushSegment();
        if (frag.childNodes.length >= 4){
          container.appendChild(frag.cloneNode(true));
          while (frag.firstChild) frag.removeChild(frag.firstChild);
        }
      }

      i = end;
      if (i < u8.length){
        requestAnimationFrame(pump);
      } else {
        try { acc += decoder.decode(); } catch(e) {}
        flushSegment();
        if (frag.childNodes.length) container.appendChild(frag);
      }
    }
    requestAnimationFrame(pump);
  }

  // Utils
  function concatBytes(a, b){ const out = new Uint8Array(a.length + b.length); out.set(a, 0); out.set(b, a.length); return out; }
  function u16(n){ const b=new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, false); return b; }
  function be32(view, off){ return (view.getUint32(off, false))>>>0; }
  function eqMagic(view, arr){ for (let i=0;i<4;i++) if (view.getUint8(i)!==arr[i]) return false; return true; }

  // KDF domain separation
  async function buildPasswordBytes(phrase, fileBytes){
    const domain = new TextEncoder().encode('EMS2-KDF\0'); // domain prefix
    const p = enc.encode(phrase);
    const h = await crypto.subtle.digest('SHA-256', fileBytes);
    const fhash = new Uint8Array(h);
    // return: domain || len(p)||p || len(fhash)||fhash
    return concatBytes(domain, concatBytes(concatBytes(u16(p.length), p), concatBytes(u16(fhash.length), fhash)));
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
      onProgress: (x) => { setProgress(35 + Math.round((x||0)*50), 'Analýza metadat…', 'Pracovní profil'); }
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

    setProgress(35, 'Analýza metadat…', 'Struktura balíčku');
    const pwd = await buildPasswordBytes(phrase, fileBytes);
    const key = await deriveKeyArgon2id(pwd, salt, mKiB, t, par);
    setProgress(86, 'Kontrola formátu…', 'Kompozice bloků');
    const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv: nonce, tagLength: 128, additionalData: header }, key, ct);
    return new Uint8Array(pt);
  }

  async function fetchWithProgress(url){
    setProgress(5, 'Načítám balíček…', 'Přenos');
    const sep = url.includes('?') ? '&' : '?';
    const bustUrl = url + sep + 'v=' + Date.now().toString(36);
    const resp = await fetch(bustUrl, { cache:'no-store' });
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
          setProgress(pct, 'Načítám balíček…', Math.round((received/len)*100) + '%');
        }
      }
      let size = 0; for (const c of chunks) size += c.byteLength;
      const out = new Uint8Array(size);
      let off = 0;
      for (const c of chunks){ out.set(c, off); off += c.byteLength; }
      return out.buffer;
    } else {
      const buf = await resp.arrayBuffer();
      setProgress(30, 'Načítám balíček…', 'Přenos');
      return buf;
    }
  }

  async function run(){
    const path = $('deviceSelect').value;
    const fileInput = $('dataInput').files[0];
    const phrase = $('refCode').value.trim();
    const container = $('result');

    if (!path || !fileInput || !phrase) { container.textContent = 'Protokol nelze zobrazit.'; return; }

    showOverlay();
    await new Promise(r => requestAnimationFrame(() => r()));
    try{
      const fullBuf = await fetchWithProgress(path);
      const fileBuf = await fileInput.arrayBuffer();
      lastCipher = new Uint8Array(fullBuf);
      lastFileBytes = new Uint8Array(fileBuf);
      setProgress(92, 'Sestavuji výpis…', 'Příprava');

      const pt = await decryptEMS2(fullBuf, phrase, lastFileBytes);
      lastPlain = pt;
      hideOverlay();
      renderSegmented(pt, container);
    } catch(e){
      hideOverlay();
      container.textContent = 'Protokol nelze zobrazit.';
    }
  }

  window.addEventListener('DOMContentLoaded', () => {
    const btn = $('runBtn'); if (btn) btn.addEventListener('click', run);
    const wipeBtn = $('wipeBtn'); if (wipeBtn) wipeBtn.addEventListener('click', secureWipe);
  });

  window.addEventListener('pagehide', secureWipe);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') secureWipe(); });
})();