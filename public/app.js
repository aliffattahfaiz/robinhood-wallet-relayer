"use strict";
(function () {
  const E = window.ethers;
  const $ = (id) => document.getElementById(id);

  const VAULT_KEY = "rhwr_vault";
  const FAILS_KEY = "rhwr_fails";
  const LOCK_KEY = "rhwr_lock_min";
  const MAX_FAILS = 4;
  const KDF_ITER = 600000;

  // ---------- chain presets ----------
  const CHAINS = {
    "rh-main": {
      name: "Robinhood Mainnet", chainId: 4663,
      rpc: "https://rpc.mainnet.chain.robinhood.com",
    },
    "rh-test": {
      name: "Robinhood Testnet", chainId: 46630,
      rpc: "https://rpc.testnet.chain.robinhood.com",
    },
    "custom": { name: "Custom", chainId: 1, rpc: "" },
  };

  // ---------- helpers ----------
  function shrink(addr) {
    return addr.slice(0, 6) + "…" + addr.slice(-4);
  }
  function normKey(k) {
    const t = k.trim().toLowerCase();
    if (!t.startsWith("0x")) return "0x" + t;
    return t;
  }
  function parseEther(v) {
    try { return E.parseEther(String(v)); } catch { return 0n; }
  }
  function fmt(v) { return E.formatEther(v); }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function randInt(min, max) { return min + Math.floor(Math.random() * (max - min + 1)); }

  // ---------- encrypted vault (password-protected storage) ----------
  const V = {
    b64(u) { let s = ""; for (const b of u) s += String.fromCharCode(b); return btoa(s); },
    unb64(s) { const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; },
    async key(pw, salt, iter) {
      const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
      return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    },
    async encrypt(pw, plain) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const k = await this.key(pw, salt, KDF_ITER);
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, new TextEncoder().encode(plain));
      return JSON.stringify({ n: KDF_ITER, s: this.b64(salt), i: this.b64(iv), c: this.b64(new Uint8Array(ct)) });
    },
    async decrypt(pw, blob) {
      const o = JSON.parse(blob);
      const k = await this.key(pw, this.unb64(o.s), o.n || 100000);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: this.unb64(o.i) }, k, this.unb64(o.c));
      return new TextDecoder().decode(pt);
    }
  };

  let vaultPass = null;
  function getVault() { try { return localStorage.getItem(VAULT_KEY); } catch { return null; } }
  function setVault(b) { try { if (b === null) localStorage.removeItem(VAULT_KEY); else localStorage.setItem(VAULT_KEY, b); } catch { } }
  function getFails() { try { return parseInt(localStorage.getItem(FAILS_KEY) || "0", 10) || 0; } catch { return 0; } }
  function setFails(n) { try { localStorage.setItem(FAILS_KEY, String(n)); } catch { } }
  function clearFails() { try { localStorage.removeItem(FAILS_KEY); } catch { } }

  // ---------- app state ----------
  let main = null;       // private key string
  let buffers = [];      // private key strings
  let hots = [];         // private key strings
  let generated = [];    // {address, privateKey} — tab 1
  let running = false;
  let stopFlag = false;

  // ---------- log ----------
  function log(msg, cls) {
    const el = $("log");
    const line = document.createElement("div");
    if (cls) line.className = cls;
    const ts = new Date().toTimeString().slice(0, 8);
    line.textContent = "[" + ts + "] " + msg;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  // ---------- tabs ----------
  function switchTab(which) {
    $("tabGen").classList.toggle("hidden", which !== "gen");
    $("tabRel").classList.toggle("hidden", which !== "rel");
    $("tabSet").classList.toggle("hidden", which !== "set");
    $("tabGenBtn").classList.toggle("on", which === "gen");
    $("tabRelBtn").classList.toggle("on", which === "rel");
    $("tabSetBtn").classList.toggle("on", which === "set");
    if (which === "rel") refreshBalances();
  }
  $("tabGenBtn").onclick = () => switchTab("gen");
  $("tabRelBtn").onclick = () => switchTab("rel");
  $("tabSetBtn").onclick = () => switchTab("set");

  // ---------- amount / delay modes ----------
  $("amountMode").onchange = () => $("amountMaxBox").classList.toggle("hidden", $("amountMode").value !== "random");
  $("delayMode").onchange = () => $("delayMaxBox").classList.toggle("hidden", $("delayMode").value !== "random");
  $("preset").onchange = () => {
    const p = CHAINS[$("preset").value];
    $("chainId").value = p.chainId;
    if (p.rpc) $("rpc").value = p.rpc;
    if ($("preset").value === "custom") $("rpc").value = "";
  };
  $("lockMin").value = getLockMin();
  $("lockMin").onchange = () => {
    const raw = parseInt($("lockMin").value, 10);
    const v = Number.isNaN(raw) || raw < 0 ? 30 : raw;
    setLockMin(v);
    $("lockMin").value = v;
    if (vaultPass) armLock();
    log("Auto re-lock set to " + (v ? v + " min" : "never") + ".", "ok");
  };

  // ---------- generator ----------
  $("genRun").onclick = () => {
    const n = Math.max(1, Math.min(500, parseInt($("genCount").value, 10) || 1));
    generated = [];
    for (let i = 0; i < n; i++) {
      const w = E.Wallet.createRandom();
      generated.push({ address: w.address, privateKey: w.privateKey });
    }
    renderGenerated();
    log("Generated " + n + " wallet(s).", "ok");
    $("genStatus").textContent = n + " wallet(s) generated — copy keys now or add to buffer/hot to store them in the vault.";
  };
  $("genClear").onclick = () => { generated = []; renderGenerated(); };
  $("genCopyCsv").onclick = () => {
    const csv = generated.map((g) => g.address + "," + g.privateKey).join("\n");
    copyText(csv);
    log("Copied " + generated.length + " lines of CSV.", "ok");
  };
  $("genToBuf").onclick = () => { addKeysTo("buf", generated.map((g) => g.privateKey)); };
  $("genToHot").onclick = () => { addKeysTo("hot", generated.map((g) => g.privateKey)); };

  function renderGenerated() {
    const tb = $("genList");
    if (!generated.length) { tb.innerHTML = '<tr><td colspan="4" class="kv">No wallets generated yet.</td></tr>'; return; }
    tb.innerHTML = generated.map((g, i) =>
      '<tr><td><b>' + (i + 1) + '</b></td>' +
      '<td>' + g.address + '</td>' +
      '<td class="genkey">' + g.privateKey + '</td>' +
      '<td><button class="ghost" data-copy="' + g.address + '">addr</button> <button class="ghost" data-copy="' + g.privateKey + '">key</button></td></tr>'
    ).join("");
    tb.querySelectorAll("button[data-copy]").forEach((b) => {
      b.onclick = () => { copyText(b.dataset.copy); log("Copied.", "ok"); };
    });
  }

  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(t).catch(() => { legacyCopy(t); });
      return;
    }
    legacyCopy(t);
  }
  function legacyCopy(t) {
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch { }
    document.body.removeChild(ta);
  }

  // ---------- wallet tier management ----------
  function addKeysTo(tier, keys) {
    const arr = tier === "buf" ? buffers : hots;
    let added = 0;
    for (const raw of keys) {
      const k = normKey(raw);
      if (!/^0x[0-9a-fA-F]{64}$/.test(k)) { log("Skipped invalid key.", "bad"); continue; }
      if (arr.includes(k)) continue;
      arr.push(k); added++;
    }
    if (tier === "buf") { $("bufKeys").value = ""; } else { $("hotKeys").value = ""; }
    saveVault();
    renderTiers();
    log(added + " key(s) added to " + (tier === "buf" ? "buffer" : "hot") + ".", "ok");
  }
  $("bufAdd").onclick = () => addKeysTo("buf", $("bufKeys").value.split("\n"));
  $("hotAdd").onclick = () => addKeysTo("hot", $("hotKeys").value.split("\n"));
  $("bufGen").onclick = () => { const w = E.Wallet.createRandom(); addKeysTo("buf", [w.privateKey]); };
  $("hotGen").onclick = () => { const w = E.Wallet.createRandom(); addKeysTo("hot", [w.privateKey]); };
  $("bufClear").onclick = () => { buffers = []; saveVault(); renderTiers(); log("Cleared buffer wallets.", "warn"); };
  $("hotClear").onclick = () => { hots = []; saveVault(); renderTiers(); log("Cleared hot wallets.", "warn"); };
  $("bufToggle").onclick = () => toggleMask("buf");
  $("hotToggle").onclick = () => toggleMask("hot");
  $("mainToggle").onclick = () => {
    const ta = $("mainKey");
    ta.classList.toggle("mask");
    $("mainToggle").textContent = ta.classList.contains("mask") ? "Show" : "Hide";
  };

  function toggleMask(tier) {
    const ta = tier === "buf" ? $("bufKeys") : $("hotKeys");
    ta.classList.toggle("mask");
    const btn = tier === "buf" ? $("bufToggle") : $("hotToggle");
    btn.textContent = ta.classList.contains("mask") ? "Show" : "Hide";
  }

  $("mainSave").onclick = () => {
    const k = normKey($("mainKey").value);
    if (!/^0x[0-9a-fA-F]{64}$/.test(k)) { log("Invalid main wallet key.", "bad"); return; }
    main = k;
    $("mainKey").value = "";
    saveVault();
    renderTiers();
    log("Main wallet saved.", "ok");
  };

  // ---------- provider ----------
  function newProvider() {
    return new E.JsonRpcProvider($("rpc").value, parseInt($("chainId").value, 10) || 1, { staticNetwork: true });
  }

  $("testRpc").onclick = async () => {
    $("netStatus").textContent = "Testing…";
    try {
      const p = newProvider();
      const net = await p.getNetwork();
      const block = await p.getBlockNumber();
      $("netStatus").innerHTML = '<span class="ok">Connected.</span> chainId <b>' + net.chainId.toString() + '</b> · block <b>' + block + '</b>';
      log("RPC connected: chainId " + net.chainId.toString() + ", block " + block + ".", "ok");
    } catch (e) {
      $("netStatus").textContent = "Failed: " + (e.shortMessage || e.message);
      log("RPC test failed: " + (e.shortMessage || e.message), "bad");
    }
  };

  $("refreshBal").onclick = () => {
    $("netStatus").textContent = "Refreshing balances…";
    refreshBalances();
  };

  // ---------- balances ----------
  async function fetchBalance(address) {
    try {
      const p = newProvider();
      const bal = await p.getBalance(address);
      return fmt(bal);
    } catch { return "—"; }
  }

  async function refreshBalances() {
    const p = newProvider();
    const targets = [];
    if (main) targets.push({ key: main, label: "main" });
    buffers.forEach((k, i) => targets.push({ key: k, label: "buffer[" + i + "]" }));
    hots.forEach((k, i) => targets.push({ key: k, label: "hot[" + i + "]" }));
    const bals = {};
    await Promise.all(targets.map(async (t) => {
      try { const w = new E.Wallet(t.key); bals[t.label] = fmt(await p.getBalance(w.address)); }
      catch { bals[t.label] = "—"; }
    }));
    renderTiers(bals);
  }

  // ---------- rendering ----------
  function renderTiers(bals) {
    // main status
    if (main) {
      const w = new E.Wallet(main);
      const b = bals && bals.main ? bals.main : "—";
      $("mainStatus").innerHTML = '<span class="ok">' + w.address + '</span> <span class="kv">' + b + ' ETH</span> <button class="ghost" data-copym="' + w.address + '">copy</button>';
      $("mainStatus").querySelector("[data-copym]").onclick = (e) => { e.stopPropagation(); copyText(e.currentTarget.dataset.copym); log("Copied.", "ok"); };
    } else {
      $("mainStatus").textContent = "No main wallet.";
    }

    // buffers
    if (buffers.length) {
      const b = bals ? buffers.map((k, i) => { const w = new E.Wallet(k); return w.address + ' <span class="kv">' + ((bals && bals["buffer[" + i + "]"]) || "—") + ' ETH</span>'; }).join("<br>") : "";
      $("bufStatus").innerHTML = '<span class="ok">' + buffers.length + " buffer wallet(s)</span><br>" + b;
    } else {
      $("bufStatus").textContent = "No buffer wallets.";
    }

    // hots
    if (hots.length) {
      const b = bals ? hots.map((k, i) => { const w = new E.Wallet(k); return w.address + ' <span class="kv">' + ((bals && bals["hot[" + i + "]"]) || "—") + ' ETH</span>'; }).join("<br>") : "";
      $("hotStatus").innerHTML = '<span class="ok">' + hots.length + " hot wallet(s)</span><br>" + b;
    } else {
      $("hotStatus").textContent = "No hot wallets.";
    }

    // pairing
    renderPairs(bals);
  }

  function renderPairs(bals) {
    const n = Math.min(buffers.length, hots.length);
    if (!n) {
      $("pairStatus").textContent = "Need at least 1 buffer + 1 hot to pair. Buffer[i] forwards to hot[i] (1:1).";
      $("pairList").innerHTML = "";
      return;
    }
    $("pairStatus").innerHTML = '<span class="ok">' + n + ' pair(s)</span> <span class="kv">— unmatched: ' + (buffers.length - n) + ' buffer(s), ' + (hots.length - n) + ' hot(s)</span>';
    $("pairList").innerHTML = "";
    for (let i = 0; i < n; i++) {
      const bW = new E.Wallet(buffers[i]);
      const hW = new E.Wallet(hots[i]);
      const bb = bals && bals["buffer[" + i + "]"] ? bals["buffer[" + i + "]"] : "—";
      const hb = bals && bals["hot[" + i + "]"] ? bals["hot[" + i + "]"] : "—";
      const row = document.createElement("div");
      row.className = "pair";
      row.innerHTML =
        '<span class="kv">' + (i + 1) + '</span>' +
        '<div class="box">buffer · <b>' + bW.address + '</b> <span class="kv">' + bb + ' ETH</span></div>' +
        '<span class="arrow">↔</span>' +
        '<div class="box">hot · <b>' + hW.address + '</b> <span class="kv">' + hb + ' ETH</span></div>' +
        '<button class="rm" title="remove pair" data-pair="' + i + '">×</button>';
      row.querySelector("[data-pair]").onclick = () => {
        buffers.splice(i, 1); hots.splice(i, 1);
        saveVault(); renderTiers();
        log("Removed pair " + (i + 1) + ".", "warn");
      };
      $("pairList").appendChild(row);
    }
  }

  // ---------- export ----------
  function exportRows() {
    const rows = [];
    if (main) {
      const w = new E.Wallet(main);
      rows.push({ pairIndex: "main", mainAddress: w.address, mainKey: w.privateKey, bufferAddress: "", bufferKey: "", hotAddress: "", hotKey: "" });
    }
    const n = Math.min(buffers.length, hots.length);
    buffers.forEach((k, i) => {
      const b = new E.Wallet(k);
      const h = i < hots.length ? new E.Wallet(hots[i]) : null;
      rows.push({
        pairIndex: i + 1,
        mainAddress: "",
        mainKey: "",
        bufferAddress: b.address,
        bufferKey: b.privateKey,
        hotAddress: h ? h.address : "",
        hotKey: h ? h.privateKey : "",
      });
    });
    if (hots.length > buffers.length) {
      for (let i = buffers.length; i < hots.length; i++) {
        const h = new E.Wallet(hots[i]);
        rows.push({ pairIndex: i + 1, mainAddress: "", mainKey: "", bufferAddress: "", bufferKey: "", hotAddress: h.address, hotKey: h.privateKey });
      }
    }
    return rows;
  }
  const EXPORT_HEADERS = ["pair_index", "main_address", "main_private_key", "buffer_address", "buffer_private_key", "hot_address", "hot_private_key"];
  function rowsToAoa(rows) {
    return [EXPORT_HEADERS].concat(rows.map((r) => [r.pairIndex, r.mainAddress, r.mainKey, r.bufferAddress, r.bufferKey, r.hotAddress, r.hotKey]));
  }
  function csvCell(v) {
    const s = String(v);
    if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function toCsv(rows) {
    return rowsToAoa(rows).map((row) => row.map(csvCell).join(",")).join("\r\n");
  }

  // minimal XLSX writer: builds a valid .xlsx (zip of spreadsheetml xml) with no external deps
  function buildXlsx(rows) {
    const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    const col = (i) => { let s = ""; i += 1; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; };
    let sheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
    rowsToAoa(rows).forEach((row, ri) => {
      sheet += '<row r="' + (ri + 1) + '">';
      row.forEach((cell, ci) => {
        sheet += '<c r="' + col(ci) + (ri + 1) + '" t="inlineStr"><is><t>' + esc(cell) + '</t></is></c>';
      });
      sheet += "</row>";
    });
    sheet += "</sheetData></worksheet>";

    const files = [
      { name: "[Content_Types].xml", data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>' },
      { name: "_rels/.rels", data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>' },
      { name: "xl/workbook.xml", data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Wallets" sheetId="1" r:id="rId1"/></sheets></workbook>' },
      { name: "xl/_rels/workbook.xml.rels", data: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>' },
      { name: "xl/worksheets/sheet1.xml", data: sheet },
    ];

    // --- zip (store, no compression) ---
    const enc = new TextEncoder();
    function crc32(bytes) {
      let c = 0xFFFFFFFF;
      for (let i = 0; i < bytes.length; i++) {
        c ^= bytes[i];
        for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      return (c ^ 0xFFFFFFFF) >>> 0;
    }
    const chunks = [];
    const central = [];
    let offset = 0;
    const u32 = (dv, o, v) => dv.setUint32(o, v, true);
    const u16 = (dv, o, v) => dv.setUint16(o, v, true);

    for (const f of files) {
      const name = enc.encode(f.name);
      const data = enc.encode(f.data);
      const crc = crc32(data);
      const local = new Uint8Array(30 + name.length + data.length);
      const dv = new DataView(local.buffer);
      u32(dv, 0, 0x04034b50); u16(dv, 4, 20); u16(dv, 6, 0); u16(dv, 8, 0);
      u16(dv, 10, 0); u16(dv, 12, 0); u32(dv, 14, crc);
      u32(dv, 18, data.length); u32(dv, 22, data.length);
      u16(dv, 26, name.length); u16(dv, 28, 0);
      local.set(name, 30); local.set(data, 30 + name.length);
      chunks.push(local);
      central.push({ name, crc, size: data.length, offset });
      offset += local.length;
    }
    const cd = [];
    for (const c of central) {
      const rec = new Uint8Array(46 + c.name.length);
      const dv = new DataView(rec.buffer);
      u32(dv, 0, 0x02014b50); u16(dv, 4, 20); u16(dv, 6, 20); u16(dv, 8, 0); u16(dv, 10, 0);
      u16(dv, 12, 0); u16(dv, 14, 0); u32(dv, 16, c.crc);
      u32(dv, 20, c.size); u32(dv, 24, c.size); u16(dv, 28, c.name.length);
      u16(dv, 30, 0); u16(dv, 32, 0); u16(dv, 34, 0); u16(dv, 36, 0);
      u32(dv, 38, 0); u32(dv, 42, c.offset);
      rec.set(c.name, 46);
      cd.push(rec);
    }
    const cdOffset = offset;
    const cdSize = cd.reduce((s, r) => s + r.length, 0);
    const eocd = new Uint8Array(22);
    const dv = new DataView(eocd.buffer);
    u32(dv, 0, 0x06054b50); u16(dv, 4, 0); u16(dv, 6, 0);
    u16(dv, 8, central.length); u16(dv, 10, central.length);
    u32(dv, 12, cdSize); u32(dv, 16, cdOffset); u16(dv, 20, 0);

    const out = new Uint8Array(cdOffset + cdSize + 22);
    let p = 0;
    for (const c of chunks) { out.set(c, p); p += c.length; }
    for (const c of cd) { out.set(c, p); p += c.length; }
    out.set(eocd, p);
    return out;
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
  }

  function guardExport() {
    if (!main && !buffers.length && !hots.length) {
      log("Nothing to export — no wallets set.", "bad");
      return false;
    }
    if (!confirm("Export ALL wallet addresses + private keys in plaintext?\nAnyone with this file/clipboard can spend everything. Continue?")) return false;
    return true;
  }
  $("exportCsv").onclick = () => {
    if (!guardExport()) return;
    const rows = exportRows();
    downloadBlob(new Blob([toCsv(rows)], { type: "text/csv;charset=utf-8" }), "rh-wallets.csv");
    log("Exported " + rows.length + " wallet(s) as CSV.", "ok");
  };
  $("exportXlsx").onclick = () => {
    if (!guardExport()) return;
    const rows = exportRows();
    const bytes = buildXlsx(rows);
    downloadBlob(new Blob([bytes], { type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }), "rh-wallets.xlsx");
    log("Exported " + rows.length + " wallet(s) as XLSX.", "ok");
  };
  $("exportClip").onclick = () => {
    if (!guardExport()) return;
    const rows = exportRows();
    copyText(toCsv(rows));
    log("Exported " + rows.length + " wallet(s) to clipboard.", "ok");
  };

  // ---------- relay ----------
  function pickAmount() {
    const mode = $("amountMode").value;
    const min = parseEther($("amountMin").value);
    if (mode === "fixed") return min;
    const max = parseEther($("amountMax").value);
    if (max <= min) return min;
    const diff = max - min;
    const r = BigInt(randInt(0, 10000));
    return min + (diff * r) / 10000n;
  }
  async function pickDelay() {
    const mode = $("delayMode").value;
    const min = parseInt($("delayMin").value, 10) || 0;
    if (mode === "fixed") return min;
    const max = parseInt($("delayMax").value, 10) || min;
    return randInt(Math.min(min, max), Math.max(min, max));
  }

  async function sendOne(fromKey, toAddress, amount, label) {
    const p = newProvider();
    const wallet = new E.Wallet(fromKey, p);
    const bal = await p.getBalance(wallet.address);
    if (bal < amount) {
      log(label + " — insufficient balance on " + shrink(wallet.address) + " (" + fmt(bal) + " ETH, need " + fmt(amount) + ")", "bad");
      return false;
    }
    try {
      const fee = await p.getFeeData();
      const nonce = await p.getTransactionCount(wallet.address, "pending");
      const tx = await wallet.sendTransaction({
        to: toAddress, value: amount, nonce,
        gasLimit: 21000,
        maxFeePerGas: fee.maxFeePerGas, maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
      });
      log(label + " — sent " + fmt(amount) + " ETH → " + shrink(toAddress) + " · tx " + shrink(tx.hash), "ok");
      const rec = await tx.wait();
      log(label + " — confirmed · " + shrink(rec.hash), "ok");
      return true;
    } catch (e) {
      log(label + " — failed: " + (e.shortMessage || e.reason || e.message), "bad");
      return false;
    }
  }

  async function relayPair(i) {
    const dir = $("direction").value;
    const amount = pickAmount();
    if (dir === "down") {
      await sendOne(main, new E.Wallet(buffers[i]).address, amount, "main → buffer[" + i + "]");
      if (stopFlag) return;
      await sleep(await pickDelay());
      await sendOne(buffers[i], new E.Wallet(hots[i]).address, amount, "buffer[" + i + "] → hot[" + i + "] (1:1)");
    } else {
      await sendOne(hots[i], new E.Wallet(buffers[i]).address, amount, "hot[" + i + "] → buffer[" + i + "]");
      if (stopFlag) return;
      await sleep(await pickDelay());
      await sendOne(buffers[i], new E.Wallet(main).address, amount, "buffer[" + i + "] → main (1:1)");
    }
  }

  async function runRelay() {
    if (running) return;
    if (!main) { log("Set a main wallet first.", "bad"); return; }
    const n = Math.min(buffers.length, hots.length);
    if (!n) { log("Need at least 1 buffer + 1 hot wallet.", "bad"); return; }
    const dir = $("direction").value === "down" ? "deposit (main → buffer → hot)" : "sweep (hot → buffer → main)";
    if (!confirm("Relay " + dir + " for " + n + " pair(s)?\n\nEach hop sends real signed transactions. Continue?")) return;
    running = true; stopFlag = false;
    $("relayRun").disabled = true;
    log("Relay started — " + ($("direction").value === "down" ? "deposit" : "sweep") + " · " + n + " pair(s).", "ok");
    for (let i = 0; i < n && !stopFlag; i++) {
      await relayPair(i);
      if (!stopFlag && i < n - 1) await sleep(await pickDelay());
    }
    running = false;
    $("relayRun").disabled = false;
    log(stopFlag ? "Relay stopped." : "Relay finished.", stopFlag ? "warn" : "ok");
    refreshBalances();
  }
  $("relayRun").onclick = runRelay;
  $("relayStop").onclick = () => { stopFlag = true; log("Stop requested — finishing current tx…", "warn"); };

  $("copyLog").onclick = () => { copyText($("log").innerText); log("Log copied.", "ok"); };
  $("clearLog").onclick = () => { $("log").innerHTML = ""; };

  // ---------- vault persistence ----------
  function saveVault() {
    if (!vaultPass) return;
    const payload = JSON.stringify({ main, buffers, hots });
    V.encrypt(vaultPass, payload).then(setVault).catch(() => {});
  }
  function getLockMin() { try { const v = parseInt(localStorage.getItem(LOCK_KEY) || "30", 10); return Number.isNaN(v) || v < 0 ? 30 : v; } catch { return 30; } }
  function setLockMin(v) { try { localStorage.setItem(LOCK_KEY, String(v)); } catch { } }
  function deepWipe() {
    setVault(null); clearFails(); vaultPass = null;
    main = null; buffers = []; hots = [];
  }
  function relock() {
    vaultPass = null; main = null; buffers = []; hots = [];
    renderTiers();
    initVault();
  }
  let lockTimer = null;
  function armLock() {
    if (lockTimer) clearTimeout(lockTimer);
    const min = getLockMin();
    if (min <= 0 || !vaultPass) return;
    lockTimer = setTimeout(() => {
      log("Auto re-lock: cleared keys from memory after " + min + " min idle.", "warn");
      relock();
    }, min * 60000);
  }
  ["click", "keydown", "mousemove", "scroll", "touchstart"].forEach((ev) =>
    window.addEventListener(ev, () => { if (vaultPass) armLock(); }, { passive: true })
  );
  async function onVaultSubmit() {
    const pw = $("vaultPass").value;
    const blob = getVault();
    if (!blob) {
      if (pw.length < 4) { $("vaultMsg").textContent = "Password must be at least 4 characters."; return; }
      if (pw !== $("vaultConfirm").value) { $("vaultMsg").textContent = "Passwords do not match."; return; }
      setVault(await V.encrypt(pw, "{}"));
      clearFails();
    } else {
      if (getFails() >= MAX_FAILS) {
        deepWipe(); initVault();
        $("vaultMsg").textContent = "Too many failed attempts. Saved keys were wiped.";
        return;
      }
      try { await V.decrypt(pw, blob); }
      catch (e) {
        const n = getFails() + 1;
        if (n >= MAX_FAILS) {
          deepWipe(); initVault();
          $("vaultMsg").textContent = "Too many failed attempts. Saved keys were wiped.";
          return;
        }
        setFails(n);
        $("vaultMsg").textContent = "Wrong password. " + (MAX_FAILS - n) + " attempt(s) left before saved keys are wiped.";
        return;
      }
    }
    vaultPass = pw;
    clearFails();
    $("vaultOverlay").style.display = "none";
    await restoreState();
    armLock();
  }
  async function restoreState() {
    const blob = getVault();
    if (blob && vaultPass) {
      try {
        const d = JSON.parse(await V.decrypt(vaultPass, blob));
        main = d.main || null;
        buffers = Array.isArray(d.buffers) ? d.buffers : [];
        hots = Array.isArray(d.hots) ? d.hots : [];
        renderTiers();
        log("Unlocked. " + (main ? 1 : 0) + " main, " + buffers.length + " buffer, " + hots.length + " hot wallet(s) restored.", "ok");
        refreshBalances();
      } catch (e) {
        log("Could not restore saved state.", "bad");
      }
    } else {
      renderTiers();
    }
  }
  async function onVaultReset() {
    if (!confirm("Reset clears ALL saved keys and settings. Continue?")) return;
    deepWipe();
    initVault();
  }
  function wipe() {
    if (!confirm("Wipe ALL saved keys from this browser? This deletes the encrypted vault — it cannot be undone.")) return;
    deepWipe();
    renderTiers();
    initVault();
  }
  $("wipe").onclick = wipe;
  $("vaultBtn").onclick = onVaultSubmit;
  $("vaultReset").onclick = onVaultReset;
  $("vaultPass").addEventListener("keydown", (e) => { if (e.key === "Enter") onVaultSubmit(); });

  function initVault() {
    $("vaultTitle").textContent = getVault() ? "Unlock" : "Set a password";
    $("vaultDesc").textContent = getVault()
      ? "Enter your password to access your saved main / buffer / hot wallets."
      : "Create a password. Main + buffer + hot private keys are encrypted with it (AES-256-GCM) and saved only in this browser.";
    $("vaultConfirmLabel").style.display = getVault() ? "none" : "";
    $("vaultConfirm").style.display = getVault() ? "none" : "";
    $("vaultBtn").textContent = getVault() ? "Unlock" : "Create & unlock";
    $("vaultMsg").textContent = "";
    $("vaultOverlay").style.display = "flex";
  }

  window.addEventListener("beforeunload", () => { main = null; buffers = []; hots = []; });

  initVault();
  $("amountMode").onchange();
  $("delayMode").onchange();
})();
