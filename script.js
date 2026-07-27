/* =========================================================
   Cyber Cheat Sheet — application logic
   Vanilla JS. No frameworks, no build step, no backend.
   ========================================================= */
(function () {
  "use strict";

  /* ---------------------------------------------------------
     Category configuration
  --------------------------------------------------------- */
  var ICONS = {
    linux: '<path d="M4 17l6-10 6 10M4 17h12M9 13h2"/><circle cx="10" cy="5" r="1.6"/>',
    windows: '<rect x="3" y="4" width="8" height="8" rx="1"/><rect x="13" y="4" width="8" height="8" rx="1"/><rect x="3" y="14" width="8" height="6" rx="1"/><rect x="13" y="14" width="8" height="6" rx="1"/>',
    powershell: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8l4 4-4 4M13 16h4"/>',
    nmap: '<circle cx="12" cy="12" r="8"/><path d="M12 4v8l5 3"/>',
    wireshark: '<path d="M3 12h4l2-7 4 14 2-7h6"/>',
    splunk: '<path d="M4 19V9M9 19V5M14 19v-8M19 19v-4"/>',
    kql: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    sigma: '<path d="M5 4h14l-7 8 7 8H5l7-8z"/>',
    yara: '<path d="M12 3l2.4 5.5L20 9l-4.4 3.8L17 19l-5-3.2L7 19l1.4-6.2L4 9l5.6-.5z"/>'
  };

  var CATEGORIES = [
    { key: "linux", label: "Linux Commands", short: "Linux", file: "data/linux.json",
      desc: "Core shell, filesystem, networking and forensic commands for Linux/Unix systems." },
    { key: "windows", label: "Windows Commands", short: "Windows", file: "data/windows.json",
      desc: "CMD utilities for administration, networking, and incident response on Windows hosts." },
    { key: "powershell", label: "PowerShell", short: "PowerShell", file: "data/powershell.json",
      desc: "Object-oriented cmdlets for administration, automation, and Windows threat hunting." },
    { key: "nmap", label: "Nmap Examples", short: "Nmap", file: "data/nmap.json",
      desc: "Host discovery, port scanning, service detection and NSE scripting recipes." },
    { key: "wireshark", label: "Wireshark Filters", short: "Wireshark", file: "data/wireshark.json",
      desc: "Display filters for isolating protocols, hosts, and suspicious traffic patterns." },
    { key: "splunk", label: "Splunk Queries", short: "Splunk", file: "data/splunk.json",
      desc: "SPL searches for log analysis, correlation, and detection engineering." },
    { key: "kql", label: "KQL Queries", short: "KQL", file: "data/kql.json",
      desc: "Kusto queries for Microsoft Sentinel, Defender, and Log Analytics workspaces." },
    { key: "sigma", label: "Sigma Rules", short: "Sigma", file: "data/sigma.json",
      desc: "Vendor-agnostic YAML detection rules covering common attacker behaviors." },
    { key: "yara", label: "YARA Rules", short: "YARA", file: "data/yara.json",
      desc: "Pattern-matching signatures for identifying and classifying malware samples." }
  ];
  var CAT_BY_KEY = {};
  CATEGORIES.forEach(function (c) { CAT_BY_KEY[c.key] = c; });

  var TIPS = [
    "Nmap's -Pn flag skips host discovery — essential when ICMP is filtered but ports are still open.",
    "In Splunk, tstats against an accelerated data model can be 10-100x faster than a raw search over the same range.",
    "'ss -tulnp' has replaced 'netstat' on most modern Linux distributions — learn it, it's faster too.",
    "Sigma rules are vendor-agnostic — the same YAML can be converted to Splunk SPL, KQL, or Elastic queries.",
    "PowerShell's Get-WinEvent with -FilterHashtable filters at the log provider, which is far faster than piping to Where-Object.",
    "A YARA rule with only 'strings' and no 'condition' logic will fail to compile — always pair strings with a condition.",
    "'chattr +i' makes a Linux file immutable even to root, until the flag is cleared — handy for tamper-resistant logs.",
    "In Wireshark, 'tcp.analysis.flags' surfaces every packet the expert system considers anomalous in one filter.",
    "certutil.exe can download files via -urlcache — a living-off-the-land technique worth alerting on.",
    "Event ID 4104 captures full PowerShell Script Block content when logging is enabled — enable it before you need it.",
    "'find / -perm -4000' is one of the fastest first steps for spotting SUID privilege-escalation paths on Linux.",
    "DNS queries longer than ~50 characters are a simple, high-signal heuristic for DNS-tunneling exfiltration."
  ];

  /* ---------------------------------------------------------
     State
  --------------------------------------------------------- */
  var STORE = { all: [], byCategory: {}, loaded: false, loadError: false };
  var favorites = loadJSON("ccs_favorites", []);
  var recentlyViewed = loadJSON("ccs_recent", []);
  var expandedIds = new Set();
  var hoverCardId = null;

  function loadJSON(key, fallback) {
    try { var v = JSON.parse(localStorage.getItem(key)); return v || fallback; }
    catch (e) { return fallback; }
  }
  function persist(key, val) {
    try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) { /* storage unavailable */ }
  }
  function isFav(id) { return favorites.indexOf(id) !== -1; }
  function toggleFav(id) {
    var i = favorites.indexOf(id);
    if (i === -1) { favorites.push(id); } else { favorites.splice(i, 1); }
    persist("ccs_favorites", favorites);
  }
  function pushRecent(id) {
    recentlyViewed = recentlyViewed.filter(function (x) { return x !== id; });
    recentlyViewed.unshift(id);
    recentlyViewed = recentlyViewed.slice(0, 12);
    persist("ccs_recent", recentlyViewed);
  }
  function entryById(id) { return STORE.all.find(function (e) { return e.id === id; }); }

  /* ---------------------------------------------------------
     Utilities
  --------------------------------------------------------- */
  function escapeHtml(str) {
    return String(str == null ? "" : str).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function highlight(text, query) {
    var esc = escapeHtml(text);
    if (!query) return esc;
    try {
      var q = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return esc.replace(new RegExp("(" + q + ")", "ig"), "<mark>$1</mark>");
    } catch (e) { return esc; }
  }
  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments, ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }
  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function icon(name, extra) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' + (extra || "") + '>' + (ICONS[name] || "") + "</svg>";
  }
  function dayIndex(mod) {
    var start = new Date(new Date().getFullYear(), 0, 0);
    var diff = new Date() - start;
    var day = Math.floor(diff / 86400000);
    return mod > 0 ? day % mod : 0;
  }

  /* ---------------------------------------------------------
     Toasts
  --------------------------------------------------------- */
  function toast(msg) {
    var c = qs("#toast-container");
    var el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6 9 17l-5-5"/></svg><span></span>';
    el.querySelector("span").textContent = msg;
    c.appendChild(el);
    setTimeout(function () {
      el.classList.add("leaving");
      setTimeout(function () { el.remove(); }, 220);
    }, 2200);
  }

  function copyText(text, btn) {
    function done(ok) {
      if (!ok) { toast("Copy failed — select and copy manually"); return; }
      toast("Copied to clipboard");
      if (btn) {
        btn.classList.add("copied");
        var original = btn.innerHTML;
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M20 6 9 17l-5-5"/></svg>';
        setTimeout(function () { btn.classList.remove("copied"); btn.innerHTML = original; }, 1400);
      }
    }
    if (navigator.clipboard && window.isSecureContext !== false) {
      navigator.clipboard.writeText(text).then(function () { done(true); }).catch(function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, cb) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      cb(ok);
    } catch (e) { cb(false); }
  }

  /* ---------------------------------------------------------
     Data loading
  --------------------------------------------------------- */
  function loadData() {
    var promises = CATEGORIES.map(function (c) {
      return fetch(c.file).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      }).then(function (json) {
        STORE.byCategory[c.key] = json;
        return json;
      }).catch(function (err) {
        console.warn("Failed to load", c.file, err);
        STORE.byCategory[c.key] = [];
        return [];
      });
    });
    return Promise.all(promises).then(function (lists) {
      STORE.all = [].concat.apply([], lists);
      STORE.loaded = true;
      STORE.loadError = STORE.all.length === 0;
    });
  }

  /* ---------------------------------------------------------
     Card rendering
  --------------------------------------------------------- */
  function difficultyBadge(d) {
    return '<span class="badge ' + escapeHtml(d) + '">' + escapeHtml(d) + "</span>";
  }

  function cardHTML(e, query) {
    var fav = isFav(e.id);
    var expanded = expandedIds.has(e.id);
    var hasExtra = e.example || e.output || e.notes;
    var codeMulti = e.code && e.code.indexOf("\n") !== -1;
    var tagsHtml = (e.tags || []).map(function (t) {
      return '<span class="tag">' + escapeHtml(t) + "</span>";
    }).join("");

    var extraHtml = "";
    if (e.example) extraHtml += '<div><span class="ex-label">Example usage</span><pre>' + highlight(e.example, query) + "</pre></div>";
    if (e.output) extraHtml += '<div><span class="ex-label">Sample output</span><pre>' + highlight(e.output, query) + "</pre></div>";
    if (e.notes) extraHtml += '<div><span class="ex-label">Notes</span><div class="ex-val">' + highlight(e.notes, query) + "</div></div>";

    return (
      '<article class="entry-card' + (expanded ? " expanded" : "") + '" data-id="' + e.id + '" tabindex="0">' +
        '<div class="entry-head">' +
          '<h3 class="entry-title">' + highlight(e.title, query) + "</h3>" +
          '<div class="entry-badges">' + difficultyBadge(e.difficulty) + "</div>" +
        "</div>" +
        '<div class="code-block' + (codeMulti ? "" : " single-line") + '">' +
          "<code>" + highlight(e.code, query) + "</code>" +
          '<button class="copy-btn" data-copy-id="' + e.id + '" title="Copy to clipboard" aria-label="Copy command">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>' +
          "</button>" +
        "</div>" +
        '<p class="entry-desc">' + highlight(e.description, query) + "</p>" +
        (hasExtra ? '<div class="entry-extra">' + extraHtml + "</div>" : "") +
        '<div class="entry-tags">' + tagsHtml + "</div>" +
        '<div class="entry-foot">' +
          '<span class="tag" style="text-transform:uppercase;letter-spacing:.05em;">' + escapeHtml(CAT_BY_KEY[e.category] ? CAT_BY_KEY[e.category].short : e.category) + "</span>" +
          '<div class="entry-actions">' +
            '<button class="fav-btn' + (fav ? " active" : "") + '" data-fav-id="' + e.id + '" title="' + (fav ? "Remove from favorites" : "Add to favorites") + '" aria-label="Toggle favorite">' +
              '<svg viewBox="0 0 24 24" fill="' + (fav ? "currentColor" : "none") + '" stroke="currentColor" stroke-width="2"><path d="M12 17.3 6.2 21l1.6-6.9L2 9.2l7-.6L12 2l3 6.6 7 .6-5.8 4.9 1.6 6.9z"/></svg>' +
            "</button>" +
            (hasExtra ?
              '<button class="expand-btn" data-expand-id="' + e.id + '" title="Expand details" aria-label="Expand details">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M6 9l6 6 6-6"/></svg>' +
              "</button>" : "") +
          "</div>" +
        "</div>" +
      "</article>"
    );
  }

  function bindCardEvents(root) {
    qsa(".copy-btn", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var e = entryById(btn.getAttribute("data-copy-id"));
        if (e) { copyText(e.code, btn); pushRecent(e.id); }
      });
    });
    qsa(".fav-btn", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-fav-id");
        toggleFav(id);
        var nowFav = isFav(id);
        btn.classList.toggle("active", nowFav);
        btn.querySelector("svg").setAttribute("fill", nowFav ? "currentColor" : "none");
        toast(nowFav ? "Added to favorites" : "Removed from favorites");
        if (location.hash.indexOf("/favorites") === 1 && !nowFav) {
          btn.closest(".entry-card").remove();
        }
      });
    });
    qsa(".expand-btn", root).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = btn.getAttribute("data-expand-id");
        var card = btn.closest(".entry-card");
        var willExpand = !card.classList.contains("expanded");
        card.classList.toggle("expanded", willExpand);
        if (willExpand) { expandedIds.add(id); pushRecent(id); } else { expandedIds.delete(id); }
      });
    });
    qsa(".entry-card", root).forEach(function (card) {
      card.addEventListener("mouseenter", function () { hoverCardId = card.getAttribute("data-id"); });
      card.addEventListener("mouseleave", function () { if (hoverCardId === card.getAttribute("data-id")) hoverCardId = null; });
      card.addEventListener("focusin", function () { hoverCardId = card.getAttribute("data-id"); });
    });
  }

  /* ---------------------------------------------------------
     Filters bar (shared by category + favorites + search)
  --------------------------------------------------------- */
  function topTags(list, n) {
    var counts = {};
    list.forEach(function (e) { (e.tags || []).forEach(function (t) { counts[t] = (counts[t] || 0) + 1; }); });
    return Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, n);
  }

  function renderFiltersBar(opts) {
    // opts: { list, placeholder }
    var tags = topTags(opts.list, 8);
    var chipHtml = '<button class="chip active" data-diff="All">All</button>' +
      ["Easy", "Medium", "Hard"].map(function (d) { return '<button class="chip" data-diff="' + d + '">' + d + "</button>"; }).join("");
    var tagChipHtml = tags.map(function (t) { return '<button class="chip" data-tag="' + escapeHtml(t) + '">' + escapeHtml(t) + "</button>"; }).join("");
    return (
      '<div class="filters-bar">' +
        '<div class="search-box">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
          '<input type="text" id="filter-search" placeholder="' + escapeHtml(opts.placeholder || "Search…") + '" autocomplete="off">' +
        "</div>" +
        '<div class="chip-group" id="diff-chips">' + chipHtml + "</div>" +
        (tags.length ? '<div class="chip-group" id="tag-chips">' + tagChipHtml + "</div>" : "") +
        '<span class="result-count" id="result-count"></span>' +
      "</div>"
    );
  }

  function attachFilterBehavior(container, sourceList, renderGrid) {
    var state = { q: "", diff: "All", tag: null };
    function apply() {
      var q = state.q.trim().toLowerCase();
      var filtered = sourceList.filter(function (e) {
        if (state.diff !== "All" && e.difficulty !== state.diff) return false;
        if (state.tag && (e.tags || []).indexOf(state.tag) === -1) return false;
        if (!q) return true;
        var hay = (e.title + " " + e.code + " " + e.description + " " + (e.tags || []).join(" ")).toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      renderGrid(filtered, state.q.trim());
      var rc = qs("#result-count", container);
      if (rc) rc.textContent = filtered.length + " result" + (filtered.length === 1 ? "" : "s");
    }
    var input = qs("#filter-search", container);
    if (input) input.addEventListener("input", debounce(function () { state.q = input.value; apply(); }, 120));
    qsa("#diff-chips .chip", container).forEach(function (chip) {
      chip.addEventListener("click", function () {
        qsa("#diff-chips .chip", container).forEach(function (c) { c.classList.remove("active"); });
        chip.classList.add("active");
        state.diff = chip.getAttribute("data-diff");
        apply();
      });
    });
    qsa("#tag-chips .chip", container).forEach(function (chip) {
      chip.addEventListener("click", function () {
        var t = chip.getAttribute("data-tag");
        var already = chip.classList.contains("active");
        qsa("#tag-chips .chip", container).forEach(function (c) { c.classList.remove("active"); });
        if (already) { state.tag = null; } else { chip.classList.add("active"); state.tag = t; }
        apply();
      });
    });
    apply();
    return input;
  }

  /* ---------------------------------------------------------
     Views
  --------------------------------------------------------- */
  function emptyState(msg, sub) {
    return '<div class="empty-state">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
      "<h3>" + escapeHtml(msg) + "</h3><p>" + escapeHtml(sub || "") + "</p></div>";
  }

  function viewHome() {
    var totalCount = STORE.all.length;
    var statCards = CATEGORIES.map(function (c) {
      var n = (STORE.byCategory[c.key] || []).length;
      return '<a class="stat-card" href="#/category/' + c.key + '" data-count="' + n + '">' +
        '<div class="stat-icon">' + icon(c.key) + "</div>" +
        '<div class="stat-num" data-target="' + n + '">0</div>' +
        '<div class="stat-label">' + escapeHtml(c.label) + "</div>" +
      "</a>";
    }).join("");

    var catCards = CATEGORIES.map(function (c) {
      var n = (STORE.byCategory[c.key] || []).length;
      return '<a class="cat-card" href="#/category/' + c.key + '">' +
        '<div class="cat-icon">' + icon(c.key) + "</div>" +
        "<h3>" + escapeHtml(c.label) + "</h3>" +
        "<p>" + escapeHtml(c.desc) + "</p>" +
        '<span class="cat-count">' + n + " entries</span>" +
      "</a>";
    }).join("");

    var cotd = totalCount ? STORE.all[dayIndex(totalCount)] : null;
    var recentEntries = recentlyViewed.map(entryById).filter(Boolean).slice(0, 4);

    var html =
      '<section class="hero">' +
        '<div class="container">' +
          '<span class="hero-badge"><span class="dot"></span> 100% Offline &middot; No login &middot; No tracking</span>' +
          "<h1>Cyber <span class=\"glow\">Cheat Sheet</span></h1>" +
          '<p class="lede">The ultimate offline reference for SOC analysts, ethical hackers, blue teams and cybersecurity students — commands, queries, filters and detection rules in one searchable dashboard.</p>' +
          '<div class="hero-actions">' +
            '<a class="btn btn-primary" href="#/category/linux">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" width="18" height="18"><path d="M5 12h14M13 6l6 6-6 6"/></svg> Browse Commands' +
            "</a>" +
            '<a class="btn btn-secondary" href="#/search" id="hero-search-cta">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" width="18" height="18"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg> Search Database' +
            "</a>" +
          "</div>" +

          '<div class="search-wrap">' +
            '<div class="search-box">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
              '<input type="text" id="home-search" placeholder="Search everything — try &quot;ping&quot;, &quot;4625&quot;, or &quot;persistence&quot;" autocomplete="off">' +
              '<span class="kbd">/</span>' +
            "</div>" +
            '<div class="search-suggestions" id="home-suggestions"></div>' +
          "</div>" +

          '<div class="stats-grid" id="stats-grid">' + statCards + "</div>" +
        "</div>" +
      "</section>" +

      '<section class="section">' +
        '<div class="container">' +
          '<div class="section-head"><div><span class="eyebrow">Reference library</span><h2>Browse by category</h2><p>Nine focused cheat sheets covering the full incident-response and offensive-security toolchain.</p></div></div>' +
          '<div class="cat-grid">' + catCards + "</div>" +
        "</div>" +
      "</section>" +

      '<section class="section" style="padding-top:0;">' +
        '<div class="container">' +
          '<div class="feature-row">' +
            (cotd ?
              '<div class="cotd-card">' +
                '<div class="cotd-top"><span class="eyebrow">Command of the day</span>' +
                '<button class="btn btn-ghost btn-sm" id="cotd-refresh">' +
                  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/></svg> Shuffle' +
                "</button></div>" +
                '<div id="cotd-slot">' + cardHTML(cotd, "") + "</div>" +
              "</div>" :
              ""
            ) +
            '<div>' +
              '<div class="cotd-card" style="margin-bottom:16px;">' +
                '<div class="cotd-top"><span class="eyebrow">Random tip</span>' +
                '<button class="btn btn-ghost btn-sm" id="tip-refresh"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/></svg> New tip</button></div>' +
                '<p class="entry-desc" id="tip-slot" style="font-size:.92rem;">' + escapeHtml(TIPS[dayIndex(TIPS.length)]) + "</p>" +
              "</div>" +
              (recentEntries.length ?
                '<div class="cotd-card"><div class="cotd-top"><span class="eyebrow">Recently viewed</span></div>' +
                '<div style="display:flex;flex-direction:column;gap:8px;">' +
                recentEntries.map(function (e) {
                  return '<a href="#/category/' + e.category + '" style="display:flex;justify-content:space-between;gap:10px;padding:8px 10px;border-radius:8px;background:rgba(148,163,184,0.05);font-size:.85rem;">' +
                    '<span style="font-family:var(--mono);color:var(--text);">' + escapeHtml(e.title) + "</span>" +
                    '<span class="tag">' + escapeHtml(CAT_BY_KEY[e.category].short) + "</span></a>";
                }).join("") +
                "</div></div>" :
                '<div class="cotd-card"><div class="cotd-top"><span class="eyebrow">Recently viewed</span></div>' +
                '<p class="entry-desc" style="font-size:.85rem;">Items you expand or copy will show up here for quick access.</p></div>'
              ) +
            "</div>" +
          "</div>" +
        "</div>" +
      "</section>";

    return html;
  }

  function afterRenderHome() {
    animateCounters();
    var input = qs("#home-search");
    var box = qs("#home-suggestions");
    function runSuggest() {
      var q = input.value.trim().toLowerCase();
      if (!q) { box.classList.remove("open"); box.innerHTML = ""; return; }
      var results = STORE.all.filter(function (e) {
        return (e.title + " " + e.code + " " + e.description).toLowerCase().indexOf(q) !== -1;
      }).slice(0, 8);
      if (!results.length) { box.classList.remove("open"); box.innerHTML = ""; return; }
      box.innerHTML = results.map(function (e) {
        return '<div class="suggestion-item" data-id="' + e.id + '">' +
          '<span class="s-title">' + highlight(e.title, q) + "</span>" +
          '<span class="s-cat">' + escapeHtml(CAT_BY_KEY[e.category].short) + "</span></div>";
      }).join("");
      box.classList.add("open");
      qsa(".suggestion-item", box).forEach(function (item) {
        item.addEventListener("click", function () {
          location.hash = "#/search/" + encodeURIComponent(input.value.trim());
        });
      });
    }
    input.addEventListener("input", debounce(runSuggest, 100));
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && input.value.trim()) {
        location.hash = "#/search/" + encodeURIComponent(input.value.trim());
      }
    });
    document.addEventListener("click", function (e) {
      if (box && !box.contains(e.target) && e.target !== input) box.classList.remove("open");
    });

    var cotdBtn = qs("#cotd-refresh");
    if (cotdBtn) cotdBtn.addEventListener("click", function () {
      var pick = STORE.all[Math.floor(Math.random() * STORE.all.length)];
      qs("#cotd-slot").innerHTML = cardHTML(pick, "");
      bindCardEvents(qs("#cotd-slot"));
    });
    var tipBtn = qs("#tip-refresh");
    if (tipBtn) tipBtn.addEventListener("click", function () {
      qs("#tip-slot").textContent = TIPS[Math.floor(Math.random() * TIPS.length)];
    });

    bindCardEvents(qs("#cotd-slot"));
  }

  function animateCounters() {
    qsa(".stat-num").forEach(function (el) {
      var target = parseInt(el.getAttribute("data-target"), 10) || 0;
      var start = 0, duration = 700, startTime = null;
      function step(ts) {
        if (!startTime) startTime = ts;
        var progress = Math.min((ts - startTime) / duration, 1);
        el.textContent = Math.floor(progress * target);
        if (progress < 1) requestAnimationFrame(step); else el.textContent = target;
      }
      requestAnimationFrame(step);
    });
  }

  function viewCategory(key) {
    var cat = CAT_BY_KEY[key];
    if (!cat) return "<div class=\"container section\">" + emptyState("Unknown category") + "</div>";
    var list = STORE.byCategory[key] || [];
    var html =
      '<div class="container section">' +
        '<div class="breadcrumbs"><a href="#/">Home</a><span class="sep">/</span><span class="current">' + escapeHtml(cat.label) + "</span></div>" +
        '<div class="section-head"><div><span class="eyebrow">' + list.length + " entries</span><h2>" + icon(key, 'width="24" height="24" style="vertical-align:-4px;margin-right:8px;color:var(--accent);"') + escapeHtml(cat.label) + "</h2><p>" + escapeHtml(cat.desc) + "</p></div>" +
          '<a class="btn btn-ghost btn-sm" id="print-btn"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v8H6z"/></svg> Print</a>' +
        "</div>" +
        renderFiltersBar({ list: list, placeholder: "Search " + cat.label.toLowerCase() + "…" }) +
        '<div class="cards-grid" id="cards-grid"></div>' +
      "</div>";
    return html;
  }

  function afterRenderCategory(key) {
    var list = STORE.byCategory[key] || [];
    var container = document;
    var grid = qs("#cards-grid");
    function renderGrid(items, q) {
      if (!items.length) {
        grid.innerHTML = emptyState("No matches found", "Try a different search term or clear the filters.");
        return;
      }
      grid.innerHTML = items.map(function (e) { return cardHTML(e, q); }).join("");
      bindCardEvents(grid);
    }
    attachFilterBehavior(document, list, renderGrid);
    var printBtn = qs("#print-btn");
    if (printBtn) printBtn.addEventListener("click", function () { window.print(); });
  }

  function viewFavorites() {
    var list = favorites.map(entryById).filter(Boolean);
    var html =
      '<div class="container section">' +
        '<div class="breadcrumbs"><a href="#/">Home</a><span class="sep">/</span><span class="current">Favorites</span></div>' +
        '<div class="section-head"><div><span class="eyebrow">' + list.length + " saved</span><h2>Your favorites</h2><p>Starred commands, queries and rules, stored locally in your browser.</p></div>" +
          '<div style="display:flex;gap:8px;">' +
            '<button class="btn btn-secondary btn-sm" id="export-fav">Export JSON</button>' +
            '<label class="btn btn-secondary btn-sm" style="cursor:pointer;">Import JSON<input type="file" id="import-fav" accept="application/json" style="display:none;"></label>' +
          "</div>" +
        "</div>" +
        (list.length ? renderFiltersBar({ list: list, placeholder: "Search favorites…" }) : "") +
        '<div class="cards-grid" id="cards-grid">' +
          (list.length ? "" : emptyState("No favorites yet", "Click the star on any card to save it here.")) +
        "</div>" +
      "</div>";
    return html;
  }

  function afterRenderFavorites() {
    var list = favorites.map(entryById).filter(Boolean);
    var grid = qs("#cards-grid");
    if (list.length) {
      function renderGrid(items, q) {
        if (!items.length) { grid.innerHTML = emptyState("No matches found", "Try a different search term or clear the filters."); return; }
        grid.innerHTML = items.map(function (e) { return cardHTML(e, q); }).join("");
        bindCardEvents(grid);
      }
      attachFilterBehavior(document, list, renderGrid);
    }
    var exportBtn = qs("#export-fav");
    if (exportBtn) exportBtn.addEventListener("click", function () {
      var blob = new Blob([JSON.stringify(favorites, null, 2)], { type: "application/json" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "cyber-cheat-sheet-favorites.json";
      a.click();
      toast("Favorites exported");
    });
    var importInput = qs("#import-fav");
    if (importInput) importInput.addEventListener("change", function () {
      var file = importInput.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        try {
          var ids = JSON.parse(reader.result);
          if (!Array.isArray(ids)) throw new Error("bad format");
          ids.forEach(function (id) { if (favorites.indexOf(id) === -1) favorites.push(id); });
          persist("ccs_favorites", favorites);
          toast("Favorites imported");
          render();
        } catch (e) { toast("Import failed — invalid file"); }
      };
      reader.readAsText(file);
    });
  }

  function viewSearch(initialQuery) {
    var html =
      '<div class="container section">' +
        '<div class="breadcrumbs"><a href="#/">Home</a><span class="sep">/</span><span class="current">Search</span></div>' +
        '<div class="section-head"><div><span class="eyebrow">Global search</span><h2>Search the entire database</h2><p>Searches titles, commands, descriptions and tags across all nine categories at once.</p></div></div>' +
        '<div class="filters-bar">' +
          '<div class="search-box" style="flex:1;">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>' +
            '<input type="text" id="global-search" placeholder="Search everything…" autocomplete="off" value="' + escapeHtml(initialQuery || "") + '">' +
          "</div>" +
          '<div class="chip-group" id="cat-chips">' +
            '<button class="chip active" data-cat="All">All</button>' +
            CATEGORIES.map(function (c) { return '<button class="chip" data-cat="' + c.key + '">' + c.short + "</button>"; }).join("") +
          "</div>" +
          '<span class="result-count" id="result-count"></span>' +
        "</div>" +
        '<div class="cards-grid" id="cards-grid"></div>' +
      "</div>";
    return html;
  }

  function afterRenderSearch(initialQuery) {
    var input = qs("#global-search");
    var grid = qs("#cards-grid");
    var state = { cat: "All" };
    function run() {
      var q = input.value.trim().toLowerCase();
      var list = STORE.all.filter(function (e) {
        if (state.cat !== "All" && e.category !== state.cat) return false;
        if (!q) return false;
        var hay = (e.title + " " + e.code + " " + e.description + " " + (e.tags || []).join(" ")).toLowerCase();
        return hay.indexOf(q) !== -1;
      });
      qs("#result-count").textContent = q ? (list.length + " result" + (list.length === 1 ? "" : "s")) : "Start typing to search";
      if (!q) { grid.innerHTML = emptyState("Search across everything", "Try a command name, an event ID, or a technique like \u201cpersistence\u201d."); return; }
      if (!list.length) { grid.innerHTML = emptyState("No matches found", "Try a broader term or clear the category filter."); return; }
      grid.innerHTML = list.map(function (e) { return cardHTML(e, input.value.trim()); }).join("");
      bindCardEvents(grid);
    }
    input.addEventListener("input", debounce(run, 120));
    qsa("#cat-chips .chip").forEach(function (chip) {
      chip.addEventListener("click", function () {
        qsa("#cat-chips .chip").forEach(function (c) { c.classList.remove("active"); });
        chip.classList.add("active");
        state.cat = chip.getAttribute("data-cat");
        run();
      });
    });
    if (initialQuery) run(); else input.focus();
  }

  function viewAbout() {
    return (
      '<div class="container section">' +
        '<div class="breadcrumbs"><a href="#/">Home</a><span class="sep">/</span><span class="current">About</span></div>' +
        '<span class="eyebrow">About this project</span>' +
        "<h2 style=\"font-size:2rem;margin:0 0 24px;\">About Cyber Cheat Sheet</h2>" +
        '<div class="prose">' +
          "<h2>Purpose</h2>" +
          "<p>Cyber Cheat Sheet is a single-page, offline-first reference built for SOC analysts, incident responders, ethical hackers, and students who need fast, reliable access to the commands, queries, filters and detection rules they use every day — without waiting on a network connection or a login screen.</p>" +
          "<h2>How to use it</h2>" +
          "<ul>" +
            "<li>Use the global search on the home page or the <a href=\"#/search\">Search page</a> to look across every category at once.</li>" +
            "<li>Open any category from the navigation bar to browse, filter by difficulty or tag, and search within that topic.</li>" +
            "<li>Click the copy icon on any card to copy the command, query, filter or rule to your clipboard.</li>" +
            "<li>Star a card to save it to <a href=\"#/favorites\">Favorites</a>, which is stored locally in your browser via localStorage — nothing is sent anywhere.</li>" +
            "<li>Press <span class=\"kbd\">/</span> to jump to the nearest search box, and <span class=\"kbd\">Esc</span> to collapse an expanded card.</li>" +
          "</ul>" +
          "<h2>Data &amp; storage</h2>" +
          "<p>All reference data ships as static JSON files in the <code>/data</code> folder. Favorites and recently-viewed items are stored only in your browser's localStorage — there is no backend, no database, no account, and no analytics.</p>" +
          "<h2>Disclaimer</h2>" +
          '<div class="disclaimer-box">This site is provided for educational and authorized-use reference purposes only. Several tools referenced here (e.g. Nmap, network scanners, credential and packet-analysis utilities) can be misused. Only use them against systems and networks you own or are explicitly authorized to test. The maintainers of this page are not responsible for misuse.</div>' +
        "</div>" +
      "</div>"
    );
  }

  /* ---------------------------------------------------------
     Router
  --------------------------------------------------------- */
  function parseHash() {
    var h = location.hash.replace(/^#/, "") || "/";
    var parts = h.split("/").filter(Boolean);
    return parts;
  }

  function render() {
    var parts = parseHash();
    var app = qs("#app");
    var route = "/";
    var html = "";

    if (parts.length === 0) {
      route = "/";
      html = STORE.loaded ? viewHome() : "";
    } else if (parts[0] === "category" && parts[1]) {
      route = "/category/" + parts[1];
      html = viewCategory(parts[1]);
    } else if (parts[0] === "favorites") {
      route = "/favorites";
      html = viewFavorites();
    } else if (parts[0] === "about") {
      route = "/about";
      html = viewAbout();
    } else if (parts[0] === "search") {
      route = "/search";
      html = viewSearch(parts[1] ? decodeURIComponent(parts[1]) : "");
    } else {
      route = "/";
      html = viewHome();
    }

    app.innerHTML = html;

    if (parts.length === 0) { afterRenderHome(); }
    else if (parts[0] === "category" && parts[1]) { afterRenderCategory(parts[1]); }
    else if (parts[0] === "favorites") { afterRenderFavorites(); }
    else if (parts[0] === "search") { afterRenderSearch(parts[1] ? decodeURIComponent(parts[1]) : ""); }

    setActiveNav(route);
    window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
    closeDrawer();
  }

  function setActiveNav(route) {
    var normalized = route.split("/").slice(0, 3).join("/");
    qsa(".nav-links a, .mobile-drawer a").forEach(function (a) {
      var r = a.getAttribute("data-route");
      a.classList.toggle("active", r === route || (r !== "/" && route.indexOf(r) === 0));
    });
  }

  /* ---------------------------------------------------------
     Mobile drawer
  --------------------------------------------------------- */
  function buildDrawer() {
    var drawer = qs("#mobile-drawer");
    var links = [
      { href: "#/", label: "Home", route: "/" },
      { href: "#/category/linux", label: "Linux", route: "/category/linux" },
      { href: "#/category/windows", label: "Windows", route: "/category/windows" },
      { href: "#/category/powershell", label: "PowerShell", route: "/category/powershell" },
      { href: "#/category/nmap", label: "Nmap", route: "/category/nmap" },
      { href: "#/category/wireshark", label: "Wireshark", route: "/category/wireshark" },
      { href: "#/category/splunk", label: "Splunk", route: "/category/splunk" },
      { href: "#/category/kql", label: "KQL", route: "/category/kql" },
      { href: "#/category/sigma", label: "Sigma", route: "/category/sigma" },
      { href: "#/category/yara", label: "YARA", route: "/category/yara" },
      { href: "#/favorites", label: "Favorites", route: "/favorites" },
      { href: "#/about", label: "About", route: "/about" }
    ];
    drawer.innerHTML = links.map(function (l) {
      return '<a href="' + l.href + '" data-route="' + l.route + '">' + l.label + "</a>";
    }).join("");
  }
  function openDrawer() {
    qs("#mobile-drawer").classList.add("open");
    qs("#drawer-backdrop").classList.add("open");
    qs("#nav-toggle").setAttribute("aria-expanded", "true");
  }
  function closeDrawer() {
    var d = qs("#mobile-drawer"), b = qs("#drawer-backdrop"), t = qs("#nav-toggle");
    if (d) d.classList.remove("open");
    if (b) b.classList.remove("open");
    if (t) t.setAttribute("aria-expanded", "false");
  }

  /* ---------------------------------------------------------
     Global listeners: keyboard shortcuts, scroll-to-top, print
  --------------------------------------------------------- */
  function setupGlobalUI() {
    qs("#nav-toggle").addEventListener("click", function () {
      var isOpen = qs("#mobile-drawer").classList.contains("open");
      if (isOpen) closeDrawer(); else openDrawer();
    });
    qs("#drawer-backdrop").addEventListener("click", closeDrawer);
    qs("#favorites-nav-btn").addEventListener("click", function () { location.hash = "#/favorites"; });
    qs("#print-link").addEventListener("click", function (e) { e.preventDefault(); window.print(); });
    qs("#foot-year").textContent = new Date().getFullYear();

    var scrollBtn = qs("#scroll-top");
    window.addEventListener("scroll", debounce(function () {
      scrollBtn.classList.toggle("visible", window.scrollY > 480);
    }, 50));
    scrollBtn.addEventListener("click", function () { window.scrollTo({ top: 0, behavior: "smooth" }); });

    document.addEventListener("keydown", function (e) {
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
        e.preventDefault();
        var target = qs("#home-search") || qs("#filter-search") || qs("#global-search");
        if (target) target.focus();
      } else if (e.key === "Escape") {
        if (qs("#mobile-drawer.open")) closeDrawer();
        qsa(".entry-card.expanded").forEach(function (c) { c.classList.remove("expanded"); expandedIds.delete(c.getAttribute("data-id")); });
        var sug = qs("#home-suggestions");
        if (sug) sug.classList.remove("open");
        if (document.activeElement) document.activeElement.blur();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "c") {
        var sel = window.getSelection ? window.getSelection().toString() : "";
        if (!sel && hoverCardId) {
          var entry = entryById(hoverCardId);
          if (entry) { e.preventDefault(); copyText(entry.code, qs('.copy-btn[data-copy-id="' + hoverCardId + '"]')); pushRecent(entry.id); }
        }
      }
    });
  }

  /* ---------------------------------------------------------
     Service worker (PWA)
  --------------------------------------------------------- */
  function registerServiceWorker() {
    if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) {
      navigator.serviceWorker.register("service-worker.js").catch(function () { /* offline registration best-effort */ });
    }
  }

  /* ---------------------------------------------------------
     Boot
  --------------------------------------------------------- */
  document.addEventListener("DOMContentLoaded", function () {
    buildDrawer();
    setupGlobalUI();
    registerServiceWorker();

    loadData().then(function () {
      qs("#loading-screen").classList.add("hidden");
      if (STORE.loadError) {
        toast("Could not load data files — serve this site over http(s) (see README)");
      }
      render();
    });

    window.addEventListener("hashchange", render);
  });
})();
