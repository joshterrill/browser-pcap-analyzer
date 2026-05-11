(() => {
  "use strict";

  const TABLE_WINDOW_SIZE = 5000;
  const TABLE_WINDOW_BUFFER = 1000;
  const PACKET_ROW_HEIGHT = 36;
  const THEME_KEY = "web-pcap-theme";
  const CHART_COLORS = ["#246bfe", "#16805d", "#a36500", "#be3144", "#7257c5", "#087389", "#6b7280"];
  const TEXT_DECODER = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { fatal: false }) : null;

  const state = {
    fileName: "",
    packets: [],
    filteredPackets: [],
    analysis: null,
    selectedPacket: null,
    sortKey: "index",
    sortDir: 1,
    detailView: "decoded",
    tableWindowStart: 0,
    isRenderingPacketRows: false
  };

  const els = {};

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    cacheElements();
    initTheme();
    bindEvents();
    renderEmptyDetail();
  }

  function cacheElements() {
    Object.assign(els, {
      fileInput: document.getElementById("fileInput"),
      status: document.getElementById("status"),
      workspace: document.getElementById("workspace"),
      exportCsv: document.getElementById("exportCsv"),
      clearCapture: document.getElementById("clearCapture"),
      themeToggle: document.getElementById("themeToggle"),
      statPackets: document.getElementById("statPackets"),
      statBytes: document.getElementById("statBytes"),
      statDuration: document.getElementById("statDuration"),
      statProtocols: document.getElementById("statProtocols"),
      statName: document.getElementById("statName"),
      tabs: Array.from(document.querySelectorAll(".tab")),
      panels: {
        overview: document.getElementById("overviewPanel"),
        packets: document.getElementById("packetsPanel"),
        conversations: document.getElementById("conversationsPanel"),
        endpoints: document.getElementById("endpointsPanel"),
        artifacts: document.getElementById("artifactsPanel")
      },
      filterInput: document.getElementById("filterInput"),
      filterStatus: document.getElementById("filterStatus"),
      quickFilters: Array.from(document.querySelectorAll("[data-filter]")),
      packetList: document.querySelector(".packet-list"),
      packetRows: document.getElementById("packetRows"),
      packetTable: document.getElementById("packetTable"),
      decodedDetail: document.getElementById("decodedDetail"),
      payloadDetail: document.getElementById("payloadDetail"),
      hexDetail: document.getElementById("hexDetail"),
      detailTabs: Array.from(document.querySelectorAll(".detail-tab")),
      protocolChart: document.getElementById("protocolChart"),
      timelineChart: document.getElementById("timelineChart"),
      sizeChart: document.getElementById("sizeChart"),
      protocolCountLabel: document.getElementById("protocolCountLabel"),
      timelineLabel: document.getElementById("timelineLabel"),
      topTalkers: document.getElementById("topTalkers"),
      conversationRows: document.getElementById("conversationRows"),
      conversationCount: document.getElementById("conversationCount"),
      endpointRows: document.getElementById("endpointRows"),
      endpointCount: document.getElementById("endpointCount"),
      dnsRows: document.getElementById("dnsRows"),
      dnsCount: document.getElementById("dnsCount"),
      httpRows: document.getElementById("httpRows"),
      httpCount: document.getElementById("httpCount")
    });
  }

  function bindEvents() {
    els.fileInput.addEventListener("change", event => {
      const file = event.target.files && event.target.files[0];
      if (file) {
        loadFile(file);
      }
      event.target.value = "";
    });

    els.clearCapture.addEventListener("click", clearCapture);
    els.exportCsv.addEventListener("click", exportFilteredCsv);
    els.themeToggle.addEventListener("click", toggleTheme);

    els.tabs.forEach(tab => {
      tab.addEventListener("click", () => activateTab(tab.dataset.tab));
    });

    els.detailTabs.forEach(tab => {
      tab.addEventListener("click", () => activateDetailTab(tab.dataset.detail));
    });

    els.filterInput.addEventListener("input", debounce(() => {
      applyFilter();
      renderPacketTable();
    }, 80));

    els.quickFilters.forEach(button => {
      button.addEventListener("click", () => {
        els.filterInput.value = button.dataset.filter;
        applyFilter();
        renderPacketTable();
      });
    });

    els.packetTable.querySelector("thead").addEventListener("click", event => {
      const th = event.target.closest("th[data-sort]");
      if (!th) {
        return;
      }
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortDir *= -1;
      } else {
        state.sortKey = key;
        state.sortDir = 1;
      }
      sortFilteredPackets();
      state.tableWindowStart = 0;
      renderPacketTable();
    });

    els.packetRows.addEventListener("click", event => {
      const row = event.target.closest("tr[data-index]");
      if (!row) {
        return;
      }
      const packet = state.packets[Number(row.dataset.index) - 1];
      if (packet) {
        state.selectedPacket = packet;
        renderPacketTableSelection();
        renderPacketDetails(packet);
      }
    });

    els.packetList.addEventListener("scroll", () => {
      updatePacketWindowForScroll();
    });

    window.addEventListener("resize", debounce(() => {
      if (state.analysis) {
        renderCharts();
      }
    }, 150));
  }

  function initTheme() {
    const savedTheme = safeStorageGet(THEME_KEY);
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    setTheme(savedTheme || (prefersDark ? "dark" : "light"), false);
  }

  function toggleTheme() {
    const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(nextTheme, true);
    if (state.analysis) {
      renderCharts();
    }
  }

  function setTheme(theme, persist) {
    const normalized = theme === "dark" ? "dark" : "light";
    const isDark = normalized === "dark";
    document.documentElement.dataset.theme = normalized;
    if (els.themeToggle) {
      const label = isDark ? "Switch to light mode" : "Switch to dark mode";
      els.themeToggle.setAttribute("aria-label", label);
      els.themeToggle.setAttribute("title", label);
    }
    if (persist) {
      safeStorageSet(THEME_KEY, normalized);
    }
  }

  function safeStorageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  function safeStorageSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // Ignore private browsing or local file storage restrictions.
    }
  }

  async function loadFile(file) {
    setStatus(`Loading ${file.name} (${formatBytes(file.size)})...`);
    els.workspace.classList.add("is-hidden");
    try {
      await nextFrame();
      const buffer = await file.arrayBuffer();
      const result = parseCapture(buffer, file.name);
      state.fileName = file.name;
      state.packets = result.packets;
      state.filteredPackets = result.packets.slice();
      state.analysis = buildAnalysis(result.packets);
      state.selectedPacket = result.packets[0] || null;
      state.sortKey = "index";
      state.sortDir = 1;
      els.filterInput.value = "";
      renderAll(result);
      setStatus(`${file.name}: ${formatNumber(result.packets.length)} packets parsed${result.warnings.length ? `, ${result.warnings.length} warning(s)` : ""}.`);
    } catch (error) {
      console.error(error);
      clearStateOnly();
      els.workspace.classList.add("is-hidden");
      setStatus(`Could not parse capture: ${error.message}`, true);
    }
  }

  function renderAll(result) {
    els.workspace.classList.remove("is-hidden");
    els.exportCsv.disabled = result.packets.length === 0;
    els.clearCapture.disabled = false;
    renderStats(result);
    applyFilter();
    renderPacketTable();
    renderPacketDetails(state.selectedPacket);
    renderOverview();
    renderConversations();
    renderEndpoints();
    renderArtifacts();
  }

  function renderStats(result) {
    const analysis = state.analysis;
    els.statPackets.textContent = formatNumber(result.packets.length);
    els.statBytes.textContent = formatBytes(analysis.totalBytes);
    els.statDuration.textContent = formatDuration(analysis.duration);
    els.statProtocols.textContent = formatNumber(analysis.protocolCounts.size);
    els.statName.textContent = state.fileName || "-";
  }

  function renderOverview() {
    const protocolCount = state.analysis.protocolCounts.size;
    els.protocolCountLabel.textContent = `${formatNumber(protocolCount)} protocol${protocolCount === 1 ? "" : "s"}`;
    els.timelineLabel.textContent = state.analysis.timeline.startTs != null && state.analysis.timeline.endTs != null
      ? `${formatLocalTime(state.analysis.timeline.startTs)} - ${formatLocalTime(state.analysis.timeline.endTs)}`
      : (state.analysis.duration > 0 ? formatDuration(state.analysis.duration) : "single timestamp");
    renderTopTalkers();
    renderCharts();
  }

  function renderCharts() {
    setOverviewChartHeights();
    drawProtocolChart(els.protocolChart, state.analysis.protocolCounts);
    drawTimelineChart(els.timelineChart, state.analysis.timeline);
    drawSizeChart(els.sizeChart, state.analysis.sizeBuckets);
  }

  function setOverviewChartHeights() {
    const protocolRows = Math.max(1, Math.min(8, state.analysis.protocolCounts.size || 1));
    const height = Math.max(112, Math.min(224, 42 + protocolRows * 23));
    [els.protocolChart, els.timelineChart, els.sizeChart].forEach(canvas => {
      canvas.style.setProperty("--chart-height", `${height}px`);
    });
  }

  function renderTopTalkers() {
    const rows = state.analysis.endpoints.slice(0, 8);
    if (!rows.length) {
      els.topTalkers.innerHTML = `<div class="empty-table">No endpoints decoded.</div>`;
      return;
    }
    const maxBytes = Math.max(...rows.map(row => row.bytes), 1);
    els.topTalkers.innerHTML = rows.map((row, index) => {
      const width = Math.max(3, (row.bytes / maxBytes) * 100);
      const color = CHART_COLORS[index % CHART_COLORS.length];
      return `
        <div class="rank-row">
          <div class="rank-label mono" title="${escapeHtml(row.address)}">${escapeHtml(row.address)}</div>
          <div class="rank-value">${formatBytes(row.bytes)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${width.toFixed(1)}%;background:${color}"></div></div>
        </div>
      `;
    }).join("");
  }

  function renderConversations() {
    const rows = state.analysis.conversations;
    els.conversationCount.textContent = `${formatNumber(rows.length)} conversation${rows.length === 1 ? "" : "s"}`;
    if (!rows.length) {
      els.conversationRows.innerHTML = `<tr><td colspan="7" class="empty-table">No conversations decoded.</td></tr>`;
      return;
    }
    els.conversationRows.innerHTML = rows.slice(0, 1000).map(row => `
      <tr>
        <td>${escapeHtml(row.protocol)}</td>
        <td class="mono">${escapeHtml(row.a)}</td>
        <td class="mono">${escapeHtml(row.b)}</td>
        <td class="mono">${formatNumber(row.packets)}</td>
        <td class="mono">${formatBytes(row.bytes)}</td>
        <td class="mono">${formatDuration(row.firstRel)}</td>
        <td class="mono">${formatDuration(row.lastRel)}</td>
      </tr>
    `).join("");
  }

  function renderEndpoints() {
    const rows = state.analysis.endpoints;
    els.endpointCount.textContent = `${formatNumber(rows.length)} endpoint${rows.length === 1 ? "" : "s"}`;
    if (!rows.length) {
      els.endpointRows.innerHTML = `<tr><td colspan="7" class="empty-table">No endpoints decoded.</td></tr>`;
      return;
    }
    els.endpointRows.innerHTML = rows.slice(0, 1000).map(row => `
      <tr>
        <td class="mono">${escapeHtml(row.address)}</td>
        <td class="mono">${formatNumber(row.packets)}</td>
        <td class="mono">${formatBytes(row.bytes)}</td>
        <td class="mono">${formatBytes(row.sentBytes)}</td>
        <td class="mono">${formatBytes(row.receivedBytes)}</td>
        <td class="mono">${escapeHtml(row.ports.slice(0, 12).join(", ") || "-")}</td>
        <td>${escapeHtml(row.protocols.join(", ") || "-")}</td>
      </tr>
    `).join("");
  }

  function renderArtifacts() {
    const dnsRows = state.analysis.dnsRecords;
    const httpRows = state.analysis.httpMessages;
    els.dnsCount.textContent = `${formatNumber(dnsRows.length)} record${dnsRows.length === 1 ? "" : "s"}`;
    els.httpCount.textContent = `${formatNumber(httpRows.length)} message${httpRows.length === 1 ? "" : "s"}`;

    if (!dnsRows.length) {
      els.dnsRows.innerHTML = `<tr><td colspan="5" class="empty-table">No DNS records decoded.</td></tr>`;
    } else {
      els.dnsRows.innerHTML = dnsRows.slice(0, 1000).map(row => `
        <tr>
          <td class="mono">${row.packetIndex}</td>
          <td class="mono">${formatDuration(row.relTime)}</td>
          <td>${escapeHtml(row.type)}</td>
          <td class="mono">${escapeHtml(row.name)}</td>
          <td class="mono">${escapeHtml(row.answer || "-")}</td>
        </tr>
      `).join("");
    }

    if (!httpRows.length) {
      els.httpRows.innerHTML = `<tr><td colspan="5" class="empty-table">No HTTP messages decoded.</td></tr>`;
    } else {
      els.httpRows.innerHTML = httpRows.slice(0, 1000).map(row => `
        <tr>
          <td class="mono">${row.packetIndex}</td>
          <td class="mono">${formatDuration(row.relTime)}</td>
          <td class="mono">${escapeHtml(row.src)}</td>
          <td class="mono">${escapeHtml(row.host || "-")}</td>
          <td>${escapeHtml(row.summary)}</td>
        </tr>
      `).join("");
    }
  }

  function applyFilter() {
    const filter = els.filterInput.value.trim();
    state.filteredPackets = filter ? state.packets.filter(packet => packetMatchesFilter(packet, filter)) : state.packets.slice();
    sortFilteredPackets();
    state.tableWindowStart = 0;
    if (!state.selectedPacket || !state.filteredPackets.includes(state.selectedPacket)) {
      state.selectedPacket = state.filteredPackets[0] || null;
      renderPacketDetails(state.selectedPacket);
    }
  }

  function sortFilteredPackets() {
    const key = state.sortKey;
    const dir = state.sortDir;
    state.filteredPackets.sort((a, b) => compareValues(sortValue(a, key), sortValue(b, key)) * dir);
  }

  function sortValue(packet, key) {
    if (key === "protocol") {
      return packet.protocol;
    }
    if (key === "len") {
      return packet.len;
    }
    return packet[key] ?? "";
  }

  function compareValues(a, b) {
    if (typeof a === "number" && typeof b === "number") {
      return a - b;
    }
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
  }

  function renderPacketTable() {
    if (els.packetList) {
      els.packetList.scrollTop = 0;
    }
    renderPacketTableWindow();
  }

  function updatePacketWindowForScroll() {
    if (state.isRenderingPacketRows || !els.packetList || state.filteredPackets.length <= TABLE_WINDOW_SIZE) {
      return;
    }
    const total = state.filteredPackets.length;
    const firstVisibleIndex = clamp(Math.floor(els.packetList.scrollTop / PACKET_ROW_HEIGHT), 0, Math.max(0, total - 1));
    const currentStart = state.tableWindowStart;
    const currentEnd = currentStart + TABLE_WINDOW_SIZE;
    const nearTop = firstVisibleIndex < currentStart + TABLE_WINDOW_BUFFER;
    const nearBottom = firstVisibleIndex > currentEnd - TABLE_WINDOW_BUFFER;
    if (!nearTop && !nearBottom) {
      return;
    }
    const maxStart = Math.max(0, total - TABLE_WINDOW_SIZE);
    const nextStart = clamp(firstVisibleIndex - TABLE_WINDOW_BUFFER, 0, maxStart);
    if (nextStart !== currentStart) {
      state.tableWindowStart = nextStart;
      renderPacketTableWindow();
    }
  }

  function renderPacketTableWindow() {
    const total = state.filteredPackets.length;
    const maxStart = Math.max(0, total - TABLE_WINDOW_SIZE);
    const start = clamp(state.tableWindowStart, 0, maxStart);
    const end = Math.min(total, start + TABLE_WINDOW_SIZE);
    state.tableWindowStart = start;
    state.isRenderingPacketRows = true;
    els.packetRows.textContent = "";
    const fragment = document.createDocumentFragment();
    if (start > 0) {
      fragment.appendChild(createPacketSpacerRow(start * PACKET_ROW_HEIGHT));
    }
    for (let index = start; index < end; index += 1) {
      fragment.appendChild(createPacketRow(state.filteredPackets[index]));
    }
    if (end < total) {
      fragment.appendChild(createPacketSpacerRow((total - end) * PACKET_ROW_HEIGHT));
    }
    els.packetRows.appendChild(fragment);
    updatePacketRenderStatus(start, end);
    requestAnimationFrame(() => {
      state.isRenderingPacketRows = false;
    });
  }

  function createPacketRow(packet) {
    const tr = document.createElement("tr");
    tr.dataset.index = String(packet.index);
    if (state.selectedPacket && state.selectedPacket.index === packet.index) {
      tr.classList.add("is-selected");
    }
    tr.appendChild(td(packet.index, "mono"));
    tr.appendChild(td(formatDuration(packet.relTime), "mono"));
    tr.appendChild(td(packet.src || "-", "mono"));
    tr.appendChild(td(packet.dst || "-", "mono"));
    const protocolCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `protocol-pill ${packet.protocol.toLowerCase()}`;
    pill.textContent = packet.protocol;
    protocolCell.appendChild(pill);
    tr.appendChild(protocolCell);
    tr.appendChild(td(packet.len, "mono"));
    tr.appendChild(td(packet.info || packet.summary || "-"));
    return tr;
  }

  function createPacketSpacerRow(height) {
    const tr = document.createElement("tr");
    tr.className = "virtual-spacer";
    tr.setAttribute("aria-hidden", "true");
    const cell = document.createElement("td");
    cell.colSpan = 7;
    cell.style.height = `${height}px`;
    tr.appendChild(cell);
    return tr;
  }

  function updatePacketRenderStatus(start, end) {
    const total = state.filteredPackets.length;
    if (total === 0) {
      els.filterStatus.textContent = "0 matched";
      return;
    }
    const windowText = `${formatNumber(start + 1)}-${formatNumber(end)}`;
    els.filterStatus.textContent = `${formatNumber(total)} rows`;
  }

  function renderPacketTableSelection() {
    const rows = els.packetRows.querySelectorAll("tr[data-index]");
    rows.forEach(row => {
      row.classList.toggle("is-selected", state.selectedPacket && Number(row.dataset.index) === state.selectedPacket.index);
    });
  }

  function td(value, className = "") {
    const cell = document.createElement("td");
    if (className) {
      cell.className = className;
    }
    cell.textContent = String(value);
    return cell;
  }

  function renderPacketDetails(packet) {
    if (!packet) {
      renderEmptyDetail();
      return;
    }
    els.decodedDetail.innerHTML = packet.layers.map(layer => `
      <section class="layer">
        <h3>${escapeHtml(layer.name)}</h3>
        <dl class="kv">
          ${layer.fields.map(([name, value]) => `
            <dt>${escapeHtml(name)}</dt>
            <dd${isMonoValue(value) ? " class=\"mono\"" : ""}>${escapeHtml(formatFieldValue(value))}</dd>
          `).join("")}
        </dl>
      </section>
    `).join("");
    els.payloadDetail.textContent = formatPayloadText(packet);
    els.hexDetail.textContent = hexDump(packet.bytes);
  }

  function renderEmptyDetail() {
    if (els.decodedDetail) {
      els.decodedDetail.innerHTML = `<div class="empty-detail">Select a packet to inspect decoded layers.</div>`;
    }
    if (els.payloadDetail) {
      els.payloadDetail.textContent = "";
    }
    if (els.hexDetail) {
      els.hexDetail.textContent = "";
    }
  }

  function formatPayloadText(packet) {
    const payload = getPayloadBytes(packet);
    if (!payload.length) {
      return "No decoded transport payload.";
    }
    return decodeAscii(payload);
  }

  function getPayloadBytes(packet) {
    if (packet.tcp && packet.tcp.payloadLength > 0) {
      return packet.bytes.slice(packet.tcp.payloadOffset, packet.tcp.payloadOffset + packet.tcp.payloadLength);
    }
    if (packet.udp && packet.udp.payloadLength > 0) {
      return packet.bytes.slice(packet.udp.payloadOffset, packet.udp.payloadOffset + packet.udp.payloadLength);
    }
    return new Uint8Array(0);
  }

  function activateTab(tabName) {
    els.tabs.forEach(tab => tab.classList.toggle("is-active", tab.dataset.tab === tabName));
    Object.entries(els.panels).forEach(([name, panel]) => {
      panel.classList.toggle("is-hidden", name !== tabName);
    });
    if (tabName === "overview" && state.analysis) {
      renderCharts();
    }
  }

  function activateDetailTab(view) {
    state.detailView = view;
    els.detailTabs.forEach(tab => tab.classList.toggle("is-active", tab.dataset.detail === view));
    els.decodedDetail.classList.toggle("is-hidden", view !== "decoded");
    els.payloadDetail.classList.toggle("is-hidden", view !== "payload");
    els.hexDetail.classList.toggle("is-hidden", view !== "hex");
  }

  function clearCapture() {
    clearStateOnly();
    els.workspace.classList.add("is-hidden");
    els.exportCsv.disabled = true;
    els.clearCapture.disabled = true;
    els.filterInput.value = "";
    setStatus("No capture loaded");
    renderEmptyDetail();
  }

  function clearStateOnly() {
    state.fileName = "";
    state.packets = [];
    state.filteredPackets = [];
    state.analysis = null;
    state.selectedPacket = null;
    state.tableWindowStart = 0;
    state.isRenderingPacketRows = false;
  }

  function setStatus(message, isError = false) {
    els.status.textContent = message;
    els.status.classList.toggle("error", isError);
  }

  function exportFilteredCsv() {
    const header = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
    const rows = state.filteredPackets.map(packet => [
      packet.index,
      formatDuration(packet.relTime),
      packet.src || "",
      packet.dst || "",
      packet.protocol,
      packet.len,
      packet.info || packet.summary || ""
    ]);
    const csv = [header, ...rows].map(row => row.map(csvCell).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${(state.fileName || "capture").replace(/\.[^.]+$/, "")}-packets.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function packetMatchesFilter(packet, filter) {
    const tokens = filter.match(/"[^"]+"|'[^']+'|\S+/g) || [];
    return tokens.every(token => matchToken(packet, token));
  }

  function matchToken(packet, rawToken) {
    let token = rawToken.trim();
    let negate = false;
    if (token.startsWith("!")) {
      negate = true;
      token = token.slice(1);
    }
    token = stripQuotes(token);
    const result = matchPositiveToken(packet, token.toLowerCase());
    return negate ? !result : result;
  }

  function matchPositiveToken(packet, token) {
    if (!token) {
      return true;
    }
    const protocolNames = packet.protocols.map(protocol => protocol.toLowerCase());
    if (protocolNames.includes(token) || packet.protocol.toLowerCase() === token) {
      return true;
    }
    if (token === "syn") {
      return Boolean(packet.tcp && packet.tcp.flags.includes("SYN"));
    }
    if (token === "ack") {
      return Boolean(packet.tcp && packet.tcp.flags.includes("ACK"));
    }
    if (token === "tcp.flags.syn") {
      return Boolean(packet.tcp && packet.tcp.flags.includes("SYN"));
    }
    if (token === "tcp.flags.reset" || token === "tcp.flags.rst") {
      return Boolean(packet.tcp && packet.tcp.flags.includes("RST"));
    }

    const operatorMatch = token.match(/^([a-z0-9_.:-]+)(==|=|!=|>=|<=|>|<)(.+)$/);
    if (operatorMatch) {
      return matchExpression(packet, operatorMatch[1], operatorMatch[2], operatorMatch[3]);
    }

    const colonMatch = token.match(/^([a-z0-9_.-]+):(.+)$/);
    if (colonMatch) {
      return matchExpression(packet, colonMatch[1], "=", colonMatch[2]);
    }

    return packet.searchText.includes(token);
  }

  function matchExpression(packet, field, op, rawValue) {
    const value = stripQuotes(rawValue).toLowerCase();
    const numberValue = Number(value);
    const equals = values => values.some(item => String(item ?? "").toLowerCase() === value);
    const includes = values => values.some(item => String(item ?? "").toLowerCase().includes(value));

    if (field === "contains") {
      return packet.searchText.includes(value);
    }
    if (field === "proto" || field === "protocol") {
      return compareStringSet(packet.protocols.concat(packet.protocol), op, value);
    }
    if (field === "ip.addr" || field === "addr" || field === "host") {
      return compareBool(op, equals([packet.src, packet.dst]) || includes([packet.src, packet.dst]));
    }
    if (field === "ip.src" || field === "src") {
      return compareString(packet.src, op, value);
    }
    if (field === "ip.dst" || field === "dst") {
      return compareString(packet.dst, op, value);
    }
    if (field === "tcp.port") {
      return packet.transport === "TCP" && compareNumberSet([packet.sport, packet.dport], op, numberValue);
    }
    if (field === "udp.port") {
      return packet.transport === "UDP" && compareNumberSet([packet.sport, packet.dport], op, numberValue);
    }
    if (field === "port" || field === "sport" || field === "dport") {
      const ports = field === "sport" ? [packet.sport] : field === "dport" ? [packet.dport] : [packet.sport, packet.dport];
      return compareNumberSet(ports, op, numberValue);
    }
    if (field === "len" || field === "frame.len" || field === "length") {
      return compareNumber(packet.len, op, numberValue);
    }
    if (field === "dns.qry.name" || field === "dns.name") {
      const names = packet.dns ? packet.dns.questions.map(q => q.name).concat(packet.dns.answers.map(a => a.name)) : [];
      return compareStringSet(names, op, value);
    }
    if (field === "http.host") {
      return compareString(packet.http && packet.http.host, op, value);
    }
    return packet.searchText.includes(`${field}${op}${value}`) || packet.searchText.includes(value);
  }

  function compareString(actual, op, expected) {
    const value = String(actual ?? "").toLowerCase();
    if (op === "!=") {
      return value !== expected;
    }
    if (op === "=" || op === "==") {
      return value === expected || value.includes(expected);
    }
    return false;
  }

  function compareStringSet(values, op, expected) {
    const normalized = values.map(value => String(value ?? "").toLowerCase());
    if (op === "!=") {
      return normalized.every(value => value !== expected && !value.includes(expected));
    }
    return normalized.some(value => value === expected || value.includes(expected));
  }

  function compareNumberSet(values, op, expected) {
    if (!Number.isFinite(expected)) {
      return false;
    }
    return values.some(value => compareNumber(Number(value), op, expected));
  }

  function compareNumber(actual, op, expected) {
    if (!Number.isFinite(actual) || !Number.isFinite(expected)) {
      return false;
    }
    if (op === ">" ) {
      return actual > expected;
    }
    if (op === "<") {
      return actual < expected;
    }
    if (op === ">=") {
      return actual >= expected;
    }
    if (op === "<=") {
      return actual <= expected;
    }
    if (op === "!=") {
      return actual !== expected;
    }
    return actual === expected;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function compareBool(op, value) {
    return op === "!=" ? !value : value;
  }

  function parseCapture(buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    if (bytes.length < 4) {
      throw new Error("file is too small to be a capture");
    }

    let result;
    if (isClassicPcap(bytes)) {
      result = parseClassicPcap(buffer, fileName);
    } else if (isPcapNg(bytes)) {
      result = parsePcapNg(buffer, fileName);
    } else {
      throw new Error("unsupported format; expected classic PCAP or PCAPNG");
    }
    finalizePackets(result.packets);
    return result;
  }

  function isClassicPcap(bytes) {
    const signature = hexSignature(bytes, 4);
    return ["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d"].includes(signature);
  }

  function isPcapNg(bytes) {
    return bytes.length >= 12 && bytes[0] === 0x0a && bytes[1] === 0x0d && bytes[2] === 0x0d && bytes[3] === 0x0a;
  }

  function parseClassicPcap(buffer, fileName) {
    const dv = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    const sig = hexSignature(bytes, 4);
    const little = sig === "d4c3b2a1" || sig === "4d3cb2a1";
    const nanos = sig === "4d3cb2a1" || sig === "a1b23c4d";
    const versionMajor = dv.getUint16(4, little);
    const versionMinor = dv.getUint16(6, little);
    const snaplen = dv.getUint32(16, little);
    const linkType = dv.getUint32(20, little) & 0xffff;
    const warnings = [];
    const packets = [];
    let offset = 24;
    let index = 1;

    while (offset + 16 <= bytes.length) {
      const tsSec = dv.getUint32(offset, little);
      const tsFrac = dv.getUint32(offset + 4, little);
      const inclLen = dv.getUint32(offset + 8, little);
      const origLen = dv.getUint32(offset + 12, little);
      offset += 16;
      if (inclLen > bytes.length - offset) {
        warnings.push(`packet ${index} is truncated`);
        break;
      }
      const data = bytes.slice(offset, offset + inclLen);
      const timestamp = tsSec + tsFrac / (nanos ? 1e9 : 1e6);
      packets.push(decodePacket(data, {
        index,
        timestamp,
        caplen: inclLen,
        len: origLen,
        linkType,
        fileName
      }));
      offset += inclLen;
      index += 1;
    }

    return {
      format: `PCAP ${versionMajor}.${versionMinor}`,
      snaplen,
      linkType,
      packets,
      warnings
    };
  }

  function parsePcapNg(buffer, fileName) {
    const dv = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    const packets = [];
    const warnings = [];
    let offset = 0;
    let little = true;
    let sectionReady = false;
    let interfaces = [];
    let index = 1;

    while (offset + 12 <= bytes.length) {
      const shbAtOffset = bytes[offset] === 0x0a && bytes[offset + 1] === 0x0d && bytes[offset + 2] === 0x0d && bytes[offset + 3] === 0x0a;
      if (shbAtOffset) {
        const order = detectPcapNgByteOrder(bytes, offset);
        if (!order) {
          warnings.push(`section header at offset ${offset} has invalid byte order magic`);
          break;
        }
        little = order === "little";
        sectionReady = true;
        interfaces = [];
      } else if (!sectionReady) {
        throw new Error("PCAPNG does not start with a section header block");
      }

      const blockType = dv.getUint32(offset, little);
      const blockLength = dv.getUint32(offset + 4, little);
      if (blockLength < 12 || offset + blockLength > bytes.length) {
        warnings.push(`invalid block length at offset ${offset}`);
        break;
      }
      const bodyStart = offset + 8;
      const bodyEnd = offset + blockLength - 4;

      if (blockType === 0x0a0d0d0a) {
        const major = dv.getUint16(bodyStart + 4, little);
        const minor = dv.getUint16(bodyStart + 6, little);
        if (major !== 1) {
          warnings.push(`PCAPNG section version ${major}.${minor} may not be fully supported`);
        }
      } else if (blockType === 0x00000001) {
        if (bodyEnd - bodyStart >= 8) {
          const linkType = dv.getUint16(bodyStart, little);
          const snaplen = dv.getUint32(bodyStart + 4, little);
          const options = parsePcapNgOptions(dv, bytes, bodyStart + 8, bodyEnd, little);
          interfaces.push({
            linkType,
            snaplen,
            tsResolution: pcapNgTimestampResolution(options),
            name: optionText(options, 2) || `Interface ${interfaces.length}`
          });
        }
      } else if (blockType === 0x00000006) {
        if (bodyEnd - bodyStart >= 20) {
          const interfaceId = dv.getUint32(bodyStart, little);
          const tsHigh = dv.getUint32(bodyStart + 4, little);
          const tsLow = dv.getUint32(bodyStart + 8, little);
          const capLen = dv.getUint32(bodyStart + 12, little);
          const packetLen = dv.getUint32(bodyStart + 16, little);
          const dataStart = bodyStart + 20;
          const dataEnd = dataStart + capLen;
          if (dataEnd <= bodyEnd) {
            const iface = interfaces[interfaceId] || { linkType: 1, tsResolution: 1e-6, name: `Interface ${interfaceId}` };
            const timestamp = pcapNgTimestampSeconds(tsHigh, tsLow, iface.tsResolution);
            const data = bytes.slice(dataStart, dataEnd);
            packets.push(decodePacket(data, {
              index,
              timestamp,
              caplen: capLen,
              len: packetLen,
              linkType: iface.linkType,
              interfaceName: iface.name,
              fileName
            }));
            index += 1;
          } else {
            warnings.push(`enhanced packet block at offset ${offset} is truncated`);
          }
        }
      } else if (blockType === 0x00000003) {
        if (bodyEnd - bodyStart >= 4) {
          const packetLen = dv.getUint32(bodyStart, little);
          const dataStart = bodyStart + 4;
          const capLen = Math.min(packetLen, bodyEnd - dataStart);
          const data = bytes.slice(dataStart, dataStart + capLen);
          const iface = interfaces[0] || { linkType: 1, name: "Interface 0" };
          packets.push(decodePacket(data, {
            index,
            timestamp: null,
            caplen: capLen,
            len: packetLen,
            linkType: iface.linkType,
            interfaceName: iface.name,
            fileName
          }));
          index += 1;
        }
      }

      offset += blockLength;
    }

    return {
      format: "PCAPNG",
      snaplen: interfaces[0] ? interfaces[0].snaplen : 0,
      linkType: interfaces[0] ? interfaces[0].linkType : 1,
      packets,
      warnings
    };
  }

  function detectPcapNgByteOrder(bytes, offset) {
    if (offset + 12 > bytes.length) {
      return null;
    }
    if (bytes[offset + 8] === 0x4d && bytes[offset + 9] === 0x3c && bytes[offset + 10] === 0x2b && bytes[offset + 11] === 0x1a) {
      return "little";
    }
    if (bytes[offset + 8] === 0x1a && bytes[offset + 9] === 0x2b && bytes[offset + 10] === 0x3c && bytes[offset + 11] === 0x4d) {
      return "big";
    }
    return null;
  }

  function parsePcapNgOptions(dv, bytes, start, end, little) {
    const options = [];
    let offset = start;
    while (offset + 4 <= end) {
      const code = dv.getUint16(offset, little);
      const length = dv.getUint16(offset + 2, little);
      offset += 4;
      if (code === 0) {
        break;
      }
      if (offset + length > end) {
        break;
      }
      options.push({ code, value: bytes.slice(offset, offset + length) });
      offset += paddedLength(length);
    }
    return options;
  }

  function pcapNgTimestampResolution(options) {
    const option = options.find(item => item.code === 9 && item.value.length >= 1);
    if (!option) {
      return 1e-6;
    }
    const value = option.value[0];
    if (value & 0x80) {
      return Math.pow(2, -(value & 0x7f));
    }
    return Math.pow(10, -value);
  }

  function optionText(options, code) {
    const option = options.find(item => item.code === code);
    if (!option) {
      return "";
    }
    return decodeAscii(option.value).replace(/\0/g, "").trim();
  }

  function pcapNgTimestampSeconds(high, low, resolution) {
    return (high * 4294967296 + low) * resolution;
  }

  function decodePacket(bytes, meta) {
    const packet = {
      index: meta.index,
      timestamp: meta.timestamp,
      relTime: 0,
      caplen: meta.caplen,
      len: meta.len,
      linkType: meta.linkType,
      interfaceName: meta.interfaceName || "",
      bytes,
      protocols: ["Frame"],
      protocol: "Frame",
      transport: "",
      app: "",
      src: "",
      dst: "",
      sport: null,
      dport: null,
      info: "",
      summary: "",
      warnings: [],
      layers: [],
      searchText: ""
    };

    packet.layers.push({
      name: "Frame",
      fields: [
        ["Number", packet.index],
        ["Arrival Time", packet.timestamp == null ? "-" : formatAbsoluteTime(packet.timestamp)],
        ["Relative Time", "0 ms"],
        ["Captured Length", `${formatNumber(packet.caplen)} bytes`],
        ["Original Length", `${formatNumber(packet.len)} bytes`],
        ["Link Type", `${linkTypeName(packet.linkType)} (${packet.linkType})`],
        ["Interface", packet.interfaceName || "-"],
        ["File", meta.fileName || "-"]
      ]
    });

    try {
      decodeLinkLayer(packet, bytes);
    } catch (error) {
      packet.warnings.push(error.message);
      packet.info = packet.info || `Decode error: ${error.message}`;
    }

    if (!packet.info) {
      packet.info = packet.summary || packet.protocol;
    }
    packet.protocol = chooseProtocol(packet);
    packet.searchText = buildPacketSearchText(packet);
    return packet;
  }

  function finalizePackets(packets) {
    const firstTimestamp = packets.find(packet => packet.timestamp != null)?.timestamp ?? null;
    for (const packet of packets) {
      packet.relTime = firstTimestamp == null || packet.timestamp == null ? 0 : Math.max(0, packet.timestamp - firstTimestamp);
      const frame = packet.layers[0];
      const relField = frame.fields.find(field => field[0] === "Relative Time");
      if (relField) {
        relField[1] = formatDuration(packet.relTime);
      }
      packet.searchText = buildPacketSearchText(packet);
    }
  }

  function decodeLinkLayer(packet, bytes) {
    if (packet.linkType === 1) {
      parseEthernet(packet, bytes, 0);
      return;
    }
    if (packet.linkType === 101 || packet.linkType === 228) {
      parseRawIp(packet, bytes, 0);
      return;
    }
    if (packet.linkType === 113) {
      parseLinuxCooked(packet, bytes, 0);
      return;
    }
    if (packet.linkType === 276) {
      parseLinuxCookedV2(packet, bytes, 0);
      return;
    }
    if (packet.linkType === 0) {
      parseNullLoopback(packet, bytes, 0);
      return;
    }
    packet.summary = `${linkTypeName(packet.linkType)} frame`;
    packet.info = `Unsupported link type ${packet.linkType}`;
  }

  function parseEthernet(packet, bytes, offset) {
    if (bytes.length < offset + 14) {
      markTruncated(packet, "Ethernet header");
      return;
    }
    const dst = formatMac(bytes, offset);
    const src = formatMac(bytes, offset + 6);
    let etherType = readU16BE(bytes, offset + 12);
    let payloadOffset = offset + 14;
    const vlans = [];

    while ((etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100) && bytes.length >= payloadOffset + 4) {
      const tci = readU16BE(bytes, payloadOffset);
      vlans.push(tci & 0x0fff);
      etherType = readU16BE(bytes, payloadOffset + 2);
      payloadOffset += 4;
    }

    packet.protocols.push("Ethernet");
    packet.src = packet.src || src;
    packet.dst = packet.dst || dst;
    packet.srcMac = src;
    packet.dstMac = dst;
    packet.layers.push({
      name: "Ethernet II",
      fields: [
        ["Destination", dst],
        ["Source", src],
        ["Type", `${etherTypeName(etherType)} (0x${hex(etherType, 4)})`],
        ["VLAN", vlans.length ? vlans.join(", ") : "-"]
      ]
    });
    dispatchEtherType(packet, bytes, payloadOffset, etherType);
  }

  function parseLinuxCooked(packet, bytes, offset) {
    if (bytes.length < offset + 16) {
      markTruncated(packet, "Linux cooked header");
      return;
    }
    const packetType = readU16BE(bytes, offset);
    const addressType = readU16BE(bytes, offset + 2);
    const addressLength = readU16BE(bytes, offset + 4);
    const address = Array.from(bytes.slice(offset + 6, offset + 6 + Math.min(addressLength, 8))).map(value => hex(value, 2)).join(":");
    const protocol = readU16BE(bytes, offset + 14);
    packet.protocols.push("SLL");
    packet.layers.push({
      name: "Linux Cooked Capture",
      fields: [
        ["Packet Type", packetType],
        ["Address Type", addressType],
        ["Address", address || "-"],
        ["Protocol", `${etherTypeName(protocol)} (0x${hex(protocol, 4)})`]
      ]
    });
    dispatchEtherType(packet, bytes, offset + 16, protocol);
  }

  function parseLinuxCookedV2(packet, bytes, offset) {
    if (bytes.length < offset + 20) {
      markTruncated(packet, "Linux cooked v2 header");
      return;
    }
    const protocol = readU16BE(bytes, offset);
    const interfaceIndex = readU32BE(bytes, offset + 4);
    const addressType = readU16BE(bytes, offset + 8);
    const packetType = bytes[offset + 10];
    const addressLength = bytes[offset + 11];
    const address = Array.from(bytes.slice(offset + 12, offset + 12 + Math.min(addressLength, 8))).map(value => hex(value, 2)).join(":");
    packet.protocols.push("SLL2");
    packet.layers.push({
      name: "Linux Cooked Capture v2",
      fields: [
        ["Protocol", `${etherTypeName(protocol)} (0x${hex(protocol, 4)})`],
        ["Interface Index", interfaceIndex],
        ["Address Type", addressType],
        ["Packet Type", packetType],
        ["Address", address || "-"]
      ]
    });
    dispatchEtherType(packet, bytes, offset + 20, protocol);
  }

  function parseNullLoopback(packet, bytes, offset) {
    if (bytes.length < offset + 4) {
      markTruncated(packet, "loopback header");
      return;
    }
    const familyLE = readU32LE(bytes, offset);
    const familyBE = readU32BE(bytes, offset);
    packet.protocols.push("Loopback");
    packet.layers.push({
      name: "Null Loopback",
      fields: [
        ["Family LE", familyLE],
        ["Family BE", familyBE]
      ]
    });
    if ([2, 24, 28, 30].includes(familyLE) || [2, 24, 28, 30].includes(familyBE)) {
      const family = [2, 24, 28, 30].includes(familyLE) ? familyLE : familyBE;
      if (family === 2) {
        parseIPv4(packet, bytes, offset + 4);
      } else {
        parseIPv6(packet, bytes, offset + 4);
      }
    } else {
      packet.info = `Loopback family ${familyLE}`;
    }
  }

  function parseRawIp(packet, bytes, offset) {
    if (bytes.length <= offset) {
      markTruncated(packet, "raw IP packet");
      return;
    }
    const version = bytes[offset] >> 4;
    if (version === 4) {
      parseIPv4(packet, bytes, offset);
    } else if (version === 6) {
      parseIPv6(packet, bytes, offset);
    } else {
      packet.info = `Unknown raw IP version ${version}`;
    }
  }

  function dispatchEtherType(packet, bytes, offset, etherType) {
    if (etherType === 0x0800) {
      parseIPv4(packet, bytes, offset);
    } else if (etherType === 0x86dd) {
      parseIPv6(packet, bytes, offset);
    } else if (etherType === 0x0806) {
      parseArp(packet, bytes, offset);
    } else {
      packet.info = `${etherTypeName(etherType)} payload (${formatNumber(Math.max(0, bytes.length - offset))} bytes)`;
    }
  }

  function parseIPv4(packet, bytes, offset) {
    if (bytes.length < offset + 20) {
      markTruncated(packet, "IPv4 header");
      return;
    }
    const version = bytes[offset] >> 4;
    const ihl = (bytes[offset] & 0x0f) * 4;
    if (version !== 4 || ihl < 20 || bytes.length < offset + ihl) {
      markTruncated(packet, "IPv4 header");
      return;
    }
    const dscp = bytes[offset + 1] >> 2;
    const totalLength = readU16BE(bytes, offset + 2);
    const identification = readU16BE(bytes, offset + 4);
    const flagsFragment = readU16BE(bytes, offset + 6);
    const ttl = bytes[offset + 8];
    const protocol = bytes[offset + 9];
    const checksum = readU16BE(bytes, offset + 10);
    const src = formatIPv4(bytes, offset + 12);
    const dst = formatIPv4(bytes, offset + 16);
    const fragmentOffset = flagsFragment & 0x1fff;
    const dontFragment = Boolean(flagsFragment & 0x4000);
    const moreFragments = Boolean(flagsFragment & 0x2000);
    const payloadOffset = offset + ihl;
    const packetEnd = Math.min(bytes.length, offset + (totalLength || bytes.length - offset));

    packet.protocols.push("IPv4");
    packet.src = src;
    packet.dst = dst;
    packet.ipVersion = 4;
    packet.layers.push({
      name: "Internet Protocol Version 4",
      fields: [
        ["Source", src],
        ["Destination", dst],
        ["Header Length", `${ihl} bytes`],
        ["Total Length", totalLength],
        ["DSCP", dscp],
        ["Identification", `0x${hex(identification, 4)}`],
        ["Flags", `${dontFragment ? "DF " : ""}${moreFragments ? "MF" : ""}`.trim() || "-"],
        ["Fragment Offset", fragmentOffset],
        ["TTL", ttl],
        ["Protocol", `${ipProtocolName(protocol)} (${protocol})`],
        ["Header Checksum", `0x${hex(checksum, 4)}`]
      ]
    });

    if (fragmentOffset > 0) {
      packet.info = `IPv4 fragment offset=${fragmentOffset} length=${Math.max(0, packetEnd - payloadOffset)}`;
      return;
    }
    dispatchIpProtocol(packet, bytes, payloadOffset, packetEnd, protocol, 4);
  }

  function parseIPv6(packet, bytes, offset) {
    if (bytes.length < offset + 40) {
      markTruncated(packet, "IPv6 header");
      return;
    }
    const version = bytes[offset] >> 4;
    if (version !== 6) {
      packet.info = `Unknown IPv6 version ${version}`;
      return;
    }
    const trafficClass = ((bytes[offset] & 0x0f) << 4) | (bytes[offset + 1] >> 4);
    const flowLabel = ((bytes[offset + 1] & 0x0f) << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const payloadLength = readU16BE(bytes, offset + 4);
    let nextHeader = bytes[offset + 6];
    const hopLimit = bytes[offset + 7];
    const src = formatIPv6(bytes, offset + 8);
    const dst = formatIPv6(bytes, offset + 24);
    let payloadOffset = offset + 40;
    const packetEnd = Math.min(bytes.length, payloadOffset + payloadLength);
    const extensions = [];

    while (isIPv6ExtensionHeader(nextHeader) && payloadOffset + 2 <= packetEnd) {
      const current = nextHeader;
      if (current === 44) {
        nextHeader = bytes[payloadOffset];
        const fragmentData = readU16BE(bytes, payloadOffset + 2);
        extensions.push(`${ipProtocolName(current)} offset=${fragmentData >> 3}`);
        payloadOffset += 8;
        if ((fragmentData >> 3) > 0) {
          packet.info = `IPv6 fragment offset=${fragmentData >> 3}`;
          break;
        }
      } else if (current === 51) {
        nextHeader = bytes[payloadOffset];
        const headerLength = (bytes[payloadOffset + 1] + 2) * 4;
        extensions.push(`${ipProtocolName(current)} ${headerLength} bytes`);
        payloadOffset += headerLength;
      } else {
        nextHeader = bytes[payloadOffset];
        const headerLength = (bytes[payloadOffset + 1] + 1) * 8;
        extensions.push(`${ipProtocolName(current)} ${headerLength} bytes`);
        payloadOffset += headerLength;
      }
      if (payloadOffset > packetEnd) {
        markTruncated(packet, "IPv6 extension header");
        return;
      }
    }

    packet.protocols.push("IPv6");
    packet.src = src;
    packet.dst = dst;
    packet.ipVersion = 6;
    packet.layers.push({
      name: "Internet Protocol Version 6",
      fields: [
        ["Source", src],
        ["Destination", dst],
        ["Traffic Class", trafficClass],
        ["Flow Label", `0x${hex(flowLabel, 5)}`],
        ["Payload Length", payloadLength],
        ["Next Header", `${ipProtocolName(nextHeader)} (${nextHeader})`],
        ["Hop Limit", hopLimit],
        ["Extensions", extensions.join(", ") || "-"]
      ]
    });

    if (!packet.info || !packet.info.startsWith("IPv6 fragment")) {
      dispatchIpProtocol(packet, bytes, payloadOffset, packetEnd, nextHeader, 6);
    }
  }

  function dispatchIpProtocol(packet, bytes, offset, end, protocol, version) {
    if (protocol === 6) {
      parseTcp(packet, bytes, offset, end);
    } else if (protocol === 17) {
      parseUdp(packet, bytes, offset, end);
    } else if (protocol === 1) {
      parseIcmp(packet, bytes, offset, end);
    } else if (protocol === 58) {
      parseIcmpv6(packet, bytes, offset, end);
    } else {
      packet.info = `${version === 6 ? "IPv6" : "IPv4"} ${ipProtocolName(protocol)} payload (${formatNumber(Math.max(0, end - offset))} bytes)`;
    }
  }

  function parseTcp(packet, bytes, offset, end) {
    if (end < offset + 20) {
      markTruncated(packet, "TCP header");
      return;
    }
    const srcPort = readU16BE(bytes, offset);
    const dstPort = readU16BE(bytes, offset + 2);
    const seq = readU32BE(bytes, offset + 4);
    const ack = readU32BE(bytes, offset + 8);
    const dataOffset = (bytes[offset + 12] >> 4) * 4;
    const ns = Boolean(bytes[offset + 12] & 0x01);
    const flagsByte = bytes[offset + 13];
    const flags = tcpFlagNames(flagsByte, ns);
    const windowSize = readU16BE(bytes, offset + 14);
    const checksum = readU16BE(bytes, offset + 16);
    const urgentPointer = readU16BE(bytes, offset + 18);
    if (dataOffset < 20 || offset + dataOffset > end) {
      markTruncated(packet, "TCP options");
      return;
    }
    const payloadOffset = offset + dataOffset;
    const payloadLength = Math.max(0, end - payloadOffset);

    packet.protocols.push("TCP");
    packet.transport = "TCP";
    packet.sport = srcPort;
    packet.dport = dstPort;
    packet.tcp = { srcPort, dstPort, seq, ack, dataOffset, flags, windowSize, payloadOffset, payloadLength };
    packet.layers.push({
      name: "Transmission Control Protocol",
      fields: [
        ["Source Port", srcPort],
        ["Destination Port", dstPort],
        ["Sequence Number", seq],
        ["Acknowledgment Number", ack],
        ["Header Length", `${dataOffset} bytes`],
        ["Flags", flags.join(", ") || "-"],
        ["Window", windowSize],
        ["Checksum", `0x${hex(checksum, 4)}`],
        ["Urgent Pointer", urgentPointer],
        ["Payload Length", payloadLength]
      ]
    });

    packet.info = `${srcPort} -> ${dstPort} [${flags.join(",") || "none"}] Seq=${seq} Ack=${ack} Win=${windowSize} Len=${payloadLength}`;
    if (payloadLength > 0) {
      if (!parseTls(packet, bytes, payloadOffset, end)) {
        parseHttp(packet, bytes, payloadOffset, end);
      }
    }
  }

  function parseUdp(packet, bytes, offset, end) {
    if (end < offset + 8) {
      markTruncated(packet, "UDP header");
      return;
    }
    const srcPort = readU16BE(bytes, offset);
    const dstPort = readU16BE(bytes, offset + 2);
    const length = readU16BE(bytes, offset + 4);
    const checksum = readU16BE(bytes, offset + 6);
    const payloadOffset = offset + 8;
    const payloadEnd = Math.min(end, offset + Math.max(length, 8));
    const payloadLength = Math.max(0, payloadEnd - payloadOffset);

    packet.protocols.push("UDP");
    packet.transport = "UDP";
    packet.sport = srcPort;
    packet.dport = dstPort;
    packet.udp = { srcPort, dstPort, length, checksum, payloadOffset, payloadLength };
    packet.layers.push({
      name: "User Datagram Protocol",
      fields: [
        ["Source Port", srcPort],
        ["Destination Port", dstPort],
        ["Length", length],
        ["Checksum", `0x${hex(checksum, 4)}`],
        ["Payload Length", payloadLength]
      ]
    });

    packet.info = `${srcPort} -> ${dstPort} Len=${payloadLength}`;
    if ((srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353) && payloadLength >= 12) {
      parseDns(packet, bytes, payloadOffset, payloadEnd);
    }
  }

  function parseIcmp(packet, bytes, offset, end) {
    if (end < offset + 4) {
      markTruncated(packet, "ICMP header");
      return;
    }
    const type = bytes[offset];
    const code = bytes[offset + 1];
    const checksum = readU16BE(bytes, offset + 2);
    const name = icmpTypeName(type, code);
    packet.protocols.push("ICMP");
    packet.transport = "ICMP";
    packet.layers.push({
      name: "Internet Control Message Protocol",
      fields: [
        ["Type", `${name} (${type})`],
        ["Code", code],
        ["Checksum", `0x${hex(checksum, 4)}`]
      ]
    });
    packet.info = `${name} code=${code}`;
  }

  function parseIcmpv6(packet, bytes, offset, end) {
    if (end < offset + 4) {
      markTruncated(packet, "ICMPv6 header");
      return;
    }
    const type = bytes[offset];
    const code = bytes[offset + 1];
    const checksum = readU16BE(bytes, offset + 2);
    const name = icmpv6TypeName(type);
    packet.protocols.push("ICMPv6");
    packet.transport = "ICMPv6";
    packet.layers.push({
      name: "Internet Control Message Protocol v6",
      fields: [
        ["Type", `${name} (${type})`],
        ["Code", code],
        ["Checksum", `0x${hex(checksum, 4)}`]
      ]
    });
    packet.info = `${name} code=${code}`;
  }

  function parseArp(packet, bytes, offset) {
    if (bytes.length < offset + 28) {
      markTruncated(packet, "ARP packet");
      return;
    }
    const hardwareType = readU16BE(bytes, offset);
    const protocolType = readU16BE(bytes, offset + 2);
    const hardwareLength = bytes[offset + 4];
    const protocolLength = bytes[offset + 5];
    const operation = readU16BE(bytes, offset + 6);
    let cursor = offset + 8;
    const senderHardware = formatMac(bytes, cursor);
    cursor += hardwareLength;
    const senderProtocol = protocolLength === 4 ? formatIPv4(bytes, cursor) : bytesToHex(bytes, cursor, protocolLength);
    cursor += protocolLength;
    const targetHardware = hardwareLength === 6 ? formatMac(bytes, cursor) : bytesToHex(bytes, cursor, hardwareLength);
    cursor += hardwareLength;
    const targetProtocol = protocolLength === 4 ? formatIPv4(bytes, cursor) : bytesToHex(bytes, cursor, protocolLength);

    packet.protocols.push("ARP");
    packet.protocol = "ARP";
    packet.src = senderProtocol || senderHardware;
    packet.dst = targetProtocol || targetHardware;
    packet.arp = { operation, senderHardware, senderProtocol, targetHardware, targetProtocol };
    packet.layers.push({
      name: "Address Resolution Protocol",
      fields: [
        ["Hardware Type", hardwareType],
        ["Protocol Type", `${etherTypeName(protocolType)} (0x${hex(protocolType, 4)})`],
        ["Hardware Size", hardwareLength],
        ["Protocol Size", protocolLength],
        ["Opcode", `${arpOperation(operation)} (${operation})`],
        ["Sender MAC", senderHardware],
        ["Sender IP", senderProtocol],
        ["Target MAC", targetHardware],
        ["Target IP", targetProtocol]
      ]
    });
    packet.info = operation === 1
      ? `Who has ${targetProtocol}? Tell ${senderProtocol}`
      : `${senderProtocol} is at ${senderHardware}`;
  }

  function parseDns(packet, bytes, offset, end) {
    const id = readU16BE(bytes, offset);
    const flags = readU16BE(bytes, offset + 2);
    const questionCount = readU16BE(bytes, offset + 4);
    const answerCount = readU16BE(bytes, offset + 6);
    const authorityCount = readU16BE(bytes, offset + 8);
    const additionalCount = readU16BE(bytes, offset + 10);
    const isResponse = Boolean(flags & 0x8000);
    const opcode = (flags >> 11) & 0x0f;
    const rcode = flags & 0x0f;
    const questions = [];
    const answers = [];
    let cursor = offset + 12;

    try {
      for (let i = 0; i < Math.min(questionCount, 100); i += 1) {
        const nameResult = readDnsName(bytes, cursor, offset, end);
        cursor = nameResult.offset;
        if (cursor + 4 > end) {
          throw new Error("truncated DNS question");
        }
        const type = readU16BE(bytes, cursor);
        const qclass = readU16BE(bytes, cursor + 2);
        cursor += 4;
        questions.push({ name: nameResult.name, type: dnsTypeName(type), typeCode: type, class: qclass });
      }

      const recordTotal = Math.min(answerCount + authorityCount + additionalCount, 200);
      for (let i = 0; i < recordTotal; i += 1) {
        const record = readDnsRecord(bytes, cursor, offset, end);
        cursor = record.offset;
        answers.push(record.record);
      }
    } catch (error) {
      packet.warnings.push(`DNS parse warning: ${error.message}`);
    }

    packet.protocols.push("DNS");
    packet.app = "DNS";
    packet.dns = {
      id,
      flags,
      isResponse,
      opcode,
      rcode,
      questions,
      answers,
      counts: { questions: questionCount, answers: answerCount, authority: authorityCount, additional: additionalCount }
    };
    packet.layers.push({
      name: "Domain Name System",
      fields: [
        ["Transaction ID", `0x${hex(id, 4)}`],
        ["Message Type", isResponse ? "Response" : "Query"],
        ["Opcode", opcode],
        ["Response Code", dnsRcodeName(rcode)],
        ["Questions", questionCount],
        ["Answers", answerCount],
        ["Authority RRs", authorityCount],
        ["Additional RRs", additionalCount],
        ["Question Names", questions.map(item => `${item.name} ${item.type}`).join(", ") || "-"],
        ["Answer Data", answers.map(item => `${item.name} ${item.type} ${item.data || ""}`.trim()).join(", ") || "-"]
      ]
    });

    if (isResponse) {
      const answer = answers.find(item => item.data) || answers[0];
      const question = questions[0];
      packet.info = answer
        ? `DNS response ${answer.name} ${answer.type} ${answer.data || dnsRcodeName(rcode)}`
        : `DNS response ${question ? `${question.name} ${question.type}` : ""} ${dnsRcodeName(rcode)}`.trim();
    } else {
      const question = questions[0];
      packet.info = question ? `DNS query ${question.name} ${question.type}` : "DNS query";
    }
  }

  function readDnsRecord(bytes, cursor, base, end) {
    const nameResult = readDnsName(bytes, cursor, base, end);
    cursor = nameResult.offset;
    if (cursor + 10 > end) {
      throw new Error("truncated DNS record");
    }
    const typeCode = readU16BE(bytes, cursor);
    const dnsClass = readU16BE(bytes, cursor + 2);
    const ttl = readU32BE(bytes, cursor + 4);
    const rdlength = readU16BE(bytes, cursor + 8);
    cursor += 10;
    if (cursor + rdlength > end) {
      throw new Error("truncated DNS rdata");
    }
    const data = decodeDnsRdata(bytes, cursor, rdlength, typeCode, base, end);
    const record = {
      name: nameResult.name,
      type: dnsTypeName(typeCode),
      typeCode,
      class: dnsClass,
      ttl,
      data
    };
    return { record, offset: cursor + rdlength };
  }

  function readDnsName(bytes, cursor, base, end) {
    const labels = [];
    let offset = cursor;
    let jumped = false;
    let nextOffset = cursor;
    const seen = new Set();

    for (let depth = 0; depth < 128; depth += 1) {
      if (offset >= end) {
        throw new Error("truncated DNS name");
      }
      if (seen.has(offset)) {
        throw new Error("DNS compression loop");
      }
      seen.add(offset);
      const length = bytes[offset];
      if (length === 0) {
        offset += 1;
        if (!jumped) {
          nextOffset = offset;
        }
        return { name: labels.join(".") || ".", offset: nextOffset };
      }
      if ((length & 0xc0) === 0xc0) {
        if (offset + 1 >= end) {
          throw new Error("truncated DNS pointer");
        }
        const pointer = ((length & 0x3f) << 8) | bytes[offset + 1];
        if (!jumped) {
          nextOffset = offset + 2;
        }
        offset = base + pointer;
        jumped = true;
        continue;
      }
      if (length & 0xc0) {
        throw new Error("invalid DNS label");
      }
      offset += 1;
      if (offset + length > end) {
        throw new Error("truncated DNS label");
      }
      labels.push(decodeAscii(bytes.slice(offset, offset + length)));
      offset += length;
      if (!jumped) {
        nextOffset = offset;
      }
    }
    throw new Error("DNS name too deep");
  }

  function decodeDnsRdata(bytes, offset, length, typeCode, base, end) {
    if (typeCode === 1 && length === 4) {
      return formatIPv4(bytes, offset);
    }
    if (typeCode === 28 && length === 16) {
      return formatIPv6(bytes, offset);
    }
    if ([2, 5, 12].includes(typeCode)) {
      try {
        return readDnsName(bytes, offset, base, end).name;
      } catch {
        return bytesToHex(bytes, offset, length);
      }
    }
    if (typeCode === 15 && length >= 3) {
      try {
        return `${readU16BE(bytes, offset)} ${readDnsName(bytes, offset + 2, base, end).name}`;
      } catch {
        return bytesToHex(bytes, offset, length);
      }
    }
    if (typeCode === 16) {
      const parts = [];
      let cursor = offset;
      const stop = offset + length;
      while (cursor < stop) {
        const partLen = bytes[cursor];
        cursor += 1;
        if (cursor + partLen > stop) {
          break;
        }
        parts.push(decodeAscii(bytes.slice(cursor, cursor + partLen)));
        cursor += partLen;
      }
      return parts.join(" ");
    }
    return bytesToHex(bytes, offset, Math.min(length, 24));
  }

  function parseHttp(packet, bytes, offset, end) {
    const sample = decodeAscii(bytes.slice(offset, Math.min(end, offset + 4096)));
    const lineEnd = sample.indexOf("\r\n") >= 0 ? sample.indexOf("\r\n") : sample.indexOf("\n");
    if (lineEnd <= 0) {
      return false;
    }
    const firstLine = sample.slice(0, lineEnd).trim();
    const requestMatch = firstLine.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP\/\d(?:\.\d)?)$/);
    const responseMatch = firstLine.match(/^(HTTP\/\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$/);
    if (!requestMatch && !responseMatch) {
      return false;
    }

    const headersText = sample.split(/\r?\n\r?\n/, 1)[0];
    const hostMatch = headersText.match(/\r?\nHost:\s*([^\r\n]+)/i);
    const host = hostMatch ? hostMatch[1].trim() : "";
    packet.protocols.push("HTTP");
    packet.app = "HTTP";

    if (requestMatch) {
      packet.http = {
        type: "request",
        method: requestMatch[1],
        target: requestMatch[2],
        version: requestMatch[3],
        host,
        firstLine
      };
      packet.info = `HTTP ${requestMatch[1]} ${requestMatch[2]}${host ? ` Host: ${host}` : ""}`;
    } else {
      packet.http = {
        type: "response",
        version: responseMatch[1],
        status: responseMatch[2],
        reason: responseMatch[3] || "",
        host,
        firstLine
      };
      packet.info = `HTTP ${responseMatch[2]} ${responseMatch[3] || ""}`.trim();
    }

    packet.layers.push({
      name: "Hypertext Transfer Protocol",
      fields: [
        ["Type", packet.http.type],
        ["Start Line", firstLine],
        ["Host", host || "-"],
        ["Payload Preview", sample.slice(0, 500).replace(/\r/g, "\\r").replace(/\n/g, "\\n ")]
      ]
    });
    return true;
  }

  function parseTls(packet, bytes, offset, end) {
    if (end < offset + 5) {
      return false;
    }
    const contentType = bytes[offset];
    const major = bytes[offset + 1];
    const minor = bytes[offset + 2];
    const recordLength = readU16BE(bytes, offset + 3);
    if (![20, 21, 22, 23].includes(contentType) || major !== 3 || recordLength > Math.max(0, end - offset - 5) + 16384) {
      return false;
    }
    let handshake = "";
    if (contentType === 22 && end >= offset + 6) {
      handshake = tlsHandshakeType(bytes[offset + 5]);
    }
    packet.protocols.push("TLS");
    packet.app = "TLS";
    packet.tls = { contentType, version: `TLS ${major}.${minor}`, recordLength, handshake };
    packet.layers.push({
      name: "Transport Layer Security",
      fields: [
        ["Content Type", tlsContentType(contentType)],
        ["Record Version", `0x${hex(major, 2)}${hex(minor, 2)}`],
        ["Record Length", recordLength],
        ["Handshake Type", handshake || "-"]
      ]
    });
    packet.info = `TLS ${handshake || tlsContentType(contentType)} Len=${recordLength}`;
    return true;
  }

  function buildAnalysis(packets) {
    const protocolCounts = new Map();
    const endpointMap = new Map();
    const conversationMap = new Map();
    const dnsRecords = [];
    const httpMessages = [];
    const totalBytes = packets.reduce((sum, packet) => sum + packet.len, 0);
    const firstTs = packets.find(packet => packet.timestamp != null)?.timestamp ?? null;
    const lastTs = [...packets].reverse().find(packet => packet.timestamp != null)?.timestamp ?? firstTs;
    const duration = firstTs == null || lastTs == null ? 0 : Math.max(0, lastTs - firstTs);
    const sizeBuckets = [
      { label: "0-63", min: 0, max: 63, count: 0 },
      { label: "64-127", min: 64, max: 127, count: 0 },
      { label: "128-255", min: 128, max: 255, count: 0 },
      { label: "256-511", min: 256, max: 511, count: 0 },
      { label: "512-1023", min: 512, max: 1023, count: 0 },
      { label: "1024-1518", min: 1024, max: 1518, count: 0 },
      { label: ">1518", min: 1519, max: Infinity, count: 0 }
    ];
    const timeline = makeTimeline(duration, firstTs, lastTs);

    for (const packet of packets) {
      protocolCounts.set(packet.protocol, (protocolCounts.get(packet.protocol) || 0) + 1);
      const bucket = sizeBuckets.find(item => packet.len >= item.min && packet.len <= item.max);
      if (bucket) {
        bucket.count += 1;
      }
      if (timeline.bins.length) {
        const index = duration > 0 ? Math.min(timeline.bins.length - 1, Math.floor((packet.relTime / duration) * timeline.bins.length)) : 0;
        timeline.bins[index].packets += 1;
        timeline.bins[index].bytes += packet.len;
      }
      addEndpoint(endpointMap, packet.src, packet, "sent");
      addEndpoint(endpointMap, packet.dst, packet, "received");
      addConversation(conversationMap, packet);

      if (packet.dns) {
        for (const question of packet.dns.questions) {
          dnsRecords.push({
            packetIndex: packet.index,
            relTime: packet.relTime,
            type: packet.dns.isResponse ? "Response" : "Query",
            name: question.name,
            answer: packet.dns.isResponse ? (packet.dns.answers.find(answer => answer.data)?.data || dnsRcodeName(packet.dns.rcode)) : question.type
          });
        }
        for (const answer of packet.dns.answers.filter(answer => answer.data)) {
          dnsRecords.push({
            packetIndex: packet.index,
            relTime: packet.relTime,
            type: answer.type,
            name: answer.name,
            answer: answer.data
          });
        }
      }

      if (packet.http) {
        httpMessages.push({
          packetIndex: packet.index,
          relTime: packet.relTime,
          src: packet.src,
          host: packet.http.host,
          summary: packet.http.firstLine
        });
      }
    }

    return {
      totalBytes,
      duration,
      protocolCounts: sortMapDesc(protocolCounts),
      endpoints: Array.from(endpointMap.values()).map(normalizeEndpoint).sort((a, b) => b.bytes - a.bytes),
      conversations: Array.from(conversationMap.values()).sort((a, b) => b.bytes - a.bytes),
      dnsRecords,
      httpMessages,
      timeline,
      sizeBuckets
    };
  }

  function addEndpoint(map, address, packet, direction) {
    if (!address || address === "-") {
      return;
    }
    if (!map.has(address)) {
      map.set(address, {
        address,
        packets: 0,
        bytes: 0,
        sentBytes: 0,
        receivedBytes: 0,
        ports: new Set(),
        protocols: new Set()
      });
    }
    const endpoint = map.get(address);
    endpoint.packets += 1;
    endpoint.bytes += packet.len;
    if (direction === "sent") {
      endpoint.sentBytes += packet.len;
      if (packet.sport != null) {
        endpoint.ports.add(packet.sport);
      }
    } else {
      endpoint.receivedBytes += packet.len;
      if (packet.dport != null) {
        endpoint.ports.add(packet.dport);
      }
    }
    endpoint.protocols.add(packet.protocol);
  }

  function normalizeEndpoint(endpoint) {
    return {
      ...endpoint,
      ports: Array.from(endpoint.ports).sort((a, b) => a - b),
      protocols: Array.from(endpoint.protocols).sort()
    };
  }

  function addConversation(map, packet) {
    if (!packet.src || !packet.dst) {
      return;
    }
    const protocol = packet.transport || packet.protocol;
    const a = endpointWithPort(packet.src, packet.sport, protocol);
    const b = endpointWithPort(packet.dst, packet.dport, protocol);
    const sorted = [a, b].sort();
    const key = `${protocol}|${sorted[0]}|${sorted[1]}`;
    if (!map.has(key)) {
      map.set(key, {
        protocol,
        a: sorted[0],
        b: sorted[1],
        packets: 0,
        bytes: 0,
        firstRel: packet.relTime,
        lastRel: packet.relTime
      });
    }
    const row = map.get(key);
    row.packets += 1;
    row.bytes += packet.len;
    row.firstRel = Math.min(row.firstRel, packet.relTime);
    row.lastRel = Math.max(row.lastRel, packet.relTime);
  }

  function endpointWithPort(address, port, protocol) {
    if ((protocol === "TCP" || protocol === "UDP") && port != null) {
      return `${address}:${port}`;
    }
    return address;
  }

  function makeTimeline(duration, startTs, endTs) {
    const count = duration > 0 ? 60 : 1;
    return {
      startTs,
      endTs,
      duration,
      bins: Array.from({ length: count }, (_, index) => ({ index, packets: 0, bytes: 0 }))
    };
  }

  function drawProtocolChart(canvas, protocolCounts) {
    const ctx = prepareCanvas(canvas);
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    clearCanvas(ctx, width, height);
    const entries = Array.from(protocolCounts.entries()).slice(0, 8);
    if (!entries.length) {
      drawEmptyCanvas(ctx, width, height, "No protocol data");
      return;
    }
    const labelColor = cssVar("--muted-strong");
    const max = Math.max(...entries.map(([, count]) => count), 1);
    const left = 88;
    const right = 22;
    const top = 16;
    const bottom = 12;
    const rowHeight = Math.min(24, (height - top - bottom) / entries.length);
    ctx.font = "12px ui-sans-serif, system-ui";
    entries.forEach(([name, count], index) => {
      const y = top + index * rowHeight;
      const barWidth = (width - left - right) * (count / max);
      ctx.fillStyle = labelColor;
      ctx.fillText(name, 12, y + 14);
      ctx.fillStyle = CHART_COLORS[index % CHART_COLORS.length];
      roundRect(ctx, left, y + 2, Math.max(2, barWidth), 13, 4);
      ctx.fill();
      ctx.fillStyle = labelColor;
      ctx.fillText(formatNumber(count), left + barWidth + 8, y + 14);
    });
  }

  function drawTimelineChart(canvas, timeline) {
    const ctx = prepareCanvas(canvas);
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    clearCanvas(ctx, width, height);
    const bins = timeline.bins;
    if (!bins.length) {
      drawEmptyCanvas(ctx, width, height, "No timeline data");
      return;
    }
    const maxBytes = Math.max(...bins.map(bin => bin.bytes), 1);
    const gridColor = cssVar("--canvas-grid");
    const labelColor = cssVar("--canvas-muted");
    const pad = { top: 18, right: 14, bottom: 28, left: 38 };
    const chartWidth = width - pad.left - pad.right;
    const chartHeight = height - pad.top - pad.bottom;
    const barWidth = Math.max(1, chartWidth / bins.length - 1);
    ctx.strokeStyle = gridColor;
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top);
    ctx.lineTo(pad.left, pad.top + chartHeight);
    ctx.lineTo(pad.left + chartWidth, pad.top + chartHeight);
    ctx.stroke();
    drawTimelineMarkers(ctx, timeline, pad, chartWidth, chartHeight, width, height, gridColor, labelColor);
    bins.forEach((bin, index) => {
      const x = pad.left + index * (chartWidth / bins.length);
      const barHeight = (bin.bytes / maxBytes) * chartHeight;
      ctx.fillStyle = "#246bfe";
      ctx.fillRect(x, pad.top + chartHeight - barHeight, barWidth, Math.max(1, barHeight));
    });
    ctx.fillStyle = labelColor;
    ctx.font = "11px ui-sans-serif, system-ui";
    ctx.fillText("bytes", 8, 18);
    if (timeline.startTs == null || timeline.endTs == null) {
      ctx.fillText("start", pad.left, height - 7);
      ctx.fillText("end", width - pad.right - 22, height - 7);
    }
  }

  function drawTimelineMarkers(ctx, timeline, pad, chartWidth, chartHeight, width, height, gridColor, labelColor) {
    if (timeline.startTs == null || timeline.endTs == null || timeline.duration <= 0) {
      return;
    }
    const markers = localMinuteMarkers(timeline.startTs, timeline.endTs, 5);
    ctx.save();
    ctx.font = "10px ui-sans-serif, system-ui";
    ctx.textAlign = "center";
    ctx.strokeStyle = gridColor;
    ctx.fillStyle = labelColor;
    const labeled = new Set(thinMarkers(markers, chartWidth));
    for (const marker of markers) {
      const x = pad.left + ((marker - timeline.startTs) / timeline.duration) * chartWidth;
      if (x < pad.left || x > width - pad.right) {
        continue;
      }
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + chartHeight);
      ctx.stroke();
      if (labeled.has(marker)) {
        ctx.fillText(formatLocalTime(marker), x, height - 7);
      }
    }
    ctx.restore();
  }

  function localMinuteMarkers(startTs, endTs, intervalMinutes) {
    const markers = [];
    const date = new Date(startTs * 1000);
    date.setSeconds(0, 0);
    const minutes = date.getMinutes();
    const remainder = minutes % intervalMinutes;
    if (remainder !== 0) {
      date.setMinutes(minutes + (intervalMinutes - remainder));
    }
    if (date.getTime() / 1000 < startTs) {
      date.setMinutes(date.getMinutes() + intervalMinutes);
    }
    for (let time = date.getTime(); time / 1000 <= endTs; time = addLocalMinutes(time, intervalMinutes)) {
      markers.push(time / 1000);
    }
    return markers;
  }

  function addLocalMinutes(timeMs, minutes) {
    const date = new Date(timeMs);
    date.setMinutes(date.getMinutes() + minutes);
    return date.getTime();
  }

  function thinMarkers(markers, chartWidth) {
    if (markers.length <= 1) {
      return markers;
    }
    const maxLabels = Math.max(2, Math.floor(chartWidth / 70));
    const step = Math.max(1, Math.ceil(markers.length / maxLabels));
    return markers.filter((_, index) => index % step === 0);
  }

  function drawSizeChart(canvas, buckets) {
    const ctx = prepareCanvas(canvas);
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    clearCanvas(ctx, width, height);
    if (!buckets.length) {
      drawEmptyCanvas(ctx, width, height, "No packet sizes");
      return;
    }
    const max = Math.max(...buckets.map(bucket => bucket.count), 1);
    const gridColor = cssVar("--canvas-grid");
    const labelColor = cssVar("--canvas-muted");
    const pad = { top: 18, right: 16, bottom: 26, left: 36 };
    const chartWidth = width - pad.left - pad.right;
    const chartHeight = height - pad.top - pad.bottom;
    const slot = chartWidth / buckets.length;
    ctx.strokeStyle = gridColor;
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top);
    ctx.lineTo(pad.left, pad.top + chartHeight);
    ctx.lineTo(pad.left + chartWidth, pad.top + chartHeight);
    ctx.stroke();
    buckets.forEach((bucket, index) => {
      const barHeight = (bucket.count / max) * chartHeight;
      const x = pad.left + index * slot + 5;
      const barWidth = Math.max(3, slot - 10);
      const y = pad.top + chartHeight - barHeight;
      ctx.fillStyle = CHART_COLORS[index % CHART_COLORS.length];
      ctx.fillRect(x, y, barWidth, Math.max(1, barHeight));
      ctx.fillStyle = labelColor;
      ctx.font = "10px ui-sans-serif, system-ui";
      ctx.textAlign = "center";
      ctx.fillText(bucket.label, x + barWidth / 2, height - 8);
    });
    ctx.textAlign = "left";
  }

  function prepareCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const width = Math.max(240, canvas.clientWidth);
    const height = Math.max(96, canvas.clientHeight || Number(canvas.getAttribute("height")) || 160);
    const targetWidth = Math.floor(width * dpr);
    const targetHeight = Math.floor(height * dpr);
    if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
      canvas.width = targetWidth;
      canvas.height = targetHeight;
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return ctx;
  }

  function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function clearCanvas(ctx, width, height) {
    ctx.clearRect(0, 0, width, height);
  }

  function drawEmptyCanvas(ctx, width, height, message) {
    ctx.fillStyle = cssVar("--canvas-muted");
    ctx.font = "13px ui-sans-serif, system-ui";
    ctx.textAlign = "center";
    ctx.fillText(message, width / 2, height / 2);
    ctx.textAlign = "left";
  }

  function roundRect(ctx, x, y, width, height, radius) {
    const r = Math.min(radius, width / 2, height / 2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + width, y, x + width, y + height, r);
    ctx.arcTo(x + width, y + height, x, y + height, r);
    ctx.arcTo(x, y + height, x, y, r);
    ctx.arcTo(x, y, x + width, y, r);
    ctx.closePath();
  }

  function chooseProtocol(packet) {
    const priority = ["HTTP", "DNS", "TLS", "ICMPv6", "ICMP", "TCP", "UDP", "ARP", "IPv6", "IPv4", "Ethernet", "SLL2", "SLL", "Loopback", "Frame"];
    return priority.find(protocol => packet.protocols.includes(protocol)) || packet.protocols[packet.protocols.length - 1] || "Frame";
  }

  function buildPacketSearchText(packet) {
    const values = [
      packet.index,
      packet.relTime,
      packet.src,
      packet.dst,
      packet.sport,
      packet.dport,
      packet.protocol,
      packet.protocols.join(" "),
      packet.info,
      packet.summary
    ];
    if (packet.dns) {
      values.push(...packet.dns.questions.map(item => `${item.name} ${item.type}`));
      values.push(...packet.dns.answers.map(item => `${item.name} ${item.type} ${item.data}`));
    }
    if (packet.http) {
      values.push(packet.http.firstLine, packet.http.host);
    }
    return values.filter(value => value != null && value !== "").join(" ").toLowerCase();
  }

  function markTruncated(packet, what) {
    packet.warnings.push(`${what} truncated`);
    packet.info = `${what} truncated`;
  }

  function linkTypeName(linkType) {
    const names = {
      0: "BSD loopback",
      1: "Ethernet",
      101: "Raw IP",
      113: "Linux cooked",
      228: "IPv4/IPv6",
      276: "Linux cooked v2"
    };
    return names[linkType] || "Unknown";
  }

  function etherTypeName(type) {
    const names = {
      0x0800: "IPv4",
      0x0806: "ARP",
      0x86dd: "IPv6",
      0x8100: "802.1Q VLAN",
      0x88a8: "802.1ad VLAN"
    };
    return names[type] || "EtherType";
  }

  function ipProtocolName(protocol) {
    const names = {
      0: "Hop-by-Hop Options",
      1: "ICMP",
      2: "IGMP",
      6: "TCP",
      17: "UDP",
      43: "Routing",
      44: "Fragment",
      50: "ESP",
      51: "Authentication",
      58: "ICMPv6",
      59: "No Next Header",
      60: "Destination Options",
      132: "SCTP"
    };
    return names[protocol] || "Protocol";
  }

  function isIPv6ExtensionHeader(header) {
    return [0, 43, 44, 51, 60].includes(header);
  }

  function tcpFlagNames(flags, ns) {
    const names = [];
    if (ns) names.push("NS");
    if (flags & 0x80) names.push("CWR");
    if (flags & 0x40) names.push("ECE");
    if (flags & 0x20) names.push("URG");
    if (flags & 0x10) names.push("ACK");
    if (flags & 0x08) names.push("PSH");
    if (flags & 0x04) names.push("RST");
    if (flags & 0x02) names.push("SYN");
    if (flags & 0x01) names.push("FIN");
    return names;
  }

  function icmpTypeName(type, code) {
    const names = {
      0: "Echo Reply",
      3: "Destination Unreachable",
      5: "Redirect",
      8: "Echo Request",
      11: "Time Exceeded",
      12: "Parameter Problem"
    };
    if (type === 3 && code === 3) {
      return "Port Unreachable";
    }
    return names[type] || "ICMP";
  }

  function icmpv6TypeName(type) {
    const names = {
      1: "Destination Unreachable",
      2: "Packet Too Big",
      3: "Time Exceeded",
      4: "Parameter Problem",
      128: "Echo Request",
      129: "Echo Reply",
      133: "Router Solicitation",
      134: "Router Advertisement",
      135: "Neighbor Solicitation",
      136: "Neighbor Advertisement"
    };
    return names[type] || "ICMPv6";
  }

  function arpOperation(op) {
    const names = {
      1: "request",
      2: "reply",
      3: "request reverse",
      4: "reply reverse"
    };
    return names[op] || "operation";
  }

  function dnsTypeName(type) {
    const names = {
      1: "A",
      2: "NS",
      5: "CNAME",
      6: "SOA",
      12: "PTR",
      15: "MX",
      16: "TXT",
      28: "AAAA",
      33: "SRV",
      41: "OPT",
      65: "HTTPS",
      255: "ANY"
    };
    return names[type] || `TYPE${type}`;
  }

  function dnsRcodeName(code) {
    const names = {
      0: "NoError",
      1: "FormErr",
      2: "ServFail",
      3: "NXDomain",
      4: "NotImp",
      5: "Refused"
    };
    return names[code] || `RCode${code}`;
  }

  function tlsContentType(type) {
    const names = {
      20: "Change Cipher Spec",
      21: "Alert",
      22: "Handshake",
      23: "Application Data"
    };
    return names[type] || "TLS Record";
  }

  function tlsHandshakeType(type) {
    const names = {
      1: "Client Hello",
      2: "Server Hello",
      4: "New Session Ticket",
      8: "Encrypted Extensions",
      11: "Certificate",
      12: "Server Key Exchange",
      13: "Certificate Request",
      14: "Server Hello Done",
      15: "Certificate Verify",
      16: "Client Key Exchange",
      20: "Finished"
    };
    return names[type] || `Handshake ${type}`;
  }

  function readU16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
  }

  function readU32BE(bytes, offset) {
    return ((bytes[offset] * 0x1000000) + ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])) >>> 0;
  }

  function readU32LE(bytes, offset) {
    return ((bytes[offset + 3] * 0x1000000) + ((bytes[offset + 2] << 16) | (bytes[offset + 1] << 8) | bytes[offset])) >>> 0;
  }

  function formatMac(bytes, offset) {
    if (bytes.length < offset + 6) {
      return "-";
    }
    return Array.from(bytes.slice(offset, offset + 6)).map(value => hex(value, 2)).join(":");
  }

  function formatIPv4(bytes, offset) {
    if (bytes.length < offset + 4) {
      return "-";
    }
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
  }

  function formatIPv6(bytes, offset) {
    if (bytes.length < offset + 16) {
      return "-";
    }
    const words = [];
    for (let i = 0; i < 16; i += 2) {
      words.push(readU16BE(bytes, offset + i));
    }
    let bestStart = -1;
    let bestLength = 0;
    for (let i = 0; i < words.length; i += 1) {
      if (words[i] !== 0) {
        continue;
      }
      let j = i;
      while (j < words.length && words[j] === 0) {
        j += 1;
      }
      if (j - i > bestLength) {
        bestStart = i;
        bestLength = j - i;
      }
      i = j;
    }
    if (bestLength < 2) {
      bestStart = -1;
    }
    if (bestStart >= 0) {
      const before = words.slice(0, bestStart).map(word => word.toString(16));
      const after = words.slice(bestStart + bestLength).map(word => word.toString(16));
      if (!before.length && !after.length) {
        return "::";
      }
      if (!before.length) {
        return `::${after.join(":")}`;
      }
      if (!after.length) {
        return `${before.join(":")}::`;
      }
      return `${before.join(":")}::${after.join(":")}`;
    }
    return words.map(word => word.toString(16)).join(":");
  }

  function bytesToHex(bytes, offset, length) {
    const end = Math.min(bytes.length, offset + length);
    const parts = [];
    for (let i = offset; i < end; i += 1) {
      parts.push(hex(bytes[i], 2));
    }
    return parts.join(" ");
  }

  function hexDump(bytes) {
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const slice = bytes.slice(offset, offset + 16);
      const hexPart = Array.from(slice).map(value => hex(value, 2)).join(" ").padEnd(47, " ");
      const asciiPart = Array.from(slice).map(value => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".").join("");
      lines.push(`${hex(offset, 6)}  ${hexPart}  ${asciiPart}`);
    }
    return lines.join("\n");
  }

  function decodeAscii(bytes) {
    if (TEXT_DECODER) {
      return TEXT_DECODER.decode(bytes);
    }
    return Array.from(bytes).map(value => String.fromCharCode(value)).join("");
  }

  function hex(value, width) {
    return Number(value).toString(16).padStart(width, "0");
  }

  function hexSignature(bytes, length) {
    return Array.from(bytes.slice(0, length)).map(value => hex(value, 2)).join("");
  }

  function paddedLength(length) {
    return (length + 3) & ~3;
  }

  function sortMapDesc(map) {
    return new Map(Array.from(map.entries()).sort((a, b) => b[1] - a[1]));
  }

  function formatBytes(value) {
    const bytes = Number(value) || 0;
    if (bytes < 1024) {
      return `${formatNumber(bytes)} B`;
    }
    const units = ["KB", "MB", "GB", "TB"];
    let current = bytes / 1024;
    let unitIndex = 0;
    while (current >= 1024 && unitIndex < units.length - 1) {
      current /= 1024;
      unitIndex += 1;
    }
    return `${current >= 10 ? current.toFixed(1) : current.toFixed(2)} ${units[unitIndex]}`;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat().format(value);
  }

  function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) {
      return "0 ms";
    }
    if (seconds < 1) {
      return `${(seconds * 1000).toFixed(seconds < 0.01 ? 3 : 1)} ms`;
    }
    if (seconds < 60) {
      return `${seconds.toFixed(seconds < 10 ? 3 : 2)} s`;
    }
    const minutes = Math.floor(seconds / 60);
    const rest = seconds - minutes * 60;
    return `${minutes}m ${rest.toFixed(1)}s`;
  }

  function formatAbsoluteTime(seconds) {
    if (!Number.isFinite(seconds)) {
      return "-";
    }
    return new Date(seconds * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
  }

  function formatLocalTime(seconds) {
    if (!Number.isFinite(seconds)) {
      return "-";
    }
    return new Intl.DateTimeFormat(undefined, {
      hour: "2-digit",
      minute: "2-digit"
    }).format(new Date(seconds * 1000));
  }

  function formatFieldValue(value) {
    if (Array.isArray(value)) {
      return value.join(", ");
    }
    if (value == null || value === "") {
      return "-";
    }
    return String(value);
  }

  function isMonoValue(value) {
    const text = formatFieldValue(value);
    return /(?:\d+\.\d+\.\d+\.\d+)|(?:[0-9a-f]{2}:){2,}|(?:0x[0-9a-f]+)/i.test(text) || /^\d+$/.test(text);
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function csvCell(value) {
    const text = String(value ?? "");
    if (/[",\n\r]/.test(text)) {
      return `"${text.replace(/"/g, "\"\"")}"`;
    }
    return text;
  }

  function stripQuotes(value) {
    if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
      return value.slice(1, -1);
    }
    return value;
  }

  function debounce(fn, delay) {
    let timer = 0;
    return (...args) => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => fn(...args), delay);
    };
  }

  function nextFrame() {
    return new Promise(resolve => requestAnimationFrame(resolve));
  }
})();
