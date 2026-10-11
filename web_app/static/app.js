"use strict";

// Helper selectors
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

// Application State
const state = {
  sessionId: null,
  source: null,
  results: [],
  exifResults: [],
  githubData: null,
  gravatarData: null,
  keybaseData: null,
  snapchatData: null,
  instagramData: null,
  phoneData: null,
  breachData: null,
  dorksData: [],
  socidData: {},
  osintFrameworkData: null,
  holeheData: [],
  correlations: [],
  riskAssessment: null,
  networkNodes: [],
  networkLinks: [],
  networkSimulationRunning: false,
  currentView: "profiles",
  filter: "found",
  exifFilter: "all",
  sortBy: "default",
  startedAt: null,
  timer: null,
  finished: false,
  selectedExifRaw: null,
};

// Cached DOM Elements
const elements = {
  form: $("#search-form"),
  input: $("#username-input"),
  searchButton: $("#search-button"),
  clearButton: $("#search-clear-btn"),
  error: $("#form-error"),
  advancedToggle: $("#advanced-toggle"),
  advanced: $("#advanced-options"),
  timeout: $("#timeout-input"),
  timeoutVal: $("#timeout-val"),
  maxImages: $("#max-images-input"),
  imagesVal: $("#images-val"),
  proxy: $("#proxy-input"),
  nsfw: $("#nsfw-input"),
  scanExif: $("#exif-input"),
  deepOsint: $("#deep-osint-input"),
  
  casePanel: $("#case-panel"),
  how: $("#how-it-works"),
  caseId: $("#case-id"),
  caseStatusBadge: $("#case-status-badge"),
  caseStatusText: $("#case-status-text"),
  title: $("#case-title"),
  subtitle: $("#case-subtitle"),
  progressBar: $("#progress-bar"),
  progressPercent: $("#progress-percent"),
  
  found: $("#found-count"),
  exifCount: $("#exif-count"),
  gpsBadgeCount: $("#gps-badge-count"),
  checked: $("#checked-count"),
  total: $("#total-count"),
  elapsed: $("#elapsed-time"),
  exposureScore: $("#exposure-score"),
  exposureLevel: $("#exposure-level"),
  metricRiskCard: $("#metric-risk-card"),
  
  list: $("#result-list"),
  empty: $("#empty-results"),
  
  // Tabs & Views
  viewTabs: $$(".view-tab"),
  viewProfiles: $("#view-profiles-container"),
  viewExif: $("#view-exif-container"),
  viewDeepOsint: $("#view-deep-osint-container"),
  viewMap: $("#view-map-container"),
  viewFramework: $("#view-framework-container"),
  viewDossier: $("#view-dossier-container"),
  
  tabProfilesCount: $("#tab-profiles-count"),
  tabExifCount: $("#tab-exif-count"),
  tabDeepCount: $("#tab-deep-count"),
  tabFramework: $("#tab-framework"),
  
  // Exif View
  exifGrid: $("#exif-grid"),
  emptyExif: $("#empty-exif"),
  exifFilterBtns: $$(".exif-filter-btn"),
  exifFilterAllCount: $("#exif-filter-all-count"),
  exifFilterGpsCount: $("#exif-filter-gps-count"),
  exifFilterCameraCount: $("#exif-filter-camera-count"),
  
  // Deep OSINT Content
  githubContent: $("#github-osint-content"),
  gravatarContent: $("#gravatar-osint-content"),
  keybaseContent: $("#keybase-osint-content"),
  snapchatContent: $("#snapchat-osint-content"),
  instagramContent: $("#instagram-osint-content"),
  socidContent: $("#socid-osint-content"),
  phoneContent: $("#phone-osint-content"),
  breachContent: $("#breach-osint-content"),
  dorksContent: $("#dorks-osint-content"),
  holeheContent: $("#holehe-osint-content"),
  contactsContent: $("#contacts-osint-content"),
  correlationsContent: $("#correlations-osint-content"),

  // Framework View
  frameworkSearchInput: $("#framework-search-input"),
  frameworkCategoriesContainer: $("#framework-categories-container"),

  // OSINT Node Map
  mapCanvas: $("#osint-network-canvas"),
  mapTooltip: $("#map-node-tooltip"),
  mapResetBtn: $("#map-reset-btn"),
  
  // Dossier View
  dossierPdfBtn: $("#dossier-pdf-btn"),
  dossierClaimedNum: $("#dossier-claimed-num"),
  dossierImagesNum: $("#dossier-images-num"),
  dossierGpsNum: $("#dossier-gps-num"),
  dossierExposureNum: $("#dossier-exposure-num"),
  
  // Action Buttons
  downloadPdfBtn: $("#download-pdf-btn"),
  exportJsonBtn: $("#export-json-button"),
  cancel: $("#cancel-button"),
  newSearch: $("#new-search-button"),
  copyAll: $("#copy-all-button"),
  
  resultFilter: $("#result-filter"),
  sortSelect: $("#sort-select"),
  toastContainer: $("#toast-container"),
  
  // Modal
  exifModal: $("#exif-modal"),
  modalTitle: $("#modal-title"),
  modalSubtitle: $("#modal-subtitle"),
  modalCloseBtn: $("#modal-close-btn"),
  modalCopyJson: $("#modal-copy-json"),
  modalImgLink: $("#modal-img-link"),
  modalTagsContainer: $("#modal-tags-container"),
  
  themeToggle: $("#theme-toggle"),
  themeIconSun: $("#theme-icon-sun"),
  themeIconMoon: $("#theme-icon-moon"),
  serverDot: $("#server-dot"),
  serverLabel: $("#server-label"),
  exiftoolPill: $("#exiftool-pill"),
  exifLabel: $("#exif-label"),
  networkCount: $("#network-count"),
};

// ============================================================================
// Toast Notification System
// ============================================================================
function showToast(message, type = "info") {
  if (!elements.toastContainer) return;

  const toast = document.createElement("div");
  toast.className = `toast-item ${type === "success" ? "toast-success" : type === "error" ? "toast-error" : ""}`;

  let iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
  if (type === "success") {
    iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
  } else if (type === "error") {
    iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
  }

  toast.innerHTML = `${iconSvg}<span>${message}</span>`;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

// Copy Text Helper
async function copyToClipboard(text, successMsg = "Copied to clipboard!") {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMsg, "success");
    return true;
  } catch {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    document.body.appendChild(textArea);
    textArea.select();
    try {
      document.execCommand("copy");
      showToast(successMsg, "success");
      return true;
    } catch {
      showToast("Unable to copy to clipboard", "error");
      return false;
    } finally {
      textArea.remove();
    }
  }
}

function formatElapsed(seconds) {
  const value = Math.max(0, Math.floor(seconds));
  const mins = String(Math.floor(value / 60)).padStart(2, "0");
  const secs = String(value % 60).padStart(2, "0");
  return `${mins}:${secs}`;
}

// ============================================================================
// State Management
// ============================================================================
function setRunningState(running) {
  elements.searchButton.disabled = running;
  const buttonSpan = elements.searchButton.querySelector("span");
  if (buttonSpan) {
    buttonSpan.textContent = running ? "Scanning & Auditing…" : "Launch Investigation";
  }
  elements.cancel.hidden = !running;
  elements.newSearch.hidden = running;

  const hasClaimed = state.results.some((r) => r.status === "claimed");
  const canDownload = hasClaimed || state.exifResults.length > 0;
  elements.downloadPdfBtn.disabled = !canDownload;
  elements.exportJsonBtn.disabled = !canDownload;
  elements.dossierPdfBtn.disabled = !canDownload;

  if (running) {
    elements.caseStatusBadge.className = "case-status-badge scanning";
    elements.caseStatusText.textContent = "Scanning Active";
  }
}

function resetCase() {
  state.results = [];
  state.exifResults = [];
  state.githubData = null;
  state.gravatarData = null;
  state.keybaseData = null;
  state.snapchatData = null;
  state.instagramData = null;
  state.phoneData = null;
  state.breachData = null;
  state.dorksData = [];
  state.socidData = {};
  state.holeheData = [];
  state.correlations = [];
  state.riskAssessment = null;
  state.networkNodes = [];
  state.networkLinks = [];
  state.finished = false;
  state.filter = "found";
  state.exifFilter = "all";
  state.sortBy = "default";
  
  elements.list.innerHTML = "";
  elements.exifGrid.innerHTML = "";
  elements.found.textContent = "0";
  elements.exifCount.textContent = "0";
  elements.gpsBadgeCount.textContent = "0 GPS Geotags";
  elements.checked.textContent = "0";
  elements.total.textContent = "of — platforms";
  elements.elapsed.textContent = "00:00";
  elements.exposureScore.textContent = "0";
  elements.exposureLevel.textContent = "LOW EXPOSURE";
  elements.progressBar.style.width = "0%";
  elements.progressPercent.textContent = "0%";
  elements.empty.hidden = false;

  elements.tabProfilesCount.textContent = "0";
  elements.tabExifCount.textContent = "0";
  elements.tabDeepCount.textContent = "0";
  
  elements.dossierClaimedNum.textContent = "0";
  elements.dossierImagesNum.textContent = "0";
  elements.dossierGpsNum.textContent = "0";
  elements.dossierExposureNum.textContent = "0/100";

  elements.downloadPdfBtn.disabled = true;
  elements.exportJsonBtn.disabled = true;
  elements.dossierPdfBtn.disabled = true;

  resetDeepOsintViews();
  switchView("profiles");
  updateTabCounts();
}

function resetDeepOsintViews() {
  if (elements.githubContent) elements.githubContent.innerHTML = `<p class="panel-card-empty">No GitHub intelligence available yet for this handle.</p>`;
  if (elements.gravatarContent) elements.gravatarContent.innerHTML = `<p class="panel-card-empty">No Gravatar profile linked to this username.</p>`;
  if (elements.keybaseContent) elements.keybaseContent.innerHTML = `<p class="panel-card-empty">No Keybase identity records found for this username.</p>`;
  if (elements.snapchatContent) elements.snapchatContent.innerHTML = `<p class="panel-card-empty">Querying Snapchat public registry…</p>`;
  if (elements.instagramContent) elements.instagramContent.innerHTML = `<p class="panel-card-empty">Awaiting Instagram profile target…</p>`;
  if (elements.socidContent) elements.socidContent.innerHTML = `<p class="panel-card-empty">Extracting user IDs from claimed platform responses…</p>`;
  if (elements.phoneContent) elements.phoneContent.innerHTML = `<p class="panel-card-empty">No phone number identified from metadata or profiles yet.</p>`;
  if (elements.breachContent) elements.breachContent.innerHTML = `<p class="panel-card-empty">Awaiting email discovery to cross-reference known breach databases…</p>`;
  if (elements.dorksContent) elements.dorksContent.innerHTML = `<p class="panel-card-empty">Generating targeted OSINT search dorks…</p>`;
  if (elements.holeheContent) elements.holeheContent.innerHTML = `<p class="panel-card-empty">Harvesting emails to probe registered accounts…</p>`;
  if (elements.contactsContent) elements.contactsContent.innerHTML = `<p class="panel-card-empty">Scanning profiles for contact details…</p>`;
  if (elements.correlationsContent) elements.correlationsContent.innerHTML = `<p class="panel-card-empty">Analyzing avatar hashes across claimed platforms…</p>`;
}

// ============================================================================
// View Tabs Management
// ============================================================================
function switchView(viewName) {
  state.currentView = viewName;
  elements.viewTabs.forEach((tab) => {
    const isActive = tab.dataset.view === viewName;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-selected", String(isActive));
  });

  elements.viewProfiles.hidden = viewName !== "profiles";
  elements.viewExif.hidden = viewName !== "exif";
  elements.viewDeepOsint.hidden = viewName !== "deep-osint";
  if (elements.viewMap) elements.viewMap.hidden = viewName !== "map";
  if (elements.viewFramework) elements.viewFramework.hidden = viewName !== "framework";
  elements.viewDossier.hidden = viewName !== "dossier";

  if (viewName === "exif") {
    renderExifCards();
  } else if (viewName === "map") {
    loadAndRenderNetworkGraph();
  } else if (viewName === "framework") {
    loadAndRenderOsintFramework();
  }
}

// ============================================================================
// Profiles List View
// ============================================================================
function createResultCard(result) {
  const card = document.createElement("article");
  card.className = `result-card status-${result.status}`;
  card.dataset.site = result.site.toLowerCase();
  card.dataset.url = result.url.toLowerCase();
  card.dataset.status = result.status;
  card.dataset.response = String(result.response_time ?? 999999);

  const isClaimed = result.status === "claimed";
  const statusLabel = isClaimed ? "Confirmed" : result.status === "available" ? "Not Found" : "Error";

  // Quick avatar indicator if this site was scanned with exif
  const siteExif = state.exifResults.filter((e) => e.site_name.toLowerCase() === result.site.toLowerCase());
  const avatarItem = siteExif.find((e) => e.is_avatar) || siteExif[0];
  const avatarThumbHtml = avatarItem
    ? `<img class="card-avatar-thumb" src="${escapeHtml(avatarItem.original_url)}" alt="${escapeHtml(result.site)} avatar" onerror="this.remove()">`
    : "";

  card.innerHTML = `
    <div class="result-card-inner">
      <div class="card-top-row">
        <div class="site-identity">
          ${avatarThumbHtml}
          <div class="site-titles">
            <h3 class="site-name">${escapeHtml(result.site)}</h3>
            <span class="site-handle">@${escapeHtml(result.username)}</span>
          </div>
        </div>
        <span class="status-badge ${result.status}">
          <span class="status-dot-sm ${isClaimed ? 'dot-success' : 'dot-muted'}"></span>
          ${statusLabel}
        </span>
      </div>

      <div class="card-link-row">
        <a class="profile-link" href="${escapeHtml(result.url)}" target="_blank" rel="noopener noreferrer" title="Open profile directly in new tab">
          <span class="link-url-text">${escapeHtml(result.url)}</span>
          <svg class="external-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
            <polyline points="15 3 21 3 21 9"/>
            <line x1="10" y1="14" x2="21" y2="3"/>
          </svg>
        </a>
      </div>

      <div class="card-footer-row">
        <span class="card-response-time" title="Query Latency">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
          </svg>
          ${result.response_time !== null && result.response_time !== undefined ? `${result.response_time} ms` : "—"}
        </span>

        <div class="card-btn-actions">
          <button class="icon-action-btn copy-btn" type="button" title="Copy profile URL">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  `;

  const copyBtn = card.querySelector(".copy-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => copyToClipboard(result.url, `Copied ${result.site} link!`));
  }

  return card;
}

function renderProfiles() {
  const query = elements.resultFilter.value.trim().toLowerCase();
  const filter = state.filter;

  let filtered = state.results.filter((item) => {
    if (filter === "found" && item.status !== "claimed") return false;
    if (filter === "issues" && (item.status === "claimed" || item.status === "available")) return false;
    if (query && !item.site.toLowerCase().includes(query) && !item.url.toLowerCase().includes(query)) {
      return false;
    }
    return true;
  });

  if (state.sortBy === "alpha") {
    filtered.sort((a, b) => a.site.localeCompare(b.site));
  } else if (state.sortBy === "fastest") {
    filtered.sort((a, b) => (a.response_time ?? 999999) - (b.response_time ?? 999999));
  }

  elements.list.innerHTML = "";
  if (filtered.length === 0) {
    elements.empty.hidden = false;
  } else {
    elements.empty.hidden = true;
    const fragment = document.createDocumentFragment();
    filtered.forEach((r) => fragment.appendChild(createResultCard(r)));
    elements.list.appendChild(fragment);
  }
}

// ============================================================================
// ExifTool Forensics Cards
// ============================================================================
function renderExifCards() {
  let items = [...state.exifResults];
  if (state.exifFilter === "gps") {
    items = items.filter((i) => i.has_gps);
  } else if (state.exifFilter === "camera") {
    items = items.filter((i) => i.camera && i.camera !== "Unknown / Stripped");
  }

  elements.exifGrid.innerHTML = "";
  if (items.length === 0) {
    elements.emptyExif.hidden = false;
    return;
  }
  elements.emptyExif.hidden = false;

  const fragment = document.createDocumentFragment();
  items.forEach((img, idx) => {
    const card = document.createElement("article");
    card.className = `exif-card ${img.has_gps ? "has-gps-alert" : ""}`;

    const roleBadge = img.is_avatar ? "AVATAR" : "MEDIA";
    const cameraText = escapeHtml(img.camera || "Unknown / Stripped");
    const dateText = escapeHtml(img.date_original || "No EXIF date");
    const softwareText = escapeHtml(img.software || "None recorded");
    const dimText = escapeHtml(img.dimensions || "—");

    let gpsHtml = "";
    if (img.has_gps) {
      gpsHtml = `
        <div class="exif-gps-badge-row">
          <span class="gps-pin-tag">📍 GPS DETECTED</span>
          <span class="gps-coords-text">${img.latitude}, ${img.longitude}</span>
          <div class="gps-links-wrap">
            <a class="gps-map-link google" href="${escapeHtml(img.google_maps_url)}" target="_blank" rel="noopener noreferrer">
              Google Maps ↗
            </a>
            <a class="gps-map-link osm" href="${escapeHtml(img.osm_url)}" target="_blank" rel="noopener noreferrer">
              OpenStreetMap ↗
            </a>
          </div>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="exif-card-inner">
        <div class="exif-img-preview-box">
          <img class="exif-thumb-img" src="${escapeHtml(img.original_url)}" alt="${escapeHtml(img.site_name)} image" loading="lazy" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🖼️</text></svg>'">
          <span class="exif-role-tag ${img.is_avatar ? 'role-avatar' : 'role-media'}">${roleBadge}</span>
        </div>

        <div class="exif-details-box">
          <div class="exif-top-meta">
            <span class="exif-site-badge">${escapeHtml(img.site_name)}</span>
            <span class="exif-handle">@${escapeHtml(img.username)}</span>
          </div>

          <div class="exif-url-row">
            <a class="exif-direct-url" href="${escapeHtml(img.original_url)}" target="_blank" rel="noopener noreferrer" title="View original image source">
              <span>${escapeHtml(img.original_url)}</span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15 3 21 3 21 9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </a>
          </div>

          <div class="exif-metadata-grid">
            <div class="meta-item">
              <span class="meta-label">Camera / Device</span>
              <strong class="meta-value">${cameraText}</strong>
            </div>
            <div class="meta-item">
              <span class="meta-label">Software Signature</span>
              <strong class="meta-value">${softwareText}</strong>
            </div>
            <div class="meta-item">
              <span class="meta-label">Date Created</span>
              <strong class="meta-value">${dateText}</strong>
            </div>
            <div class="meta-item">
              <span class="meta-label">Dimensions / Size</span>
              <strong class="meta-value">${dimText} • ${escapeHtml(img.file_size || '—')}</strong>
            </div>
          </div>

          ${gpsHtml}

          ${img.reverse_image_links ? `
            <div class="exif-reverse-search-row">
              <span class="reverse-label">Reverse Visual &amp; Scene Search:</span>
              <div class="reverse-search-btns">
                <a href="${escapeHtml(img.reverse_image_links.google_lens)}" target="_blank" rel="noopener noreferrer" class="reverse-search-btn" title="Search via Google Lens">
                  <span>Google Lens ↗</span>
                </a>
                <a href="${escapeHtml(img.reverse_image_links.yandex)}" target="_blank" rel="noopener noreferrer" class="reverse-search-btn" title="Search via Yandex Visual">
                  <span>Yandex ↗</span>
                </a>
                <a href="${escapeHtml(img.reverse_image_links.tineye)}" target="_blank" rel="noopener noreferrer" class="reverse-search-btn" title="Search via TinEye">
                  <span>TinEye ↗</span>
                </a>
                <a href="${escapeHtml(img.reverse_image_links.bing)}" target="_blank" rel="noopener noreferrer" class="reverse-search-btn" title="Search via Bing Visual">
                  <span>Bing ↗</span>
                </a>
                <a href="https://geospy.ai" target="_blank" rel="noopener noreferrer" class="reverse-search-btn" title="AI Architectural &amp; Scene Geolocation">
                  <span>Geospy AI ↗</span>
                </a>
              </div>
            </div>
          ` : ''}

          <div class="exif-card-actions">
            <button class="inspect-tags-btn" type="button" data-idx="${idx}">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <span>View All Raw EXIF Tags (${img.raw_tags_count || 0})</span>
            </button>
          </div>
        </div>
      </div>
    `;

    const inspectBtn = card.querySelector(".inspect-tags-btn");
    if (inspectBtn) {
      inspectBtn.addEventListener("click", () => openExifModal(img));
    }

    fragment.appendChild(card);
  });

  elements.exifGrid.appendChild(fragment);
  elements.emptyExif.hidden = items.length > 0;
}

// ============================================================================
// Raw EXIF Modal
// ============================================================================
function openExifModal(img) {
  state.selectedExifRaw = img;
  elements.modalTitle.textContent = `${img.site_name} (${img.is_avatar ? "Avatar" : "Media"})`;
  elements.modalSubtitle.textContent = img.original_url;
  elements.modalImgLink.href = img.original_url;

  const raw = img.raw_metadata || {};
  const rows = Object.entries(raw).map(([key, val]) => `
    <tr>
      <td class="tag-key-cell"><code>${escapeHtml(key)}</code></td>
      <td class="tag-val-cell">${escapeHtml(typeof val === "object" ? JSON.stringify(val) : String(val))}</td>
    </tr>
  `).join("");

  elements.modalTagsContainer.innerHTML = `
    <table class="modal-tags-table">
      <thead>
        <tr>
          <th>EXIF Tag Name</th>
          <th>Extracted Value</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  `;

  elements.exifModal.hidden = false;
  document.body.classList.add("modal-open");
}

function closeExifModal() {
  elements.exifModal.hidden = true;
  document.body.classList.remove("modal-open");
}

// ============================================================================
// Deep OSINT Renderers
// ============================================================================
function updateGitHubCard(gh) {
  if (!gh) return;
  state.githubData = gh;
  elements.githubContent.innerHTML = `
    <div class="osint-profile-row">
      <img class="osint-avatar-circle" src="${escapeHtml(gh.avatar_url)}" alt="GitHub avatar" onerror="this.remove()">
      <div>
        <h4 class="osint-name">${escapeHtml(gh.name || gh.username)}</h4>
        <a class="osint-link" href="${escapeHtml(gh.html_url)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(gh.username)} on GitHub ↗</a>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">Bio:</span><span class="kv-val">${escapeHtml(gh.bio || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Location:</span><span class="kv-val">${escapeHtml(gh.location || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Company:</span><span class="kv-val">${escapeHtml(gh.company || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Public Email:</span><span class="kv-val highlight">${escapeHtml(gh.email || 'None on profile')}</span></div>
      <div class="osint-kv"><span class="kv-label">Public Repos:</span><span class="kv-val">${gh.public_repos || 0}</span></div>
      <div class="osint-kv"><span class="kv-label">Public SSH Keys:</span><span class="kv-val">${gh.public_ssh_keys_count || 0}</span></div>
    </div>
    ${gh.commit_emails_discovered && gh.commit_emails_discovered.length > 0 ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Git Commit Author Emails Discovered:</span>
        <div class="email-tags-list">
          ${gh.commit_emails_discovered.map(e => `<span class="email-tag">${escapeHtml(e)}</span>`).join('')}
        </div>
      </div>
    ` : ''}
  `;
}

function updateGravatarCard(grav) {
  if (!grav) return;
  state.gravatarData = grav;
  const accounts = grav.linked_accounts || [];
  elements.gravatarContent.innerHTML = `
    <div class="osint-profile-row">
      ${grav.avatar_url ? `<img class="osint-avatar-circle" src="${escapeHtml(grav.avatar_url)}" alt="Gravatar avatar">` : ''}
      <div>
        <h4 class="osint-name">${escapeHtml(grav.display_name || 'Gravatar Record')}</h4>
        <a class="osint-link" href="${escapeHtml(grav.profile_url)}" target="_blank" rel="noopener noreferrer">View Gravatar Profile ↗</a>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">About:</span><span class="kv-val">${escapeHtml(grav.about_me || 'No bio')}</span></div>
      <div class="osint-kv"><span class="kv-label">Location:</span><span class="kv-val">${escapeHtml(grav.current_location || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Linked Accounts:</span><span class="kv-val">${accounts.length} verified</span></div>
    </div>
    ${accounts.length > 0 ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Verified Linked Networks:</span>
        <div class="linked-accounts-chips">
          ${accounts.map(a => `<a class="account-chip" href="${escapeHtml(a.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(a.domain)}</a>`).join('')}
        </div>
      </div>
    ` : ''}
  `;
}

function updateKeybaseCard(kb) {
  if (!kb || !elements.keybaseContent) return;
  state.keybaseData = kb;
  const proofs = kb.proofs || [];
  elements.keybaseContent.innerHTML = `
    <div class="osint-profile-row">
      <div class="osint-avatar-circle" style="display:flex;align-items:center;justify-content:center;background:#2563eb;color:#fff;font-size:1.2rem;">🔑</div>
      <div>
        <h4 class="osint-name">${escapeHtml(kb.full_name || kb.username)}</h4>
        <a class="osint-link" href="${escapeHtml(kb.profile_url)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(kb.username)} on Keybase ↗</a>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">Bio:</span><span class="kv-val">${escapeHtml(kb.bio || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Location:</span><span class="kv-val">${escapeHtml(kb.location || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Cryptographic Proofs:</span><span class="kv-val">${proofs.length} verified</span></div>
    </div>
    ${proofs.length > 0 ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Verified Cryptographic Identity Proofs:</span>
        <div class="linked-accounts-chips">
          ${proofs.map(p => `
            <a class="account-chip" href="${escapeHtml(p.human_url || p.service_url)}" target="_blank" rel="noopener noreferrer">
              <strong>${escapeHtml(p.service)}:</strong> ${escapeHtml(p.nametag)}
            </a>
          `).join('')}
        </div>
      </div>
    ` : ''}
    ${kb.cryptocurrency_addresses && kb.cryptocurrency_addresses.length > 0 ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Cryptocurrency Wallets:</span>
        <div class="email-tags-list">
          ${kb.cryptocurrency_addresses.map(c => `<span class="email-tag" style="background:rgba(234,179,8,0.12);color:#facc15;border-color:rgba(234,179,8,0.3);">${escapeHtml(c)}</span>`).join('')}
        </div>
      </div>
    ` : ''}
  `;
}

function updateContactsCard(contacts) {
  const emails = contacts.emails || [];
  const phones = contacts.phones || [];
  if (emails.length === 0 && phones.length === 0) {
    elements.contactsContent.innerHTML = `<p class="panel-card-empty">No explicit contact emails or phone numbers found in scanned profiles.</p>`;
    return;
  }

  let html = `<div class="contacts-grid">`;
  if (emails.length > 0) {
    html += `
      <div class="contact-section">
        <span class="contact-sec-title">Public Email Addresses:</span>
        <ul class="contact-list">
          ${emails.map(e => `<li><span class="contact-pill email">📧 ${escapeHtml(e)}</span></li>`).join('')}
        </ul>
      </div>
    `;
  }
  if (phones.length > 0) {
    html += `
      <div class="contact-section">
        <span class="contact-sec-title">Phone Numbers (libphonenumber):</span>
        <ul class="contact-list">
          ${phones.map(p => `<li><span class="contact-pill phone">📞 ${escapeHtml(p)}</span></li>`).join('')}
        </ul>
      </div>
    `;
  }
  html += `</div>`;
  elements.contactsContent.innerHTML = html;
}

function updateCorrelationsCard(correlations) {
  if (!correlations || correlations.length === 0) {
    elements.correlationsContent.innerHTML = `<p class="panel-card-empty">No matching profile pictures reused across separate platforms.</p>`;
    return;
  }

  let html = `<div class="correlation-groups-wrap">`;
  correlations.forEach((c) => {
    html += `
      <div class="correlation-card">
        <div class="corr-top">
          <img class="corr-thumb" src="${escapeHtml(c.avatar_url)}" alt="Shared avatar">
          <div>
            <span class="corr-title">Identical Avatar Reused Across ${c.shared_count} Platforms</span>
            <code class="corr-hash">MD5: ${escapeHtml(c.md5_hash)}</code>
          </div>
        </div>
        <div class="corr-sites-pills">
          ${c.sites.map(s => `<span class="corr-site-pill">${escapeHtml(s)}</span>`).join('')}
        </div>
      </div>
    `;
  });
  html += `</div>`;
  elements.correlationsContent.innerHTML = html;
}

function updateSnapchatCard(snap) {
  if (!snap || !elements.snapchatContent) return;
  state.snapchatData = snap;
  elements.snapchatContent.innerHTML = `
    <div class="osint-profile-row">
      ${snap.avatar_url ? `<img class="osint-avatar-circle" src="${escapeHtml(snap.avatar_url)}" alt="Snapchat avatar" style="border-color:#eab308;">` : '<div class="osint-avatar-circle" style="background:#eab308;display:flex;align-items:center;justify-content:center;color:#000;font-size:1.2rem;">👻</div>'}
      <div>
        <h4 class="osint-name">${escapeHtml(snap.display_name || snap.username)}</h4>
        <a class="osint-link" href="${escapeHtml(snap.profile_url)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(snap.username)} on Snapchat ↗</a>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">Display Name:</span><span class="kv-val">${escapeHtml(snap.display_name || snap.username)}</span></div>
      <div class="osint-kv"><span class="kv-label">Bio:</span><span class="kv-val">${escapeHtml(snap.bio || 'No public bio')}</span></div>
      <div class="osint-kv"><span class="kv-label">3D Bitmoji Avatar:</span><span class="kv-val">${snap.avatar_url ? 'Extracted' : 'None'}</span></div>
    </div>
    ${snap.avatar_url ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Snapchat Avatar Media:</span>
        <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:8px;">
          <a href="${escapeHtml(snap.avatar_url)}" target="_blank" rel="noopener noreferrer" class="account-chip">
            View Full Bitmoji ↗
          </a>
          ${snap.snapcode_url ? `<a href="${escapeHtml(snap.snapcode_url)}" target="_blank" rel="noopener noreferrer" class="account-chip">View Snapcode SVG ↗</a>` : ''}
        </div>
      </div>
    ` : ''}
  `;
}

function updateHoleheCard(holeheList) {
  if (!elements.holeheContent) return;
  if (!holeheList || !Array.isArray(holeheList) || holeheList.length === 0) {
    elements.holeheContent.innerHTML = `<p class="panel-card-empty">No active registered platform accounts found for candidate emails.</p>`;
    return;
  }
  
  elements.holeheContent.innerHTML = `
    <div class="osint-sub-block">
      <span class="sub-block-title">Active Account Registrations Detected (${holeheList.length} Platforms):</span>
      <div class="linked-accounts-chips" style="margin-top:8px;">
        ${holeheList.map(h => `
          <div class="account-chip" style="background:rgba(16,185,129,0.12);border-color:rgba(16,185,129,0.3);color:#34d399;">
            <strong>${escapeHtml(h.service)}</strong>
            ${h.email_recovery ? `<span style="opacity:0.75;font-size:0.75rem;">(${escapeHtml(h.email_recovery)})</span>` : ''}
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function updateInstagramCard(ig) {
  if (!ig || !elements.instagramContent) return;
  state.instagramData = ig;
  elements.instagramContent.innerHTML = `
    <div class="osint-profile-row">
      ${ig.profile_pic_url ? `<img class="osint-avatar-circle" src="${escapeHtml(ig.profile_pic_url)}" alt="Instagram avatar" style="border-color:#e1306c;">` : '<div class="osint-avatar-circle" style="background:linear-gradient(45deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.2rem;">📸</div>'}
      <div>
        <h4 class="osint-name">${escapeHtml(ig.full_name || ig.username)}</h4>
        <a class="osint-link" href="${escapeHtml(ig.profile_url)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(ig.username)} on Instagram ↗</a>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">Account ID:</span><span class="kv-val">${escapeHtml(ig.user_id || 'Not public')}</span></div>
      <div class="osint-kv"><span class="kv-label">Phone Hint:</span><span class="kv-val highlight">${escapeHtml(ig.phone_hint || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Email Hint:</span><span class="kv-val highlight">${escapeHtml(ig.email_hint || 'None')}</span></div>
      <div class="osint-kv"><span class="kv-label">Followers / Following:</span><span class="kv-val">${ig.followers_count || 0} / ${ig.following_count || 0}</span></div>
      <div class="osint-kv"><span class="kv-label">Account Status:</span><span class="kv-val">${ig.is_private ? '🔒 Private' : '🌐 Public'} ${ig.is_verified ? '✓ Verified' : ''}</span></div>
      <div class="osint-kv"><span class="kv-label">Bio:</span><span class="kv-val">${escapeHtml(ig.biography || 'No bio')}</span></div>
    </div>
    ${ig.profile_pic_url ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Instagram Avatar Visual Search:</span>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;">
          <a href="https://lens.google.com/uploadbyurl?url=${encodeURIComponent(ig.profile_pic_url)}" target="_blank" rel="noopener noreferrer" class="account-chip">Google Lens ↗</a>
          <a href="https://yandex.com/images/search?rpt=imageview&url=${encodeURIComponent(ig.profile_pic_url)}" target="_blank" rel="noopener noreferrer" class="account-chip">Yandex Visual ↗</a>
        </div>
      </div>
    ` : ''}
  `;
}

function updateSocidCard(socidMap) {
  if (!elements.socidContent) return;
  if (!socidMap || typeof socidMap !== "object" || Object.keys(socidMap).length === 0) {
    elements.socidContent.innerHTML = `<p class="panel-card-empty">No internal profile or user IDs extracted from platforms yet.</p>`;
    return;
  }
  state.socidData = socidMap;
  const entries = Object.entries(socidMap);
  elements.socidContent.innerHTML = `
    <div class="osint-sub-block">
      <span class="sub-block-title">Extracted Platform Identifiers (${entries.length} Found):</span>
      <div class="socid-chips-grid" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:8px;margin-top:8px;">
        ${entries.map(([k, v]) => `
          <div class="account-chip" style="background:rgba(139,92,246,0.12);border-color:rgba(139,92,246,0.3);color:#c084fc;display:flex;flex-direction:column;align-items:flex-start;padding:8px 10px;">
            <strong style="text-transform:uppercase;font-size:0.75rem;letter-spacing:0.5px;color:#a78bfa;">${escapeHtml(k)}</strong>
            <code style="font-size:0.8rem;word-break:break-all;color:#f1f5f9;margin-top:2px;">${escapeHtml(v)}</code>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function updatePhoneCard(p) {
  if (!p || !elements.phoneContent) return;
  state.phoneData = p;
  const dorks = p.dork_links || {};
  elements.phoneContent.innerHTML = `
    <div class="osint-profile-row">
      <div class="osint-avatar-circle" style="background:#10b981;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.2rem;">📞</div>
      <div>
        <h4 class="osint-name">${escapeHtml(p.international || p.e164 || p.raw_input)}</h4>
        <span class="osint-link">${escapeHtml(p.location || 'International')} &bull; ${escapeHtml(p.carrier || 'Unknown Carrier')}</span>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">National Format:</span><span class="kv-val">${escapeHtml(p.national || '—')}</span></div>
      <div class="osint-kv"><span class="kv-label">Geographic Region:</span><span class="kv-val">${escapeHtml(p.location || 'Unknown')}</span></div>
      <div class="osint-kv"><span class="kv-label">Telecom Operator:</span><span class="kv-val highlight">${escapeHtml(p.carrier || 'Unspecified')}</span></div>
      <div class="osint-kv"><span class="kv-label">Line Type:</span><span class="kv-val">${escapeHtml(p.line_type || 'Standard')} ${p.is_voip ? '⚠️ (VoIP)' : ''}</span></div>
      <div class="osint-kv"><span class="kv-label">Spam / VoIP Risk:</span><span class="kv-val highlight" style="color:${p.is_voip ? '#f59e0b' : '#34d399'};">${escapeHtml(p.spam_risk || 'Normal / Low')}</span></div>
      <div class="osint-kv"><span class="kv-label">E.164 Global ID:</span><span class="kv-val"><code>${escapeHtml(p.e164 || '—')}</code></span></div>
    </div>

    <div class="osint-sub-block">
      <span class="sub-block-title">Messaging &amp; Account Identity Pivots:</span>
      <div class="linked-accounts-chips" style="margin-top:6px;">
        ${dorks.whatsapp_chat ? `<a class="account-chip" href="${escapeHtml(dorks.whatsapp_chat)}" target="_blank" rel="noopener noreferrer" style="color:#22c55e;">💬 WhatsApp Chat ↗</a>` : ''}
        ${dorks.telegram_link ? `<a class="account-chip" href="${escapeHtml(dorks.telegram_link)}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">✈️ Telegram ↗</a>` : ''}
        ${dorks.viber_chat ? `<a class="account-chip" href="${escapeHtml(dorks.viber_chat)}" target="_blank" rel="noopener noreferrer" style="color:#a855f7;">🟣 Viber ↗</a>` : ''}
        ${dorks.epieos_lookup ? `<a class="account-chip" href="${escapeHtml(dorks.epieos_lookup)}" target="_blank" rel="noopener noreferrer" style="color:#f59e0b;">🔍 Epieos Phone / Google ↗</a>` : ''}
        ${dorks.osint_industries ? `<a class="account-chip" href="${escapeHtml(dorks.osint_industries)}" target="_blank" rel="noopener noreferrer">🏢 OSINT Industries ↗</a>` : ''}
        ${dorks.osint_ui_lookup ? `<a class="account-chip" href="${escapeHtml(dorks.osint_ui_lookup)}" target="_blank" rel="noopener noreferrer">🌐 OSINT-UI Lookup ↗</a>` : ''}
        ${dorks.tellows_spam ? `<a class="account-chip" href="${escapeHtml(dorks.tellows_spam)}" target="_blank" rel="noopener noreferrer" style="color:#f87171;">🛡️ Tellows Spam Score ↗</a>` : ''}
        ${dorks.truecaller_search ? `<a class="account-chip" href="${escapeHtml(dorks.truecaller_search)}" target="_blank" rel="noopener noreferrer">📞 Truecaller ↗</a>` : ''}
        ${dorks.syncme_search ? `<a class="account-chip" href="${escapeHtml(dorks.syncme_search)}" target="_blank" rel="noopener noreferrer">👥 Sync.me ↗</a>` : ''}
        ${dorks.osm_map ? `<a class="account-chip" href="${escapeHtml(dorks.osm_map)}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">🗺️ OpenStreetMap Region ↗</a>` : ''}
      </div>
    </div>
  `;
}

function updateBreachCard(br) {
  if (!br || !elements.breachContent) return;
  state.breachData = br;
  const breaches = br.breaches || [];
  elements.breachContent.innerHTML = `
    <div class="osint-profile-row">
      <div class="osint-avatar-circle" style="background:#dc2626;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.2rem;">⚠️</div>
      <div>
        <h4 class="osint-name">${escapeHtml(br.email)}</h4>
        <span class="osint-link" style="color:${br.breach_count > 0 ? '#f87171' : '#34d399'};">
          ${br.breach_count > 0 ? `Found in ${br.breach_count} Data Breaches` : 'Clean: No Public Breaches'}
        </span>
      </div>
    </div>
    <div class="osint-keyvals-grid">
      <div class="osint-kv"><span class="kv-label">HIBP Breaches:</span><span class="kv-val highlight" style="color:${br.breach_count > 0 ? '#ef4444' : '#22c55e'};">${br.breach_count}</span></div>
      <div class="osint-kv"><span class="kv-label">Pastes Exposure:</span><span class="kv-val">${br.pastes_count || 0}</span></div>
      <div class="osint-kv"><span class="kv-label">HIBP Profile:</span><span class="kv-val"><a href="${escapeHtml(br.hibp_url || '#')}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">Have I Been Pwned ↗</a></span></div>
      <div class="osint-kv"><span class="kv-label">DeHashed Pivot:</span><span class="kv-val"><a href="${escapeHtml(br.dehashed_url || '#')}" target="_blank" rel="noopener noreferrer" style="color:#38bdf8;">Search DeHashed ↗</a></span></div>
    </div>
    ${breaches.length > 0 ? `
      <div class="osint-sub-block">
        <span class="sub-block-title">Compromised Services:</span>
        <div class="linked-accounts-chips" style="margin-top:6px;">
          ${breaches.map(b => `
            <div class="account-chip" style="background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.3);color:#f87171;">
              <strong>${escapeHtml(b.Name || b.Title || 'Breach')}</strong>
              ${b.BreachDate ? `<span style="opacity:0.75;font-size:0.75rem;">(${b.BreachDate})</span>` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    ` : ''}
  `;
}

function updateDorksCard(dorks) {
  if (!elements.dorksContent) return;
  if (!dorks || !Array.isArray(dorks) || dorks.length === 0) {
    elements.dorksContent.innerHTML = `<p class="panel-card-empty">No Google dorks generated.</p>`;
    return;
  }
  state.dorksData = dorks;
  elements.dorksContent.innerHTML = `
    <div class="osint-sub-block">
      <span class="sub-block-title">Targeted Google Dorks (Click to execute search on Google):</span>
      <div class="dorks-cards-list" style="display:flex;flex-direction:column;gap:8px;margin-top:8px;">
        ${dorks.map(d => `
          <div class="dork-card-item" style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
            <div>
              <strong style="color:#f8fafc;font-size:0.85rem;">${escapeHtml(d.name)}</strong>
              <code style="display:block;font-size:0.75rem;color:#94a3b8;margin-top:2px;">${escapeHtml(d.query)}</code>
            </div>
            <a href="${escapeHtml(d.url)}" target="_blank" rel="noopener noreferrer" class="action-btn action-btn-link" style="font-size:0.75rem;padding:4px 8px;text-decoration:none;">
              Google Search ↗
            </a>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

async function loadAndRenderOsintFramework() {
  if (!elements.frameworkCategoriesContainer) return;
  if (!state.osintFrameworkData) {
    try {
      const res = await fetch("/api/osint-framework");
      if (!res.ok) throw new Error("Failed to fetch OSINT framework database");
      const data = await res.json();
      state.osintFrameworkData = data.categories || [];
    } catch (err) {
      elements.frameworkCategoriesContainer.innerHTML = `<p class="panel-card-empty">Error loading framework directory: ${escapeHtml(err.message)}</p>`;
      return;
    }
  }
  renderOsintFrameworkList(elements.frameworkSearchInput ? elements.frameworkSearchInput.value.trim().toLowerCase() : "");
}

function renderOsintFrameworkList(query) {
  if (!elements.frameworkCategoriesContainer || !state.osintFrameworkData) return;
  const categories = state.osintFrameworkData;

  let html = "";
  let totalTools = 0;

  categories.forEach((cat) => {
    let filteredTools = cat.tools;
    if (query) {
      filteredTools = cat.tools.filter(t => 
        t.name.toLowerCase().includes(query) ||
        t.description.toLowerCase().includes(query) ||
        (t.tags && t.tags.some(tag => tag.toLowerCase().includes(query)))
      );
    }
    if (filteredTools.length === 0) return;
    totalTools += filteredTools.length;

    html += `
      <div class="framework-category-block">
        <div class="framework-category-header">
          <span class="framework-category-icon">${cat.icon || '📁'}</span>
          <h4 class="framework-category-name">${escapeHtml(cat.name)}</h4>
          <span class="framework-category-count">${filteredTools.length} Tools</span>
        </div>
        <div class="framework-tools-grid">
          ${filteredTools.map(tool => `
            <div class="framework-tool-card">
              <div class="tool-card-top">
                <h5 class="tool-name">${escapeHtml(tool.name)}</h5>
                <a href="${escapeHtml(tool.url)}" target="_blank" rel="noopener noreferrer" class="tool-link-btn" title="Open ${escapeHtml(tool.name)} Project">
                  Project ↗
                </a>
              </div>
              <p class="tool-desc">${escapeHtml(tool.description)}</p>
              ${tool.tags && tool.tags.length > 0 ? `
                <div class="tool-tags-row">
                  ${tool.tags.map(t => `<span class="tool-tag">${escapeHtml(t)}</span>`).join('')}
                </div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `;
  });

  if (totalTools === 0) {
    html = `<p class="panel-card-empty" style="grid-column:1/-1;">No OSINT tools match "${escapeHtml(query)}". Try another search keyword.</p>`;
  }

  elements.frameworkCategoriesContainer.innerHTML = html;
}

// ============================================================================
// Interactive OSINT Entity & Node Topology Graph
// ============================================================================
let graphAnimFrame = null;
let graphNodes = [];
let graphLinks = [];
let hoveredNode = null;
let draggedNode = null;
let graphInitialized = false;

const NODE_COLORS = {
  target: { fill: "#38bdf8", glow: "rgba(56, 189, 248, 0.4)", radius: 22, icon: "🎯" },
  profile: { fill: "#3b82f6", glow: "rgba(59, 130, 246, 0.3)", radius: 15, icon: "👤" },
  image: { fill: "#a855f7", glow: "rgba(168, 85, 247, 0.3)", radius: 13, icon: "📷" },
  location: { fill: "#ef4444", glow: "rgba(239, 68, 68, 0.4)", radius: 14, icon: "📍" },
  hardware: { fill: "#f59e0b", glow: "rgba(245, 158, 11, 0.35)", radius: 13, icon: "⚙️" },
  email: { fill: "#10b981", glow: "rgba(16, 185, 129, 0.35)", radius: 13, icon: "📧" },
  phone: { fill: "#10b981", glow: "rgba(16, 185, 129, 0.35)", radius: 13, icon: "📞" },
  crypto: { fill: "#6366f1", glow: "rgba(99, 102, 241, 0.35)", radius: 14, icon: "🔑" },
  proof: { fill: "#818cf8", glow: "rgba(129, 140, 248, 0.3)", radius: 11, icon: "✓" },
  account_holehe: { fill: "#059669", glow: "rgba(5, 150, 105, 0.35)", radius: 12, icon: "⚡" },
  social: { fill: "#eab308", glow: "rgba(234, 179, 8, 0.35)", radius: 14, icon: "👻" },
  instagram: { fill: "#e1306c", glow: "rgba(225, 48, 108, 0.4)", radius: 15, icon: "📸" },
  breach: { fill: "#dc2626", glow: "rgba(220, 38, 38, 0.4)", radius: 14, icon: "⚠️" },
  socid: { fill: "#8b5cf6", glow: "rgba(139, 92, 246, 0.35)", radius: 12, icon: "🆔" },
  dork: { fill: "#f97316", glow: "rgba(249, 115, 22, 0.35)", radius: 12, icon: "🎯" },
  default: { fill: "#94a3b8", glow: "rgba(148, 163, 184, 0.2)", radius: 12, icon: "•" },
};

async function loadAndRenderNetworkGraph() {
  if (!elements.mapCanvas) return;
  const canvas = elements.mapCanvas;
  const rect = canvas.parentElement.getBoundingClientRect();
  const width = Math.max(300, rect.width || 1000);
  const height = 520;
  
  canvas.width = width * (window.devicePixelRatio || 1);
  canvas.height = height * (window.devicePixelRatio || 1);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  if (!state.sessionId) {
    drawEmptyGraphPlaceholder(canvas);
    return;
  }

  try {
    const res = await fetch(`/api/graph/${state.sessionId}`);
    if (!res.ok) throw new Error("Graph API response not ok");
    const data = await res.json();
    initGraphData(data.nodes || [], data.links || [], width, height);
    setupGraphInteractions();
    startGraphSimulation();
  } catch (err) {
    console.debug("Network graph load error:", err);
    drawEmptyGraphPlaceholder(canvas);
  }
}

function drawEmptyGraphPlaceholder(canvas) {
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr);
  ctx.fillStyle = "#64748b";
  ctx.font = "14px Inter, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("Launch an investigation to generate the real-time OSINT entity topology.", (canvas.width / dpr) / 2, (canvas.height / dpr) / 2);
  ctx.restore();
}

function initGraphData(rawNodes, rawLinks, width, height) {
  const centerX = width / 2;
  const centerY = height / 2;
  const total = rawNodes.length;

  graphNodes = rawNodes.map((n, i) => {
    const angle = (i / Math.max(1, total - 1)) * 2 * Math.PI;
    const dist = n.group === "target" ? 0 : 90 + (i % 3) * 60;
    const style = NODE_COLORS[n.group] || NODE_COLORS.default;
    return {
      ...n,
      x: n.group === "target" ? centerX : centerX + Math.cos(angle) * dist,
      y: n.group === "target" ? centerY : centerY + Math.sin(angle) * dist,
      vx: 0,
      vy: 0,
      radius: style.radius,
      fill: style.fill,
      glow: style.glow,
      icon: style.icon,
    };
  });

  const nodeMap = new Map(graphNodes.map((n) => [n.id, n]));
  graphLinks = rawLinks
    .map((l) => ({
      sourceNode: nodeMap.get(l.source),
      targetNode: nodeMap.get(l.target),
      rel: l.rel,
    }))
    .filter((l) => l.sourceNode && l.targetNode);
}

function startGraphSimulation() {
  if (graphAnimFrame) cancelAnimationFrame(graphAnimFrame);
  let ticks = 0;
  const maxTicks = 180;

  function step() {
    simulateGraphPhysics();
    drawGraph();
    ticks++;
    if (ticks < maxTicks || draggedNode) {
      graphAnimFrame = requestAnimationFrame(step);
    } else {
      graphAnimFrame = null;
    }
  }

  graphAnimFrame = requestAnimationFrame(step);
}

function simulateGraphPhysics() {
  const canvas = elements.mapCanvas;
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.width / dpr;
  const height = canvas.height / dpr;
  const centerX = width / 2;
  const centerY = height / 2;

  // Spring force along links
  const targetDist = 75;
  const kSpring = 0.04;
  for (const link of graphLinks) {
    const dx = link.targetNode.x - link.sourceNode.x;
    const dy = link.targetNode.y - link.sourceNode.y;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    const force = (dist - targetDist) * kSpring;
    const fx = (dx / dist) * force;
    const fy = (dy / dist) * force;

    if (link.sourceNode !== draggedNode && link.sourceNode.group !== "target") {
      link.sourceNode.vx += fx;
      link.sourceNode.vy += fy;
    }
    if (link.targetNode !== draggedNode && link.targetNode.group !== "target") {
      link.targetNode.vx -= fx;
      link.targetNode.vy -= fy;
    }
  }

  // Node-Node repulsion
  const kRepulse = 800;
  for (let i = 0; i < graphNodes.length; i++) {
    const a = graphNodes[i];
    for (let j = i + 1; j < graphNodes.length; j++) {
      const b = graphNodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const distSq = dx * dx + dy * dy || 1;
      const dist = Math.sqrt(distSq);
      if (dist < 220) {
        const force = kRepulse / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        if (a !== draggedNode && a.group !== "target") {
          a.vx -= fx;
          a.vy -= fy;
        }
        if (b !== draggedNode && b.group !== "target") {
          b.vx += fx;
          b.vy += fy;
        }
      }
    }

    // Centering force
    if (a !== draggedNode && a.group !== "target") {
      a.vx += (centerX - a.x) * 0.005;
      a.vy += (centerY - a.y) * 0.005;
    }

    // Velocity damping and position update
    if (a !== draggedNode) {
      a.vx *= 0.82;
      a.vy *= 0.82;
      a.x += a.vx;
      a.y += a.vy;

      // Keep in canvas bounds
      const pad = a.radius + 15;
      a.x = Math.max(pad, Math.min(width - pad, a.x));
      a.y = Math.max(pad, Math.min(height - pad, a.y));
    }
  }
}

function drawGraph() {
  const canvas = elements.mapCanvas;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const width = canvas.width / dpr;
  const height = canvas.height / dpr;

  ctx.save();
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  // Draw Links
  ctx.strokeStyle = "rgba(148, 163, 184, 0.22)";
  ctx.lineWidth = 1.2;
  for (const link of graphLinks) {
    ctx.beginPath();
    ctx.moveTo(link.sourceNode.x, link.sourceNode.y);
    ctx.lineTo(link.targetNode.x, link.targetNode.y);
    ctx.stroke();
  }

  // Draw Nodes
  for (const node of graphNodes) {
    const isHover = node === hoveredNode;
    const isTarget = node.group === "target";

    // Glow ring
    if (isHover || isTarget) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius + (isHover ? 7 : 4), 0, Math.PI * 2);
      ctx.fillStyle = node.glow;
      ctx.fill();
    }

    // Node Body
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
    ctx.fillStyle = node.fill;
    ctx.fill();
    ctx.strokeStyle = "#ffffff";
    ctx.lineWidth = isHover ? 2.5 : 1.5;
    ctx.stroke();

    // Node Label
    ctx.font = isTarget ? "bold 11px Inter, sans-serif" : "10px Inter, sans-serif";
    ctx.fillStyle = "#e2e8f0";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    
    const displayLabel = node.label.length > 18 ? node.label.slice(0, 16) + "…" : node.label;
    ctx.fillText(displayLabel, node.x, node.y + node.radius + 4);
  }

  ctx.restore();
}

function setupGraphInteractions() {
  if (graphInitialized || !elements.mapCanvas) return;
  graphInitialized = true;
  const canvas = elements.mapCanvas;

  function getNodeAtPos(evt) {
    const rect = canvas.getBoundingClientRect();
    const mouseX = evt.clientX - rect.left;
    const mouseY = evt.clientY - rect.top;

    for (let i = graphNodes.length - 1; i >= 0; i--) {
      const node = graphNodes[i];
      const dx = mouseX - node.x;
      const dy = mouseY - node.y;
      if (Math.sqrt(dx * dx + dy * dy) <= node.radius + 6) {
        return node;
      }
    }
    return null;
  }

  canvas.addEventListener("mousemove", (evt) => {
    const rect = canvas.getBoundingClientRect();
    const mouseX = evt.clientX - rect.left;
    const mouseY = evt.clientY - rect.top;

    if (draggedNode) {
      draggedNode.x = mouseX;
      draggedNode.y = mouseY;
      if (!graphAnimFrame) startGraphSimulation();
      return;
    }

    const node = getNodeAtPos(evt);
    if (node !== hoveredNode) {
      hoveredNode = node;
      canvas.style.cursor = node ? "pointer" : "default";
      updateMapTooltip(node, evt.clientX, evt.clientY);
      drawGraph();
    }
  });

  canvas.addEventListener("mousedown", (evt) => {
    const node = getNodeAtPos(evt);
    if (node) {
      draggedNode = node;
      if (!graphAnimFrame) startGraphSimulation();
    }
  });

  window.addEventListener("mouseup", () => {
    draggedNode = null;
  });

  canvas.addEventListener("click", (evt) => {
    const node = getNodeAtPos(evt);
    if (node && node.url) {
      window.open(node.url, "_blank", "noopener,noreferrer");
    }
  });

  canvas.addEventListener("mouseleave", () => {
    if (!draggedNode) {
      hoveredNode = null;
      updateMapTooltip(null);
      drawGraph();
    }
  });
}

function updateMapTooltip(node, clientX, clientY) {
  if (!elements.mapTooltip) return;
  if (!node) {
    elements.mapTooltip.hidden = true;
    return;
  }

  const containerRect = elements.mapCanvas.parentElement.getBoundingClientRect();
  const left = clientX - containerRect.left + 15;
  const top = clientY - containerRect.top + 15;

  elements.mapTooltip.style.left = `${Math.min(containerRect.width - 240, Math.max(10, left))}px`;
  elements.mapTooltip.style.top = `${Math.min(containerRect.height - 110, Math.max(10, top))}px`;
  elements.mapTooltip.hidden = false;

  const urlHtml = node.url ? `<a href="${escapeHtml(node.url)}" target="_blank" rel="noopener noreferrer" style="display:inline-block;margin-top:6px;color:#38bdf8;font-size:0.75rem;">Open Resource ↗</a>` : '';

  elements.mapTooltip.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
      <span class="legend-dot" style="background:${node.fill};width:8px;height:8px;border-radius:50%;"></span>
      <strong style="font-size:0.8rem;text-transform:uppercase;color:#94a3b8;">${escapeHtml(node.group)}</strong>
    </div>
    <div style="font-weight:600;font-size:0.875rem;color:#f8fafc;margin-bottom:2px;">${escapeHtml(node.label)}</div>
    ${node.details ? `<div style="font-size:0.75rem;color:#cbd5e1;line-height:1.3;">${escapeHtml(node.details)}</div>` : ''}
    ${urlHtml}
  `;
}

function updateRiskAssessment(risk) {
  if (!risk) return;
  state.riskAssessment = risk;
  elements.exposureScore.textContent = risk.score || 0;
  elements.exposureLevel.textContent = risk.level || "LOW EXPOSURE";
  if (risk.color) {
    elements.exposureScore.style.color = risk.color;
    elements.exposureLevel.style.color = risk.color;
  }
  elements.dossierExposureNum.textContent = `${risk.score || 0}/100`;
}

function updateTabCounts() {
  const claimedCount = state.results.filter((r) => r.status === "claimed").length;
  const issuesCount = state.results.filter((r) => r.status !== "claimed" && r.status !== "available").length;

  $("#found-tab-count").textContent = claimedCount;
  $("#all-tab-count").textContent = state.results.length;
  $("#issues-tab-count").textContent = issuesCount;

  elements.tabProfilesCount.textContent = claimedCount;
  elements.tabExifCount.textContent = state.exifResults.length;
  elements.tabDeepCount.textContent = (state.githubData ? 1 : 0) + 
    (state.gravatarData ? 1 : 0) + 
    (state.keybaseData ? 1 : 0) + 
    (state.snapchatData ? 1 : 0) + 
    (state.instagramData ? 1 : 0) + 
    (state.phoneData ? 1 : 0) + 
    (state.breachData ? 1 : 0) + 
    (state.dorksData && state.dorksData.length > 0 ? 1 : 0) + 
    (Object.keys(state.socidData || {}).length > 0 ? 1 : 0) + 
    (state.holeheData && state.holeheData.length > 0 ? 1 : 0);

  // Exif filter counts
  elements.exifFilterAllCount.textContent = state.exifResults.length;
  elements.exifFilterGpsCount.textContent = state.exifResults.filter((e) => e.has_gps).length;
  elements.exifFilterCameraCount.textContent = state.exifResults.filter((e) => e.camera && e.camera !== "Unknown / Stripped").length;

  // Dossier counts
  elements.dossierClaimedNum.textContent = claimedCount;
  elements.dossierImagesNum.textContent = state.exifResults.length;
  elements.dossierGpsNum.textContent = state.exifResults.filter((e) => e.has_gps).length;
}

// ============================================================================
// Event Stream Consumer
// ============================================================================
function connectEventStream(sessionId) {
  if (state.source) {
    state.source.close();
  }

  const queryParams = new URLSearchParams({
    usernames: elements.input.value.trim(),
    timeout: elements.timeout.value || "10",
    proxy: elements.proxy.value.trim() || "",
    nsfw: elements.nsfw.checked ? "1" : "0",
    scan_exif: elements.scanExif.checked ? "1" : "0",
    deep_osint: elements.deepOsint.checked ? "1" : "0",
    max_images_per_site: elements.maxImages.value || "5",
  });

  const source = new EventSource(`/api/stream/${sessionId}?${queryParams.toString()}`);
  state.source = source;

  source.onmessage = (messageEvent) => {
    if (!messageEvent.data) return;
    try {
      const event = JSON.parse(messageEvent.data);
      handleServerEvent(event);
    } catch {
      // ignore json decode errors for heartbeat
    }
  };

  source.onerror = () => {
    if (state.source) {
      state.source.close();
      state.source = null;
    }
    if (!state.finished) {
      clearInterval(state.timer);
      setRunningState(false);
      if (state.results.length > 0) {
        elements.caseStatusBadge.className = "case-status-badge finished";
        elements.caseStatusText.textContent = "Completed";
      } else {
        elements.caseStatusBadge.className = "case-status-badge error";
        elements.caseStatusText.textContent = "Disconnected";
        elements.error.textContent = "Connection interrupted. You can retry with a shorter timeout or fewer platforms.";
      }
    }
  };
}

function handleServerEvent(event) {
  switch (event.type) {
    case "start": {
      elements.total.textContent = `of ${event.total} queries`;
      break;
    }

    case "result": {
      state.results.push(event);
      elements.checked.textContent = event.checked;
      elements.found.textContent = event.found;

      if (event.total > 0) {
        const pct = Math.min(100, Math.round((event.checked / event.total) * 100));
        elements.progressBar.style.width = `${pct}%`;
        elements.progressPercent.textContent = `${pct}%`;
      }

      updateTabCounts();
      renderProfiles();

      // Enable download if matches found
      if (event.found > 0) {
        elements.downloadPdfBtn.disabled = false;
        elements.exportJsonBtn.disabled = false;
        elements.dossierPdfBtn.disabled = false;
      }
      break;
    }

    case "exif_result": {
      if (Array.isArray(event.images)) {
        event.images.forEach((img) => state.exifResults.push(img));
      }
      elements.exifCount.textContent = state.exifResults.length;
      const gpsCount = state.exifResults.filter((e) => e.has_gps).length;
      elements.gpsBadgeCount.textContent = `${gpsCount} GPS Geotags`;

      if (event.risk_assessment) {
        updateRiskAssessment(event.risk_assessment);
      }

      updateTabCounts();
      if (state.currentView === "exif") {
        renderExifCards();
      }
      elements.downloadPdfBtn.disabled = false;
      elements.exportJsonBtn.disabled = false;
      elements.dossierPdfBtn.disabled = false;
      break;
    }

    case "osint_github": {
      updateGitHubCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_gravatar": {
      updateGravatarCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_keybase": {
      updateKeybaseCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_snapchat": {
      updateSnapchatCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_instagram": {
      updateInstagramCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_socid": {
      updateSocidCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_phone": {
      updatePhoneCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_breach": {
      updateBreachCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_dorks": {
      updateDorksCard(event.data);
      updateTabCounts();
      break;
    }

    case "osint_holehe": {
      if (Array.isArray(event.data)) {
        state.holeheData.push(...event.data);
      }
      updateHoleheCard(state.holeheData);
      updateTabCounts();
      break;
    }

    case "osint_complete": {
      if (event.correlations) {
        state.correlations = event.correlations;
        updateCorrelationsCard(event.correlations);
      }
      if (event.risk_assessment) {
        updateRiskAssessment(event.risk_assessment);
      }
      break;
    }

    case "complete": {
      state.finished = true;
      clearInterval(state.timer);
      setRunningState(false);

      elements.progressBar.style.width = "100%";
      elements.progressPercent.textContent = "100%";
      elements.caseStatusBadge.className = "case-status-badge finished";
      elements.caseStatusText.textContent = "Scan Complete";
      elements.title.textContent = `Investigation Complete: ${event.found} Profile(s) Found`;
      elements.subtitle.textContent = `Scanned ${event.checked} platform records & audited image media in ${event.elapsed}s.`;

      showToast(`Investigation finished! Found ${event.found} profiles.`, "success");
      updateTabCounts();
      break;
    }

    case "cancelled": {
      state.finished = true;
      clearInterval(state.timer);
      setRunningState(false);
      elements.caseStatusBadge.className = "case-status-badge cancelled";
      elements.caseStatusText.textContent = "Cancelled";
      elements.title.textContent = "Investigation Cancelled";
      showToast("Search cancelled", "info");
      break;
    }

    case "error": {
      clearInterval(state.timer);
      setRunningState(false);
      elements.caseStatusBadge.className = "case-status-badge error";
      elements.caseStatusText.textContent = "Error Encountered";
      showToast(event.message || "An error occurred during scan", "error");
      break;
    }
  }
}

// ============================================================================
// Actions: PDF & JSON Download
// ============================================================================
function triggerPdfDownload() {
  if (!state.sessionId) {
    showToast("No active investigation session to download", "error");
    return;
  }
  showToast("Preparing PDF Dossier...", "info");
  const downloadUrl = `/api/report/pdf/${state.sessionId}`;
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = `sherlock_osint_report_${state.sessionId.slice(0, 8)}.pdf`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function triggerJsonDownload() {
  if (!state.sessionId) {
    showToast("No active investigation session to export", "error");
    return;
  }
  showToast("Downloading JSON Intelligence Export...", "info");
  const downloadUrl = `/api/report/json/${state.sessionId}`;
  const link = document.createElement("a");
  link.href = downloadUrl;
  link.download = `sherlock_osint_data_${state.sessionId.slice(0, 8)}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// ============================================================================
// Search Form Submission
// ============================================================================
async function handleSubmit(event) {
  event.preventDefault();
  elements.error.textContent = "";

  const usernames = elements.input.value.trim();
  if (!usernames) {
    elements.error.textContent = "Please enter at least one target username.";
    elements.input.focus();
    return;
  }

  resetCase();
  elements.casePanel.hidden = false;
  elements.casePanel.scrollIntoView({ behavior: "smooth", block: "start" });

  const timeout = parseInt(elements.timeout.value, 10) || 20;
  const maxImages = parseInt(elements.maxImages.value, 10) || 5;
  const proxy = elements.proxy.value.trim();
  const nsfw = elements.nsfw.checked;
  const scanExif = elements.scanExif.checked;
  const deepOsint = elements.deepOsint.checked;

  setRunningState(true);

  try {
    const response = await fetch("/api/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usernames,
        timeout,
        proxy,
        nsfw,
        scan_exif: scanExif,
        deep_osint: deepOsint,
        max_images_per_site: maxImages,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      elements.error.textContent = data.error || "Unable to launch investigation.";
      setRunningState(false);
      return;
    }

    state.sessionId = data.session_id;
    elements.caseId.textContent = `#CASE-${data.session_id.slice(0, 8).toUpperCase()}`;
    elements.title.textContent = `Investigating: ${data.usernames.map(u => `@${u}`).join(", ")}`;
    elements.subtitle.textContent = "Querying platforms and extracting ExifTool image forensics…";

    state.startedAt = Date.now();
    clearInterval(state.timer);
    state.timer = setInterval(() => {
      const elapsedSec = (Date.now() - state.startedAt) / 1000;
      elements.elapsed.textContent = formatElapsed(elapsedSec);
    }, 1000);

    connectEventStream(data.session_id);

  } catch (err) {
    elements.error.textContent = `Network error: ${err.message}`;
    setRunningState(false);
  }
}

// ============================================================================
// Event Listeners Initialization
// ============================================================================
function initListeners() {
  // Search Form
  elements.form.addEventListener("submit", handleSubmit);

  // Input Clear Button
  elements.input.addEventListener("input", () => {
    elements.clearButton.hidden = elements.input.value.length === 0;
  });
  elements.clearButton.addEventListener("click", () => {
    elements.input.value = "";
    elements.clearButton.hidden = true;
    elements.input.focus();
  });

  // Sample Chips
  $$(".preset-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      elements.input.value = chip.dataset.preset;
      elements.clearButton.hidden = false;
      elements.form.requestSubmit();
    });
  });

  // Settings Drawer Toggle
  elements.advancedToggle.addEventListener("click", () => {
    const isHidden = elements.advanced.hidden;
    elements.advanced.hidden = !isHidden;
    elements.advancedToggle.setAttribute("aria-expanded", String(isHidden));
  });

  elements.timeout.addEventListener("input", (e) => {
    elements.timeoutVal.textContent = `${e.target.value}s`;
  });
  elements.maxImages.addEventListener("input", (e) => {
    elements.imagesVal.textContent = `${e.target.value} images`;
  });

  // Cancel Button
  elements.cancel.addEventListener("click", async () => {
    if (!state.sessionId) return;
    try {
      await fetch(`/api/cancel/${state.sessionId}`, { method: "POST" });
      showToast("Cancellation requested…", "info");
    } catch {
      showToast("Error sending cancel request", "error");
    }
  });

  // New Search Button
  elements.newSearch.addEventListener("click", () => {
    elements.input.focus();
    elements.input.select();
    elements.form.scrollIntoView({ behavior: "smooth" });
  });

  // Download PDF Action
  elements.downloadPdfBtn.addEventListener("click", triggerPdfDownload);
  elements.dossierPdfBtn.addEventListener("click", triggerPdfDownload);

  // Export JSON Action
  elements.exportJsonBtn.addEventListener("click", triggerJsonDownload);

  // Copy All Profile Links
  elements.copyAll.addEventListener("click", () => {
    const claimed = state.results.filter((r) => r.status === "claimed").map((r) => r.url);
    if (claimed.length === 0) {
      showToast("No confirmed links to copy yet", "info");
      return;
    }
    copyToClipboard(claimed.join("\n"), `Copied ${claimed.length} profile links!`);
  });

  // View Navigation Tabs
  elements.viewTabs.forEach((tab) => {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  });

  // Direct shortcuts to open OSINT Framework Directory anytime
  const openFrameworkDirectly = () => {
    elements.casePanel.hidden = false;
    switchView("framework");
    const fwElem = $("#view-framework-container");
    if (fwElem) fwElem.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const headerFwBtn = $("#header-framework-btn");
  if (headerFwBtn) headerFwBtn.addEventListener("click", openFrameworkDirectly);

  const quickFwChip = $("#quick-framework-chip");
  if (quickFwChip) quickFwChip.addEventListener("click", openFrameworkDirectly);

  // OSINT Map Reset Button
  if (elements.mapResetBtn) {
    elements.mapResetBtn.addEventListener("click", () => {
      loadAndRenderNetworkGraph();
    });
  }

  // Profile Filter Tabs
  $$(".filter-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$(".filter-tab").forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      state.filter = tab.dataset.filter;
      renderProfiles();
    });
  });

  // Filter input & Sort select
  elements.resultFilter.addEventListener("input", renderProfiles);
  elements.sortSelect.addEventListener("change", (e) => {
    state.sortBy = e.target.value;
    renderProfiles();
  });

  // Framework Search Input
  if (elements.frameworkSearchInput) {
    elements.frameworkSearchInput.addEventListener("input", (e) => {
      renderOsintFrameworkList(e.target.value.trim().toLowerCase());
    });
  }

  // Exif Filter Buttons
  elements.exifFilterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      elements.exifFilterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.exifFilter = btn.dataset.exifFilter;
      renderExifCards();
    });
  });

  // Modal Close
  elements.modalCloseBtn.addEventListener("click", closeExifModal);
  elements.exifModal.addEventListener("click", (e) => {
    if (e.target === elements.exifModal) closeExifModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !elements.exifModal.hidden) closeExifModal();
  });

  // Copy JSON inside modal
  elements.modalCopyJson.addEventListener("click", () => {
    if (state.selectedExifRaw && state.selectedExifRaw.raw_metadata) {
      copyToClipboard(JSON.stringify(state.selectedExifRaw.raw_metadata, null, 2), "Copied raw EXIF JSON!");
    }
  });

  // Dark / Light Theme Toggle
  elements.themeToggle.addEventListener("click", () => {
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    const nextTheme = isDark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    localStorage.setItem("sherlock-theme", nextTheme);
    updateThemeIcons(nextTheme);
  });

  // Initial Theme from Storage
  const savedTheme = localStorage.getItem("sherlock-theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcons(savedTheme);

  // Check ExifTool and Server Status
  checkSystemStatus();
}

function updateThemeIcons(theme) {
  if (theme === "light") {
    elements.themeIconSun.classList.remove("sr-only");
    elements.themeIconMoon.classList.add("sr-only");
  } else {
    elements.themeIconSun.classList.add("sr-only");
    elements.themeIconMoon.classList.remove("sr-only");
  }
}

async function checkSystemStatus() {
  try {
    const [statusRes, sitesRes] = await Promise.all([
      fetch("/api/status").then(r => r.json()),
      fetch("/api/sites").then(r => r.json()).catch(() => null),
    ]);

    if (statusRes.status === "ok") {
      elements.serverDot.className = "status-dot online";
      elements.serverLabel.textContent = `Engine Online (v${statusRes.version})`;
      if (statusRes.exiftool_available) {
        elements.exiftoolPill.classList.add("active");
        elements.exifLabel.textContent = "ExifTool 13.59 Active";
      } else {
        elements.exifLabel.textContent = "ExifTool Offline";
      }
    }

    if (sitesRes && sitesRes.total) {
      elements.networkCount.textContent = `${sitesRes.total}+ platforms`;
    }
  } catch {
    elements.serverDot.className = "status-dot offline";
    elements.serverLabel.textContent = "Engine Offline";
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Kick off
document.addEventListener("DOMContentLoaded", initListeners);
