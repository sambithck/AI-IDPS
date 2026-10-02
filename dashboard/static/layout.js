/* dashboard/static/layout.js
   Enterprise SOC Shell — sidebar + topbar for all dashboard pages. */

var NAV = [
  { key: "live",       label: "SOC Overview",      href: "/dashboard",            icon: "fa-chart-line" },
  { key: "analytics",  label: "Attack Analytics",   href: "/dashboard/analytics",  icon: "fa-chart-bar" },
  { key: "forensics",  label: "Forensics & PCAP",   href: "/dashboard/forensics",  icon: "fa-search" }
];

function renderShell(opts) {
  var active   = opts.active   || "";
  var title    = opts.title    || "AI-IDPS";
  var subtitle = opts.subtitle || "";

  requireAuth();

  var username = localStorage.getItem("idps_username") || "user";
  var role     = localStorage.getItem("idps_role")     || "viewer";
  var initials = username.slice(0, 2).toUpperCase();

  var navHtml = "";
  for (var i = 0; i < NAV.length; i++) {
    var item = NAV[i];
    var cls  = (item.key === active) ? "active" : "";
    navHtml +=
      '<a href="' + item.href + '" class="' + cls + '">' +
        '<span class="icon"><i class="fa-solid ' + item.icon + '"></i></span>' +
        item.label +
      '</a>';
  }

  var rbacBadge = "";
  if (role === "admin")   rbacBadge = '<span class="badge badge-critical" style="font-size:9px;padding:2px 7px;">ADMIN</span>';
  if (role === "analyst") rbacBadge = '<span class="badge badge-info" style="font-size:9px;padding:2px 7px;">ANALYST</span>';
  if (role === "viewer")  rbacBadge = '<span class="badge badge-low" style="font-size:9px;padding:2px 7px;">VIEWER</span>';

  var shell =
    '<div class="app-shell">' +
      '<aside class="sidebar">' +
        '<div class="logo">' +
          '<div class="mark"><i class="fa-solid fa-shield-halved"></i></div>' +
          '<div class="logo-text">' +
            '<div class="title">AI-IDPS</div>' +
            '<div class="subtitle">Security Operations</div>' +
          '</div>' +
        '</div>' +

        '<div class="nav-section-label">Monitor</div>' +
        '<nav>' + navHtml + '</nav>' +

        '<div class="spacer"></div>' +

        '<div class="sidebar-footer">' +
          '<div class="user-pill">' +
            '<div class="avatar">' + initials + '</div>' +
            '<div class="info">' +
              '<div class="name">' + username + ' ' + rbacBadge + '</div>' +
              '<div class="role">' + role + '</div>' +
            '</div>' +
          '</div>' +
          '<button class="logout-btn" onclick="logout()">' +
            '<i class="fa-solid fa-right-from-bracket"></i> Sign out' +
          '</button>' +
          '<div class="status-list">' +
            '<div class="status-row"><span class="status-dot purple" id="ws-status-dot"></span><span id="ws-status-text">Connecting...</span></div>' +
            '<div class="status-row"><span class="status-dot green"></span> IDS Engine Active</div>' +
            '<div class="status-row"><span class="status-dot green"></span> System Normal</div>' +
          '</div>' +
        '</div>' +
      '</aside>' +

      '<main class="main">' +
        '<div class="topbar">' +
          '<div>' +
            '<h1 id="page-title">' + title + '</h1>' +
            '<div class="subtitle" id="page-subtitle">' + subtitle + '</div>' +
          '</div>' +
          '<div class="topbar-right">' +
            '<div class="search-box">' +
              '<i class="fa-solid fa-magnifying-glass"></i>' +
              '<input type="text" placeholder="Search threats, IPs...">' +
            '</div>' +
            '<div class="notif-btn" id="notif-btn">' +
              '<i class="fa-solid fa-bell"></i>' +
              '<span class="notif-count" id="notif-count">0</span>' +
            '</div>' +
            '<div class="live-pill"><span class="live-dot"></span> LIVE</div>' +
          '</div>' +
        '</div>' +
        '<div class="content" id="page-content"></div>' +
      '</main>' +
    '</div>';

  document.body.insertAdjacentHTML("afterbegin", shell);

  // Move inline content into slot
  var placeholder = document.getElementById("page-content");
  var pending      = document.getElementById("page-content-source");
  if (pending) {
    placeholder.innerHTML = pending.innerHTML;
    pending.remove();
  }
}

function setWsStatus(connected) {
  var dot  = document.getElementById("ws-status-dot");
  var text = document.getElementById("ws-status-text");
  if (!dot || !text) return;
  if (connected) {
    dot.className   = "status-dot purple";
    text.textContent = "Live Feed Connected";
  } else {
    dot.className   = "status-dot red";
    text.textContent = "Disconnected";
  }
}
