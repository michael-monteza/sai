<?php
/** @var array $user @var string $csrf @var string $base @var callable $can */
$e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES);
// group => [[tab, icon, label, permission, badge id, badge colour]]
$nav = [
    'Overview' => [
        ['overview', 'gauge', 'Executive Dashboard', 'dashboard.read'],
        ['inventory', 'server', 'AI Fleet Inventory', 'inventory.read', 'bShadow', 'danger'],
        ['workstations', 'monitor', 'Workstations', 'workstations.read'],
        ['adoption', 'sprout', 'AI Adoption', 'adoption.read'],
        ['reports', 'line-chart', 'Reports & Analytics', 'reports.read'],
    ],
    'AI Services & DNS' => [
        ['registry', 'database', 'AI Services & DNS Registry', 'registry.read'],
        ['discovery', 'radar', 'Domain Discovery', 'discovery.read', 'bDisc', 'warning'],
        ['risk', 'shield-alert', 'Risk Matrix & Engine', 'inventory.read'],
    ],
    'Governance & Assurance' => [
        ['governance', 'file-text', 'Governance & Requests', 'governance.read', 'bReq', 'warning'],
        ['iso', 'shield-check', 'ISO 42001 Readiness', 'iso.read', 'bIso', 'success'],
    ],
    'Operations' => [
        ['collectors', 'activity', 'Collectors & Monitoring', 'collectors.read'],
        ['integrations', 'plug', 'SIEM & Webhooks', 'integrations.read'],
        ['audit', 'clipboard-list', 'Audit Log', 'audit.read'],
    ],
    'Administration' => [
        ['users', 'users', 'User Management', 'users.read'],
        ['companies', 'building', 'Companies', 'tenants.read'],
        ['authentication', 'key', 'Authentication', 'settings.auth'],
    ],
];
// Layout budget so every item always fits without scrolling: n items, g group headings, fixed chrome (brand, search, profile, optional company switcher).
$n = $g = 0;
foreach ($nav as $items) { $c = count(array_filter($items, static fn ($i) => $can($i[3]))); if ($c) { $g++; $n += $c; } }
$fixed = 60 + 46 + $g * 26 + 80 + ($can('tenants.read') ? 44 : 0) + 12;
$ico = static fn (string $id, string $cls = 'i'): string => '<svg class="' . $cls . '" aria-hidden="true" focusable="false"><use href="#i-' . $id . '"/></svg>';
?>
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAIP - Shadow AI Platform</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link href="<?= $base ?>/assets/app.css?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/app.css') ?>" rel="stylesheet">
<meta name="saip-base" content="<?= $e($base) ?>">
</head>
<body>
<!-- Icon sprite: Lucide-style 24x24 stroke icons -->
<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false"><defs>
  <symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
  <symbol id="i-panel" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/><path d="m16 15-3-3 3-3"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></symbol>
  <symbol id="i-x" viewBox="0 0 24 24"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></symbol>
  <symbol id="i-gauge" viewBox="0 0 24 24"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></symbol>
  <symbol id="i-server" viewBox="0 0 24 24"><rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/></symbol>
  <symbol id="i-monitor" viewBox="0 0 24 24"><rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8M12 17v4"/></symbol>
  <symbol id="i-sprout" viewBox="0 0 24 24"><path d="M7 20h10"/><path d="M10 20c5.5-2.5.8-6.4 3-10"/><path d="M9.5 9.4c1.1.8 1.8 2.2 2.3 3.7-2 .4-3.5.4-4.8-.3-1.2-.6-2.3-1.9-3-4.2 2.8-.5 4.4 0 5.5.8z"/><path d="M14.1 6a7 7 0 0 0-1.1 4c1.9-.1 3.3-.6 4.3-1.4 1-1 1.6-2.3 1.7-4.6-2.7.1-4 1-4.9 2z"/></symbol>
  <symbol id="i-line-chart" viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="m19 9-5 5-4-4-3 3"/></symbol>
  <symbol id="i-network" viewBox="0 0 24 24"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/></symbol>
  <symbol id="i-plug" viewBox="0 0 24 24"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></symbol>
  <symbol id="i-database" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5"/><path d="M3 12a9 3 0 0 0 18 0"/></symbol>
  <symbol id="i-radar" viewBox="0 0 24 24"><path d="M19.07 4.93A10 10 0 0 0 6.99 3.34"/><path d="M4 6h.01"/><path d="M2.29 9.62A10 10 0 1 0 21.31 8.35"/><path d="M16.24 7.76A6 6 0 1 0 8.23 16.67"/><path d="M12 18h.01"/><path d="M17.99 11.66A6 6 0 0 1 15.77 16.67"/><circle cx="12" cy="12" r="2"/><path d="m13.41 10.59 5.66-5.66"/></symbol>
  <symbol id="i-shield-alert" viewBox="0 0 24 24"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/></symbol>
  <symbol id="i-file-text" viewBox="0 0 24 24"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8M16 13H8M16 17H8"/></symbol>
  <symbol id="i-shield-check" viewBox="0 0 24 24"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></symbol>
  <symbol id="i-activity" viewBox="0 0 24 24"><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></symbol>
  <symbol id="i-clipboard-list" viewBox="0 0 24 24"><rect width="8" height="4" x="8" y="2" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M12 11h4M12 16h4M8 11h.01M8 16h.01"/></symbol>
  <symbol id="i-users" viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></symbol>
  <symbol id="i-building" viewBox="0 0 24 24"><path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2"/><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><path d="M10 6h4M10 10h4M10 14h4M10 18h4"/></symbol>
  <symbol id="i-help" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></symbol>
  <symbol id="i-key" viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/></symbol>
</defs></svg>

<button class="mobile-menu nav-toggle" aria-label="Open menu"><?= $ico('menu') ?></button>
<div class="layout">
  <aside id="sidebar" class="sidebar" aria-label="Primary" style="--n:<?= max(1, $n) ?>;--fixed:<?= $fixed ?>px">
    <div class="sb-brand">
      <span class="sb-logo" aria-hidden="true"><?= $ico('shield-check') ?></span>
      <span class="sb-brand-text lbl"><b>Shadow AI</b><small>Governance Platform</small></span>
      <button class="sb-collapse nav-toggle" aria-label="Switch between full menu and icon rail" title="Full menu / icon rail"><?= $ico('panel') ?></button>
    </div>

    <div class="search-box" role="search">
      <?= $ico('search', 'i search-icon') ?>
      <input type="search" id="menu-search" placeholder="Search menu" autocomplete="off" spellcheck="false" aria-label="Search menu" aria-controls="nav-container">
      <kbd class="sb-kbd" aria-hidden="true">/</kbd>
      <button class="clear-btn" id="clear-search" type="button" aria-label="Clear search"><?= $ico('x') ?></button>
    </div>

    <nav class="nav-container" id="nav-container" aria-label="Main menu">
<?php foreach ($nav as $group => $items): $vis = array_values(array_filter($items, static fn ($i) => $can($i[3]))); if (!$vis) continue; ?>
      <section class="nav-group" aria-label="<?= $e($group) ?>">
        <h2 class="group-title lbl"><?= $e($group) ?></h2>
        <ul class="nav-items">
<?php foreach ($vis as $i): ?>
          <li><a class="nav-item" href="#<?= $i[0] ?>" data-tab="<?= $i[0] ?>" title="<?= $e($i[2]) ?>"><span class="ico"><?= $ico($i[1]) ?></span><span class="label lbl"><?= $e($i[2]) ?></span><?php if (!empty($i[4])): ?><span class="badge text-bg-<?= $i[5] ?>" id="<?= $i[4] ?>"></span><?php endif; ?></a></li>
<?php endforeach; ?>
        </ul>
      </section>
<?php endforeach; ?>
      <div class="no-results" id="no-results" role="status" aria-live="polite"><?= $ico('search') ?><div>No menu options found</div></div>
    </nav>

    <div class="sidebar-foot">
      <select id="tenantSelect" class="form-select form-select-sm d-none" aria-label="Company"></select>
      <div class="profile">
        <div class="avatar" id="userAvatar" aria-hidden="true">?</div>
        <div class="who lbl"><b id="userName"></b><span id="userRole"></span><span id="tenantName"></span><span id="tzNote"></span></div>
        <a class="pf-btn" href="#guide" data-tab="guide" title="Getting Started" aria-label="Getting Started"><?= $ico('help') ?></a>
        <button class="pf-btn" id="btnPassword" type="button" title="Change password" aria-label="Change password"><?= $ico('key') ?></button>
        <form method="post" action="<?= $base ?>/logout" class="m-0"><input type="hidden" name="csrf" value="<?= $e($csrf) ?>">
          <button class="pf-btn" title="Sign out" aria-label="Sign out"><?= $ico('logout') ?></button></form>
      </div>
    </div>
  </aside>
  <main id="view" class="content"><div class="text-secondary p-4">Loading&hellip;</div></main>
</div>
<div id="modalHost"></div>
<div id="toasts" class="toast-container position-fixed bottom-0 end-0 p-3"></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script src="<?= $base ?>/assets/ui.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/ui.js') ?>"></script>
<script src="<?= $base ?>/assets/grid.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/grid.js') ?>"></script>
<script src="<?= $base ?>/assets/registry.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/registry.js') ?>"></script>
<script src="<?= $base ?>/assets/fqdn.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/fqdn.js') ?>"></script>
<script src="<?= $base ?>/assets/reports.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/reports.js') ?>"></script>
<script src="<?= $base ?>/assets/admin.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/admin.js') ?>"></script>
<script src="<?= $base ?>/assets/activity.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/activity.js') ?>"></script>
<script src="<?= $base ?>/assets/integrations.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/integrations.js') ?>"></script>
<script src="<?= $base ?>/assets/app.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/app.js') ?>"></script>
<script src="<?= $base ?>/assets/menu.js?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/menu.js') ?>"></script>
</body>
</html>
