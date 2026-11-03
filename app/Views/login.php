<?php /** @var string $error @var string $csrf @var string $base @var bool $google */ ?>
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAIP - Sign in</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="<?= $base ?>/assets/app.css?v=<?= (int)@filemtime(SAIP_ROOT . '/assets/app.css') ?>" rel="stylesheet">
</head>
<body class="d-flex align-items-center justify-content-center login-body">
<form method="post" action="<?= $base ?>/login" class="card p-4 login-card" autocomplete="off">
  <div class="d-flex align-items-center gap-2 mb-3"><span class="brand-mark login-mark">SAI</span><div><div class="fw-bold">Shadow AI Platform</div><div class="small text-secondary">Sign in to your console</div></div></div>
  <?php if ($error): ?><div class="alert alert-danger py-2 small" role="alert"><?= htmlspecialchars($error, ENT_QUOTES) ?></div><?php endif; ?>
  <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf, ENT_QUOTES) ?>">
  <label class="form-label small" for="u">Username</label>
  <input class="form-control mb-3" id="u" name="username" required autofocus autocomplete="username" maxlength="60">
  <label class="form-label small" for="p">Password</label>
  <input class="form-control mb-3" id="p" type="password" name="password" required autocomplete="current-password" maxlength="200">
  <button class="btn btn-info fw-semibold"><i class="fa-solid fa-right-to-bracket"></i> Sign in</button>
<?php if (!empty($google)): ?>
  <div class="d-flex align-items-center gap-2 my-3 text-secondary small"><hr class="flex-grow-1 m-0"><span>or</span><hr class="flex-grow-1 m-0"></div>
  <a class="btn btn-outline-secondary fw-semibold d-flex align-items-center justify-content-center gap-2" href="<?= $base ?>/auth/google">
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9.1 3.5l6.8-6.8C35.8 2.4 30.3 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.4 13.6 17.7 9.5 24 9.5z"/><path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.6 5.9c4.5-4.1 7-10.2 7-17.6z"/><path fill="#FBBC05" d="M10.5 28.7a14.5 14.5 0 0 1 0-9.4l-7.9-6.1a24 24 0 0 0 0 21.6l7.9-6.1z"/><path fill="#34A853" d="M24 48c6.5 0 11.9-2.1 15.9-5.8l-7.6-5.9c-2.1 1.4-4.9 2.3-8.3 2.3-6.3 0-11.6-4.1-13.5-9.8l-7.9 6.1C6.5 42.6 14.6 48 24 48z"/></svg>
    Sign in with Google</a>
<?php endif; ?>
</form>
</body>
</html>
