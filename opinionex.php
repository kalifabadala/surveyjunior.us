<?php
// opinionex.php - Interfaz app-like para OpinionExchange
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require_once 'config.php';
require_once 'functions.php';

// Redirigir si no autenticado
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
$user = $_SESSION['user'];
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>OpinionExchange - Generar Jumper</title>
  <link rel="stylesheet" href="opinionex.css">
</head>
<body class="app-shell">
  <header class="app-topbar" role="banner">
    <button id="btn-back" class="icon-btn" aria-label="Volver">&#8592;</button>
    <h1 class="app-title">Meinungsplatz / OpinionEx</h1>
    <div class="avatar-wrap" title="<?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?>">
      <img src="https://api.dicebear.com/8.x/adventurer/svg?seed=<?= urlencode($user['username']) ?>" alt="Perfil" class="avatar">
    </div>
  </header>

  <main class="app-main" role="main">
    <section class="card form-card" aria-labelledby="formTitle">
      <h2 id="formTitle" class="card-title">Generar Jumper</h2>
      <label for="input_urls" class="sr-only">Pega aquí las URLs</label>
      <textarea id="input_urls" class="form-control" rows="6" placeholder="Pega las URLs del panel aquí (una por línea)"></textarea>

      <div class="row" style="margin-top:12px">
        <div class="col">
          <label for="projektnummer" class="form-label">Projektnummer</label>
          <input id="projektnummer" class="form-control" type="text" inputmode="numeric" maxlength="6" placeholder="Ej: 12345">
        </div>
        <div class="col-auto" style="align-self:flex-end">
          <button id="btn-generate" class="btn primary-btn" aria-live="polite">Generar Jumper</button>
        </div>
      </div>

      <div id="form-message" class="form-message" role="status" aria-live="polite" hidden></div>
    </section>

    <section class="card result-card" id="resultCard" aria-hidden="true" aria-live="polite">
      <div id="resultInner" class="result-inner">
        <div class="result-icon" id="resultIcon">✔</div>
        <div class="result-body">
          <div id="resultTitle" class="result-title">Jumper Generado</div>
          <div id="resultUrl" class="result-url" role="textbox" aria-readonly="true"></div>
          <div class="result-actions">
            <button id="btn-copy" class="btn small-btn">Copiar</button>
            <a id="btn-open" class="btn small-btn outline" target="_blank" rel="noopener">Abrir</a>
          </div>
        </div>
      </div>
    </section>

    <section class="card history-card" id="historyCard" aria-labelledby="historyTitle">
      <h3 id="historyTitle" class="card-title">Historial</h3>
      <div id="historyList" class="history-list" aria-live="polite"></div>
    </section>
  </main>

  <button id="fab" class="fab" aria-label="Acciones rápidas">+</button>

  <div id="toastContainer" class="toast-container" aria-live="polite" aria-atomic="true"></div>

  <script src="opinionex.js"></script>
</body>
</html>