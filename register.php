<?php
// register.php (Actualizado v1.2 - Fix Mantenimiento)
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php';
require 'functions.php';
// *** LÍNEA ELIMINADA: require 'maintenance_check.php'; *** // El chequeo de mantenimiento NO debe estar en la página de registro.

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $password_confirm = $_POST['password_confirm'];

    if (empty($username) || empty($password) || empty($password_confirm)) {
        $error = 'Todos los campos son obligatorios.';
    } elseif (strlen($password) < 6) {
        $error = 'La contraseña debe tener al menos 6 caracteres.';
    } elseif ($password !== $password_confirm) {
        $error = 'Las contraseñas no coinciden.';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
         $error = 'El nombre de usuario solo puede contener letras, números y guiones bajos (_).';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $error = 'El nombre de usuario ya está en uso. Por favor, elige otro.';
            } else {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                // Por defecto: rol 'user', no puede generar, activo
                $stmt = $pdo->prepare("INSERT INTO usuarios (username, password, role, can_generate_links, active, banned) VALUES (?, ?, 'user', 0, 1, 0)");
                
                if ($stmt->execute([$username, $hash])) {
                    $success = '¡Cuenta creada con éxito! Ahora puedes iniciar sesión.';
                    if (function_exists('logActivity')) {
                        $ip_address = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
                        logActivity($pdo, null, $username, 'Registro Exitoso', 'IP: '.$ip_address);
                    }
                    // Limpiar el post para que el formulario no se rellene
                    $_POST = array();
                } else {
                    $error = 'Error al crear la cuenta. Inténtalo de nuevo.';
                }
            }
        } catch (PDOException $e) {
            error_log("Register Error: " . $e->getMessage());
            $error = 'Error en la base de datos durante el registro.';
            if (function_exists('logActivity')) logActivity($pdo, null, $username, 'Registro Error DB', $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Registro - SurveyJunior</title>
<!-- Favicon SJ con Gradiente -->
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad1' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%235a9cff;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%230d6efd;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Ccircle cx='50' cy='50' r='50' fill='url(%23grad1)' /%3E%3Ctext x='50' y='60' font-size='50' fill='%23fff' text-anchor='middle' font-family='Arial, sans-serif' font-weight='bold'%3ESJ%3C/text%3E%3C/svg%3E">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet" />
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<link rel="stylesheet" href="new-style.css">
</head>
<body>
  <div class="login-container">
    <div class="form-card">

      <!-- Banner de Cabecera -->
      <div class="login-header-banner">
        <h1>SurveyJunior.us</h1>
        <p>Jumpers, Encuestas y mas.</p>
      </div>

      <h3 class="mt-4">Crear Cuenta</h3>
      <p class="text-muted mb-4">Únete a la plataforma</p>

      <?php if ($error): ?>
          <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>
       <?php if ($success): ?>
          <div class="alert alert-success" role="alert"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>

      <form method="post" action="register.php" novalidate>
        <div class="mb-3">
            <input type="text" name="username" class="form-control form-control-modern" placeholder="Usuario" required value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : '' ?>">
        </div>
        <div class="mb-3">
            <input type="password" name="password" class="form-control form-control-modern" placeholder="Contraseña (mín. 6 caracteres)" required>
        </div>
        <div class="mb-3">
            <input type="password" name="password_confirm" class="form-control form-control-modern" placeholder="Confirmar Contraseña" required>
        </div>
        
        <button type="submit" class="btn btn-generate w-100">Registrarme</button>
      </form>
      <div class="footer-text">
        ¿Ya tienes cuenta? <a href="login.php" class="login-link">Inicia sesión aquí</a>
      </div>
    </div>
  </div>

  <!-- Contenedor para Public Toasts (Central) -->
  <div class="toast-container position-fixed bottom-0 start-50 translate-middle-x p-3" id="public-toast-container" style="z-index: 1100">
      <!-- Los toasts de actividad se insertarán aquí -->
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="public-toast.js"></script>
</body>
</html>