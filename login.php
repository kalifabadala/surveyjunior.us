<?php
// login.php (v4.3 - Fix Mantenimiento)
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php';
require 'functions.php';
// *** LÍNEA ELIMINADA: require 'maintenance_check.php'; *** // El chequeo de mantenimiento NO debe estar en la página de login.

$error = '';
if (isset($_GET['error'])) {
    $error = htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8');
}

$ip_address = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
if (strpos($ip_address, ',') !== false) { $ip_address = trim(explode(',', $ip_address)[0]); }
$ip_address = filter_var($ip_address, FILTER_VALIDATE_IP) ? $ip_address : 'Invalid IP';

// --- Anti-Fuerza Bruta Check ---
$is_blocked = false;
if (function_exists('isLoginBlocked') && isLoginBlocked($pdo, $ip_address)) {
    $error = 'Demasiados intentos fallidos. Por favor, inténtalo de nuevo en 15 minutos.';
    $is_blocked = true;
    if (function_exists('logActivity')) logActivity($pdo, null, ($_POST['username'] ?? 'N/A'), 'Login Bloqueado (IP)', $error);
}
// --- Fin Check ---

// Procesar el formulario solo si no está bloqueado
elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $remember_me = isset($_POST['remember_me']);

    if (empty($username) || empty($password)) {
        $error = 'Usuario y contraseña son requeridos.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                // --- Contraseña Correcta ---
                
                if ($user['active'] == 0 || $user['banned'] == 1) {
                    $error = 'Tu cuenta está inactiva o baneada. Contacta a un administrador.';
                    if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Login Fallido (Cuenta Inactiva)', $error);
                    goto login_form;
                }

                if ($user['current_session_token'] !== null) {
                    $five_minutes_ago = time() - 300; // 300 segundos = 5 minutos
                    if ($user['last_activity'] > $five_minutes_ago) {
                        $error = 'Cliente posee una sesion activa. Espera 5 minutos de inactividad o cierra la otra sesión.';
                        if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Login Fallido (Sesión Activa)', $error);
                        goto login_form;
                    }
                }
                // --- Fin Comprobación ---

                // --- Login Exitoso ---
                if (function_exists('clearLoginAttempts')) clearLoginAttempts($pdo, $ip_address);

                session_regenerate_id(true);

                $session_token = bin2hex(random_bytes(32));
                try {
                    $stmt_token = $pdo->prepare("UPDATE usuarios SET current_session_token = ? WHERE id = ?");
                    $stmt_token->execute([$session_token, $user['id']]);
                } catch (PDOException $e) {
                     error_log("Error al actualizar session_token en login: " . $e->getMessage());
                     $error = "Error de la base de datos al iniciar sesión.";
                     goto login_form;
                }
                
                $_SESSION['session_token'] = $session_token;
                $user['current_session_token'] = $session_token;
                $_SESSION['user'] = $user;

                if ($remember_me && function_exists('rememberUser')) {
                    rememberUser($pdo, $user['id']);
                } else {
                    if (function_exists('clearRememberMeCookie')) clearRememberMeCookie();
                    $stmt_del_token = $pdo->prepare("DELETE FROM persistent_logins WHERE user_id = ?");
                    $stmt_del_token->execute([$user['id']]);
                }

                if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Login Exitoso');
                if (function_exists('updateUserActivity')) updateUserActivity($pdo, $user['id']);
                if (function_exists('updateUserLocation')) updateUserLocation($pdo, $user['id']);

                header('Location: index.php');
                exit;

            } else {
                // --- Login Fallido (Usuario/Contraseña incorrectos) ---
                $error = 'Usuario o contraseña incorrectos.';
                if (function_exists('recordFailedLogin')) recordFailedLogin($pdo, $ip_address);
                if (function_exists('logActivity')) logActivity($pdo, null, $username, 'Login Fallido', $error);
                if (function_exists('isLoginBlocked') && isLoginBlocked($pdo, $ip_address)) {
                     $error .= ' Has alcanzado el límite de intentos.';
                     $is_blocked = true;
                     if (function_exists('logActivity')) logActivity($pdo, null, $username, 'Login Bloqueado (IP)', 'Límite alcanzado');
                }
            }
        } catch (PDOException $e) {
            error_log("Login Error: " . $e->getMessage());
            $error = 'Error en la base de datos durante el inicio de sesión.';
            if (function_exists('logActivity')) logActivity($pdo, null, $username, 'Login Error DB', $e->getMessage());
        }
    }
}

// --- Check "Recordarme" al cargar la página (si no hay sesión activa) ---
if (!isset($_SESSION['user']) && !$is_blocked) {
    if (function_exists('validateRememberMe')) {
        $userFromCookie = validateRememberMe($pdo);
        if ($userFromCookie) {
            header('Location: index.php');
            exit;
        }
    }
} elseif (isset($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}

login_form:
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Iniciar Sesión - SurveyJunior</title>
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

      <h3 class="mt-4">Iniciar Sesión</h3>
      <p class="text-muted mb-4">Accede a tu panel</p>
      
      <?php if ($error): ?>
          <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
      <?php endif; ?>
      <form method="post" action="login.php" novalidate>
        <div class="mb-3">
            <input type="text" name="username" class="form-control form-control-modern" placeholder="Usuario" required autofocus value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : '' ?>" <?= $is_blocked ? 'disabled' : '' ?>/>
        </div>
        <div class="mb-3">
            <input type="password" name="password" class="form-control form-control-modern" placeholder="Contraseña" required <?= $is_blocked ? 'disabled' : '' ?>/>
        </div>
        <div class="mb-3 form-check text-start">
            <input type="checkbox" class="form-check-input" id="remember_me" name="remember_me" value="1" <?= $is_blocked ? 'disabled' : '' ?>>
            <label class="form-check-label" for="remember_me">Recordarme</label>
        </div>
        <button type="submit" class="btn btn-generate w-100" <?= $is_blocked ? 'disabled' : '' ?>>Entrar</button>
      </form>
      <div class="footer-text">
        ¿No tienes cuenta? <a href="register.php" class="register-link">Regístrate aquí</a>
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