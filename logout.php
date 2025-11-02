<?php
// logout.php
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php';
require 'functions.php'; // Para clearRememberMeCookie

if (isset($_SESSION['user'])) {
    try {
        // *** NUEVO: Limpiar el token de sesión de la DB ***
        $stmt = $pdo->prepare("UPDATE usuarios SET current_session_token = NULL WHERE id = ? AND current_session_token = ?");
        // Solo limpia el token si coincide con el de esta sesión (por seguridad)
        $stmt->execute([$_SESSION['user']['id'], $_SESSION['session_token'] ?? null]);
    } catch (PDOException $e) {
        error_log("Error al limpiar token en logout: " . $e->getMessage());
    }
}

// Limpiar cookie de "Recordarme"
if (function_exists('clearRememberMeCookie')) {
    clearRememberMeCookie();
}

// Destruir la sesión
session_unset();
session_destroy();

// Redirigir a login
header("Location: login.php");
exit;
?>