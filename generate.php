<?php
// generate.php (Actualizado con Log v2)
if (session_status() === PHP_SESSION_NONE) { session_start(); }

// Cargar config y funciones ANTES de usarlas
require 'config.php';
// Verificar si functions.php existe antes de requerirlo
if (file_exists('functions.php')) {
    require 'functions.php';
} else {
    // Manejar el error si functions.php no existe
    $_SESSION['link_generated'] = 'Error interno: Faltan archivos de funciones.'; // Mensaje genérico
    $_SESSION['opinion_link_generated'] = 'Error interno: Faltan archivos de funciones.';
    error_log("FATAL ERROR: functions.php not found in generate.php");
    header('Location: index.php?module=home'); // Redirigir a home como fallback
    exit;
}


if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
$user = $_SESSION['user'];
$canGenerateLinks = ($user['role'] === 'admin') || ($user['can_generate_links'] == 1);

// Definir $pdo aquí si no se definió en config.php (aunque debería)
if (!isset($pdo) || !$pdo instanceof PDO) {
     // Intentar reconectar o manejar el error fatal
     // Por simplicidad, asumimos que $pdo SÍ viene de config.php
     error_log("FATAL ERROR: PDO object not available in generate.php");
     $_SESSION['link_generated'] = 'Error interno: No se pudo conectar a la base de datos.';
     $_SESSION['opinion_link_generated'] = 'Error interno: No se pudo conectar a la base de datos.';
     header('Location: index.php?module=home');
     exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // --- Lógica para JUMPER Opensurvey ---
    if (isset($_POST['generate_link']) && isset($_POST['input_url'])) {
        if (!$canGenerateLinks) {
            $_SESSION['link_generated'] = 'No tienes permiso para generar enlaces.';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey Fallido', 'Permiso denegado');
            header('Location: index.php?module=opensurvey');
            exit;
        }
        $input_url = trim($_POST['input_url']);
        $parsed_url = filter_var($input_url, FILTER_VALIDATE_URL) ? parse_url($input_url) : false; // Validar URL primero

        if (!$parsed_url || !isset($parsed_url['query'])) {
            $_SESSION['link_generated'] = 'URL no válida o sin parámetros.';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey Fallido', 'URL inválida/sin query');
            header('Location: index.php?module=opensurvey');
            exit;
        }
        parse_str($parsed_url['query'], $params);
        $account = $params['account'] ?? null;
        $project = $params['project'] ?? null;
        $uuid = $params['uuid'] ?? null;
        if ($account && $project && $uuid) {
            $url_final = "https://www.opensurvey.com/survey/".rawurlencode($account)."/".rawurlencode($project)."?statusBack=1&respBack=".rawurlencode($uuid); // Usar rawurlencode
            $_SESSION['link_generated'] = $url_final;
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey Exitoso', "Project: {$project}");
        } else {
            $_SESSION['link_generated'] = 'La URL no contiene los parámetros necesarios (account, project, uuid).';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey Fallido', 'Parámetros faltantes');
        }
        header('Location: index.php?module=opensurvey');
        exit;
    }

    // --- Lógica para JUMPER OpinionExchange ---
    if (isset($_POST['generate_opinion_exchange']) && isset($_POST['input_url_opinion'])) {
       if (!$canGenerateLinks) {
            $_SESSION['opinion_link_generated'] = 'No tienes permiso para generar enlaces.';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx Fallido', 'Permiso denegado');
            header('Location: index.php?module=opinionexchange');
            exit;
        }
        $input_url = trim($_POST['input_url_opinion']);
        $parts = filter_var($input_url, FILTER_VALIDATE_URL) ? parse_url($input_url) : false; // Validar URL

        if (!$parts || !isset($parts['query'])) {
             $_SESSION['opinion_link_generated'] = 'URL no válida o sin parámetros.';
             if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx Fallido', 'URL inválida/sin query');
             header('Location: index.php?module=opinionexchange');
             exit;
        }

        parse_str($parts['query'], $params);
        $userUD = $params['UserID'] ?? null;
        if ($userUD) {
            // Asegurarse que el UserID no contenga caracteres maliciosos antes de usarlo
            // Una validación simple podría ser verificar si es alfanumérico o tiene un formato esperado
            if (preg_match('/^[a-zA-Z0-9_-]+$/', $userUD)) { // Ejemplo: permitir alfanuméricos, guión bajo, guión
                 $url_final = "https://opex.panelmembers.io/p/exit?s=c&session=" . urlencode($userUD);
                 $_SESSION['opinion_link_generated'] = $url_final;
                 if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx Exitoso');
            } else {
                 $_SESSION['opinion_link_generated'] = 'El UserID encontrado en la URL contiene caracteres inválidos.';
                 if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx Fallido', 'UserID inválido');
            }
        } else {
            $_SESSION['opinion_link_generated'] = 'La URL proporcionada no contiene UserID válido.';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx Fallido', 'UserID faltante');
        }
        header('Location: index.php?module=opinionexchange');
        exit;
    }

    // Si llega aquí, ninguna acción POST coincidió
    if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Acceso a generate.php Fallido', 'Acción POST no reconocida');

} else {
    // Si no es POST, registrar acceso inválido
     if (function_exists('logActivity')) logActivity($pdo, $user['id'] ?? null, $user['username'] ?? null, 'Acceso a generate.php Fallido', 'Método GET no permitido');
}


// Redirección por defecto si no se especifica ninguna acción POST válida o no es POST
header('Location: index.php');
exit;
?>