<?php
// api_generate_opensurvey.php (Actualizado v3 - Validación Sesión Única)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php';

// --- Auth y Permisos ---
if (!isset($_SESSION['user']) || !($user = $_SESSION['user'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No autorizado.']);
    exit;
}
$canGenerateLinks = ($user['role'] === 'admin') || ($user['can_generate_links'] == 1);
if (!$canGenerateLinks) {
     http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No tienes permiso para generar enlaces.']);
    exit;
}

// *** NUEVO: Validar Sesión Única ***
if (isset($user['id']) && isset($_SESSION['session_token'])) {
    try {
        $stmt_check = $pdo->prepare("SELECT current_session_token FROM usuarios WHERE id = ?");
        $stmt_check->execute([$user['id']]);
        $db_token = $stmt_check->fetchColumn();
        if ($db_token !== $_SESSION['session_token']) {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Sesión inválida (iniciada en otro dispositivo).']);
            exit;
        }
    } catch (PDOException $e) {
        error_log("Error validando token de sesión en API: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error de DB al verificar sesión.']);
        exit;
    }
} else {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Sesión no encontrada.']);
    exit;
}
// *** FIN VALIDACIÓN SESIÓN ÚNICA ***

// Verificar funciones (se mueven después del auth)
if (!function_exists('logActivity')) {
     error_log("FATAL ERROR: logActivity function not available in api_generate_opensurvey.php");
     http_response_code(500);
     echo json_encode(['success' => false, 'message' => 'Error interno del servidor (Fn).']);
     exit;
}

// Validar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Método no permitido.']);
    exit;
}

// Obtener y validar input
$input_url = trim($_POST['input_url'] ?? '');
if (empty($input_url) || !filter_var($input_url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'URL no válida proporcionada.']);
    logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey API Fallido', 'URL inválida');
    exit;
}

$parsed_url = parse_url($input_url);
if (!$parsed_url || !isset($parsed_url['query'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'URL inválida o sin parámetros.']);
     logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey API Fallido', 'URL sin query');
    exit;
}

parse_str($parsed_url['query'], $params);
$account = $params['account'] ?? null;
$project = $params['project'] ?? null;
$uuid = $params['uuid'] ?? null;

if ($account && $project && $uuid) {
    $url_final = "https://www.opensurvey.com/survey/".rawurlencode($account)."/".rawurlencode($project)."?statusBack=1&respBack=".urlencode($uuid);
    logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey API Exitoso', "Project: {$project}");
    echo json_encode(['success' => true, 'jumper' => $url_final]);
} else {
    logActivity($pdo, $user['id'], $user['username'], 'Generar Opensurvey API Fallido', 'Parámetros faltantes');
    echo json_encode(['success' => false, 'message' => 'La URL no contiene los parámetros necesarios (account, project, uuid).']);
}
exit;
?>