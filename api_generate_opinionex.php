<?php
// api_generate_opinionex.php (Actualizado v3 - Validación Sesión Única)
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
     error_log("FATAL ERROR: logActivity function not available in api_generate_opinionex.php");
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
$input_url = trim($_POST['input_url_opinion'] ?? '');
if (empty($input_url) || !filter_var($input_url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'URL no válida proporcionada.']);
     logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx API Fallido', 'URL inválida');
    exit;
}

$parts = parse_url($input_url);
if (!isset($parts['query'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'La URL no contiene parámetros (query string).']);
    logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx API Fallido', 'URL sin query');
    exit;
}

parse_str($parts['query'], $params);
$userUD = $params['UserID'] ?? null;

if ($userUD) {
     if (preg_match('/^[a-zA-Z0-9_-]+$/', $userUD)) {
        $url_final = "https://opex.panelmembers.io/p/exit?s=c&session=" . urlencode($userUD);
        logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx API Exitoso');
        echo json_encode(['success' => true, 'jumper' => $url_final]);
     } else {
         http_response_code(400);
         echo json_encode(['success' => false, 'message' => 'El UserID encontrado contiene caracteres inválidos.']);
         logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx API Fallido', 'UserID inválido');
     }
} else {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'La URL proporcionada no contiene el parámetro UserID.']);
    logActivity($pdo, $user['id'], $user['username'], 'Generar OpinionEx API Fallido', 'UserID faltante');
}
exit;
?>