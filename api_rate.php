<?php
// api_rate.php (Actualizado v8 - Validación Sesión Única)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php';

// Auth
if (!isset($_SESSION['user']) || !($user = $_SESSION['user'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No autorizado.']);
    exit;
}

// *** NUEVO: Validar Sesión Única ***
if (isset($user['id']) && isset($_SESSION['session_token'])) {
    try {
        $stmt_check = $pdo->prepare("SELECT current_session_token FROM usuarios WHERE id = ?");
        $stmt_check->execute([$user['id']]);
        $db_token = $stmt_check->fetchColumn();
        if ($db_token !== $_SESSION['session_token']) {
            http_response_code(401); // 401 Unauthorized
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

// Verificar $pdo y funciones (se mueven después del auth)
if (!function_exists('logActivity') || !function_exists('getSubidRatings') || !function_exists('submitSubidRating') || !function_exists('getSubidComments')) {
     error_log("FATAL ERROR: Required functions not available in api_rate.php");
     http_response_code(500);
     echo json_encode(['success' => false, 'message' => 'Error interno del servidor (Fn).']);
     exit;
}

$subid = trim($_REQUEST['subid'] ?? '');

// --- ACCIÓN 1: OBTENER CALIFICACIONES (GET) ---
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (empty($subid) || strlen($subid) > 50) {
         http_response_code(400);
         echo json_encode(['success' => false, 'message' => 'SubID inválido para obtener calificaciones.']);
         exit;
    }
    try {
        $ratings = getSubidRatings($pdo, $subid);
        $comments = getSubidComments($pdo, $subid);
         echo json_encode(['success' => true, 'ratings' => $ratings, 'comments' => $comments]);
    } catch (Throwable $e) {
         error_log("Unexpected error during GET ratings for {$subid}: " . $e->getMessage());
         http_response_code(500);
         echo json_encode(['success' => false, 'message' => 'Error interno al obtener calificaciones: ' . $e->getMessage()]);
    }
    exit;
}

// --- ACCIÓN 2: ENVIAR CALIFICACIÓN (POST) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $subid_post = trim($_POST['subid'] ?? '');
    $rating_input = $_POST['rating'] ?? null;
    $comment = trim($_POST['comment'] ?? '');

    if (empty($subid_post) || strlen($subid_post) > 50 ||
        $rating_input === null || !in_array(intval($rating_input), [1, -1])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Datos de calificación inválidos (SubID u Rating).']);
        logActivity($pdo, $user['id'], $user['username'], 'Enviar Rating Fallido', 'Datos inválidos');
        exit;
    }
    $rating = intval($rating_input);

    try {
        $submit_success = submitSubidRating($pdo, $subid_post, $user['id'], $rating, $comment);

        if ($submit_success) {
            $newRatings = getSubidRatings($pdo, $subid_post);
            $newComments = getSubidComments($pdo, $subid_post);
            logActivity($pdo, $user['id'], $user['username'], 'Enviar Rating Exitoso', "S:{$subid_post}, R:{$rating}");
            echo json_encode(['success' => true, 'message' => '¡Gracias por tu calificación!', 'ratings' => $newRatings, 'comments' => $newComments]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'No se pudo guardar tu calificación (Error DB).']);
            logActivity($pdo, $user['id'], $user['username'], 'Enviar Rating Fallido', "Error DB S:{$subid_post}, R:{$rating}");
        }
    } catch (Throwable $e) {
        error_log("Unexpected error during POST rating for {$subid_post}: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error interno al procesar calificación: ' . $e->getMessage()]);
        logActivity($pdo, $user['id'], $user['username'], 'Enviar Rating Fallido', "Excepción S:{$subid_post}, R:{$rating}: {$e->getMessage()}");
    }
    exit;
}

// Si no coincide con GET o POST válido
http_response_code(405);
echo json_encode(['success' => false, 'message' => 'Método de solicitud inválido.']);
?>