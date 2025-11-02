<?php
// api_home_stats.php (v2 - Simplificado)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php'; // Para updateUserActivity y validación de token
require_once 'maintenance_check.php'; // Comprobar Modo Mantenimiento

// --- Auth y Permisos (Cualquier usuario logueado) ---
if (!isset($_SESSION['user']) || !($user = $_SESSION['user'])) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No autorizado.']);
    exit;
}

// --- Validación Sesión Única ---
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
// --- Fin Validación ---

// Actualizar actividad
if (function_exists('updateUserActivity')) {
    updateUserActivity($pdo, $user['id']);
}

$response = [
    'success' => true,
    'stats' => []
];

try {
    // 1. Contar Jumpers Generados por el usuario
    $stmt_jumper_count = $pdo->prepare("
        SELECT COUNT(*) FROM activity_log 
        WHERE user_id = ? 
        AND (action = 'Generar Opensurvey API Exitoso' 
             OR action = 'Generar OpinionEx API Exitoso' 
             OR action = 'Generar Meinungsplatz API Exitoso')
    ");
    $stmt_jumper_count->execute([$user['id']]);
    $response['stats']['total_jumpers'] = (int) $stmt_jumper_count->fetchColumn();

} catch (PDOException $e) {
    error_log("Error en api_home_stats: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error al consultar estadísticas de la base de datos.']);
    exit;
}

echo json_encode($response);
exit;
?>