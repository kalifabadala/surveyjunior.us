<?php
// api_admin_stats.php (v1)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php'; // Para updateUserActivity y validación de token

// --- Auth y Permisos (Solo Admin) ---
if (!isset($_SESSION['user']) || !($user = $_SESSION['user']) || $user['role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'Acceso denegado. Solo para administradores.']);
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

// Actualizar actividad del admin
if (function_exists('updateUserActivity')) {
    updateUserActivity($pdo, $user['id']);
}

$response = [
    'success' => true,
    'stats' => [],
    'chart_data' => []
];

try {
    // 1. Estadísticas de Tarjetas
    $stmt_total = $pdo->query("SELECT COUNT(*) FROM usuarios");
    $response['stats']['totalUsers'] = $stmt_total->fetchColumn();

    $stmt_online = $pdo->query("SELECT COUNT(*) FROM usuarios WHERE online = 1");
    $response['stats']['onlineUsers'] = $stmt_online->fetchColumn();

    $stmt_admins = $pdo->query("SELECT COUNT(*) FROM usuarios WHERE role = 'admin'");
    $response['stats']['adminCount'] = $stmt_admins->fetchColumn();
    
    // 2. Datos del Gráfico (Actividad de Jumpers y Logins en los últimos 7 días)
    $labels = [];
    $jumpersData = [];
    $loginsData = [];
    
    for ($i = 6; $i >= 0; $i--) {
        $date = date('Y-m-d', strtotime("-$i days"));
        $labels[] = date('M d', strtotime($date));
        
        // Contar Jumpers
        $stmt_jumpers = $pdo->prepare("
            SELECT COUNT(*) FROM activity_log 
            WHERE DATE(timestamp) = ? 
            AND (action = 'Generar Opensurvey API Exitoso' 
                 OR action = 'Generar OpinionEx API Exitoso' 
                 OR action = 'Generar Meinungsplatz API Exitoso')
        ");
        $stmt_jumpers->execute([$date]);
        $jumpersData[] = (int) $stmt_jumpers->fetchColumn();
        
        // Contar Logins
        $stmt_logins = $pdo->prepare("SELECT COUNT(*) FROM activity_log WHERE DATE(timestamp) = ? AND action LIKE 'Login%'");
        $stmt_logins->execute([$date]);
        $loginsData[] = (int) $stmt_logins->fetchColumn();
    }
    
    $response['chart_data'] = [
        'labels' => $labels,
        'jumpers' => $jumpersData,
        'logins' => $loginsData
    ];

    // 3. Estado del Modo Mantenimiento
    $response['stats']['maintenance_mode'] = file_exists('MAINTENANCE');

} catch (PDOException $e) {
    error_log("Error en api_admin_stats: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error al consultar estadísticas de la base de datos.']);
    exit;
}

echo json_encode($response);
exit;
?>