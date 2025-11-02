<?php
// api_ranking.php (v1 - API para el Leaderboard)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php';
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
    'ranking' => []
];

try {
    // Usamos 'activity_log' para contar cuántos SubIDs ha añadido cada usuario
    $stmt = $pdo->prepare("
        SELECT 
            u.username, 
            COUNT(a.id) as subid_count
        FROM activity_log a
        JOIN usuarios u ON a.user_id = u.id
        WHERE 
            a.action = 'Añadir SubID Exitoso' OR 
            a.action = 'Admin: Añadir Mapeo Manual'
        GROUP BY a.user_id
        ORDER BY subid_count DESC
        LIMIT 10
    ");
    $stmt->execute();
    $ranking_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $rank = 1;
    foreach ($ranking_data as $row) {
        $response['ranking'][] = [
            'rank' => $rank,
            'username' => htmlspecialchars($row['username']),
            'avatar_url' => 'https://api.dicebear.com/8.x/adventurer/svg?seed=' . urlencode($row['username']),
            'count' => (int) $row['subid_count']
        ];
        $rank++;
    }

} catch (PDOException $e) {
    error_log("Error en api_ranking.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error al consultar el ranking.']);
    exit;
}

echo json_encode($response);
exit;
?>
