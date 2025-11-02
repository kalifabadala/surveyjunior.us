<?php
// api_admin_actions.php (v1)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php'; 

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

// Leer el cuerpo de la solicitud JSON
$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? null;

if (!$action) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Acción no especificada.']);
    exit;
}

try {
    switch ($action) {
        
        case 'toggle_maintenance':
            $new_status = $input['value'] ?? false;
            $maintenance_file = 'MAINTENANCE';
            if ($new_status === true) {
                // Activar modo mantenimiento
                file_put_contents($maintenance_file, 'Activado el ' . date('c'));
                logActivity($pdo, $user['id'], $user['username'], 'Admin: Mantenimiento ACTIVADO');
                echo json_encode(['success' => true, 'message' => 'Modo Mantenimiento ACTIVADO.']);
            } else {
                // Desactivar modo mantenimiento
                if (file_exists($maintenance_file)) {
                    unlink($maintenance_file);
                }
                logActivity($pdo, $user['id'], $user['username'], 'Admin: Mantenimiento DESACTIVADO');
                echo json_encode(['success' => true, 'message' => 'Modo Mantenimiento DESACTIVADO.']);
            }
            break;

        case 'clear_logs':
            // Limpiar logs de más de 30 días
            $stmt = $pdo->prepare("DELETE FROM activity_log WHERE timestamp < NOW() - INTERVAL 30 DAY");
            $stmt->execute();
            $rowsAffected = $stmt->rowCount();
            logActivity($pdo, $user['id'], $user['username'], 'Admin: Limpiar Logs Antiguos', "Registros eliminados: {$rowsAffected}");
            echo json_encode(['success' => true, 'message' => "Se eliminaron {$rowsAffected} registros de log antiguos."]);
            break;

        case 'force_logout':
            // Forzar cierre de sesión de todos
            $stmt = $pdo->prepare("UPDATE usuarios SET current_session_token = NULL");
            $stmt->execute();
            $rowsAffected = $stmt->rowCount();
            // Desloguear al admin actual también
            $_SESSION['session_token'] = null; // Esto hará que su próxima acción falle y pida login
            logActivity($pdo, $user['id'], $user['username'], 'Admin: Forzar Cierre de Sesiones', "Sesiones cerradas: {$rowsAffected}");
            echo json_encode(['success' => true, 'message' => "Se cerraron {$rowsAffected} sesiones. Serás desconectado."]);
            break;

        case 'purge_cache':
            // Esta función requiere configuración en config.php
            if (defined('CLOUDFLARE_API_KEY') && defined('CLOUDFLARE_ZONE_ID') && defined('CLOUDFLARE_EMAIL')) {
                
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, "https://api.cloudflare.com/client/v4/zones/" . CLOUDFLARE_ZONE_ID . "/purge_cache");
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['purge_everything' => true]));
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'X-Auth-Email: ' . CLOUDFLARE_EMAIL,
                    'X-Auth-Key: ' . CLOUDFLARE_API_KEY,
                    'Content-Type: application/json'
                ]);
                
                $result = curl_exec($ch);
                curl_close($ch);
                
                logActivity($pdo, $user['id'], $user['username'], 'Admin: Purgar Caché Cloudflare');
                echo json_encode(['success' => true, 'message' => 'Se envió la solicitud para purgar el caché de Cloudflare.', 'details' => $result]);

            } else {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Las credenciales de API de Cloudflare no están configuradas en config.php.']);
            }
            break;

        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Acción desconocida.']);
            break;
    }
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error de Base de Datos: ' . $e->getMessage()]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error General: ' . $e->getMessage()]);
}
exit;
?>