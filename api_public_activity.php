<?php
// api_public_activity.php (v1 - API Pública de Actividad)
header('Content-Type: application/json; charset=utf-ch');
require_once 'config.php'; // Solo para la conexión a la DB

// Esta API es pública y no revela información sensible.

$activities = [];
try {
    // Unir usuarios para obtener el nombre
    $stmt = $pdo->prepare(
        "SELECT u.username, a.action, a.details 
         FROM activity_log a
         LEFT JOIN usuarios u ON a.user_id = u.id
         WHERE a.action IN (
            'Añadir SubID Exitoso', 
            'Admin: Añadir Mapeo Manual', 
            'Generar Meinungsplatz API Exitoso'
         )
         AND a.user_id IS NOT NULL
         ORDER BY a.id DESC 
         LIMIT 15" // Obtenemos los últimos 15
    );
    $stmt->execute();
    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $formatted_activities = [];
    foreach ($logs as $log) {
        $username = $log['username'] ?? 'Alguien';
        // Acortar el nombre si es largo para que quepa en el toast
        if (strlen($username) > 10) {
            $username = substr($username, 0, 8) . '...';
        }
        
        $message = '';
        if ($log['action'] === 'Generar Meinungsplatz API Exitoso') {
            $details_parts = explode(',', $log['details']);
            $projekt = $details_parts[0] ?? 'un jumper'; // "P:12345"
            $projekt_num = str_replace('P:', '', $projekt);
            $message = "generó un jumper para <b>" . htmlspecialchars(trim($projekt_num)) . "</b>";
        } else {
            $details_parts = explode(',', $log['details']);
            $projekt = $details_parts[0] ?? 'un SubID'; // "P:12345"
            $projekt_num = str_replace('P:', '', $projekt);
            $message = "añadió un SubID para <b>" . htmlspecialchars(trim($projekt_num)) . "</b>";
        }
        
        $formatted_activities[] = [
            'user' => htmlspecialchars($username),
            'message' => $message // $message ya está saneado
        ];
    }
    
    // Mezclar para que no sea siempre el mismo orden
    shuffle($formatted_activities);
    
    echo json_encode(['success' => true, 'activities' => $formatted_activities]);

} catch (PDOException $e) {
    error_log("Error en api_public_activity: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Error de DB']);
}
exit;
?>