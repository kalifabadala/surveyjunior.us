<?php
// api_generate.php (Actualizado v8 - Validación Sesión Única)
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Expires: ' . gmdate('D, d M Y H:i:s') . ' GMT');
header('Pragma: no-cache');

if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php';

// --- Auth y Permisos ---
if (!isset($_SESSION['user']) || !($user = $_SESSION['user']) || !($user['role'] === 'admin' || $user['can_generate_links'] == 1)) {
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

// Validar método
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Método no permitido.']);
    exit;
}

// Obtener y Validar Inputs
$urls = $_POST['urls'] ?? '';
$projektnummer = trim($_POST['projektnummer'] ?? '');
$isProjektnummerValid = ctype_digit($projektnummer) && (strlen($projektnummer) == 5 || strlen($projektnummer) == 6);

if (empty($urls) || empty($projektnummer) || !$isProjektnummerValid) {
    http_response_code(400);
    $errorMsg = 'Datos inválidos. Asegúrate de pegar las URLs y un Projektnummer de 5 o 6 dígitos.';
    echo json_encode(['success' => false, 'message' => $errorMsg]);
    logActivity($pdo, $user['id'], $user['username'], 'Generar Meinungsplatz API Fallido', 'Datos inválidos: ' . $errorMsg);
    exit;
}

// 1. Encontrar el user_id de 15 dígitos
$user_id = null;
try {
    $lines = explode("\n", str_replace("\r", "", $urls));
    foreach ($lines as $line) {
        $trimmed_line = trim($line);
        if (empty($trimmed_line)) continue;
        $query_string = parse_url($trimmed_line, PHP_URL_QUERY);
        if ($query_string) {
            parse_str($query_string, $params);
            if (is_array($params)){
                foreach ($params as $key => $value) {
                    if (is_string($value) && ctype_digit($value) && strlen($value) === 15) {
                        $user_id = $value; break 2;
                    }
                }
            }
        }
        if (!$user_id && preg_match('/[?&](?:m|UserID|uid|id)=([0-9]{15})(?:&|$)/i', $trimmed_line, $matches)) {
             $user_id = $matches[1]; break;
        }
    }
} catch (Exception $e) {
     error_log("Error parsing URLs in api_generate: " . $e->getMessage());
     http_response_code(400);
     echo json_encode(['success' => false, 'message' => 'Error al procesar las URLs ingresadas.']);
     exit;
}

if (!$user_id) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'No se encontró un ID de usuario (15 dígitos) en las URLs proporcionadas.']);
    logActivity($pdo, $user['id'], $user['username'], 'Generar Meinungsplatz API Fallido', 'ID Usuario 15d no encontrado');
    exit;
}

// 2. Buscar el SubID en la base de datos
$subid = null;
try {
    $subid = findSubidForProjektnummer($pdo, $projektnummer); // Devuelve string o null
} catch (Throwable $e) {
     error_log("Throwable calling findSubidForProjektnummer: " . $e->getMessage());
     http_response_code(500);
     echo json_encode(['success' => false, 'message' => 'Error fatal al buscar SubID: ' . $e->getMessage()]);
     exit;
}

// --- Continuar con la lógica normal ---
if ($subid !== null) {
    // 3. Éxito: Generar el JUMPER
    try {
        $jumper = "https://survey.maximiles.com/complete?p=" . urlencode($projektnummer . '_' . $subid) . "&m=" . urlencode($user_id);
        logActivity($pdo, $user['id'], $user['username'], 'Generar Meinungsplatz API Exitoso', "P:{$projektnummer}, S:{$subid}");

        $json_output = json_encode([
            'success' => true,
            'message' => "¡JUMPER Generado con éxito!",
            'jumper' => $jumper,
            'subid' => $subid,
            'projektnummer' => $projektnummer
        ]);
        
        if (json_last_error() !== JSON_ERROR_NONE) { throw new Exception("JSON Encoding Error: " . json_last_error_msg()); }
        echo $json_output;

    } catch (Exception $e) {
         error_log("Error generating success response in api_generate: " . $e->getMessage());
         http_response_code(500);
         echo json_encode(['success' => false, 'message' => 'Error interno al generar respuesta.']);
    }

} else {
    // 4. Error: SubID no encontrado
    logActivity($pdo, $user['id'], $user['username'], 'Generar Meinungsplatz API Fallido', "SubID no encontrado P:{$projektnummer}");
    echo json_encode([
        'success' => false,
        'error_type' => 'subid_not_found',
        'message' => "No tenemos SubID para Projektnummer <strong>".htmlspecialchars($projektnummer, ENT_QUOTES, 'UTF-8')."</strong>.",
        'projektnummer' => $projektnummer
    ]);
}
exit;
?>