<?php
// api_add_subid.php (Actualizado v7 - Corrige el "disparador" de Telegram)
header('Content-Type: application/json; charset=utf-8');
if (session_status() === PHP_SESSION_NONE) { session_start(); }

require_once 'config.php';
require_once 'functions.php';
require_once 'maintenance_check.php'; // Comprobar Modo Mantenimiento

// --- Auth y Permisos ---
if (!isset($_SESSION['user']) || !($user = $_SESSION['user']) || !($user['role'] === 'admin' || $user['can_generate_links'] == 1)) {
    http_response_code(403);
    echo json_encode(['success' => false, 'message' => 'No autorizado.']);
    exit;
}
$userId = $user['id']; // *** IMPORTANTE: Obtener el ID del usuario ***

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

// Verificar funciones
if (!function_exists('logActivity') || !function_exists('addProjektnummerSubidMap')) {
     error_log("FATAL ERROR: Required functions not available in api_add_subid.php");
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

$projektnummer = trim($_POST['projektnummer'] ?? '');
$newSubid = trim($_POST['new_subid'] ?? '');

$isProjektnummerValid = ctype_digit($projektnummer) && (strlen($projektnummer) == 5 || strlen($projektnummer) == 6);
$isSubidValid = !empty($newSubid) && strlen($newSubid) <= 50;

if (empty($projektnummer) || empty($newSubid) || !$isProjektnummerValid || !$isSubidValid) {
    http_response_code(400);
    $errorMsg = 'Datos inválidos. Projektnummer debe ser 5 o 6 dígitos y SubID no puede estar vacío (max 50).';
    echo json_encode(['success' => false, 'message' => $errorMsg]);
    logActivity($pdo, $user['id'], $user['username'], 'Añadir SubID Fallido', 'Formato inválido: ' . $errorMsg);
    exit;
}

try {
    // *** CORRECCIÓN: Pasar el $userId a la función ***
    if (addProjektnummerSubidMap($pdo, $projektnummer, $newSubid, $userId)) { 
        logActivity($pdo, $user['id'], $user['username'], 'Añadir SubID Exitoso', "P:{$projektnummer}, S:{$newSubid}");
        echo json_encode(['success' => true, 'message' => '¡SubID añadido con éxito!', 'subid' => $newSubid]);
    } else {
        // Verificar si falló por duplicado
        $stmt_check = $pdo->prepare("SELECT COUNT(*) FROM projektnummer_subid_map WHERE projektnummer = ? AND subid = ?");
        $stmt_check->execute([$projektnummer, $newSubid]);
        if ($stmt_check->fetchColumn() > 0) {
            http_response_code(409);
             echo json_encode(['success' => false, 'message' => 'Este SubID ya está registrado para este Projektnummer.']);
             logActivity($pdo, $user['id'], $user['username'], 'Añadir SubID Fallido', "Duplicado: P:{$projektnummer}, S:{$newSubid}");
        } else {
             http_response_code(500);
             echo json_encode(['success' => false, 'message' => 'No se pudo añadir el SubID (Error de DB).']);
              logActivity($pdo, $user['id'], $user['username'], 'Añadir SubID Fallido', "Error DB: P:{$projektnummer}, S:{$newSubid}");
        }
    }
} catch (Exception $e) {
    error_log("Unexpected error in api_add_subid: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Ocurrió un error inesperado.']);
     logActivity($pdo, $user['id'], $user['username'], 'Añadir SubID Fallido', "Excepción: {$e->getMessage()}");
}
?>