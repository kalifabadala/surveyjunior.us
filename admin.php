<?php
// admin.php (Actualizado v17 - Pasa UserID a addProjektnummerSubidMap)
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php';
require 'functions.php';

// --- Check "Recordarme" Cookie y Auth ---
if (!isset($_SESSION['user'])) {
    if (function_exists('validateRememberMe')) { $userFromCookie = validateRememberMe($pdo); }
    else { error_log("Error: validateRememberMe function not found"); }
}
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
     if (isset($_COOKIE[REMEMBER_ME_COOKIE_NAME]) && function_exists('clearRememberMeCookie')) { clearRememberMeCookie(); }
     header('Location: login.php'); exit;
}
$user = $_SESSION['user'];

// --- Validación Sesión Única ---
if (isset($user['id']) && isset($_SESSION['session_token'])) {
    try {
        $stmt_check = $pdo->prepare("SELECT current_session_token FROM usuarios WHERE id = ?");
        $stmt_check->execute([$user['id']]);
        $db_token = $stmt_check->fetchColumn();

        if ($db_token !== $_SESSION['session_token']) {
            session_unset(); session_destroy();
            header("Location: login.php?error=" . urlencode("Tu sesión fue cerrada porque se inició sesión en otro dispositivo."));
            exit;
        }
    } catch (PDOException $e) {
        error_log("Error validando token de sesión: " . $e->getMessage());
        session_unset(); session_destroy();
        header("Location: login.php?error=" . urlencode("Error al verificar la sesión."));
        exit;
    }
} elseif (!isset($_SESSION['session_token'])) {
    session_unset(); session_destroy();
    header("Location: login.php?error=" . urlencode("Sesión inválida. Por favor, inicia sesión de nuevo."));
    exit;
}
// --- Fin Validación ---

$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
if (function_exists('updateUserActivity')) { updateUserActivity($pdo, $user['id']); }

$message = ''; $message_type = 'info';
$section = $_GET['section'] ?? 'dashboard';
$action_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
if (strpos($action_ip, ',') !== false) { $action_ip = trim(explode(',', $action_ip)[0]); }

// --- LÓGICA DE ACCIONES ADMIN (CON LOGGING) ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_user']) && $section == 'users') {
    $new_username = trim($_POST['new_username']); $new_password = $_POST['new_password']; $new_role = $_POST['new_role']; $can_generate_links = isset($_POST['can_generate_links']) ? 1 : 0;
    if (empty($new_username) || empty($new_password) || empty($new_role)) { $message = "Usuario, contraseña y rol son obligatorios."; $message_type = 'danger'; }
    elseif (strlen($new_password) < 6) { $message = "La contraseña debe tener al menos 6 caracteres."; $message_type = 'danger'; }
    else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE username = ?"); $stmt->execute([$new_username]);
            if ($stmt->fetch()) { $message = "El nombre de usuario '{$new_username}' ya está en uso."; $message_type = 'warning'; } else {
                $hash = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO usuarios (username, password, role, can_generate_links, active, banned) VALUES (?, ?, ?, ?, 1, 0)");
                if ($stmt->execute([$new_username, $hash, $new_role, $can_generate_links])) {
                    $message = "Usuario '{$new_username}' creado exitosamente."; $message_type = 'success';
                    if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Crear Usuario', "Usuario: {$new_username}, Rol: {$new_role}");
                } else { $message = "Error al crear el usuario."; $message_type = 'danger'; }
            }
        } catch (PDOException $e) { error_log("Admin Add User Error: " . $e->getMessage()); $message = "Error de base de datos: " . $e->getMessage(); $message_type = 'danger'; }
    }
}
if (isset($_GET['action']) && $_GET['action'] == 'toggle_active' && isset($_GET['user_id']) && $section == 'users') {
    $targetUserId = intval($_GET['user_id']);
    try {
        $stmt = $pdo->prepare("SELECT username, active FROM usuarios WHERE id = ? AND username != 'admin'");
        $stmt->execute([$targetUserId]); $targetUser = $stmt->fetch();
        if ($targetUser) {
            $newStatus = $targetUser['active'] ? 0 : 1;
            $stmt = $pdo->prepare("UPDATE usuarios SET active = ? WHERE id = ?");
            if ($stmt->execute([$newStatus, $targetUserId])) {
                 $message = "Estado de ".htmlspecialchars($targetUser['username'])." cambiado."; $message_type = 'success';
                 $status_text = $newStatus ? 'Activado' : 'Desactivado';
                 if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Cambiar Estado Usuario', "Usuario ID: {$targetUserId} ({$targetUser['username']}), Nuevo Estado: {$status_text}");
            } else { $message = "Error al cambiar estado."; $message_type = 'danger'; }
        } else { $message = "Usuario no encontrado o no permitido."; $message_type = 'warning'; }
    } catch (PDOException $e) { error_log("Admin Toggle Active Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
}
if (isset($_GET['action']) && $_GET['action'] == 'toggle_generate' && isset($_GET['user_id']) && $section == 'users') {
    $targetUserId = intval($_GET['user_id']);
     try {
        $stmt = $pdo->prepare("SELECT username, can_generate_links FROM usuarios WHERE id = ? AND username != 'admin'");
        $stmt->execute([$targetUserId]); $targetUser = $stmt->fetch();
        if ($targetUser) {
            $newPerm = $targetUser['can_generate_links'] ? 0 : 1;
            $stmt = $pdo->prepare("UPDATE usuarios SET can_generate_links = ? WHERE id = ?");
             if ($stmt->execute([$newPerm, $targetUserId])) {
                 $message = "Permiso de generar enlaces de ".htmlspecialchars($targetUser['username'])." actualizado."; $message_type = 'success';
                 $perm_text = $newPerm ? 'Permitido' : 'Revocado';
                 if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Cambiar Permiso Generar', "Usuario ID: {$targetUserId} ({$targetUser['username']}), Nuevo Permiso: {$perm_text}");
            } else { $message = "Error al cambiar permiso."; $message_type = 'danger'; }
        } else { $message = "Usuario no encontrado o no permitido."; $message_type = 'warning'; }
    } catch (PDOException $e) { error_log("Admin Toggle Generate Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
}
if (isset($_GET['action']) && $_GET['action'] == 'delete_user' && isset($_GET['user_id']) && $section == 'users') {
    $targetUserId = intval($_GET['user_id']);
    try {
        $stmt = $pdo->prepare("SELECT username FROM usuarios WHERE id = ? AND username != 'admin'");
        $stmt->execute([$targetUserId]); $targetUsername = $stmt->fetchColumn();
        if ($targetUsername) {
             $pdo->beginTransaction();
             $stmt_del_tokens = $pdo->prepare("DELETE FROM persistent_logins WHERE user_id = ?"); $stmt_del_tokens->execute([$targetUserId]);
             $stmt_del = $pdo->prepare("DELETE FROM usuarios WHERE id = ?"); $deleteSuccess = $stmt_del->execute([$targetUserId]);
             $pdo->commit();
            if ($deleteSuccess) {
                $message = "Usuario ".htmlspecialchars($targetUsername)." eliminado."; $message_type = 'success';
                if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Eliminar Usuario', "Usuario ID: {$targetUserId} ({$targetUsername})");
            } else { $message = "Error al eliminar usuario."; $message_type = 'danger'; $pdo->rollBack(); }
        } else { $message = "Usuario no encontrado o no permitido."; $message_type = 'warning'; }
    } catch (PDOException $e) { $pdo->rollBack(); error_log("Admin Delete User Error: ".$e->getMessage()); $message="Error DB al eliminar: " . $e->getMessage(); $message_type = 'danger'; }
}
if (isset($_POST['change_password']) && !empty($_POST['user_id']) && !empty($_POST['new_password']) && $section == 'users') {
    $targetUserId = intval($_POST['user_id']); $newPassword = $_POST['new_password'];
    if(strlen($newPassword)>=6){
        try {
            $stmt = $pdo->prepare("SELECT username FROM usuarios WHERE id = ? AND username != 'admin'");
            $stmt->execute([$targetUserId]); $targetUsername = $stmt->fetchColumn();
            if ($targetUsername) {
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $pdo->beginTransaction();
                $stmt_upd = $pdo->prepare("UPDATE usuarios SET password = ? WHERE id = ?"); $updateSuccess = $stmt_upd->execute([$hashedPassword, $targetUserId]);
                $stmt_del_tokens = $pdo->prepare("DELETE FROM persistent_logins WHERE user_id = ?"); $stmt_del_tokens->execute([$targetUserId]);
                $pdo->commit();
                if ($updateSuccess) {
                    $message = "Contraseña de ".htmlspecialchars($targetUsername)." actualizada."; $message_type = 'success';
                     if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Cambiar Contraseña', "Usuario ID: {$targetUserId} ({$targetUsername})");
                } else { $message = "Error al actualizar contraseña."; $message_type = 'danger'; $pdo->rollBack(); }
            } else { $message = "Usuario no encontrado o no permitido."; $message_type = 'warning'; }
        } catch (PDOException $e){ $pdo->rollBack(); error_log("Admin Change Pass Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
    } else {$message="La nueva contraseña debe tener al menos 6 caracteres."; $message_type = 'danger';}
}
if (isset($_POST['add_map']) && $section == 'subid_maps') {
    $projektnummer = trim($_POST['projektnummer']); $newSubid = trim($_POST['new_subid']); 
    // *** CORRECCIÓN: Obtener el $userId del admin logueado ***
    $userId = $user['id']; 
    $isProjektnummerValid = ctype_digit($projektnummer) && (strlen($projektnummer) == 5 || strlen($projektnummer) == 6);
    $isSubidValid = !empty($newSubid) && strlen($newSubid) <= 50;
    if (!$isProjektnummerValid || !$isSubidValid) { $message = "Datos inválidos. Projektnummer debe ser 5 o 6 dígitos y SubID no puede estar vacío (max 50)."; $message_type = 'danger'; }
    else {
        // *** CORRECCIÓN: Pasar el $userId a la función ***
        if (addProjektnummerSubidMap($pdo, $projektnummer, $newSubid, $userId)) {
            $message = "Mapeo añadido con éxito."; $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Añadir Mapeo Manual', "P:{$projektnummer}, S:{$newSubid}");
        } else {
            try {
                $stmt_check = $pdo->prepare("SELECT COUNT(*) FROM projektnummer_subid_map WHERE projektnummer = ? AND subid = ?");
                $stmt_check->execute([$projektnummer, $newSubid]);
                if ($stmt_check->fetchColumn() > 0) {
                    $message = "Error: Este mapeo (Projektnummer + SubID) ya existe."; $message_type = 'warning';
                } else { $message = "Error: No se pudo añadir el mapeo (Error de DB)."; $message_type = 'danger'; }
            } catch (PDOException $e) { $message = "Error de DB al verificar duplicado: " . $e->getMessage(); $message_type = 'danger'; }
        }
    }
}
if (isset($_GET['action']) && $_GET['action'] == 'delete_map' && isset($_GET['map_id']) && $section == 'subid_maps') {
    $mapId = intval($_GET['map_id']);
    try {
        $stmt = $pdo->prepare("DELETE FROM projektnummer_subid_map WHERE id = ?");
        if ($stmt->execute([$mapId])) {
            $message = "Mapeo SubID eliminado."; $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Eliminar Mapeo SubID', "Map ID: {$mapId}");
        } else { $message = "Error al eliminar mapeo."; $message_type = 'danger'; }
    } catch (PDOException $e) { error_log("Admin Delete Map Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
}
if (isset($_POST['edit_map']) && $section == 'subid_maps') {
    $mapId = intval($_POST['map_id']);
    $newSubid = trim($_POST['new_subid']);
    $isSubidValid = !empty($newSubid) && strlen($newSubid) <= 50;
    if (!$isSubidValid) { $message = "El nuevo SubID no es válido (debe tener entre 1 y 50 caracteres)."; $message_type = 'danger'; }
    else {
        try {
            $stmt = $pdo->prepare("UPDATE projektnummer_subid_map SET subid = ? WHERE id = ?");
            if ($stmt->execute([$newSubid, $mapId])) {
                $message = "Mapeo SubID actualizado con éxito."; $message_type = 'success';
                if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Editar Mapeo SubID', "Map ID: {$mapId}, New SubID: {$newSubid}");
            } else { $message = "Error al actualizar el mapeo."; $message_type = 'danger'; }
        } catch (PDOException $e) { error_log("Admin Edit Map Error: ".$e->getMessage()); $message="Error DB al actualizar: " . $e->getMessage(); $message_type = 'danger'; }
    }
}
if (isset($_GET['action']) && $_GET['action'] == 'delete_rating' && isset($_GET['rating_id']) && $section == 'ratings') {
    $ratingId = intval($_GET['rating_id']);
    try {
        $stmt = $pdo->prepare("DELETE FROM subid_ratings WHERE id = ?");
        if ($stmt->execute([$ratingId])) {
            $message = "Calificación eliminada."; $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Eliminar Calificación', "Rating DB ID: {$ratingId}");
        } else { $message = "Error al eliminar calificación."; $message_type = 'danger'; }
    } catch (PDOException $e) { error_log("Admin Delete Rating Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_link']) && $section == 'shortener') {
    $slug = trim($_POST['slug']);
    $target_url = trim($_POST['target_url']);

    if (empty($slug) || empty($target_url)) {
        $message = "El 'Slug' y la 'URL de Destino' son obligatorios.";
        $message_type = 'danger';
    } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
        $message = "El 'Slug' solo puede contener letras, números, guiones (-) y guiones bajos (_).";
        $message_type = 'danger';
    } elseif (!filter_var($target_url, FILTER_VALIDATE_URL)) {
        $message = "La 'URL de Destino' no es una URL válida.";
        $message_type = 'danger';
    } else {
        try {
            $stmt = $pdo->prepare("INSERT INTO short_links (slug, target_url) VALUES (?, ?)");
            $stmt->execute([$slug, $target_url]);
            $message = "Enlace acortado creado con éxito: /go/{$slug}";
            $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Crear Enlace Corto', "Slug: {$slug}");
        } catch (PDOException $e) {
            if ($e->errorInfo[1] == 1062) {
                $message = "Error: El 'Slug' (atajo) '{$slug}' ya está en uso.";
                $message_type = 'warning';
            } else {
                $message = "Error de DB al crear el enlace: " . $e->getMessage();
                $message_type = 'danger';
            }
            error_log("Admin Add Link Error: " . $e->getMessage());
        }
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['edit_link']) && $section == 'shortener') {
    $linkId = intval($_POST['link_id']);
    $slug = trim($_POST['slug']);
    $target_url = trim($_POST['target_url']);

    if (empty($slug) || empty($target_url) || empty($linkId)) {
        $message = "ID, 'Slug' y 'URL de Destino' son obligatorios.";
        $message_type = 'danger';
    } elseif (!preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
        $message = "El 'Slug' solo puede contener letras, números, guiones (-) y guiones bajos (_).";
        $message_type = 'danger';
    } elseif (!filter_var($target_url, FILTER_VALIDATE_URL)) {
        $message = "La 'URL de Destino' no es una URL válida.";
        $message_type = 'danger';
    } else {
        try {
            $stmt = $pdo->prepare("UPDATE short_links SET slug = ?, target_url = ? WHERE id = ?");
            $stmt->execute([$slug, $target_url, $linkId]);
            $message = "Enlace actualizado con éxito.";
            $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Editar Enlace Corto', "ID: {$linkId}, Slug: {$slug}");
        } catch (PDOException $e) {
            if ($e->errorInfo[1] == 1062) {
                $message = "Error: El 'Slug' (atajo) '{$slug}' ya está en uso.";
                $message_type = 'warning';
            } else {
                $message = "Error de DB al actualizar el enlace: " . $e->getMessage();
                $message_type = 'danger';
            }
            error_log("Admin Edit Link Error: " . $e->getMessage());
        }
    }
}
if (isset($_GET['action']) && $_GET['action'] == 'delete_link' && isset($_GET['link_id']) && $section == 'shortener') {
    $linkId = intval($_GET['link_id']);
    try {
        $stmt = $pdo->prepare("DELETE FROM short_links WHERE id = ?");
        if ($stmt->execute([$linkId])) {
            $message = "Enlace acortado eliminado."; $message_type = 'success';
            if (function_exists('logActivity')) logActivity($pdo, $user['id'], $user['username'], 'Admin: Eliminar Enlace Corto', "ID: {$linkId}");
        } else { $message = "Error al eliminar el enlace."; $message_type = 'danger'; }
    } catch (PDOException $e) { error_log("Admin Delete Link Error: ".$e->getMessage()); $message="Error DB: " . $e->getMessage(); $message_type = 'danger'; }
}


// --- LÓGICA DE VISUALIZACIÓN POR SECCIÓN ---
$search = $_GET['search'] ?? '';
$page = max(1, intval($_GET['page'] ?? 1));
$perPage = 15;
$offset = ($page - 1) * $perPage;

$dashboardData = []; $tableData = []; $totalItems = 0; $totalPages = 0;
$debugOutput = '';

try {
    if ($section == 'dashboard') {
        $dashboardData['maintenance_mode'] = file_exists('MAINTENANCE');
        // El resto se carga por JS (api_admin_stats.php)
        
    } elseif ($section == 'users') {
        $params = [];
        $count_sql = "SELECT COUNT(*) FROM usuarios"; $list_sql = "SELECT * FROM usuarios";
        if ($search) { $count_sql .= " WHERE username LIKE ?"; $list_sql .= " WHERE username LIKE ?"; $params[] = "%$search%"; }
        $list_sql .= " ORDER BY username LIMIT ? OFFSET ?";
        $params[] = $perPage; $params[] = $offset;
        $stmt_count_params = $params; array_pop($stmt_count_params); array_pop($stmt_count_params);
        $stmt_count = $pdo->prepare($count_sql); $stmt_count->execute($stmt_count_params); $totalItems = $stmt_count->fetchColumn();
        $stmt_list = $pdo->prepare($list_sql);
        $i = 1; foreach ($params as $param) { $stmt_list->bindValue($i, $param, (is_int($param) ? PDO::PARAM_INT : PDO::PARAM_STR)); $i++; }
        $stmt_list->execute(); $tableData = $stmt_list->fetchAll(PDO::FETCH_ASSOC); $totalPages = ceil($totalItems / $perPage);

    } elseif ($section == 'logs') {
        $params = [];
        $count_sql = "SELECT COUNT(*) FROM activity_log"; $list_sql = "SELECT * FROM activity_log";
        if ($search) { $search_param = "%$search%"; $count_sql .= " WHERE username LIKE ? OR action LIKE ? OR ip_address LIKE ?"; $list_sql .= " WHERE username LIKE ? OR action LIKE ? OR ip_address LIKE ?"; $params[] = $search_param; $params[] = $search_param; $params[] = $search_param; }
        $list_sql .= " ORDER BY id DESC LIMIT ? OFFSET ?";
        $params[] = $perPage; $params[] = $offset;
        $stmt_count_params = $params; array_pop($stmt_count_params); array_pop($stmt_count_params);
        $stmt_count = $pdo->prepare($count_sql); $stmt_count->execute($stmt_count_params); $totalItems = $stmt_count->fetchColumn();
        $stmt_list = $pdo->prepare($list_sql);
        $i = 1; foreach ($params as $param) { $stmt_list->bindValue($i, $param, (is_int($param) ? PDO::PARAM_INT : PDO::PARAM_STR)); $i++; }
        $stmt_list->execute(); $tableData = $stmt_list->fetchAll(PDO::FETCH_ASSOC); $totalPages = ceil($totalItems / $perPage);

    } elseif ($section == 'subid_maps') {
        $params = [];
        $count_sql = "SELECT COUNT(*) FROM projektnummer_subid_map";
        $list_sql = "SELECT * FROM projektnummer_subid_map";
        if ($search) { $search_param = "%$search%"; $count_sql .= " WHERE projektnummer LIKE ? OR subid LIKE ?"; $list_sql .= " WHERE projektnummer LIKE ? OR subid LIKE ?"; $params[] = $search_param; $params[] = $search_param; }
        $list_sql .= " ORDER BY id DESC LIMIT ? OFFSET ?";
        $params[] = $perPage; $params[] = $offset;
        $stmt_count_params = $params; array_pop($stmt_count_params); array_pop($stmt_count_params);
        $stmt_count = $pdo->prepare($count_sql); $stmt_count->execute($stmt_count_params); $totalItems = $stmt_count->fetchColumn();
        $stmt_list = $pdo->prepare($list_sql);
        $i = 1; foreach ($params as $param) { $stmt_list->bindValue($i, $param, (is_int($param) ? PDO::PARAM_INT : PDO::PARAM_STR)); $i++; }
        $stmt_list->execute(); $tableData = $stmt_list->fetchAll(PDO::FETCH_ASSOC); $totalPages = ceil($totalItems / $perPage);

    } elseif ($section == 'ratings') {
        $params = [];
        $count_sql = "SELECT COUNT(r.id) FROM subid_ratings r LEFT JOIN usuarios u ON r.user_id = u.id";
        $list_sql = "SELECT r.*, u.username FROM subid_ratings r LEFT JOIN usuarios u ON r.user_id = u.id";
         if ($search) { $search_param = "%$search%"; $count_sql .= " WHERE r.subid LIKE ? OR r.comment LIKE ? OR u.username LIKE ?"; $list_sql .= " WHERE r.subid LIKE ? OR r.comment LIKE ? OR u.username LIKE ?"; $params[] = $search_param; $params[] = $search_param; $params[] = $search_param; }
        $list_sql .= " ORDER BY r.id DESC LIMIT ? OFFSET ?";
        $params[] = $perPage; $params[] = $offset;
        $stmt_count_params = $params; array_pop($stmt_count_params); array_pop($stmt_count_params);
        $stmt_count = $pdo->prepare($count_sql); $stmt_count->execute($stmt_count_params); $totalItems = $stmt_count->fetchColumn();
        $stmt_list = $pdo->prepare($list_sql);
         $i = 1; foreach ($params as $param) { $stmt_list->bindValue($i, $param, (is_int($param) ? PDO::PARAM_INT : PDO::PARAM_STR)); $i++; }
        $stmt_list->execute(); $tableData = $stmt_list->fetchAll(PDO::FETCH_ASSOC); $totalPages = ceil($totalItems / $perPage);
    
    } elseif ($section == 'shortener') {
        $params = [];
        $count_sql = "SELECT COUNT(*) FROM short_links";
        $list_sql = "SELECT * FROM short_links";
        if ($search) { $search_param = "%$search%"; $count_sql .= " WHERE slug LIKE ? OR target_url LIKE ?"; $list_sql .= " WHERE slug LIKE ? OR target_url LIKE ?"; $params[] = $search_param; $params[] = $search_param; }
        $list_sql .= " ORDER BY id DESC LIMIT ? OFFSET ?";
        $params[] = $perPage; $params[] = $offset;
        $stmt_count_params = $params; array_pop($stmt_count_params); array_pop($stmt_count_params);
        $stmt_count = $pdo->prepare($count_sql); $stmt_count->execute($stmt_count_params); $totalItems = $stmt_count->fetchColumn();
        $stmt_list = $pdo->prepare($list_sql);
         $i = 1; foreach ($params as $param) { $stmt_list->bindValue($i, $param, (is_int($param) ? PDO::PARAM_INT : PDO::PARAM_STR)); $i++; }
        $stmt_list->execute(); $tableData = $stmt_list->fetchAll(PDO::FETCH_ASSOC); $totalPages = ceil($totalItems / $perPage);
    }
} catch (PDOException $e) {
    $errorMessage = $e->getMessage(); error_log("Admin Section ({$section}) Query Error: " . $errorMessage);
    $message .= " Error al cargar datos para la sección '" . htmlspecialchars($section, ENT_QUOTES, 'UTF-8') . "': " . htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8');
    $message_type = 'danger';
    $dashboardData = []; $tableData = []; $totalItems = 0; $totalPages = 0;
}

// Helper function paginationLinks
function paginationLinks(int $currentPage, int $totalPages, string $baseUrl): string {
    if ($totalPages <= 1) return '';
    $links = '<ul class="pagination justify-content-center">';
    $maxPagesToShow = 5; $startPage = max(1, $currentPage - floor($maxPagesToShow / 2)); $endPage = min($totalPages, $startPage + $maxPagesToShow - 1);
    if ($endPage - $startPage + 1 < $maxPagesToShow) { $startPage = max(1, $endPage - $maxPagesToShow + 1); }
    $disabled = ($currentPage == 1) ? ' disabled' : '';
    $links .= "<li class='page-item{$disabled}'><a class='page-link' href='{$baseUrl}&page=1'>&laquo;</a></li>";
    $prevPage = $currentPage - 1;
    $links .= "<li class='page-item{$disabled}'><a class='page-link' href='{$baseUrl}&page={$prevPage}'>&lsaquo;</a></li>";
    for ($i = $startPage; $i <= $endPage; $i++) { $active = ($i == $currentPage) ? ' active' : ''; $links .= "<li class='page-item{$active}'><a class='page-link' href='{$baseUrl}&page={$i}'>{$i}</a></li>"; }
    $disabled = ($currentPage == $totalPages) ? ' disabled' : ''; $nextPage = $currentPage + 1;
    $links .= "<li class='page-item{$disabled}'><a class='page-link' href='{$baseUrl}&page={$nextPage}'>&rsaquo;</a></li>";
    $links .= "<li class='page-item{$disabled}'><a class='page-link' href='{$baseUrl}&page={$totalPages}'>&raquo;</a></li>";
    $links .= '</ul>'; return $links;
}
$paginationBaseUrl = "admin.php?section={$section}" . ($search ? '&search=' . urlencode($search) : '');

?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
<title>Admin - SurveyJunior</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad1' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%235a9cff;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%230d6efd;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Ccircle cx='50' cy='50' r='50' fill='url(%23grad1)' /%3E%3Ctext x='50' y='60' font-size='50' fill='%23fff' text-anchor='middle' font-family='Arial, sans-serif' font-weight='bold'%3ESJ%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"/>
<link rel="stylesheet" href="new-style.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
function confirmDelete(type, id) {
    let subject = 'este elemento';
    if (type === 'user') subject = 'a este usuario';
    if (type === 'map') subject = 'este mapeo SubID';
    if (type === 'rating') subject = 'esta calificación';
    if (type === 'link') subject = 'este enlace acortado'; // Nuevo
    return confirm(`¿Está seguro que desea eliminar ${subject}? Esta acción no se puede deshacer.`);
}
</script>
</head>
<body class="app-loading">
    <div class="app-shell">
        <nav class="app-sidebar">
            <a class="navbar-brand nav-link" href="index.php?module=home" title="SurveyJunior">
                <i class="bi bi-clipboard-data-fill"></i>
            </a>
            <ul class="app-nav-list">
                <li><a href="index.php?module=home" class="nav-link" title="Inicio"><i class="bi bi-house-fill"></i><span>Inicio</span></a></li>
                <li class="<?= $section === 'dashboard' ? 'active' : '' ?>"><a href="admin.php?section=dashboard" class="nav-link" title="Dashboard"><i class="bi bi-grid-1x2-fill"></i><span>Dashboard</span></a></li>
                <li class="<?= $section === 'users' ? 'active' : '' ?>"><a href="admin.php?section=users" class="nav-link" title="Usuarios"><i class="bi bi-people-fill"></i><span>Usuarios</span></a></li>
                <li class="<?= $section === 'logs' ? 'active' : '' ?>"><a href="admin.php?section=logs" class="nav-link" title="Registro Actividad"><i class="bi bi-clipboard-data-fill"></i><span>Logs</span></a></li>
                <li class="<?= $section === 'subid_maps' ? 'active' : '' ?>"><a href="admin.php?section=subid_maps" class="nav-link" title="Mapeos SubID"><i class="bi bi-link-45deg"></i><span>Mapeos</span></a></li>
                <li class="<?= $section === 'ratings' ? 'active' : '' ?>"><a href="admin.php?section=ratings" class="nav-link" title="Calificaciones"><i class="bi bi-star-fill"></i><span>Ratings</span></a></li>
                <li class="<?= $section === 'shortener' ? 'active' : '' ?>"><a href="admin.php?section=shortener" class="nav-link" title="Acortador de Enlaces"><i class="bi bi-scissors"></i><span>Acortador</span></a></li>
            </ul>
            <div class="app-sidebar-footer">
                <a href="logout.php" class="logout-btn" title="Cerrar sesión"><i class="bi bi-box-arrow-right"></i><span>Cerrar Sesión</span></a>
            </div>
        </nav>

        <main class="app-content">
            <header class="app-header">
                <div class="d-lg-none"><h4 class="page-title" id="page-title-mobile">Admin</h4></div>
                <div class="ms-auto d-flex align-items-center">
                    
                    <button class="btn btn-link nav-link me-2" id="dark-mode-toggle" type="button" title="Cambiar Tema">
                        <i class="bi bi-moon-stars-fill"></i>
                    </button>

                    <span class="navbar-text d-none d-lg-inline me-3"><?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?></span>
                    <div class="avatar-icon" data-bs-toggle="offcanvas" data-bs-target="#sessionPanelMobile">
                        <img src="https://api.dicebear.com/8.x/adventurer/svg?seed=<?= urlencode($user['username']) ?>" alt="Perfil" class="profile-pic">
                        <?php if ($user['online']): ?><span class="online-indicator"></span><?php endif; ?>
                    </div>
                </div>
            </header>

            <div class="content-body" id="admin-content">
                <?php if ($message): ?>
                <div class="alert alert-<?= $message_type ?> alert-dismissible fade show mb-4" role="alert">
                   <?= nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8')) ?>
                   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php endif; ?>

                <?php if ($section == 'dashboard'): ?>
                    <h2 class="mb-4">Dashboard</h2>
                    
                    <div class="row g-4 mb-4">
                        <div class="col-lg-6">
                            <div class="card h-100">
                                <div class="card-header d-flex justify-content-between align-items-center">
                                    <h5 class="mb-0">Control del Sitio</h5>
                                    <span class="badge" id="maintenance-status-badge">...</span>
                                </div>
                                <div class="card-body">
                                    <div class="form-check form-switch fs-5">
                                        <input class="form-check-input" type="checkbox" role="switch" id="maintenance-mode-switch" <?= $dashboardData['maintenance_mode'] ? 'checked' : '' ?>>
                                        <label class="form-check-label" for="maintenance-mode-switch">
                                            <strong>Modo Mantenimiento</strong>
                                        </label>
                                    </div>
                                    <div class="form-text mt-2">Actívalo para bloquear el sitio a todos los usuarios excepto a los administradores.</div>
                                </div>
                            </div>
                        </div>
                        <div class="col-lg-6">
                            <div class="card h-100">
                                <div class="card-header"><h5 class="mb-0">Salud y Acciones Rápidas</h5></div>
                                <div class="card-body d-flex flex-wrap gap-2 align-content-start">
                                    <a href="https://cpanel.cpanelfree.com/index.php" target="_blank" class="btn btn-outline-secondary">
                                        <i class="bi bi-hdd-rack me-1"></i> cPanel
                                    </a>
                                    <a href="https://dash.cloudflare.com/e42854a194d3990ee8e473d72436c25f/surveyjunior.us/caching/configuration" target="_blank" class="btn btn-outline-warning">
                                        <i class="bi bi-cloud-fill me-1"></i> Cloudflare
                                    </a>
                                    <a href="https://gemini.google.com/u/2/app/0ef5ca0983010d01?hl=es_419" target="_blank" class="btn btn-outline-info">
                                        <i class="bi bi-robot me-1"></i> Gemini AI
                                    </a>
                                    <button class="btn btn-warning" id="btn-purge-cache" title="Requiere API Key en config.php">
                                        <i class="bi bi-cloud-slash-fill me-1"></i> Purgar Caché CF
                                    </button>
                                    <button class="btn btn-info text-white" id="btn-clear-logs">
                                        <i class="bi bi-archive-fill me-1"></i> Limpiar Logs Antiguos
                                    </button>
                                    <button class="btn btn-danger" id="btn-force-logout">
                                        <i class="bi bi-door-closed-fill me-1"></i> Forzar Cierre de Sesiones
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="row g-3 mb-4" id="live-stats-container">
                        <div class="col-md-4">
                            <div class="stat-card users">
                                <div class="icon"><i class="bi bi-people-fill"></i></div>
                                <div><div class="value" id="stat-total-users">...</div><div class="label">Usuarios Totales</div></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="stat-card online">
                                <div class="icon"><i class="bi bi-person-check-fill"></i></div>
                                <div><div class="value" id="stat-online-users">...</div><div class="label">Usuarios En Línea</div></div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="stat-card admins">
                                <div class="icon"><i class="bi bi-shield-lock-fill"></i></div>
                                <div><div class="value" id="stat-admin-count">...</div><div class="label">Administradores</div></div>
                            </div>
                        </div>
                    </div>

                     <div class="row g-4">
                        <div class="col-lg-12">
                             <div class="card h-100">
                                <div class="card-header"><h5 class="mb-0">Actividad del Sitio (Últimos 7 Días)</h5></div>
                                <div class="card-body">
                                     <canvas id="activityChart" style="width: 100%; height: 250px;"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($section == 'users'): ?>
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h2 class="mb-0">Gestión de Usuarios (<?= $totalItems ?>)</h2>
                        <button class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#modalAddUser"><i class="bi bi-person-plus-fill me-1"></i>Añadir Usuario</button>
                    </div>
                    <form method="get" class="mb-3">
                        <input type="hidden" name="section" value="users">
                        <div class="input-group">
                            <input type="text" name="search" class="form-control form-control-modern" placeholder="Buscar por nombre de usuario..." value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" />
                            <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Buscar</button>
                        </div>
                    </form>
                    <div class="table-responsive card">
                        <table class="table table-striped table-hover table-modern align-middle mb-0">
                            <thead><tr><th>Usuario</th><th>Activo</th><th>En línea</th><th>Permiso Generar</th><th>Último Login/IP</th><th>Acciones</th></tr></thead>
                            <tbody>
                                <?php if (empty($tableData)): ?><tr><td colspan="6" class="text-center text-muted py-3">No se encontraron usuarios...</td></tr>
                                <?php else: foreach ($tableData as $u): ?>
                                <tr>
                                    <td><strong><?= htmlspecialchars($u['username'], ENT_QUOTES, 'UTF-8') ?></strong><?= $u['role']=='admin' ? ' <span class="badge bg-warning text-dark small">Admin</span>' : '' ?></td>
                                    <td><?= $u['active'] ? '<span class="badge bg-success">Sí</span>' : '<span class="badge bg-secondary">No</span>' ?></td>
                                    <td><?= $u['online'] ? '<span class="badge bg-success">Sí</span>' : '<span class="badge bg-secondary">No</span>' ?></td>
                                    <td>
                                        <?php if ($u['username'] !== 'admin'): ?><a href="admin.php?action=toggle_generate&user_id=<?= $u['id'] ?>&section=users" class="btn btn-sm <?= $u['can_generate_links'] ? 'btn-info' : 'btn-outline-info' ?>"><?= $u['can_generate_links'] ? '<i class="bi bi-check-circle"></i> Sí' : '<i class="bi bi-x-circle"></i> No' ?></a>
                                        <?php else: ?><span class="badge bg-light text-dark">-</span><?php endif; ?>
                                    </td>
                                    <td><div class="small text-muted"><div><?= htmlspecialchars($u['last_login'] ?? '-', ENT_QUOTES, 'UTF-8') ?></div><div><?= htmlspecialchars($u['last_ip'] ?? '-', ENT_QUOTES, 'UTF-8') ?></div></div></td>
                                    <td>
                                        <?php if ($u['username'] !== 'admin'): ?>
                                        <div class="dropdown">
                                            <button class="btn btn-sm btn-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">Acciones</button>
                                            <ul class="dropdown-menu">
                                                <li><a class="dropdown-item" href="admin.php?action=toggle_active&user_id=<?= $u['id'] ?>&section=users"><i class="bi bi-toggle-on me-2"></i><?= $u['active'] ? 'Desactivar' : 'Activar' ?></a></li>
                                                <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#modalPass<?= $u['id'] ?>"><i class="bi bi-key-fill me-2"></i>Cambiar Pass</a></li>
                                                <li><hr class="dropdown-divider"></li>
                                                <li><a class="dropdown-item text-danger" href="admin.php?action=delete_user&user_id=<?= $u['id'] ?>&section=users" onclick="return confirmDelete('user', <?= $u['id'] ?>);"><i class="bi bi-trash-fill me-2"></i>Eliminar</a></li>
                                            </ul>
                                        </div>
                                        <?php else: ?><span class="text-muted">-</span><?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($totalPages > 1) echo paginationLinks($page, $totalPages, $paginationBaseUrl); ?>

                <?php elseif ($section == 'logs'): ?>
                    <h2 class="mb-3">Registro de Actividad (<?= $totalItems ?>)</h2>
                    <form method="get" class="mb-3">
                        <input type="hidden" name="section" value="logs">
                        <div class="input-group">
                            <input type="text" name="search" class="form-control form-control-modern" placeholder="Buscar por usuario, acción o IP..." value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" />
                            <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Buscar</button>
                        </div>
                    </form>
                    <div class="table-responsive card">
                        <table class="table table-sm table-striped table-hover table-modern align-middle mb-0 small">
                             <thead><tr><th>ID</th><th>Timestamp</th><th>Usuario</th><th>Acción</th><th>Detalles</th><th>IP</th></tr></thead>
                             <tbody>
                                <?php if (empty($tableData)): ?><tr><td colspan="6" class="text-center text-muted py-3">No hay registros...</td></tr>
                                <?php else: foreach ($tableData as $log): ?>
                                <tr>
                                    <td><?= $log['id'] ?></td>
                                    <td><?= htmlspecialchars($log['timestamp'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($log['username'] ?? 'N/A', ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><small><?= htmlspecialchars($log['details'] ?? '-', ENT_QUOTES, 'UTF-8') ?></small></td>
                                    <td><?= htmlspecialchars($log['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                                </tr>
                                <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php if ($totalPages > 1) echo paginationLinks($page, $totalPages, $paginationBaseUrl); ?>

                <?php elseif ($section == 'subid_maps'): ?>
                     <div class="d-flex justify-content-between align-items-center mb-3">
                        <h2 class="mb-0">Mapeos Projektnummer ↔ SubID (<?= $totalItems ?>)</h2>
                        <button class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#modalAddMap">
                            <i class="bi bi-plus-lg me-1"></i>Añadir Mapeo
                        </button>
                     </div>
                     <form method="get" class="mb-3">
                        <input type="hidden" name="section" value="subid_maps">
                        <div class="input-group">
                             <input type="text" name="search" class="form-control form-control-modern" placeholder="Buscar por projektnummer o subid..." value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" />
                             <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Buscar</button>
                        </div>
                    </form>
                     <div class="table-responsive card">
                        <table class="table table-striped table-hover table-modern align-middle mb-0">
                             <thead><tr><th>ID</th><th>Projektnummer</th><th>SubID</th><th>Acciones</th></tr></thead>
                             <tbody>
                                <?php if (empty($tableData)): ?><tr><td colspan="4" class="text-center text-muted py-3">No hay mapeos...</td></tr>
                                <?php else: foreach ($tableData as $map): ?>
                                <tr>
                                    <td><?= $map['id'] ?></td>
                                    <td><?= htmlspecialchars($map['projektnummer'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($map['subid'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td>
                                        <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#modalEditMap<?= $map['id'] ?>" title="Editar">
                                            <i class="bi bi-pencil-fill"></i>
                                        </button>
                                        <a href="admin.php?action=delete_map&map_id=<?= $map['id'] ?>&section=subid_maps" class="btn btn-sm btn-danger" title="Eliminar" onclick="return confirmDelete('map', <?= $map['id'] ?>);">
                                            <i class="bi bi-trash-fill"></i>
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; endif; ?>
                             </tbody>
                        </table>
                    </div>
                     <?php if ($totalPages > 1) echo paginationLinks($page, $totalPages, $paginationBaseUrl); ?>

                 <?php elseif ($section == 'ratings'): ?>
                    <h2 class="mb-3">Calificaciones de SubID (<?= $totalItems ?>)</h2>
                    <form method="get" class="mb-3">
                        <input type="hidden" name="section" value="ratings">
                        <div class="input-group">
                            <input type="text" name="search" class="form-control form-control-modern" placeholder="Buscar por subid, comentario o usuario..." value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" />
                            <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Buscar</button>
                        </div>
                    </form>
                     <div class="table-responsive card">
                        <table class="table table-sm table-striped table-hover table-modern align-middle mb-0 small">
                             <thead><tr><th>ID</th><th>SubID</th><th>Usuario</th><th>Rating</th><th>Comentario</th><th>Timestamp</th><th>Acciones</th></tr></thead>
                             <tbody>
                                 <?php if (empty($tableData)): ?><tr><td colspan="7" class="text-center text-muted py-3">No hay calificaciones...</td></tr>
                                <?php else: foreach ($tableData as $rating): ?>
                                <tr>
                                    <td><?= $rating['id'] ?></td>
                                    <td><?= htmlspecialchars($rating['subid'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td><?= htmlspecialchars($rating['username'] ?? 'ID: '.$rating['user_id'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td> <?php if ($rating['rating'] == 1): ?><span class="badge bg-success"><i class="bi bi-hand-thumbs-up-fill"></i></span> <?php elseif ($rating['rating'] == -1): ?><span class="badge bg-danger"><i class="bi bi-hand-thumbs-down-fill"></i></span> <?php else: ?><span class="badge bg-secondary">?</span><?php endif; ?> </td>
                                    <td style="white-space: normal; min-width: 200px;"><?= nl2br(htmlspecialchars($rating['comment'] ?? '-', ENT_QUOTES, 'UTF-8')) ?></td>
                                    <td><?= htmlspecialchars($rating['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
                                     <td> <a href="admin.php?action=delete_rating&rating_id=<?= $rating['id'] ?>&section=ratings" class="btn btn-sm btn-outline-danger" title="Eliminar Calificación" onclick="return confirmDelete('rating', <?= $rating['id'] ?>);"><i class="bi bi-trash-fill"></i></a> </td>
                                </tr>
                                <?php endforeach; endif; ?>
                             </tbody>
                        </table>
                    </div>
                    <?php if ($totalPages > 1) echo paginationLinks($page, $totalPages, $paginationBaseUrl); ?>
                
                <?php elseif ($section == 'shortener'): ?>
                     <div class="d-flex justify-content-between align-items-center mb-3">
                        <h2 class="mb-0">Acortador de Enlaces (<?= $totalItems ?>)</h2>
                        <button class="btn btn-success btn-sm" data-bs-toggle="modal" data-bs-target="#modalAddLink">
                            <i class="bi bi-plus-lg me-1"></i>Añadir Enlace
                        </button>
                     </div>
                     <form method="get" class="mb-3">
                        <input type="hidden" name="section" value="shortener">
                        <div class="input-group">
                             <input type="text" name="search" class="form-control form-control-modern" placeholder="Buscar por slug o URL de destino..." value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>" />
                             <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i> Buscar</button>
                        </div>
                    </form>
                     <div class="table-responsive card">
                        <table class="table table-striped table-hover table-modern align-middle mb-0">
                             <thead><tr><th>ID</th><th>Enlace Corto (Slug)</th><th>URL de Destino</th><th>Acciones</th></tr></thead>
                             <tbody>
                                <?php if (empty($tableData)): ?><tr><td colspan="4" class="text-center text-muted py-3">No hay enlaces acortados...</td></tr>
                                <?php else: 
                                    $site_url = 'https://' . $_SERVER['HTTP_HOST'] . '/go/';
                                    foreach ($tableData as $link): ?>
                                <tr>
                                    <td><?= $link['id'] ?></td>
                                    <td>
                                        <strong><?= htmlspecialchars($link['slug'], ENT_QUOTES, 'UTF-8') ?></strong>
                                        <div class="small text-muted"><?= htmlspecialchars($site_url . $link['slug'], ENT_QUOTES, 'UTF-8') ?></div>
                                    </td>
                                    <td style="white-space: normal; word-break: break-all; min-width: 300px;"><?= htmlspecialchars($link['target_url'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td>
                                        <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#modalEditLink<?= $link['id'] ?>" title="Editar">
                                            <i class="bi bi-pencil-fill"></i>
                                        </button>
                                        <button type="button" class="btn btn-sm btn-info" title="Copiar Enlace" 
                                                onclick="copyJumper('<?= htmlspecialchars($site_url . $link['slug'], ENT_QUOTES, 'UTF-8') ?>', this)">
                                            <i class="bi bi-clipboard-check-fill"></i>
                                        </button>
                                        <a href="admin.php?action=delete_link&link_id=<?= $link['id'] ?>&section=shortener" class="btn btn-sm btn-danger ms-1" title="Eliminar" onclick="return confirmDelete('link', <?= $link['id'] ?>);">
                                            <i class="bi bi-trash-fill"></i>
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; endif; ?>
                             </tbody>
                        </table>
                    </div>
                     <?php if ($totalPages > 1) echo paginationLinks($page, $totalPages, $paginationBaseUrl); ?>

                <?php else: ?>
                     <div class="alert alert-warning">Sección administrativa no reconocida: <?= htmlspecialchars($section, ENT_QUOTES, 'UTF-8') ?>.</div>
                <?php endif; ?>

            </div> </main>

        <nav class="app-tab-bar">
            <a href="index.php?module=home" class="nav-link"><i class="bi bi-house-fill"></i></a>
            <a href="admin.php?section=dashboard" class="nav-link <?= $section === 'dashboard' ? 'active' : '' ?>"><i class="bi bi-grid-1x2-fill"></i></a>
            <a href="admin.php?section=users" class="nav-link <?= $section === 'users' ? 'active' : '' ?>"><i class="bi bi-people-fill"></i></a>
            <a href="admin.php?section=logs" class="nav-link <?= $section === 'logs' ? 'active' : '' ?>"><i class="bi bi-clipboard-data-fill"></i></a>
             <a href="admin.php?section=subid_maps" class="nav-link <?= $section === 'subid_maps' ? 'active' : '' ?>"><i class="bi bi-link-45deg"></i></a>
             <a href="admin.php?section=ratings" class="nav-link <?= $section === 'ratings' ? 'active' : '' ?>"><i class="bi bi-star-fill"></i></a>
             <a href="admin.php?section=shortener" class="nav-link <?= $section === 'shortener' ? 'active' : '' ?>"><i class="bi bi-scissors"></i></a>
        </nav>
    </div>

    <div class="offcanvas offcanvas-end" tabindex="-1" id="sessionPanelMobile" aria-labelledby="sessionPanelMobileLabel">
        <div class="offcanvas-header"><h5 class="offcanvas-title" id="sessionPanelMobileLabel">Mi Perfil</h5><button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Close"></button></div>
        <div class="offcanvas-body">
            <div class="card border-0 bg-transparent">
                <div class="card-body text-center">
                    <div class="avatar-lg mb-3"><img src="https://api.dicebear.com/8.x/adventurer/svg?seed=<?= urlencode($user['username']) ?>" alt="Perfil" class="profile-pic-lg"></div>
                    <h5 class="card-title"><?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?></h5>
                    <div class="mb-2">
                        <span class="badge bg-primary"><?= htmlspecialchars($user['role'], ENT_QUOTES, 'UTF-8') ?></span>
                        <?php if ($user['online']): ?><span class="badge bg-success">En línea</span><?php else: ?><span class="badge bg-secondary">Ausente</span><?php endif; ?>
                    </div>
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item d-flex justify-content-between"><span><i class="bi bi-wifi me-2"></i>IP</span><span class="text-muted"><?= htmlspecialchars($user['last_ip'] ?? '-', ENT_QUOTES, 'UTF-8') ?></span></li>
                    <li class="list-group-item d-flex justify-content-between"><span><i class="bi bi-geo-alt me-2"></i>Ubicación</span><span class="text-muted"><?= htmlspecialchars($user['last_location_details'] ?? ($user['location'] ?? '-'), ENT_QUOTES, 'UTF-8') ?></span></li>
                    <li class="list-group-item d-flex justify-content-between"><span><i class="bi bi-laptop me-2"></i>Dispositivo</span><span class="text-muted"><?= htmlspecialchars($user['last_device'] ?? '-', ENT_QUOTES, 'UTF-8') ?></span></li>
                </ul>
                <div class="card-body" id="notes-container">
                    <h6 class="mb-2">Bloc de Notas Rápido</h6>
                    <textarea id="personal-notes-pad" class="form-control form-control-modern" rows="4" placeholder="Escribe notas temporales aquí... (Se guardan en tu navegador)"></textarea>
                    <div id="notes-save-status" class="text-start mt-1"></div>
                </div>
                
                <div class="card-body border-top" id="recent-history-container">
                    <h6 class="mb-2">Historial Reciente</h6>
                    <ul class="list-group list-group-flush recent-history-list" id="recent-history-list">
                        </ul>
                </div>
                <div class="card-body border-top">
                    <button class="btn btn-outline-info w-100" data-bs-toggle="modal" data-bs-target="#whatsNewModal"><i class="bi bi-gift-fill me-2"></i>Novedades</button>
                    <?php if ($user['role'] === 'admin'): ?>
                    <a href="admin.php?section=dashboard" class="btn btn-warning w-100 mt-2 nav-link"><i class="bi bi-gear-fill me-2"></i>Panel Admin</a>
                    <?php endif; ?>
                    <a href="logout.php" class="btn btn-outline-danger w-100 mt-2"><i class="bi bi-box-arrow-right me-2"></i>Cerrar Sesión</a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="modalAddUser" tabindex="-1" aria-labelledby="modalAddUserLabel" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=users" class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="modalAddUserLabel">Añadir Nuevo Usuario</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button></div>
                <div class="modal-body">
                    <div class="mb-3"><label for="new_username" class="form-label">Nombre de Usuario</label><input type="text" class="form-control form-control-modern" id="new_username" name="new_username" required></div>
                    <div class="mb-3"><label for="new_password" class="form-label">Contraseña</label><input type="password" class="form-control form-control-modern" id="new_password" name="new_password" required minlength="6"></div>
                    <div class="mb-3"><label for="new_role" class="form-label">Rol</label><select class="form-select" id="new_role" name="new_role" required><option value="user" selected>Usuario</option><option value="admin">Administrador</option></select></div>
                    <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="can_generate_links" name="can_generate_links" value="1"><label class="form-check-label" for="can_generate_links">Puede generar enlaces</label></div>
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button><button type="submit" name="add_user" class="btn btn-success">Crear Usuario</button></div>
            </form>
        </div>
    </div>
    <?php if ($section == 'users' && !empty($tableData)): foreach ($tableData as $u_modal): if ($u_modal['username'] !== 'admin'): ?>
    <div class="modal fade" id="modalPass<?= $u_modal['id'] ?>" tabindex="-1" aria-labelledby="modalLabel<?= $u_modal['id'] ?>" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=users" class="modal-content">
                <input type="hidden" name="user_id" value="<?= $u_modal['id'] ?>" />
                <div class="modal-header"><h5 class="modal-title" id="modalLabel<?= $u_modal['id'] ?>">Cambiar contraseña para <?= htmlspecialchars($u_modal['username'], ENT_QUOTES, 'UTF-8') ?></h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button></div>
                <div class="modal-body"><div class="mb-3"><label for="newPassword<?= $u_modal['id'] ?>" class="form-label">Nueva contraseña</label><input type="password" class="form-control form-control-modern" id="newPassword<?= $u_modal['id'] ?>" name="new_password" required minlength="6" /></div></div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button><button type="submit" name="change_password" class="btn btn-primary">Guardar</button></div>
            </form>
        </div>
    </div>
    <?php endif; endforeach; endif; ?>

    <div class="modal fade" id="modalAddMap" tabindex="-1" aria-labelledby="modalAddMapLabel" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=subid_maps" class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modalAddMapLabel">Añadir Nuevo Mapeo</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="new_projektnummer" class="form-label">Projektnummer</label>
                        <input type="text" class="form-control form-control-modern" id="new_projektnummer" name="projektnummer"
                               maxlength="6" pattern="\d{5,6}" title="Debe ser un número de 5 o 6 dígitos" placeholder="Ej: 123456" required>
                    </div>
                    <div class="mb-3">
                        <label for="new_subid_modal" class="form-label">SubID</label>
                        <input type="text" class="form-control form-control-modern" id="new_subid_modal" name="new_subid"
                               maxlength="50" pattern=".{1,50}" title="Debe tener entre 1 y 50 caracteres" placeholder="Ej: f8113cee o 7" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="add_map" class="btn btn-success">Añadir Mapeo</button>
                </div>
            </form>
        </div>
    </div>
    
    <?php if ($section == 'subid_maps' && !empty($tableData)):
        foreach ($tableData as $map_modal): ?>
    <div class="modal fade" id="modalEditMap<?= $map_modal['id'] ?>" tabindex="-1" aria-labelledby="modalLabelMap<?= $map_modal['id'] ?>" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=subid_maps" class="modal-content">
                <input type="hidden" name="map_id" value="<?= $map_modal['id'] ?>" />
                <div class="modal-header">
                    <h5 class="modal-title" id="modalLabelMap<?= $map_modal['id'] ?>">Editar Mapeo (ID: <?= $map_modal['id'] ?>)</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Projektnummer</label>
                        <input type="text" class="form-control" value="<?= htmlspecialchars($map_modal['projektnummer'], ENT_QUOTES, 'UTF-8') ?>" disabled />
                    </div>
                    <div class="mb-3">
                        <label for="new_subid_<?= $map_modal['id'] ?>" class="form-label">Nuevo SubID</label>
                        <input type="text" class="form-control form-control-modern" id="new_subid_<?= $map_modal['id'] ?>" name="new_subid"
                               value="<?= htmlspecialchars($map_modal['subid'], ENT_QUOTES, 'UTF-8') ?>"
                               maxlength="50" pattern=".{1,50}" title="Debe tener entre 1 y 50 caracteres" required />
                        <div class="form-text">Edita el SubID (ej. '5' por '5a58e40f').</div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="edit_map" class="btn btn-primary">Guardar Cambios</button>
                </div>
            </form>
        </div>
    </div>
    <?php endforeach; endif; ?>

    <div class="modal fade" id="modalAddLink" tabindex="-1" aria-labelledby="modalAddLinkLabel" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=shortener" class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="modalAddLinkLabel">Añadir Nuevo Enlace Acortado</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="new_slug" class="form-label">Atajo (Slug)</label>
                        <div class="input-group">
                            <span class="input-group-text">/go/</span>
                            <input type="text" class="form-control form-control-modern" id="new_slug" name="slug"
                                   pattern="[a-zA-Z0-9_-]+" title="Solo letras, números, _ y -" placeholder="Ej: meinungplatzDE" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="new_target_url" class="form-label">URL de Destino</label>
                        <textarea class="form-control form-control-modern" id="new_target_url" name="target_url" rows="4" placeholder="https://..." required></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="add_link" class="btn btn-success">Crear Enlace</button>
                </div>
            </form>
        </div>
    </div>

    <?php if ($section == 'shortener' && !empty($tableData)):
        foreach ($tableData as $link_modal): ?>
    <div class="modal fade" id="modalEditLink<?= $link_modal['id'] ?>" tabindex="-1" aria-labelledby="modalLabelLink<?= $link_modal['id'] ?>" aria-hidden="true">
        <div class="modal-dialog">
            <form method="post" action="admin.php?section=shortener" class="modal-content">
                <input type="hidden" name="link_id" value="<?= $link_modal['id'] ?>" />
                <div class="modal-header">
                    <h5 class="modal-title" id="modalLabelLink<?= $link_modal['id'] ?>">Editar Enlace (ID: <?= $link_modal['id'] ?>)</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="edit_slug_<?= $link_modal['id'] ?>" class="form-label">Atajo (Slug)</label>
                        <div class="input-group">
                            <span class="input-group-text">/go/</span>
                            <input type="text" class="form-control form-control-modern" id="edit_slug_<?= $link_modal['id'] ?>" name="slug"
                                   value="<?= htmlspecialchars($link_modal['slug'], ENT_QUOTES, 'UTF-8') ?>"
                                   pattern="[a-zA-Z0-9_-]+" title="Solo letras, números, _ y -" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="edit_target_url_<?= $link_modal['id'] ?>" class="form-label">URL de Destino</label>
                        <textarea class="form-control form-control-modern" id="edit_target_url_<?= $link_modal['id'] ?>" name="target_url" rows="4" required><?= htmlspecialchars($link_modal['target_url'], ENT_QUOTES, 'UTF-8') ?></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" name="edit_link" class="btn btn-primary">Guardar Cambios</button>
                </div>
            </form>
        </div>
    </div>
    <?php endforeach; endif; ?>
    <div class="modal fade" id="whatsNewModal" tabindex="-1" aria-labelledby="whatsNewModalLabel" aria-hidden="true">
         <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="whatsNewModalLabel"><i class="bi bi-stars me-2 text-warning"></i>¡Nuevas Funciones!</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
                <div class="modal-body">
                     <p>¡Hola, <?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?>! Hemos actualizado:</p>
                     <ul>
                        <li><strong>¡Nuevo Módulo: Acortador!</strong> Ahora puedes crear enlaces cortos /go/ personalizados.</li>
                        <li><strong>¡Nuevo Dashboard Admin!</strong> Gráfico de actividad, modo mantenimiento y acciones rápidas.</li>
                        <li><strong>¡Nuevo Nombre!</strong> El sitio ahora es "SurveyJunior".</li>
                        <li><strong>Estadísticas:</strong> ¡Tu página de inicio ahora muestra cuántos jumpers has generado! 🚀</li>
                    </ul>
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-primary" data-bs-dismiss="modal">¡Entendido!</button></div>
            </div>
        </div>
    </div>
    
    <div class="modal fade" id="inactivityModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="inactivityModalLabel" aria-hidden="true"> <div class="modal-dialog modal-dialog-centered"> <div class="modal-content"> <div class="modal-header"><h5 class="modal-title" id="inactivityModalLabel"><i class="bi bi-clock-history me-2"></i>Sesión a punto de expirar</h5></div> <div class="modal-body"><p>Has estado inactivo. Tu sesión se cerrará automáticamente en <span id="inactivityCountdown">60</span> segundos.</p><p>¿Deseas continuar tu sesión?</p></div> <div class="modal-footer"><button type="button" class="btn btn-secondary" id="logoutBtn">Cerrar Sesión</button><button type="button" class="btn btn-primary" id="stayLoggedInBtn">Continuar Sesión</button></div> </div> </div> </div>

     <div class="toast-container position-fixed bottom-0 end-0 p-3"></div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="new-script.js"></script>
    
    <script>
    // Usamos un listener aquí porque este script está al final del body de admin.php
    document.addEventListener('DOMContentLoaded', () => {
        
        // --- Lógica del Gráfico y Stats en Vivo (Solo se ejecuta si estamos en el dashboard) ---
        const ctx = document.getElementById('activityChart');
        let adminChart = null;
        let adminStatsInterval = null;

        const fetchAdminStats = async () => {
            try {
                const response = await fetch('api_admin_stats.php');
                if (!response.ok) {
                    if (response.status === 401) { // Sesión expirada
                        if (adminStatsInterval) clearInterval(adminStatsInterval);
                        alert("Tu sesión ha expirado en otro dispositivo.");
                        window.location.href = 'login.php?error=Sesión+expirada.';
                    }
                    throw new Error(`Error de red: ${response.statusText}`);
                }
                
                const data = await response.json();
                if (!data.success) { throw new Error(data.message); }

                // Actualizar tarjetas de estadísticas
                const totalUsersEl = document.getElementById('stat-total-users');
                const onlineUsersEl = document.getElementById('stat-online-users');
                const adminCountEl = document.getElementById('stat-admin-count');
                
                if (totalUsersEl && totalUsersEl.textContent !== data.stats.totalUsers) totalUsersEl.textContent = data.stats.totalUsers;
                if (onlineUsersEl && onlineUsersEl.textContent !== data.stats.onlineUsers) onlineUsersEl.textContent = data.stats.onlineUsers;
                if (adminCountEl && adminCountEl.textContent !== data.stats.adminCount) adminCountEl.textContent = data.stats.adminCount;

                // Actualizar switch de mantenimiento
                const maintenanceSwitch = document.getElementById('maintenance-mode-switch');
                const maintenanceBadge = document.getElementById('maintenance-status-badge');
                if (maintenanceSwitch) maintenanceSwitch.checked = data.stats.maintenance_mode;
                if(maintenanceBadge) {
                    if(data.stats.maintenance_mode) {
                        maintenanceBadge.textContent = 'ACTIVO';
                        maintenanceBadge.className = 'badge bg-danger';
                    } else {
                        maintenanceBadge.textContent = 'Inactivo';
                        maintenanceBadge.className = 'badge bg-success';
                    }
                }

                // Actualizar o crear el gráfico
                if (adminChart) {
                    // Actualizar datos
                    adminChart.data.labels = data.chart_data.labels;
                    adminChart.data.datasets[0].data = data.chart_data.jumpers;
                    adminChart.data.datasets[1].data = data.chart_data.logins;
                    adminChart.update();
                } else if (ctx) {
                    // Crear gráfico
                    adminChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: data.chart_data.labels,
                            datasets: [
                                {
                                    label: 'Jumpers Generados',
                                    data: data.chart_data.jumpers,
                                    borderColor: 'rgba(25, 135, 84, 1)',
                                    backgroundColor: 'rgba(25, 135, 84, 0.1)',
                                    fill: true,
                                    tension: 0.3
                                },
                                {
                                    label: 'Logins',
                                    data: data.chart_data.logins,
                                    borderColor: 'rgba(13, 110, 253, 1)',
                                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                                    fill: true,
                                    tension: 0.3
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
                        }
                    });
                }
                
            } catch (error) {
                console.error("Error al cargar estadísticas del admin:", error);
                if (adminStatsInterval) clearInterval(adminStatsInterval);
            }
        };

        // --- Ejecutar solo si estamos en el dashboard ---
        if (document.getElementById('live-stats-container')) {
            fetchAdminStats(); // Cargar inmediatamente
            adminStatsInterval = setInterval(fetchAdminStats, 10000); // Actualizar cada 10 segundos
        }

        // --- Listeners de Acciones Rápidas ---
        
        // Función helper para API de Acciones
        const postAdminAction = async (action, data = {}) => {
            try {
                const response = await fetch('api_admin_actions.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action, ...data })
                });
                if (response.status === 401) {
                    window.location.href = 'login.php?error=Sesión+expirada.';
                    return { success: false, message: 'Sesión expirada.' };
                }
                const result = await response.json();
                if (!response.ok) { throw new Error(result.message || 'Error de servidor'); }
                return result;
            } catch (error) {
                console.error(`Error en acción '${action}':`, error);
                return { success: false, message: error.message };
            }
        };
        
        // Listener del switch de Mantenimiento
        const maintenanceSwitch = document.getElementById('maintenance-mode-switch');
        if (maintenanceSwitch) {
            maintenanceSwitch.addEventListener('change', async (e) => {
                const isChecked = e.target.checked;
                const result = await postAdminAction('toggle_maintenance', { value: isChecked });
                // Actualizar el badge inmediatamente
                const maintenanceBadge = document.getElementById('maintenance-status-badge');
                if(maintenanceBadge) {
                    if(isChecked) {
                        maintenanceBadge.textContent = 'ACTIVO';
                        maintenanceBadge.className = 'badge bg-danger';
                    } else {
                        maintenanceBadge.textContent = 'Inactivo';
                        maintenanceBadge.className = 'badge bg-success';
                    }
                }
            });
        }
        
        // Listener botón Purgar Caché
        const btnPurgeCache = document.getElementById('btn-purge-cache');
        if (btnPurgeCache) {
            btnPurgeCache.addEventListener('click', async () => {
                if (!confirm("¿Seguro que quieres purgar el caché de Cloudflare?")) return;
                btnPurgeCache.disabled = true;
                btnPurgeCache.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Purgando...';
                const result = await postAdminAction('purge_cache');
                if (result.success) {
                    alert('¡Éxito! Caché de Cloudflare purgado.');
                } else {
                    alert('Error: ' + result.message);
                }
                btnPurgeCache.innerHTML = '<i class="bi bi-cloud-slash-fill me-1"></i> Purgar Caché CF';
                btnPurgeCache.disabled = false;
            });
        }

        // Listener botón Limpiar Logs
        const btnClearLogs = document.getElementById('btn-clear-logs');
        if (btnClearLogs) {
            btnClearLogs.addEventListener('click', async () => {
                if (!confirm("¿Seguro que quieres eliminar logs de más de 30 días? Esta acción no se puede deshacer.")) return;
                const result = await postAdminAction('clear_logs');
                if (result.success) {
                    alert(result.message);
                } else {
                    alert('Error: ' + result.message);
                }
            });
        }
        
        // Listener botón Forzar Logout
        const btnForceLogout = document.getElementById('btn-force-logout');
        if (btnForceLogout) {
            btnForceLogout.addEventListener('click', async () => {
                if (!confirm("¿Seguro que quieres cerrar la sesión de TODOS los usuarios (incluyéndote a ti)?")) return;
                const result = await postAdminAction('force_logout');
                if (result.success) {
                    alert(result.message);
                    window.location.href = 'login.php'; // Redirigir a login
                } else {
                    alert('Error: ' + result.message);
                }
            });
        }

        // Script para actualizar el título de la pestaña del navegador en admin
        const adminPageTitleMobile = document.getElementById('page-title-mobile');
        if (adminPageTitleMobile) {
            const adminTitleElement = document.querySelector('#admin-content h2');
            if (adminTitleElement) {
                adminPageTitleMobile.textContent = adminTitleElement.textContent.split('(')[0].trim();
            } else {
                adminPageTitleMobile.textContent = 'Admin';
            }
        }

        // Script para copiar URL corta
        const toastContainer = document.querySelector('.toast-container');
        window.showToast = function(message, type = 'info', duration = 5000) {
            if (!toastContainer) { console.warn("Toast container not found!"); return; }
            const toastId = 'toast-' + Date.now();
            const textClass = (type === 'warning' || type === 'light' || type === 'info') ? 'text-dark' : 'text-white';
            const closeClass = (type === 'warning' || type === 'light' || type === 'info') ? '' : 'btn-close-white';
            const toastHTML = `<div id="${toastId}" class="toast align-items-center bg-${type} ${textClass} border-0" role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="${duration}"><div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close ${closeClass} me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div></div>`;
            toastContainer.insertAdjacentHTML('beforeend', toastHTML);
            const toastElement = document.getElementById(toastId);
            if (!toastElement) return;
            const toast = new bootstrap.Toast(toastElement);
            toast.show();
            toastElement.addEventListener('hidden.bs.toast', () => toastElement.remove());
        }

        window.copyJumper = function(text, buttonElement) {
            if (!navigator.clipboard) { showToast("Navegador no soporta copia.", 'warning'); return; }
            navigator.clipboard.writeText(text).then(() => {
                const originalHtml = buttonElement.innerHTML;
                buttonElement.innerHTML = '<i class="bi bi-check-lg"></i>';
                buttonElement.disabled = true;
                showToast('¡Enlace copiado!', 'success', 2000);
                setTimeout(() => { 
                    if (document.body.contains(buttonElement)) { 
                        buttonElement.innerHTML = originalHtml; 
                        buttonElement.disabled = false; 
                    } 
                }, 2000);
            }).catch(err => {
                console.error('Error al copiar:', err);
                showToast('Error al copiar.', 'danger');
            });
        }

    });
    </script>
    </body>
</html>