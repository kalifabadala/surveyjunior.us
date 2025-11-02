<?php
// functions.php (Completo - v6.1 - Depuración Avanzada de Webhook)

// Función para URLs https
function secure_url($url) {
    if (strpos($url, 'https://') === 0) return $url;
    if (strpos($url, 'http://') === 0) return 'https://' . substr($url, 7);
    if (strpos($url, '/') === 0) return 'https://' . $_SERVER['HTTP_HOST'] . $url;
    return $url;
}

// Actualiza actividad y usuarios en línea
function updateUserActivity(PDO $pdo, $userId) {
    $now = time();
    $threshold = $now - 300; // 5 minutos (300 segundos)
    try {
        $stmt = $pdo->prepare("UPDATE usuarios SET last_activity = :now, online = 1, last_login = CASE WHEN last_login IS NULL THEN NOW() ELSE last_login END WHERE id = :id");
        $stmt->execute(['now' => $now, 'id' => $userId]);
        $stmt2 = $pdo->prepare("UPDATE usuarios SET online = 0, current_session_token = NULL WHERE last_activity < :threshold AND online = 1");
        $stmt2->execute(['threshold' => $threshold]);
    } catch (PDOException $e) {
        error_log("Error updating user activity: " . $e->getMessage());
    }
}

// --- Registro de Actividad ---
function logActivity(PDO $pdo, ?int $userId, ?string $username, string $action, ?string $details = null): void {
    if (!isset($pdo) || !$pdo instanceof PDO) { error_log("PDO object not available for logging activity."); return; }
    try {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        if (strpos($ip, ',') !== false) { $ip_array = explode(',', $ip); $ip = trim($ip_array[0]); }
        $ip = filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'Invalid IP format'; $ip = mb_substr($ip, 0, 45);
        $username = ($username === null) ? null : mb_substr($username, 0, 100);
        $action = mb_substr($action, 0, 255);
        $details = ($details === null) ? null : mb_substr($details, 0, 1000);
        $stmt = $pdo->prepare("INSERT INTO activity_log (user_id, username, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?, NOW())");
        $stmt->execute([$userId, $username, $action, $details, $ip]);
    } catch (PDOException $e) { error_log("Error logging activity: " . $e->getMessage()); }
}

// --- Protección Anti-Fuerza Bruta ---
define('LOGIN_ATTEMPT_LIMIT', 5); define('LOGIN_ATTEMPT_WINDOW', 15 * 60);
function isLoginBlocked(PDO $pdo, string $ip): bool {
    if (!isset($pdo) || !$pdo instanceof PDO) return false;
    try {
        $currentTime = time(); $windowStart = $currentTime - LOGIN_ATTEMPT_WINDOW;
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND attempt_time > ?");
        $stmt->execute([$ip, $windowStart]); $attempts = $stmt->fetchColumn();
        return ($attempts !== false && $attempts >= LOGIN_ATTEMPT_LIMIT);
    } catch (PDOException $e) { error_log("Error checking login attempts for IP {$ip}: " . $e->getMessage()); return false; }
}
function recordFailedLogin(PDO $pdo, string $ip): void {
     if (!isset($pdo) || !$pdo instanceof PDO) return;
    try {
        $stmt = $pdo->prepare("INSERT INTO login_attempts (ip_address, attempt_time) VALUES (?, ?)"); $stmt->execute([$ip, time()]);
        $cleanupTime = time() - 3600; $pdo->prepare("DELETE FROM login_attempts WHERE attempt_time < ?")->execute([$cleanupTime]);
    } catch (PDOException $e) { error_log("Error recording failed login for IP {$ip}: " . $e->getMessage()); }
}
function clearLoginAttempts(PDO $pdo, string $ip): void {
     if (!isset($pdo) || !$pdo instanceof PDO) return;
     try { $stmt = $pdo->prepare("DELETE FROM login_attempts WHERE ip_address = ?"); $stmt->execute([$ip]); }
     catch (PDOException $e) { error_log("Error clearing login attempts for IP {$ip}: " . $e->getMessage()); }
}

// --- Funciones "Recordarme" ---
define('REMEMBER_ME_COOKIE_NAME', 'survey_remember'); define('REMEMBER_ME_DURATION', 60 * 60 * 24 * 30);
function clearRememberMeCookie(): void {
    $is_secure_cookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                     || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    setcookie(REMEMBER_ME_COOKIE_NAME, '', [
        'expires' => time() - 3600, 'path' => '/', 'domain' => '',
        'secure' => $is_secure_cookie, 'httponly' => true, 'samesite' => 'Lax'
    ]);
}
function rememberUser(PDO $pdo, int $userId): void {
     if (!isset($pdo) || !$pdo instanceof PDO) return;
    try {
        $selector = bin2hex(random_bytes(16)); $validator = bin2hex(random_bytes(32));
        $token_hash = password_hash($validator, PASSWORD_DEFAULT); $expires = date('Y-m-d H:i:s', time() + REMEMBER_ME_DURATION);
        $pdo->beginTransaction();
        $stmt_delete = $pdo->prepare("DELETE FROM persistent_logins WHERE user_id = ?"); $stmt_delete->execute([$userId]);
        $stmt_insert = $pdo->prepare("INSERT INTO persistent_logins (user_id, selector, token_hash, expires) VALUES (?, ?, ?, ?)"); $stmt_insert->execute([$userId, $selector, $token_hash, $expires]);
        $pdo->commit();
        $cookie_value = $selector . ':' . $validator;
        $is_secure_cookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        setcookie(REMEMBER_ME_COOKIE_NAME, $cookie_value, ['expires' => time() + REMEMBER_ME_DURATION, 'path' => '/', 'domain' => '', 'secure' => $is_secure_cookie, 'httponly' => true, 'samesite' => 'Lax']);
    } catch (Exception $e) { if ($pdo->inTransaction()) { $pdo->rollBack(); } error_log("Error remembering user {$userId}: " . $e->getMessage()); }
}
function validateRememberMe(PDO $pdo): ?array {
    if (!isset($pdo) || !$pdo instanceof PDO || empty($_COOKIE[REMEMBER_ME_COOKIE_NAME])) { return null; }
    if (strpos($_COOKIE[REMEMBER_ME_COOKIE_NAME], ':') === false) { if (function_exists('clearRememberMeCookie')) clearRememberMeCookie(); return null; }
    list($selector, $validator) = explode(':', $_COOKIE[REMEMBER_ME_COOKIE_NAME], 2);
    if (empty($selector) || empty($validator) || !ctype_xdigit($selector) || !ctype_xdigit($validator)) { if (function_exists('clearRememberMeCookie')) clearRememberMeCookie(); return null; }
    try {
        $stmt = $pdo->prepare("SELECT * FROM persistent_logins WHERE selector = ? AND expires >= NOW()"); $stmt->execute([$selector]); $token_data = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($token_data && password_verify($validator, $token_data['token_hash'])) {
            $stmt_user = $pdo->prepare("SELECT * FROM usuarios WHERE id = ? AND active = 1 AND banned = 0"); $stmt_user->execute([$token_data['user_id']]); $user = $stmt_user->fetch(PDO::FETCH_ASSOC);
            if ($user) {
                
                if ($user['current_session_token'] !== null) {
                    $five_minutes_ago = time() - 300; // 5 minutos
                    if ($user['last_activity'] > $five_minutes_ago) {
                        error_log("Login (Recordarme) bloqueado: Sesión activa para " . $user['username']);
                        if (function_exists('clearRememberMeCookie')) clearRememberMeCookie();
                        return null;
                    }
                }
                
                session_regenerate_id(true);
                $session_token = bin2hex(random_bytes(32));
                try {
                    $stmt_token = $pdo->prepare("UPDATE usuarios SET current_session_token = ? WHERE id = ?");
                    $stmt_token->execute([$session_token, $user['id']]);
                } catch (PDOException $e) {
                     error_log("Error al actualizar session_token en Recordarme: " . $e->getMessage());
                     if (function_exists('clearRememberMeCookie')) clearRememberMeCookie();
                     return null;
                }
                $_SESSION['session_token'] = $session_token;
                $user['current_session_token'] = $session_token;
                $_SESSION['user'] = $user;
                rememberUser($pdo, $user['id']);
                logActivity($pdo, $user['id'], $user['username'], 'Login (Recordarme)');
                updateUserActivity($pdo, $user['id']);
                updateUserLocation($pdo, $user['id']);
                return $user;
            } else { error_log("Remember Me valid token for invalid user ID: " . $token_data['user_id']); }
        } elseif ($token_data) { error_log("Remember Me invalid validator for selector: " . $selector); $pdo->prepare("DELETE FROM persistent_logins WHERE id = ?")->execute([$token_data['id']]); }
    } catch (PDOException $e) { error_log("Error validating Remember Me: " . $e->getMessage()); } catch (Exception $e) { error_log("General Error during Remember Me validation: " . $e->getMessage()); }
    if (function_exists('clearRememberMeCookie')) clearRememberMeCookie();
    if ($selector) { try { $pdo->prepare("DELETE FROM persistent_logins WHERE selector = ?")->execute([$selector]); } catch (PDOException $e) { /* Ignorar */ } }
    return null;
}

// --- Geolocalización IP ---
function updateUserLocation(PDO $pdo, int $userId): void {
     if (!isset($pdo) || !$pdo instanceof PDO) return;
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? null;
    if ($ip && strpos($ip, ',') !== false) { $ip = trim(explode(',', $ip)[0]); }
    if (!$ip || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) { return; }
    $location_details = 'Desconocida';
    $url = "http://ip-api.com/json/{$ip}?fields=status,message,country,city";
    $options = ['http' => ['timeout' => 2, 'ignore_errors' => true]];
    $context = stream_context_create($options);
    $response = @file_get_contents($url, false, $context);
    if ($response !== false) {
        $data = json_decode($response, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            $city = trim($data['city'] ?? ''); $country = trim($data['country'] ?? '');
            if ($city && $country) { $location_details = $city . ', ' . $country; }
            elseif ($country) { $location_details = $country; }
            elseif ($city) { $location_details = $city; }
        } elseif (isset($data['message'])) { error_log("IP Geolocation API ({$ip}) Error: ".$data['message']); }
    } else { error_log("IP Geolocation API ({$ip}) Request Failed."); }
    $location_details = mb_substr($location_details, 0, 250);
    try {
        $stmt_check = $pdo->prepare("SELECT last_location_details FROM usuarios WHERE id = ?"); $stmt_check->execute([$userId]);
        $current_location = $stmt_check->fetchColumn();
        if ($current_location !== $location_details && !($current_location === 'Desconocida' && $location_details === 'Desconocida')) {
            $stmt_update = $pdo->prepare("UPDATE usuarios SET last_location_details = ? WHERE id = ?");
            $stmt_update->execute([$location_details, $userId]);
            if (isset($_SESSION['user']) && $_SESSION['user']['id'] === $userId) { $_SESSION['user']['last_location_details'] = $location_details; }
        }
    } catch (PDOException $e) { error_log("Error updating user location for user {$userId}: " . $e->getMessage()); }
}

// --- Funciones Módulo Meinungsplatz ---
function findSubidForProjektnummer(PDO $pdo, string $projektnummer): ?string
{
    if (!ctype_digit($projektnummer) || !(strlen($projektnummer) == 5 || strlen($projektnummer) == 6)) {
        error_log("Fn: Invalid projektnummer format passed to findSubidForProjektnummer: " . $projektnummer);
        return null;
    }
    try {
        $stmt = $pdo->prepare("
            SELECT subid
            FROM projektnummer_subid_map
            WHERE TRIM(projektnummer) = ?
            ORDER BY id DESC
            LIMIT 1
        ");
        $stmt->execute([$projektnummer]);
        $result = $stmt->fetchColumn();
        return ($result !== false) ? (string)$result : null;
    } catch (PDOException $e) {
        error_log("Fn: findSubidForProjektnummer Error: " . $e->getMessage());
        return null;
    }
}

/**
 * *** MODIFICADO: Ahora envía notificación vía Webhook ***
 */
function addProjektnummerSubidMap(PDO $pdo, string $projektnummer, string $subid, int $userId): bool {
    if (!ctype_digit($projektnummer) || !(strlen($projektnummer) == 5 || strlen($projektnummer) == 6) || empty($subid) || strlen($subid) > 50) {
        error_log("Fn: Invalid format for addProjektnummerSubidMap: P={$projektnummer}, S={$subid}");
        return false;
    }
    
    try {
        $stmt = $pdo->prepare("INSERT INTO projektnummer_subid_map (projektnummer, subid, created_at) VALUES (?, ?, NOW())");
        $success = $stmt->execute([$projektnummer, $subid]);

        if ($success) {
            $username = 'Desconocido';
            try {
                $stmt_user = $pdo->prepare("SELECT username FROM usuarios WHERE id = ?");
                $stmt_user->execute([$userId]);
                $username_result = $stmt_user->fetchColumn();
                if ($username_result) {
                    $username = $username_result;
                } else {
                    $username = "ID: {$userId}";
                }
            } catch (PDOException $e) {
                error_log("Error getting username for Telegram notification: " . $e->getMessage());
            }
            
            $message = "<b>Nuevo SubID Añadido (Meinungsplatz)</b>\n\n";
            $message .= "👤 <b>Usuario:</b> " . htmlspecialchars($username, ENT_QUOTES) . "\n";
            $message .= "🔗 <b>Projektnummer:</b> " . htmlspecialchars($projektnummer, ENT_QUOTES) . "\n";
            $message .= "🔑 <b>SubID:</b> " . htmlspecialchars($subid, ENT_QUOTES);
            
            if (function_exists('sendTelegramNotification')) {
                sendTelegramNotification($message); // Enviar la notificación
            }
        }
        
        return $success; // Devolver el resultado original

    }
    catch (PDOException $e) {
        error_log("Fn: addProjektnummerSubidMap Error: " . $e->getMessage());
        return false;
    }
}

function getSubidRatings(PDO $pdo, string $subid): array {
    if (empty($subid) || strlen($subid) > 50) {
         error_log("Fn(Debug): Invalid SubID format passed to getSubidRatings: " . $subid);
         return ['positive' => 0, 'negative' => 0, 'total' => 0];
    }
    try {
        $stmt = $pdo->prepare("SELECT SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as positive, SUM(CASE WHEN rating = -1 THEN 1 ELSE 0 END) as negative, COUNT(*) as total FROM subid_ratings WHERE subid = ?");
        $stmt->execute([$subid]); $result = $stmt->fetch(PDO::FETCH_ASSOC);
        $ratings_array = ['positive' => (int)($result['positive'] ?? 0), 'negative' => (int)($result['negative'] ?? 0), 'total' => (int)($result['total'] ?? 0)];
        return $ratings_array;
    } catch (PDOException $e) { error_log("Fn(Debug): getSubidRatings PDOException S:{$subid}: Code[{$e->getCode()}] - {$e->getMessage()}"); return ['positive' => 0, 'negative' => 0, 'total' => 0, 'db_error' => $e->getMessage()]; }
      catch (Throwable $t) { error_log("Fn(Debug): getSubidRatings Throwable S:{$subid}: {$t->getMessage()}"); return ['positive' => 0, 'negative' => 0, 'total' => 0, 'php_error' => $t->getMessage()]; }
}
function getSubidComments(PDO $pdo, string $subid, int $limit = 5): array {
    if (empty($subid) || strlen($subid) > 50) {
         error_log("Fn: Invalid SubID format passed to getSubidComments: " . $subid);
         return [];
    }
    try {
        $stmt = $pdo->prepare(" SELECT r.comment, r.created_at, u.username FROM subid_ratings r LEFT JOIN usuarios u ON r.user_id = u.id WHERE r.subid = ? AND r.comment IS NOT NULL AND r.comment != '' ORDER BY r.created_at DESC LIMIT ? ");
        $stmt->bindValue(1, $subid, PDO::PARAM_STR);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) { error_log("Fn: getSubidComments PDOException S:{$subid}: " . $e->getMessage()); return []; }
}
function getUserRatingForSubid(PDO $pdo, string $subid, int $userId): ?int {
    if (empty($subid) || strlen($subid) > 50) { return null; }
    try { $stmt = $pdo->prepare("SELECT rating FROM subid_ratings WHERE subid = ? AND user_id = ?"); $stmt->execute([$subid, $userId]); $rating = $stmt->fetchColumn(); return $rating !== false ? (int)$rating : null; }
    catch (PDOException $e) { error_log("Fn: getUserRatingForSubid PDOException S:{$subid}/U:{$userId}: Code[{$e->getCode()}] - {$e->getMessage()}"); return null; }
    catch (Throwable $t) { error_log("Fn: getUserRatingForSubid Throwable S:{$subid}/U:{$userId}: {$t->getMessage()}"); return null; }
}
function submitSubidRating(PDO $pdo, string $subid, int $userId, int $rating, ?string $comment): bool {
    if (empty($subid) || strlen($subid) > 50 || !in_array($rating, [1, -1])) { error_log("Fn: Invalid input for submitSubidRating S:{$subid}/U:{$userId}/R:{$rating}"); return false; }
    $comment = ($comment === null) ? null : mb_substr(trim($comment), 0, 500);
    try {
        $stmt = $pdo->prepare("INSERT INTO subid_ratings (subid, user_id, rating, comment, created_at) VALUES (?, ?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE rating = VALUES(rating), comment = VALUES(comment), created_at = NOW()");
        return $stmt->execute([$subid, $userId, $rating, $comment]);
    } catch (PDOException $e) { error_log("Fn: submitSubidRating PDOException S:{$subid}/U:{$userId}: Code[{$e->getCode()}] - {$e->getMessage()}"); return false; }
    catch (Throwable $t) { error_log("Fn: submitSubidRating Throwable S:{$subid}/U:{$userId}: {$t->getMessage()}"); return false; }
}

// --- Función de Notificación de Telegram (vía Webhook de Make.com) ---
function sendTelegramNotification(string $message): void {
    if (!defined('MAKE_WEBHOOK_URL') || empty(MAKE_WEBHOOK_URL) || MAKE_WEBHOOK_URL === 'AQUI_VA_TU_URL_DE_MAKE.COM') {
        error_log("Error de Webhook: 'MAKE_WEBHOOK_URL' no está definida en config.php.");
        return;
    }
    
    error_log("Attempting to send Telegram notification via Make.com webhook...");

    $url = MAKE_WEBHOOK_URL . '?message=' . urlencode($message);

    try {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        
        $response = curl_exec($ch);
        
        if (curl_errno($ch)) {
            error_log("Error de cURL (Telegram Webhook): " . curl_error($ch));
        } else {
            if ($response !== "Accepted") {
                 error_log("Error de Webhook Make.com: Respuesta inesperada: " . $response);
            } else {
                 error_log("Éxito de Webhook: Make.com aceptó la solicitud.");
            }
        }
        curl_close($ch);
    } catch (Exception $e) {
        error_log("Excepción al enviar a Make.com: " . $e->getMessage());
    }
}
// --- FIN FUNCIÓN ---

// --- Marcador FINAL ---
define('FUNCTIONS_PHP_LOADED', true);
?>