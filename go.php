<?php
// go.php (v7 - Lógica Aleatoria para MeinungsplatzDE)
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php'; 
require 'functions.php'; // Requerido para logActivity

$slug = $_GET['slug'] ?? null;

$target_url = null;
$error = false;

if (empty($slug) || !preg_match('/^[a-zA-Z0-9_-]+$/', $slug)) {
    $error = true;
} else {
    
    // --- Lógica de UUID Dinámico (TalkAUSTRIA) ---
    if ($slug === 'TalkAUSTRIA') {
        
        $baseUrl = 'https://talkonlinepanel.com/at/friend_referral/';
        $baseUuid = 'db54aba0-a864-11f0-bb1b-';
        $randomPart = bin2hex(random_bytes(6)); 
        $target_url = $baseUrl . $baseUuid . $randomPart;
        
        if (function_exists('logActivity')) {
            logActivity($pdo, null, 'SYSTEM_GO', 'Redirect Dinámico: TalkAUSTRIA', $target_url);
        }

    // --- Lógica de UUID Dinámico (GallupAustria) ---
    } elseif ($slug === 'GallupAustria') {
        
        $baseUrl = 'https://www2.gallupforum.at/friend_referral/';
        $baseUuid = '63afd5b0-a7d3-11f0-b905-';
        $randomPart = bin2hex(random_bytes(6)); 
        $target_url = $baseUrl . $baseUuid . $randomPart;
        
        if (function_exists('logActivity')) {
            logActivity($pdo, null, 'SYSTEM_GO', 'Redirect Dinámico: GallupAustria', $target_url);
        }
    
    // *** CORRECCIÓN: Lógica de Rotador ALEATORIO (MeinungsplatzDE) ***
    } elseif ($slug === 'MeinungsplatzDE') {
        
        // 1. Definir la lista de URLs
        $link_list = [
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend/start?sponsorship_token=CoIsyyL4bcJlsJCWtnin6URyKMmCk2gAl4zyA0kx_Cw',
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend/start?sponsorship_token=16swxs4KLFvWNA7_WkjzN3A7N28NFk7RCnuG2xT1IdE',
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend?sponsorship_token=j_a5VnpYqtffkPlZ5F966xxuPuzdNGXG7cFsWN10owo',
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend/start?sponsorship_token=1xhBUOua1acky9qomAxg_zE1koR1e1N1evRqi5KvBRo',
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend?sponsorship_token=dt7kj1gZ6GGbBgPW6SoBScW6peE0lZ2TZTtl1LW5yCI',
            'https://meinungsplatz.de/registration/fo-registration-refer-a-friend?sponsorship_token=2joTgRsauIP4XSljVrSmv6APY-9Gb52IbSoYOiLRkxI'
        ];
        
        // 2. Elegir un índice aleatorio del array
        $random_index = array_rand($link_list);
        
        // 3. Seleccionar la URL aleatoria
        $target_url = $link_list[$random_index];
        
        if (function_exists('logActivity')) {
            logActivity($pdo, null, 'SYSTEM_GO', 'Redirect Aleatorio: MeinungsplatzDE', $target_url);
        }

    } else {
        // --- Lógica de DB normal para todos los OTROS slugs ---
        try {
            $stmt = $pdo->prepare("SELECT target_url FROM short_links WHERE slug = ? LIMIT 1");
            $stmt->execute([$slug]);
            $target_url = $stmt->fetchColumn();

            if (!$target_url) {
                $error = true; // El slug no era dinámico Y tampoco se encontró en la DB
            }
        } catch (PDOException $e) {
            error_log("Error en go.php (DB): " . $e->getMessage());
            $error = true;
        }
    }
}

if ($error || !$target_url) {
    // Si el slug no es válido o no se encuentra
    header("Location: index.php?error=link_not_found");
    exit;
}

// Si llegamos aquí, $target_url está definido (ya sea desde la DB o dinámicamente)
// Mostramos la página de redirección.
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Redirigiendo... - SurveyJunior</title>
    
    <!-- Meta refresh como fallback (si JavaScript falla) -->
    <meta http-equiv="refresh" content="5;url=<?= htmlspecialchars($target_url, ENT_QUOTES, 'UTF-8') ?>">
    
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad1' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%235a9cff;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%230d6efd;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Ccircle cx='50' cy='50' r='50' fill='url(%23grad1)' /%3E%3Ctext x='50' y='60' font-size='50' fill='%23fff' text-anchor='middle' font-family='Arial, sans-serif' font-weight='bold'%3ESJ%3C/text%3E%3C/svg%3E">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"/>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <link rel="stylesheet" href="new-style.css">
</head>
<body>
    
    <!-- Usamos la misma clase que login.php para centrar todo y tener el fondo animado -->
    <div class="login-container">
        
        <!-- Usamos la misma clase de tarjeta para el diseño -->
        <div class="form-card text-center">
        
            <!-- El banner de SurveyJunior -->
            <div class="login-header-banner">
                <h1>SurveyJunior.us</h1>
                <p>Jumpers, Encuestas y mas.</p>
            </div>

            <!-- El Cohete Animado -->
            <div class="splash-rocket-icon mt-4">
                🚀
            </div>

            <!-- El mensaje de cuenta regresiva -->
            <h3 class="mt-3 mb-3">
                Será redirigido en <span id="countdown">5</span> segundos...
            </h3>
            
            <!-- El mensaje de destino (mostrando el slug) -->
            <p class="text-muted mb-2">En breves segundos será redirigido a:</p>
            
            <!-- Mostramos el {slug} como un botón (sin acción) -->
            <div class="btn btn-generate splash-slug-btn disabled" role="button" aria-disabled="true">
                <i class="bi bi-link-45deg me-2"></i>
                <?= htmlspecialchars($slug, ENT_QUOTES, 'UTF-8') ?>
            </div>

        </div>
    </div>

    <script>
        // Script simple para la cuenta regresiva visual
        (function() {
            let seconds = 5;
            const countdownElement = document.getElementById('countdown');
            
            const interval = setInterval(() => {
                seconds--;
                if (countdownElement) {
                    countdownElement.textContent = seconds;
                }
                if (seconds <= 0) {
                    clearInterval(interval);
                    // Forzar redirección por JS
                    window.location.href = '<?= htmlspecialchars($target_url, ENT_QUOTES, 'UTF-8') ?>';
                }
            }, 1000);
        })();
    </script>
</body>
</html>