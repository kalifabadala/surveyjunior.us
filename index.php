<?php
// index.php (v16.6 - Ranking Piramidal)
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require 'config.php';
require 'functions.php';
require 'maintenance_check.php'; // Comprobar Modo Mantenimiento

// --- Check "Recordarme" Cookie ---
if (!isset($_SESSION['user'])) {
    if (function_exists('validateRememberMe')) { $userFromCookie = validateRememberMe($pdo); }
    else { error_log("Error: validateRememberMe function not found in functions.php"); }
}
if (!isset($_SESSION['user'])) { header("Location: login.php"); exit; }
$user = $_SESSION['user'];

// --- Validación Sesión Única (CON EXCEPCIÓN PARA ADMIN) ---
if (isset($user['id']) && isset($_SESSION['session_token']) && $user['role'] !== 'admin') {
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

$canGenerateLinks = ($user['role'] === 'admin') || ($user['can_generate_links'] == 1);
if (function_exists('updateUserActivity')) { updateUserActivity($pdo, $user['id']); }
$module = $_GET['module'] ?? 'home';

// --- Lógica para Carga Asíncrona (SPA) ---
$isFragmentRequest = isset($_GET['fetch']) && $_GET['fetch'] === 'fragment';

if ($isFragmentRequest) {
    // Definimos qué módulo mostrar basado en $_GET['module']
    if ($module === 'home') {
        
        ?>
        
        <!-- Saludo Dinámico -->
        <h2 class="mb-2 dynamic-greeting" id="dynamic-greeting-message">
            Cargando...
        </h2>
        
        <!-- Tarjetas Jumbo y Rango (Lado a Lado) -->
        <div class="row g-3 mb-3 justify-content-center">
            <div class="col-md-6">
                <!-- Tarjeta de Estadísticas "Jumbo" -->
                <div class="stat-card-jumbo text-center h-100">
                    <div class="stat-jumbo-icon">🚀</div>
                    <div class="stat-jumbo-value" id="stat-total-jumpers">0</div>
                    <div class="stat-jumbo-label">Jumpers Generados</div>
                    <div class="stat-jumbo-subtitle">¡Sigue así, leyenda!</div>
                </div>
            </div>
            <div class="col-md-6">
                <!-- Tarjeta de Rango (Gamificación) -->
                <div class="jumper-rank-card h-100" id="jumper-rank-card">
                    <div class="rank-icon">...</div>
                    <div class="rank-details">
                        <div class="rank-label">Tu Rango Actual:</div>
                        <div class="rank-name">...</div>
                    </div>
                </div>
            </div>
        </div>

        <h4 class="mb-2">Tus Módulos</h4>
        <div class="modules-container">
            
            <a href="index.php?module=opensurvey" class="module-card opensurvey nav-link">
                <div class="icon-wrapper"><img src="talk-logo.png" alt="Opensurvey Logo" class="icon"></div>
                <h5>JUMPER Opensurvey</h5>
                <p>Crea enlaces personalizados para tus encuestas Opensurvey.</p>
            </a>
            <a href="index.php?module=opinionexchange" class="module-card opinionexchange nav-link">
                <div class="icon-wrapper"><img src="opinion-logo.png" alt="OpinionExchange Logo" class="icon"></div>
                <h5>JUMPER OpinionExchange</h5>
                <p>Gestiona y genera enlaces para el panel de opinión.</p>
            </a>
            <a href="index.php?module=meinungsplatz" class="module-card meinungsplatz nav-link">
                <div class="icon-wrapper"><img src="meinungsplatz-logo.png" alt="Meinungsplatz Logo" class="icon"></div>
                <h5>JUMPER Meinungsplatz</h5>
                <p>Analiza URLs para generar JUMPERs de Meinungsplatz e IQSN.</p>
            </a>
            
            <!-- Botón Premium Ranking -->
            <a href="index.php?module=ranking" class="module-card premium nav-link">
                <div class="icon-wrapper">
                    <i class="bi bi-trophy-fill icon"></i>
                </div>
                <h5>Ranking de SubIDs</h5>
                <p>¡Mira quiénes son los mejores colaboradores!</p>
            </a>
            
            <?php if ($user['role'] === 'admin'): ?>
                <a href="admin.php" class="module-card admin"> <!-- Enlace normal a admin.php -->
                    <i class="bi bi-gear-fill icon"></i>
                    <h5>Panel de Administración</h5>
                    <p>Gestiona usuarios, permisos y configuración del sistema.</p>
                </a>
            <?php endif; ?>
        </div>
        <?php
    } elseif ($module === 'opensurvey') {
        ?>
        <div class="form-card">
            <h3 class="mb-4">
                <i class="bi bi-link-45deg me-2"></i>JUMPER Opensurvey
                <a href="#" class="module-help-icon" data-bs-toggle="tooltip" data-bs-html="true" data-bs-placement="right" title="Pega la URL completa de Opensurvey/Reppublika.<br>Debe contener los parámetros:<br><code>account=...</code><br><code>project=...</code><br><code>uuid=...</code>">
                    <i class="bi bi-info-circle-fill"></i>
                </a>
            </h3>
            <form id="opensurvey-form">
                <div class="mb-3"><label for="opensurvey-url" class="form-label">URL de Opensurvey</label><input id="opensurvey-url" type="url" name="input_url" class="form-control form-control-modern" placeholder="https://opensurvey.reppublika.com/..." required /><div class="form-text mt-2">Pegue aquí la URL completa.</div></div>
                <?php if ($canGenerateLinks): ?>
                    <button type="submit" class="btn btn-generate w-100">
                         <span class="btn-text"><i class="bi bi-magic me-2"></i>Generar JUMPER</span>
                         <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                    </button>
                <?php else: ?>
                    <button type="button" class="btn btn-secondary w-100" disabled><i class="bi bi-shield-exclamation me-2"></i>No autorizado</button>
                    <div class="text-danger mt-2">No tiene permiso para generar enlaces.</div>
                <?php endif; ?>
            </form>
            <div id="opensurvey-result" class="mt-4"></div>
        </div>
        <?php
    } elseif ($module === 'opinionexchange') {
        ?>
        <div class="form-card">
             <h3 class="mb-4">
                <i class="bi bi-chat-left-text me-2"></i>JUMPER OpinionExchange
                <a href="#" class="module-help-icon" data-bs-toggle="tooltip" data-bs-html="true" data-bs-placement="right" title="Pega la URL completa de la encuesta (ej. de djsresearch, maximiles, etc.).<br>Debe contener el parámetro:<br><code>UserID=...</code>">
                    <i class="bi bi-info-circle-fill"></i>
                </a>
            </h3>
            <form id="opinionexchange-form">
                <div class="mb-3"><label for="opinion-url" class="form-label">URL de Encuesta</label><input id="opinion-url" type="url" name="input_url_opinion" class="form-control form-control-modern" placeholder="https://survey.ejemplo.com/wix/p..." required /><div class="form-text mt-2">Pegue aquí la URL completa que contenga 'UserID'.</div></div>
                <?php if ($canGenerateLinks): ?>
                     <button type="submit" class="btn btn-generate w-100">
                         <span class="btn-text"><i class="bi bi-magic me-2"></i>Generar JUMPER</span>
                         <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                    </button>
                <?php else: ?>
                    <button type="button" class="btn btn-secondary w-100" disabled><i class="bi bi-shield-exclamation me-2"></i>No autorizado</button>
                    <div class="text-danger mt-2">No tiene permiso para generar enlaces.</div>
                <?php endif; ?>
            </form>
            <div id="opinionexchange-result" class="mt-4"></div>
        </div>
        <?php
    } elseif ($module === 'meinungsplatz') {
        ?>
        <div class="form-card">
             <h3 class="mb-4">
                <i class="bi bi-link-45deg me-2"></i>JUMPER Meinungsplatz 2.0
                <a href="#" class="module-help-icon" data-bs-toggle="tooltip" data-bs-html="true" data-bs-placement="right" title="Pega una o más URLs de encuesta (una por línea). El sistema buscará automáticamente un ID de usuario de 15 dígitos.<br>Introduce el 'Projektnummer' (ID de encuesta de 5 o 6 dígitos) manualmente.">
                    <i class="bi bi-info-circle-fill"></i>
                </a>
            </h3>
            <form id="meinungsplatz-form">
                <div class="mb-3"><label for="url_textarea" class="form-label">Pega aquí las URLs</label><textarea class="form-control form-control-modern" id="url_textarea" rows="5" placeholder="https://nk.decipherinc.com/survey/...?m=...&#10;https://survey.maximiles.com/..."></textarea><div class="form-text mt-2">Una URL por línea. Se buscará ID de 15 dígitos.</div></div>
                <div class="mb-3"><label for="projektnummer_input" class="form-label">Projektnummer (5 o 6 dígitos)</label><input type="text" class="form-control form-control-modern" id="projektnummer_input" maxlength="6" pattern="\d{5,6}" title="Debe ser un número de 5 o 6 dígitos" placeholder="Ej: 12345 o 123456" required /><div class="form-text mt-2">Este valor es obligatorio.</div></div>
                <button type="submit" id="generate-btn" class="btn btn-generate w-100"><span class="btn-text"><i class="bi bi-magic me-2"></i>Generar Enlace</span><span id="btn-spinner" class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span></button>
            </form>
            <div id="result-container" class="mt-4" style="display: none;"></div>
            <button type="button" id="meinungsplatz-clear-btn" class="btn btn-outline-secondary w-100 mt-3 d-none"><i class="bi bi-eraser-fill me-1"></i> Limpiar</button>
        </div>
        
        <!-- *** CAMBIO: HTML para la página de Ranking Piramidal *** -->
        <?php
    } elseif ($module === 'ranking') {
        ?>
        <div class="ranking-page-container">
            <h2 class="mb-3 dynamic-greeting"><i class="bi bi-trophy-fill me-2" style="color: #ffd700;"></i> Podio de Colaboradores</h2>
            <p class="text-muted mb-4">Top 10 de usuarios que más SubIDs han aportado.</p>
            
            <div class="pyramid-ranking-container">
                <ol class="pyramid-ranking" id="ranking-list">
                    <!-- El contenido se genera por JS -->
                    <!-- El Skeleton se carga desde el template -->
                </ol>
            </div>
        </div>
        <?php
    }
    // *** FIN CAMBIO ***
    
    else {
        if ($module !== 'home') { echo '<div class="alert alert-danger">Módulo no válido.</div>'; }
    }
    if ($isFragmentRequest) { exit; }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
    <title>Panel - SurveyJunior</title>
    <!-- Favicon SJ con Gradiente -->
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='grad1' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' style='stop-color:%235a9cff;stop-opacity:1' /%3E%3Cstop offset='100%25' style='stop-color:%230d6efd;stop-opacity:1' /%3E%3C/linearGradient%3E%3C/defs%3E%3Ccircle cx='50' cy='50' r='50' fill='url(%23grad1)' /%3E%3Ctext x='50' y='60' font-size='50' fill='%23fff' text-anchor='middle' font-family='Arial, sans-serif' font-weight='bold'%3ESJ%3C/text%3E%3C/svg%3E">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet"/>
    <link rel="stylesheet" href="new-style.css">
</head>
<body class="app-loading"> <!-- La clase 'dark-mode' se añadirá aquí por JS si es necesario -->

    <div class="app-shell">
        <!-- Sidebar -->
        <nav class="app-sidebar">
            <!-- Logo SVG -->
            <a class="navbar-brand nav-link" href="index.php?module=home" title="SurveyJunior">
                <i class="bi bi-clipboard-data-fill"></i>
            </a>
            <ul class="app-nav-list">
                <li class="<?= $module === 'home' ? 'active' : '' ?>"><a href="index.php?module=home" class="nav-link" title="Inicio"><i class="bi bi-house-fill"></i><span>Inicio</span></a></li>
                <li class="<?= $module === 'opensurvey' ? 'active' : '' ?>"><a href="index.php?module=opensurvey" class="nav-link" title="Opensurvey"><i class="bi bi-link-45deg"></i><span>Opensurvey</span></a></li>
                <li class="<?= $module === 'opinionexchange' ? 'active' : '' ?>"><a href="index.php?module=opinionexchange" class="nav-link" title="OpinionExchange"><i class="bi bi-chat-left-text-fill"></i><span>OpinionEx</span></a></li>
                <li class="<?= $module === 'meinungsplatz' ? 'active' : '' ?>"><a href="index.php?module=meinungsplatz" class="nav-link" title="Meinungsplatz"><i class="bi bi-lightbulb-fill"></i><span>Meinungsplatz</span></a></li>
                <!-- Botón Ranking Sidebar -->
                <li class="<?= $module === 'ranking' ? 'active' : '' ?>"><a href="index.php?module=ranking" class="nav-link" title="Ranking"><i class="bi bi-trophy-fill"></i><span>Ranking</span></a></li>
                <?php if ($user['role'] === 'admin'): ?>
                <li class="<?= (strpos($_SERVER['REQUEST_URI'], 'admin.php') !== false) ? 'active' : '' ?>"><a href="admin.php" title="Admin"><i class="bi bi-gear-fill"></i><span>Admin</span></a></li>
                <?php endif; ?>
            </ul>
            <div class="app-sidebar-footer">
                <a href="logout.php" class="logout-btn" title="Cerrar sesión"><i class="bi bi-box-arrow-right"></i><span>Cerrar Sesión</span></a>
            </div>
        </nav>

        <!-- Contenido Principal -->
        <main class="app-content">
            <header class="app-header">
                <div class="d-lg-none"><h4 class="page-title" id="page-title-mobile">Inicio</h4></div>
                <div class="ms-auto d-flex align-items-center">
                    
                    <!-- Botón Modo Oscuro -->
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

            <!-- Contenedor SPA (Ahora inicia con el spinner, JS lo reemplazará) -->
            <div class="content-body" id="module-content">
                 <div class="d-flex justify-content-center align-items-center h-100">
                    <div class="spinner-border text-primary" role="status"><span class="visually-hidden">Cargando...</span></div>
                </div>
            </div>
        </main>

        <!-- Tab Bar -->
        <nav class="app-tab-bar">
            <a href="index.php?module=home" class="nav-link <?= $module === 'home' ? 'active' : '' ?>"><i class="bi bi-house-fill"></i></a>
            <a href="index.php?module=opensurvey" class="nav-link <?= $module === 'opensurvey' ? 'active' : '' ?>"><i class="bi bi-link-45deg"></i></a>
            <a href="index.php?module=opinionexchange" class="nav-link <?= $module === 'opinionexchange' ? 'active' : '' ?>"><i class="bi bi-chat-left-text-fill"></i></a>
            <a href="index.php?module=meinungsplatz" class="nav-link <?= $module === 'meinungsplatz' ? 'active' : '' ?>"><i class="bi bi-lightbulb-fill"></i></a>
            <!-- Botón Ranking Tab Bar -->
            <a href="index.php?module=ranking" class="nav-link <?= $module === 'ranking' ? 'active' : '' ?>"><i class="bi bi-trophy-fill"></i></a>
            <?php if ($user['role'] === 'admin'): ?>
                <a href="admin.php" class="<?= (strpos($_SERVER['REQUEST_URI'], 'admin.php') !== false) ? 'active' : '' ?>"><i class="bi bi-gear-fill"></i></a>
            <?php endif; ?>
        </nav>
    </div>

    <!-- Panel Offcanvas (Perfil) -->
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
                
                <!-- Historial Reciente -->
                <div class="card-body border-top" id="recent-history-container">
                    <h6 class="mb-2">Historial Reciente</h6>
                    <ul class="list-group list-group-flush recent-history-list" id="recent-history-list">
                        <!-- El contenido se generará por JS -->
                    </ul>
                </div>

                <div class="card-body border-top">
                    <button class="btn btn-outline-info w-100" data-bs-toggle="modal" data-bs-target="#whatsNewModal"><i class="bi bi-gift-fill me-2"></i>Novedades</button>
                    <?php if ($user['role'] === 'admin'): ?>
                    <a href="admin.php" class="btn btn-warning w-100 mt-2"><i class="bi bi-gear-fill me-2"></i>Panel Admin</a>
                    <?php endif; ?>
                    <a href="logout.php" class="btn btn-outline-danger w-100 mt-2"><i class="bi bi-box-arrow-right me-2"></i>Cerrar Sesión</a>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal Novedades (contenido actualizado) -->
    <div class="modal fade" id="whatsNewModal" tabindex="-1" aria-labelledby="whatsNewModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="whatsNewModalLabel"><i class="bi bi-stars me-2 text-warning"></i>¡Nuevas Funciones!</h5><button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button></div>
                <div class="modal-body">
                     <p>¡Hola, <?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?>! Hemos actualizado:</p>
                     <ul>
                        <li><strong>¡Nuevo Ranking!</strong> Haz clic en el nuevo botón 🏆 para ver el podio.</li>
                        <li><strong>¡Modo Oscuro!</strong> Haz clic en el icono de la luna 🌙 en la cabecera.</li>
                        <li><strong>Carga "Fantasma":</strong> No más spinners, ahora ves un esqueleto de la página.</li>
                        <li><strong>Historial Rápido:</strong> Tu panel de perfil ahora guarda tus últimos jumpers generados.</li>
                        <li><strong>Gamificación:</strong> Tu rango (ej. Novato, Pro) ahora aparece en la página de inicio.</li>
                    </ul>
                </div>
                <div class="modal-footer"><button type="button" class="btn btn-primary" data-bs-dismiss="modal">¡Entendido!</button></div>
            </div>
        </div>
    </div>

    <!-- Modal Inactividad (sin cambios) -->
    <div class="modal fade" id="inactivityModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="inactivityModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header"><h5 class="modal-title" id="inactivityModalLabel"><i class="bi bi-clock-history me-2"></i>Sesión a punto de expirar</h5></div>
                <div class="modal-body"><p>Has estado inactivo. Tu sesión se cerrará automáticamente en <span id="inactivityCountdown">60</span> segundos.</p><p>¿Deseas continuar tu sesión?</p></div>
                <div class="modal-footer"><button type="button" class="btn btn-secondary" id="logoutBtn">Cerrar Sesión</button><button type="button" class="btn btn-primary" id="stayLoggedInBtn">Continuar Sesión</button></div>
            </div>
        </div>
    </div>
    
    <!-- Modal de Error/Añadir SubID (sin cambios) -->
    <div class="modal fade" id="subidErrorModal" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="subidErrorModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header border-0">
                    <h5 class="modal-title" id="subidErrorModalLabel"><i class="bi bi-robot me-2" style="font-size: 1.5rem; color: var(--warning-color);"></i> SubID No Encontrado</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar" id="modal-close-btn"></button>
                </div>
                <div class="modal-body text-center">
                    <p id="modal-error-message" class="mb-3">No tenemos SubID para Projektnummer <strong>...</strong>.</p>
                    <p class="mb-3">¿Deseas añadirlo manualmente?</p>
                    <form id="modal-add-subid-form">
                        <input type="hidden" id="modal-add-projektnummer" value="">
                        <div class="input-group">
                            <input type="text" class="form-control form-control-modern" id="modal-add-new-subid" placeholder="SubID (ej: f8113cee)" maxlength="50" pattern=".{1,50}" title="Debe tener entre 1 y 50 caracteres" required>
                            <button class="btn btn-success" type="submit" id="modal-add-subid-btn">
                                <span class="btn-text"><i class="bi bi-plus-circle me-1"></i>Añadir</span>
                                <span class="spinner-border spinner-border-sm d-none" role="status" aria-hidden="true"></span>
                            </button>
                        </div>
                    </form>
                </div>
                <div class="modal-footer justify-content-center border-0">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal" id="modal-cancel-add-subid-btn">
                        <i class="bi bi-arrow-left-short"></i> Volver (No añadir)
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal de Subir de Nivel (Gamificación) -->
    <div class="modal fade" id="levelUpModal" tabindex="-1" aria-labelledby="levelUpModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content level-up-modal-content">
                <div class="modal-body text-center">
                    <div class="confetti-container">
                        <!-- El confeti se genera aquí por CSS -->
                    </div>
                    <div class="level-up-icon" id="levelUpIcon">...</div>
                    <h2 class="modal-title" id="levelUpModalLabel">¡Subiste de Nivel!</h2>
                    <p class="lead">Has alcanzado el rango de:</p>
                    <h3 class="level-up-rank" id="levelUpRankName">...</h3>
                    <button type="button" class="btn btn-primary mt-3" data-bs-dismiss="modal">¡Genial!</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Templates para Éxito y Skeletons -->
    <template id="success-template">
        <div class="jumper-success-card">
            <div class="jsc-icon-wrapper"><i class="bi bi-rocket-launch-fill"></i></div>
            <h4 class="jsc-title">¡JUMPER Generado!</h4>
            <div class="jsc-link-box"><a href="#" target="_blank" class="jumper-link"></a></div>
            <div class="jsc-actions">
                <button class="btn btn-success btn-lg btn-copy-jumper" onclick="copyJumper('JUMPER_URL_PLACEHOLDER', this)"><i class="bi bi-clipboard-check-fill me-2"></i>Copiar Enlace</button>
                <a href="#" target="_blank" class="btn btn-outline-secondary jumper-link-test-btn"><i class="bi bi-box-arrow-up-right me-1"></i>Probar</a>
            </div>
        </div>
        <div class="rating-section card mt-4"><div class="card-header d-flex justify-content-between align-items-center"><h5 class="mb-0"><i class="bi bi-star-fill me-2"></i>Calificar SubID: <strong class="subid-display"></strong></h5><button class="btn btn-sm btn-outline-secondary" id="hide-rating-btn"><i class="bi bi-chevron-up"></i> Ocultar</button></div><div class="card-body"><div class="row text-center"><div class="col"><button class="btn btn-success btn-lg rating-btn" data-rating="1"><i class="bi bi-hand-thumbs-up-fill"></i><div class="rating-count positive-count">0</div></button></div><div class="col"><button class="btn btn-danger btn-lg rating-btn" data-rating="-1"><i class="bi bi-hand-thumbs-down-fill"></i><div class="rating-count negative-count">0</div></button></div></div><div id="comment-list-container" class="mt-4"></div><div class="mt-3"><label for="comment-textarea" class="form-label">Añadir/Actualizar tu comentario</label><textarea class="form-control form-control-modern" id="comment-textarea" rows="2"></textarea><button class="btn btn-primary mt-2" id="submit-rating-btn">Enviar Calificación</button></div></div></div>
    </template>
    
    <template id="skeleton-home">
        <h2 class="mb-2 dynamic-greeting"><span class="skeleton-box" style="width: 300px; height: 38px;"></span></h2>
        <div class="row g-3 mb-3 justify-content-center">
            <div class="col-md-6">
                <div class="stat-card-jumbo text-center h-100 skeleton-card">
                    <div class="stat-jumbo-icon"><span class="skeleton-box" style="width: 60px; height: 64px;"></span></div>
                    <div class="stat-jumbo-value"><span class="skeleton-box" style="width: 80px; height: 40px; margin: auto;"></span></div>
                    <div class="stat-jumbo-label"><span class="skeleton-box" style="width: 150px; margin: auto;"></span></div>
                    <div class="stat-jumbo-subtitle"><span class="skeleton-box" style="width: 120px; margin: auto;"></span></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="jumper-rank-card h-100 skeleton-card">
                    <div class="rank-icon"><span class="skeleton-box" style="width: 50px; height: 50px;"></span></div>
                    <div class="rank-details" style="flex-grow: 1;">
                        <div class="rank-label"><span class="skeleton-box" style="width: 100px;"></span></div>
                        <div class="rank-name"><span class="skeleton-box" style="width: 150px; height: 30px;"></span></div>
                    </div>
                </div>
            </div>
        </div>
        <h4 class="mb-2"><span class="skeleton-box" style="width: 180px;"></span></h4>
        <div class="modules-container">
            <div class="module-card skeleton-card"><span class="skeleton-box" style="width: 200px; height: 120px;"></span></div>
            <div class="module-card skeleton-card"><span class="skeleton-box" style="width: 200px; height: 120px;"></span></div>
            <div class="module-card skeleton-card"><span class="skeleton-box" style="width: 200px; height: 120px;"></span></div>
        </div>
    </template>
    <template id="skeleton-opensurvey">
        <div class="form-card skeleton-card">
            <h3 class="mb-4"><span class="skeleton-box" style="width: 250px;"></span></h3>
            <div class="mb-3"><span class="skeleton-box" style="width: 150px;"></span><span class="skeleton-box" style="height: 48px;"></span></div>
            <span class="skeleton-box" style="height: 48px; border-radius: 50px;"></span>
        </div>
    </template>
    <template id="skeleton-opinionexchange">
        <div class="form-card skeleton-card">
            <h3 class="mb-4"><span class="skeleton-box" style="width: 280px;"></span></h3>
            <div class="mb-3"><span class="skeleton-box" style="width: 150px;"></span><span class="skeleton-box" style="height: 48px;"></span></div>
            <span class="skeleton-box" style="height: 48px; border-radius: 50px;"></span>
        </div>
    </template>
    <template id="skeleton-meinungsplatz">
        <div class="form-card skeleton-card">
            <h3 class="mb-4"><span class="skeleton-box" style="width: 280px;"></span></h3>
            <div class="mb-3"><span class="skeleton-box" style="width: 150px;"></span><span class="skeleton-box" style="height: 100px;"></span></div>
            <div class="mb-3"><span class="skeleton-box" style="width: 200px;"></span><span class="skeleton-box" style="height: 48px;"></span></div>
            <span class="skeleton-box" style="height: 48px; border-radius: 50px;"></span>
        </div>
    </template>
    <template id="skeleton-ranking">
        <div class="ranking-page-container">
            <h2 class="mb-3 dynamic-greeting"><span class="skeleton-box" style="width: 300px; height: 38px;"></span></h2>
            <p class="text-muted mb-4"><span class="skeleton-box" style="width: 250px; height: 24px;"></span></p>
            <div class="ranking-podium row justify-content-center g-3 mb-4">
                <div class="col-4 podium-card-wrapper"><div class="podium-card rank-2 skeleton-card"><span class="skeleton-box podium-avatar"></span><span class="skeleton-box" style="width: 80%; height: 24px;"></span><span class="skeleton-box" style="width: 50%; height: 30px;"></span></div></div>
                <div class="col-4 podium-card-wrapper"><div class="podium-card rank-1 skeleton-card"><div class="podium-crown"></div><span class="skeleton-box podium-avatar"></span><span class="skeleton-box" style="width: 80%; height: 24px;"></span><span class="skeleton-box" style="width: 50%; height: 30px;"></span></div></div>
                <div class="col-4 podium-card-wrapper"><div class="podium-card rank-3 skeleton-card"><span class="skeleton-box podium-avatar"></span><span class="skeleton-box" style="width: 80%; height: 24px;"></span><span class="skeleton-box" style="width: 50%; height: 30px;"></span></div></div>
            </div>
            <h4 class="mb-3"><span class="skeleton-box" style="width: 200px; height: 32px;"></span></h4>
            <ul class="list-group ranking-list">
                <li class="list-group-item skeleton-card"><span class="skeleton-box" style="width: 100%; height: 40px;"></span></li>
                <li class="list-group-item skeleton-card"><span class="skeleton-box" style="width: 100%; height: 40px;"></span></li>
                <li class="list-group-item skeleton-card"><span class="skeleton-box" style="width: 100%; height: 40px;"></span></li>
            </ul>
        </div>
    </template>
    <!-- *** FIN SKELETONS *** -->


    <!-- Contenedor para Toasts (Privados) -->
    <div class="toast-container position-fixed bottom-0 end-0 p-3" id="toast-container"></div>
    
    <!-- Contenedor para Toasts (Públicos - ELIMINADO DE AQUÍ) -->
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="new-script.js"></script>
    <!-- Script public-toast.js (ELIMINADO DE AQUÍ) -->
</body>
</html>