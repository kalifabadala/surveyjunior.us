<?php
// maintenance_check.php (v2 - Añadido Botón Logout)
// Este script se incluye al inicio de todas las páginas públicas y APIs.

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

$is_maintenance_mode = file_exists('MAINTENANCE'); // Comprueba si el archivo "MAINTENANCE" existe

if ($is_maintenance_mode) {
    // El sitio está en mantenimiento
    $is_admin = (isset($_SESSION['user']) && $_SESSION['user']['role'] === 'admin');

    if (!$is_admin) {
        // Si no es admin, bloquear acceso.
        
        // Determinar si es una petición de API (JSON) o una página (HTML)
        $is_api_request = (strpos($_SERVER['REQUEST_URI'], '/api_') !== false);
        
        if ($is_api_request) {
            http_response_code(503); // Service Unavailable
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'success' => false, 
                'message' => 'El sitio está en mantenimiento. Por favor, inténtelo de nuevo más tarde.'
            ]);
        } else {
            // Mostrar una página HTML simple
            http_response_code(503);
            echo <<<HTML
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mantenimiento - SurveyJunior</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f8f9fa; color: #333; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .container { padding: 2rem 3rem; background: #fff; border-radius: 15px; box-shadow: 0 8px 30px rgba(0,0,0,0.05); }
        h1 { color: #0d6efd; margin-bottom: 0.5rem; }
        p { font-size: 1.1rem; color: #6c757d; }
        
        /* --- NUEVO: Estilo del Botón Logout --- */
        .btn-logout {
            display: inline-block;
            text-decoration: none;
            font-weight: 600;
            color: #fff;
            background-color: #dc3545;
            border: 1px solid #dc3545;
            padding: 0.5rem 1rem;
            font-size: 1rem;
            border-radius: 50px;
            transition: all 0.3s ease;
            margin-top: 1.5rem;
            cursor: pointer;
        }
        .btn-logout:hover { background-color: #bb2d3b; border-color: #b02a37; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 SurveyJunior</h1>
        <p>El sitio está actualmente en mantenimiento.</p>
        <p><strong>¡Volvemos pronto!</strong></p>
        
        <a href="logout.php" class="btn-logout">Cerrar Sesión</a>
    </div>
</body>
</html>
HTML;
        }
        exit; // Detener la ejecución del script original
    }
    // Si es admin, el script no hace nada y permite que la página se cargue.
}
?>