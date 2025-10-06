<?php
session_start();
require_once __DIR__ . '/../config/roles.php';

// Verificar sesión
if (!isset($_SESSION['user'])) {
    header('Location: /login.php');
    exit;
}

$roleManager = new RoleManager();
$username = $_SESSION['user'];
$allowedTools = $roleManager->canUseTools($username);

// Herramientas disponibles
$allTools = [
    'mx_lookup' => ['name' => 'MX Lookup', 'icon' => 'envelope', 'description' => 'Consultar registros MX'],
    'dns_lookup' => ['name' => 'DNS Lookup', 'icon' => 'globe', 'description' => 'Búsqueda DNS'],
    'whois' => ['name' => 'WHOIS', 'icon' => 'info-circle', 'description' => 'Información de dominio'],
    'ip_lookup' => ['name' => 'IP Lookup', 'icon' => 'router', 'description' => 'Información de IP'],
    'ssl_checker' => ['name' => 'SSL Checker', 'icon' => 'shield-check', 'description' => 'Verificar SSL'],
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mi Dashboard - Multi-Herramientas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/themes.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .tool-card {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .tool-card:hover {
            transform: translateY(-10px);
            box-shadow: var(--shadow-lg);
        }
        
        .tool-card.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .tool-card.disabled:hover {
            transform: none;
        }
        
        .tool-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .welcome-banner {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-hover));
            color: white;
            padding: 3rem 2rem;
            border-radius: 20px;
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>
    <div class="container py-4">
        <!-- Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>
                <i class="bi bi-tools"></i> Multi-Herramientas
            </h2>
            <button id="theme-toggle" class="btn btn-theme-toggle">
                🌙 Modo Oscuro
            </button>
        </div>
        
        <!-- Welcome Banner -->
        <div class="welcome-banner">
            <h1>👋 Hola, <?php echo htmlspecialchars($username); ?>!</h1>
            <p class="mb-0">Tienes acceso a <?php echo count($allowedTools); ?> herramientas</p>
        </div>
        
        <!-- Herramientas -->
        <h4 class="mb-4">
            <i class="bi bi-grid-3x3-gap-fill"></i> Tus Herramientas
        </h4>
        
        <div class="row">
            <?php foreach ($allTools as $toolId => $toolInfo): ?>
            <?php 
                $isAllowed = in_array($toolId, $allowedTools) || in_array('all', $allowedTools);
                $disabledClass = !$isAllowed ? 'disabled' : '';
            ?>
            <div class="col-md-4">
                <div class="tool-card <?php echo $disabledClass; ?>" 
                     onclick="<?php echo $isAllowed ? "window.location.href='/tools/{$toolId}.php'" : ''; ?>">
                    <div class="tool-icon" style="color: var(--primary-color);">
                        <i class="bi bi-<?php echo $toolInfo['icon']; ?>"></i>
                    </div>
                    <h5><?php echo $toolInfo['name']; ?></h5>
                    <p class="text-muted mb-0"><?php echo $toolInfo['description']; ?></p>
                    <?php if (!$isAllowed): ?>
                        <span class="badge bg-secondary mt-2">
                            <i class="bi bi-lock"></i> No disponible
                        </span>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        
        <!-- Quick Stats -->
        <div class="row mt-4">
            <div class="col-md-12">
                <div class="chart-container">
                    <h5 class="mb-3">
                        <i class="bi bi-activity"></i> Tu Actividad
                    </h5>
                    <p class="text-muted">Próximamente: Estadísticas de uso personalizado</p>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="text-center mt-5">
            <a href="/logout.php" class="btn btn-outline-danger">
                <i class="bi bi-box-arrow-right"></i> Cerrar Sesión
            </a>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/theme-manager.js"></script>
</body>
</html>
