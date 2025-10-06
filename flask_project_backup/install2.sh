#!/bin/bash

# Script de actualización del Dashboard Multi-Herramientas
# Versión 2.0 - Con roles, temas y dashboards mejorados

echo "=================================="
echo "  ACTUALIZACIÓN MULTI-HERRAMIENTAS"
echo "  Dashboard v2.0"
echo "=================================="
echo ""

# Crear directorios necesarios
mkdir -p config
mkdir -p assets/css
mkdir -p assets/js
mkdir -p pages

# 1. ARCHIVO DE CONFIGURACIÓN DE ROLES Y PERMISOS
cat > config/roles.php << 'EOF'
<?php
// Sistema de Roles y Permisos

class RoleManager {
    private $rolesFile = __DIR__ . '/roles_data.json';
    
    public function __construct() {
        if (!file_exists($this->rolesFile)) {
            $this->initializeRoles();
        }
    }
    
    private function initializeRoles() {
        $defaultRoles = [
            'admin' => [
                'name' => 'Administrador',
                'permissions' => ['all'],
                'tools' => ['all']
            ],
            'user' => [
                'name' => 'Usuario',
                'permissions' => ['view', 'use_tools'],
                'tools' => [] // Se asignan individualmente
            ],
            'guest' => [
                'name' => 'Invitado',
                'permissions' => ['view'],
                'tools' => []
            ]
        ];
        
        file_put_contents($this->rolesFile, json_encode($defaultRoles, JSON_PRETTY_PRINT));
    }
    
    public function getUserRole($userId) {
        // Obtener rol del usuario desde la base de datos
        $usersFile = __DIR__ . '/../users.json';
        if (file_exists($usersFile)) {
            $users = json_decode(file_get_contents($usersFile), true);
            foreach ($users as $user) {
                if ($user['username'] === $userId) {
                    return $user['role'] ?? 'user';
                }
            }
        }
        return 'user';
    }
    
    public function canUseTools($userId) {
        $roles = json_decode(file_get_contents($this->rolesFile), true);
        $userRole = $this->getUserRole($userId);
        
        if (!isset($roles[$userRole])) return [];
        
        $roleData = $roles[$userRole];
        
        // Si tiene permiso 'all', puede usar todas las herramientas
        if (in_array('all', $roleData['tools'])) {
            return $this->getAllTools();
        }
        
        return $roleData['tools'];
    }
    
    public function hasPermission($userId, $permission) {
        $roles = json_decode(file_get_contents($this->rolesFile), true);
        $userRole = $this->getUserRole($userId);
        
        if (!isset($roles[$userRole])) return false;
        
        $permissions = $roles[$userRole]['permissions'];
        
        return in_array('all', $permissions) || in_array($permission, $permissions);
    }
    
    private function getAllTools() {
        // Retorna todas las herramientas disponibles
        return [
            'mx_lookup',
            'dns_lookup',
            'whois',
            'ip_lookup',
            'ssl_checker',
            'port_scanner',
            'header_analyzer',
            'subdomain_finder'
        ];
    }
    
    public function assignToolsToUser($userId, $tools) {
        $usersFile = __DIR__ . '/../users.json';
        if (file_exists($usersFile)) {
            $users = json_decode(file_get_contents($usersFile), true);
            foreach ($users as &$user) {
                if ($user['username'] === $userId) {
                    $user['allowed_tools'] = $tools;
                    break;
                }
            }
            file_put_contents($usersFile, json_encode($users, JSON_PRETTY_PRINT));
        }
    }
}
EOF

# 2. SISTEMA DE TEMAS (CSS)
cat > assets/css/themes.css << 'EOF'
/* Sistema de Temas - Claro y Oscuro */

:root {
    --transition-speed: 0.3s;
}

/* TEMA CLARO (por defecto) */
[data-theme="light"] {
    --bg-primary: #f5f7fa;
    --bg-secondary: #ffffff;
    --bg-card: #ffffff;
    --bg-hover: #f8f9fa;
    
    --text-primary: #2c3e50;
    --text-secondary: #7f8c8d;
    --text-muted: #95a5a6;
    
    --border-color: #e1e8ed;
    --shadow-sm: 0 2px 4px rgba(0,0,0,0.05);
    --shadow-md: 0 4px 6px rgba(0,0,0,0.07);
    --shadow-lg: 0 10px 15px rgba(0,0,0,0.1);
    
    --primary-color: #667eea;
    --primary-hover: #5a67d8;
    --success-color: #48bb78;
    --warning-color: #ed8936;
    --danger-color: #f56565;
    --info-color: #4299e1;
}

/* TEMA OSCURO */
[data-theme="dark"] {
    --bg-primary: #1a202c;
    --bg-secondary: #2d3748;
    --bg-card: #2d3748;
    --bg-hover: #4a5568;
    
    --text-primary: #f7fafc;
    --text-secondary: #e2e8f0;
    --text-muted: #a0aec0;
    
    --border-color: #4a5568;
    --shadow-sm: 0 2px 4px rgba(0,0,0,0.2);
    --shadow-md: 0 4px 6px rgba(0,0,0,0.3);
    --shadow-lg: 0 10px 15px rgba(0,0,0,0.4);
    
    --primary-color: #7c3aed;
    --primary-hover: #6d28d9;
    --success-color: #34d399;
    --warning-color: #fbbf24;
    --danger-color: #f87171;
    --info-color: #60a5fa;
}

/* Aplicar variables */
body {
    background-color: var(--bg-primary);
    color: var(--text-primary);
    transition: background-color var(--transition-speed), color var(--transition-speed);
}

.card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    box-shadow: var(--shadow-md);
    transition: all var(--transition-speed);
}

.card:hover {
    box-shadow: var(--shadow-lg);
}

.btn-theme-toggle {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 8px 16px;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-theme-toggle:hover {
    background: var(--bg-hover);
}

/* Estilos del Dashboard */
.dashboard-header {
    background: linear-gradient(135deg, var(--primary-color), var(--primary-hover));
    padding: 2rem;
    border-radius: 12px;
    margin-bottom: 2rem;
    color: white;
}

.stat-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid var(--border-color);
    transition: all 0.3s;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: var(--shadow-lg);
}

.stat-icon {
    width: 60px;
    height: 60px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    margin-bottom: 1rem;
}

.stat-icon.primary { background: rgba(102, 126, 234, 0.1); color: var(--primary-color); }
.stat-icon.success { background: rgba(72, 187, 120, 0.1); color: var(--success-color); }
.stat-icon.warning { background: rgba(237, 137, 54, 0.1); color: var(--warning-color); }
.stat-icon.info { background: rgba(66, 153, 225, 0.1); color: var(--info-color); }

.activity-item {
    padding: 1rem;
    border-bottom: 1px solid var(--border-color);
    transition: background 0.2s;
}

.activity-item:hover {
    background: var(--bg-hover);
}

.tool-badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    margin: 4px;
}

.tool-badge.active {
    background: rgba(72, 187, 120, 0.2);
    color: var(--success-color);
}

.tool-badge.inactive {
    background: rgba(149, 165, 166, 0.2);
    color: var(--text-muted);
}

/* Gráficos */
.chart-container {
    background: var(--bg-card);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid var(--border-color);
    margin-bottom: 1.5rem;
}

/* Responsive */
@media (max-width: 768px) {
    .dashboard-header {
        padding: 1rem;
    }
    
    .stat-card {
        margin-bottom: 1rem;
    }
}
EOF

# 3. JAVASCRIPT PARA TEMAS Y FUNCIONALIDAD
cat > assets/js/theme-manager.js << 'EOF'
// Gestor de Temas

class ThemeManager {
    constructor() {
        this.currentTheme = this.loadTheme();
        this.applyTheme(this.currentTheme);
        this.initToggleButton();
    }
    
    loadTheme() {
        return localStorage.getItem('theme') || 'light';
    }
    
    saveTheme(theme) {
        localStorage.setItem('theme', theme);
    }
    
    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        this.saveTheme(theme);
        this.updateToggleButton();
    }
    
    toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }
    
    initToggleButton() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => this.toggleTheme());
        }
    }
    
    updateToggleButton() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (toggleBtn) {
            toggleBtn.innerHTML = this.currentTheme === 'light' 
                ? '🌙 Modo Oscuro' 
                : '☀️ Modo Claro';
        }
    }
}

// Inicializar al cargar la página
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
});
EOF

# 4. DASHBOARD DE ADMINISTRADOR MEJORADO
cat > pages/admin_dashboard.php << 'EOF'
<?php
session_start();
require_once __DIR__ . '/../config/roles.php';

// Verificar que es admin
if (!isset($_SESSION['user']) || $_SESSION['user'] !== 'admin') {
    header('Location: /login.php');
    exit;
}

$roleManager = new RoleManager();

// Obtener estadísticas
$usersFile = __DIR__ . '/../users.json';
$users = file_exists($usersFile) ? json_decode(file_get_contents($usersFile), true) : [];
$totalUsers = count($users);

// Contar herramientas activas
$toolsDir = __DIR__ . '/../tools';
$activeTools = 0;
if (is_dir($toolsDir)) {
    $activeTools = count(glob($toolsDir . '/*.php'));
}

// Actividad reciente (simulada)
$recentActivity = [
    ['user' => 'admin', 'tool' => 'MX Lookup', 'time' => '5 min ago'],
    ['user' => 'user1', 'tool' => 'DNS Lookup', 'time' => '15 min ago'],
    ['user' => 'admin', 'tool' => 'WHOIS', 'time' => '1 hora ago'],
];
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Admin - Multi-Herramientas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/themes.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        .sidebar {
            min-height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
        }
        
        .main-content {
            padding: 2rem;
        }
        
        .metric-card {
            background: var(--bg-card);
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
            transition: all 0.3s;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0.5rem 0;
        }
        
        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-2 sidebar p-0">
                <div class="p-4">
                    <h4 class="mb-4">
                        <i class="bi bi-tools"></i> Multi-Tools
                    </h4>
                    <nav class="nav flex-column">
                        <a class="nav-link active" href="/pages/admin_dashboard.php">
                            <i class="bi bi-speedometer2"></i> Dashboard
                        </a>
                        <a class="nav-link" href="/admin.php">
                            <i class="bi bi-people"></i> Usuarios
                        </a>
                        <a class="nav-link" href="/index.php">
                            <i class="bi bi-wrench"></i> Herramientas
                        </a>
                        <a class="nav-link" href="/pages/settings.php">
                            <i class="bi bi-gear"></i> Configuración
                        </a>
                        <hr>
                        <a class="nav-link" href="/logout.php">
                            <i class="bi bi-box-arrow-right"></i> Salir
                        </a>
                    </nav>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="col-md-10 main-content">
                <!-- Header -->
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h2>Dashboard de Administración</h2>
                        <p class="text-muted">Bienvenido, <?php echo htmlspecialchars($_SESSION['user']); ?></p>
                    </div>
                    <div>
                        <button id="theme-toggle" class="btn btn-theme-toggle">
                            🌙 Modo Oscuro
                        </button>
                    </div>
                </div>
                
                <!-- Métricas -->
                <div class="row">
                    <div class="col-md-3">
                        <div class="metric-card">
                            <div class="stat-icon primary">
                                <i class="bi bi-people-fill"></i>
                            </div>
                            <div class="metric-value" style="color: var(--primary-color);">
                                <?php echo $totalUsers; ?>
                            </div>
                            <div class="metric-label">Usuarios Totales</div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="metric-card">
                            <div class="stat-icon success">
                                <i class="bi bi-wrench-adjustable"></i>
                            </div>
                            <div class="metric-value" style="color: var(--success-color);">
                                <?php echo $activeTools; ?>
                            </div>
                            <div class="metric-label">Herramientas Activas</div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="metric-card">
                            <div class="stat-icon warning">
                                <i class="bi bi-activity"></i>
                            </div>
                            <div class="metric-value" style="color: var(--warning-color);">
                                <?php echo count($recentActivity); ?>
                            </div>
                            <div class="metric-label">Usos Recientes</div>
                        </div>
                    </div>
                    
                    <div class="col-md-3">
                        <div class="metric-card">
                            <div class="stat-icon info">
                                <i class="bi bi-graph-up"></i>
                            </div>
                            <div class="metric-value" style="color: var(--info-color);">
                                98%
                            </div>
                            <div class="metric-label">Disponibilidad</div>
                        </div>
                    </div>
                </div>
                
                <!-- Gráficos y Actividad -->
                <div class="row mt-4">
                    <div class="col-md-8">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="bi bi-bar-chart-fill"></i> Uso de Herramientas
                            </h5>
                            <canvas id="toolsChart" height="100"></canvas>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="bi bi-clock-history"></i> Actividad Reciente
                            </h5>
                            <div>
                                <?php foreach ($recentActivity as $activity): ?>
                                <div class="activity-item">
                                    <strong><?php echo htmlspecialchars($activity['user']); ?></strong>
                                    <br>
                                    <small class="text-muted">
                                        <?php echo htmlspecialchars($activity['tool']); ?> • 
                                        <?php echo htmlspecialchars($activity['time']); ?>
                                    </small>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Lista de Usuarios -->
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="chart-container">
                            <h5 class="mb-3">
                                <i class="bi bi-person-lines-fill"></i> Gestión de Usuarios
                            </h5>
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Usuario</th>
                                        <th>Email</th>
                                        <th>Rol</th>
                                        <th>Registro</th>
                                        <th>Acciones</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $user): ?>
                                    <tr>
                                        <td>
                                            <i class="bi bi-person-circle"></i>
                                            <?php echo htmlspecialchars($user['username']); ?>
                                            <?php if ($user['username'] === 'admin'): ?>
                                                <span class="badge bg-danger ms-2">TU</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><?php echo htmlspecialchars($user['email'] ?? 'N/A'); ?></td>
                                        <td>
                                            <span class="badge bg-<?php echo $user['username'] === 'admin' ? 'danger' : 'primary'; ?>">
                                                <?php echo ucfirst($roleManager->getUserRole($user['username'])); ?>
                                            </span>
                                        </td>
                                        <td><?php echo htmlspecialchars($user['created_at'] ?? 'N/A'); ?></td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary">
                                                <i class="bi bi-pencil"></i>
                                            </button>
                                            <?php if ($user['username'] !== 'admin'): ?>
                                            <button class="btn btn-sm btn-outline-danger">
                                                <i class="bi bi-trash"></i>
                                            </button>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="/assets/js/theme-manager.js"></script>
    <script>
        // Gráfico de uso de herramientas
        const ctx = document.getElementById('toolsChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['MX Lookup', 'DNS Lookup', 'WHOIS', 'IP Info', 'SSL Check'],
                datasets: [{
                    label: 'Usos',
                    data: [45, 32, 28, 19, 15],
                    backgroundColor: [
                        'rgba(102, 126, 234, 0.8)',
                        'rgba(72, 187, 120, 0.8)',
                        'rgba(237, 137, 54, 0.8)',
                        'rgba(66, 153, 225, 0.8)',
                        'rgba(159, 122, 234, 0.8)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>
</html>
EOF

# 5. DASHBOARD DE USUARIO
cat > pages/user_dashboard.php << 'EOF'
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
EOF

# 6. PÁGINA DE CONFIGURACIÓN
cat > pages/settings.php << 'EOF'
<?php
session_start();

if (!isset($_SESSION['user'])) {
    header('Location: /login.php');
    exit;
}

$isAdmin = $_SESSION['user'] === 'admin';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuración - Multi-Herramientas</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/themes.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
</head>
<body>
    <div class="container py-5">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>
                <i class="bi bi-gear"></i> Configuración
            </h2>
            <a href="<?php echo $isAdmin ? '/pages/admin_dashboard.php' : '/pages/user_dashboard.php'; ?>" 
               class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left"></i> Volver
            </a>
        </div>
        
        <div class="row">
            <div class="col-md-8">
                <!-- Apariencia -->
                <div class="chart-container mb-4">
                    <h5 class="mb-3">
                        <i class="bi bi-palette"></i> Apariencia
                    </h5>
                    <div class="mb-3">
                        <label class="form-label">Tema</label>
                        <div class="btn-group w-100" role="group">
                            <button id="theme-toggle" class="btn btn-outline-primary">
                                Cambiar Tema
                            </button>
                        </div>
                    </div>
                </div>
                
                <!-- Perfil -->
                <div class="chart-container mb-4">
                    <h5 class="mb-3">
                        <i class="bi bi-person"></i> Perfil
                    </h5>
                    <form>
                        <div class="mb-3">
                            <label class="form-label">Nombre de usuario</label>
                            <input type="text" class="form-control" value="<?php echo htmlspecialchars($_SESSION['user']); ?>" disabled>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Correo electrónico</label>
                            <input type="email" class="form-control" placeholder="tu@email.com">
                        </div>
                        <button type="submit" class="btn btn-primary">Guardar Cambios</button>
                    </form>
                </div>
                
                <?php if ($isAdmin): ?>
                <!-- Opciones de Admin -->
                <div class="chart-container">
                    <h5 class="mb-3">
                        <i class="bi bi-shield-check"></i> Opciones de Administrador
                    </h5>
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="allowRegistration">
                        <label class="form-check-label" for="allowRegistration">
                            Permitir nuevos registros
                        </label>
                    </div>
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="requireApproval">
                        <label class="form-check-label" for="requireApproval">
                            Requerir aprobación de usuarios
                        </label>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="/assets/js/theme-manager.js"></script>
</body>
</html>
EOF

# 7. ACTUALIZAR INDEX.PHP PARA REDIRECCIÓN
cat > index_redirect.php << 'EOF'
<?php
session_start();
require_once __DIR__ . '/config/roles.php';

if (!isset($_SESSION['user'])) {
    header('Location: /login.php');
    exit;
}

$roleManager = new RoleManager();
$username = $_SESSION['user'];

// Redirigir según el rol
if ($username === 'admin') {
    header('Location: /pages/admin_dashboard.php');
} else {
    header('Location: /pages/user_dashboard.php');
}
exit;
EOF

echo ""
echo "✅ INSTALACIÓN COMPLETADA"
echo ""
echo "📁 Archivos creados:"
echo "   - config/roles.php (Sistema de roles)"
echo "   - assets/css/themes.css (Temas claro/oscuro)"
echo "   - assets/js/theme-manager.js (Gestor de temas)"
echo "   - pages/admin_dashboard.php (Dashboard Admin mejorado)"
echo "   - pages/user_dashboard.php (Dashboard Usuario)"
echo "   - pages/settings.php (Configuración)"
echo ""
echo "🎨 Características añadidas:"
echo "   ✓ Sistema de roles y permisos"
echo "   ✓ Tema claro y oscuro"
echo "   ✓ Dashboard de admin con estadísticas"
echo "   ✓ Dashboard de usuario personalizado"
echo "   ✓ Gráficos y métricas"
echo "   ✓ Gestión de herramientas por usuario"
echo ""
echo "🔗 Accesos:"
echo "   Admin: http://127.0.0.1:5000/pages/admin_dashboard.php"
echo "   Usuario: http://127.0.0.1:5000/pages/user_dashboard.php"
echo "   Settings: http://127.0.0.1:5000/pages/settings.php"
echo ""
echo "⚙️  Instrucciones:"
echo "   1. Ejecuta: chmod +x setup_dashboard.sh"
echo "   2. Ejecuta: ./setup_dashboard.sh"
echo "   3. Recarga tu servidor web"
echo "   4. Accede a los nuevos dashboards"
echo ""
echo "=================================="
EOF

chmod +x setup_dashboard.sh
echo "Script creado: setup_dashboard.sh"
echo "Ejecuta: ./setup_dashboard.sh"
