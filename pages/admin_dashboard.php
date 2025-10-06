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
