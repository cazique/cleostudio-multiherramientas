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
