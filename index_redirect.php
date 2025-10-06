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
