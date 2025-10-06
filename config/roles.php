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
