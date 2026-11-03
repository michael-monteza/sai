<?php
// Role-based access control. A role lists the permissions it holds ("area.action"); "*" is everything and "area.*" every action in an area.
// Add a permission to a role here and guard the route with RequirePermission('area.action'). Users-management scope rules
// (an it_admin only manages their own company and never a higher role) are enforced in the Users module.
return [
    'roles' => [
        'super_admin' => ['label' => 'Platform administrator', 'rank' => 4, 'permissions' => ['*']],
        'it_admin'    => ['label' => 'IT administrator', 'rank' => 3, 'permissions' => [
            'dashboard.read', 'inventory.*', 'registry.*', 'discovery.*', 'workstations.*', 'collectors.*', 'monitoring.write', 'retention.write',
            'governance.*', 'iso.*', 'adoption.*', 'reports.read', 'audit.read', 'users.*', 'integrations.*']],
        'auditor'     => ['label' => 'Auditor (read-only + audit)', 'rank' => 2, 'permissions' => [
            'dashboard.read', 'inventory.read', 'registry.read', 'discovery.read', 'workstations.read', 'collectors.read', 'governance.read',
            'iso.read', 'adoption.read', 'reports.read', 'audit.read']],
        'viewer'      => ['label' => 'Management viewer', 'rank' => 1, 'permissions' => [
            'dashboard.read', 'inventory.read', 'registry.read', 'discovery.read', 'workstations.read', 'collectors.read', 'governance.read',
            'iso.read', 'adoption.read', 'reports.read']],
    ],
    'password_min_length' => 12,
    'max_failed_logins' => 5,
    'lockout_minutes' => 15,
    'idle_timeout_minutes' => 60,
    'absolute_timeout_hours' => 12,
];
