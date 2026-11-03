<?php
// Copy to config/config.php and edit. Values may also come from environment variables
// (set in Apache/Windows) so secrets never need to live in source control.
return [
    'env' => getenv('SAIP_ENV') ?: 'development',          // development | production

    'db' => [
        'host'     => getenv('SAIP_DB_HOST') ?: '127.0.0.1',
        'port'     => (int)(getenv('SAIP_DB_PORT') ?: 3306),
        'name'     => getenv('SAIP_DB_NAME') ?: 'saip',
        'user'     => getenv('SAIP_DB_USER') ?: 'root',    // dev only: create a least-privilege user for production
        'password' => getenv('SAIP_DB_PASS') ?: '',
        'ssl_ca'   => getenv('SAIP_DB_SSL_CA') ?: null,       // path to the CA bundle when the database is on another host (TLS, verified)
    ],

    // Shared secret a workstation must present to REGISTER (not to send data).
    'enrollment_key' => getenv('SAIP_ENROLLMENT_KEY') ?: 'CHANGE-ME-enrollment-key',
    // Temporary admin key for GET /collector/status until Phase 4 (session login + roles).
    'admin_api_key'  => getenv('SAIP_ADMIN_KEY') ?: 'CHANGE-ME-admin-key',

    // Development convenience: newly registered collectors become 'authorized' immediately.
    // MUST be false in production (an administrator authorizes each collector).
    'auto_authorize' => false,

    'limits' => [
        'max_body_bytes'      => 1048576,   // 1 MB
        'max_events_per_call' => 500,
        'rate_register_ip'    => 10,        // per minute per IP
        'rate_collector'      => 120,       // per minute per collector
        'rate_auth_fail_ip'   => 30,        // failed auth attempts per minute per IP
    ],

    // Outbound SIEM / webhook / Google calls. Keep allow_private false in production (blocks loopback and private destinations).
    'integrations' => ['allow_private' => false, 'allow_http' => false],

    'collector_offline_after_minutes' => 15,

    // Event viewer (events.php) is restricted to these client IPs until Phase 4 login exists.
    'viewer_allowed_ips' => ['127.0.0.1', '::1'],

    // Only trust X-Forwarded-For from these proxy IPs (empty = never trust it).
    'trusted_proxies' => [],
];
