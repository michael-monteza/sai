<?php
declare(strict_types=1);

namespace Saip\Modules;

use Psr\Http\Message\{ResponseInterface as Response, ServerRequestInterface as Request};
use Saip\{ApiException, Audit, Db, Tenants};
use Saip\Http\Controller;
use Saip\Middleware\RequirePermission as Need;
use Saip\Security\{Auth, Rbac};
use Slim\Routing\RouteCollectorProxy as Group;

/** Session/account, RBAC roles, user management, companies (tenants) and the audit log viewer. */
final class AdminModule extends Controller
{
    public static function register(Group $g): void
    {
        // any signed-in user
        $g->get('/me', [self::class, 'me']);
        $g->post('/me/password', [self::class, 'changePassword']);
        $g->post('/tenant/switch', [self::class, 'switchTenant'])->add(new Need('tenants.read'));
        $g->get('/roles', [self::class, 'roles'])->add(new Need('users.read'));

        $g->get('/users', [self::class, 'users'])->add(new Need('users.read'));
        $g->post('/users', [self::class, 'userCreate'])->add(new Need('users.write'));
        $g->post('/users/delete', [self::class, 'userDelete'])->add(new Need('users.delete'));
        $g->post('/users/{id:\d+}', [self::class, 'userUpdate'])->add(new Need('users.write'));

        $g->get('/tenants', [self::class, 'tenants'])->add(new Need('tenants.read'));
        $g->post('/tenants', [self::class, 'tenantCreate'])->add(new Need('tenants.write'));
        $g->post('/tenants/delete', [self::class, 'tenantDelete'])->add(new Need('tenants.delete'));
        $g->post('/tenants/{id:\d+}', [self::class, 'tenantUpdate'])->add(new Need('tenants.write'));

        $g->get('/audit', [self::class, 'audit'])->add(new Need('audit.read'));
        $g->get('/export/audit', [self::class, 'auditExport'])->add(new Need('audit.read'));
    }

    // ---------------- account ----------------
    public function me(Request $req, Response $res): Response
    {
        $u = $this->user($req);
        $tenant = null;
        try { $tenant = Db::one('SELECT id, name, slug FROM tenants WHERE id = ?', [Auth::tenantId($u)]); } catch (ApiException) {}
        return $this->json($res, [
            'user' => ['id' => (int)$u['id'], 'username' => $u['username'], 'display_name' => $u['display_name'], 'email' => $u['email'], 'role' => $u['role'], 'role_label' => Rbac::roles()[$u['role']]['label']],
            'permissions' => Rbac::granted($u['role']),
            'tenant' => $tenant,
            'tenants' => $u['role'] === 'super_admin' ? Db::all("SELECT id, name, slug FROM tenants WHERE status = 'active' ORDER BY name") : [],
            'csrf' => Auth::csrf(),
        ]);
    }

    public function changePassword(Request $req, Response $res): Response
    {
        $u = $this->user($req); $b = $this->body($req);
        $row = Db::one('SELECT password_hash FROM admin_users WHERE id = ?', [$u['id']]);
        if (!password_verify((string)($b['current_password'] ?? ''), $row['password_hash'])) {
            Audit::log($u['username'], 'password_change_failed', null, null, $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
            throw new ApiException(403, 'wrong_password', 'Current password is incorrect.', ['current_password' => 'incorrect']);
        }
        $new = (string)($b['new_password'] ?? '');
        Auth::checkPassword($new, $u['username']);
        if (password_verify($new, $row['password_hash'])) throw new ApiException(422, 'validation_failed', 'Choose a password you have not used just now.', ['new_password' => 'same']);
        Db::run('UPDATE admin_users SET password_hash = ?, password_changed_at = UTC_TIMESTAMP() WHERE id = ?', [Auth::hashPassword($new), $u['id']]);
        $_SESSION['born'] = time() + 1;   // this session stays valid; every other session of the user is invalidated
        Audit::log($u['username'], 'password_changed', $u['username'], null, $u['tenant_id'] !== null ? (int)$u['tenant_id'] : null);
        return $this->json($res, ['status' => 'ok']);
    }

    public function switchTenant(Request $req, Response $res): Response
    {
        $b = $this->body($req);
        Auth::switchTenant((int)($b['tenant_id'] ?? 0));
        Audit::log($this->actor($req), 'tenant_switched', (string)(int)$b['tenant_id'], null, (int)$b['tenant_id']);
        return $this->json($res, ['status' => 'ok']);
    }

    public function roles(Request $req, Response $res): Response
    {
        $me = Rbac::rank($this->user($req)['role']);
        $out = [];
        foreach (Rbac::roles() as $k => $r) $out[] = ['role' => $k, 'label' => $r['label'], 'rank' => $r['rank'], 'assignable' => $r['rank'] <= $me && ($k !== 'super_admin' || $this->user($req)['role'] === 'super_admin'), 'permissions' => $k === 'super_admin' ? ['*'] : Rbac::granted($k)];
        return $this->json($res, ['roles' => $out]);
    }

    // ---------------- users ----------------
    /** A user may be managed when the actor is a platform admin, or an admin of the same company who is not below the target's rank. */
    private function manageable(array $actor, array $target): bool
    {
        if ($actor['role'] === 'super_admin') return true;
        return $target['tenant_id'] !== null && (int)$target['tenant_id'] === (int)$actor['tenant_id'] && Rbac::rank($target['role']) <= Rbac::rank($actor['role']) && $target['role'] !== 'super_admin';
    }

    private function assertAssignable(array $actor, string $role): void
    {
        if (!Rbac::valid($role)) throw new ApiException(422, 'validation_failed', 'Invalid role.', ['role' => 'invalid']);
        if (Rbac::rank($role) > Rbac::rank($actor['role']) || ($role === 'super_admin' && $actor['role'] !== 'super_admin')) throw new ApiException(403, 'forbidden', 'You cannot assign a role above your own.');
    }

    private function lastSuperAdmin(int $exceptId): bool
    {
        return (int)Db::val("SELECT COUNT(*) FROM admin_users WHERE role = 'super_admin' AND active = 1 AND id <> ?", [$exceptId]) === 0;
    }

    public function users(Request $req, Response $res): Response
    {
        $me = $this->user($req);
        $sql = "SELECT a.id, a.username, a.display_name, a.email, a.role, a.active, a.last_login, a.last_login_ip, a.tenant_id, t.name tenant,
                       (a.locked_until IS NOT NULL AND a.locked_until > UTC_TIMESTAMP()) locked, a.failed_logins, a.created_at, (a.google_sub IS NOT NULL) google_linked, a.local_login
                FROM admin_users a LEFT JOIN tenants t ON t.id = a.tenant_id";
        $rows = $me['role'] === 'super_admin' ? Db::all("$sql ORDER BY a.username") : Db::all("$sql WHERE a.tenant_id = ? ORDER BY a.username", [$me['tenant_id']]);
        return $this->json($res, ['users' => $rows]);
    }

    public function userCreate(Request $req, Response $res): Response
    {
        $me = $this->user($req); $b = $this->body($req);
        $username = $this->str($b, 'username', 60, true);
        if (!preg_match('/^[A-Za-z0-9._@-]{3,60}$/', $username)) throw new ApiException(422, 'validation_failed', 'Username may use letters, digits . _ @ - (3-60).', ['username' => 'invalid']);
        $role = (string)($b['role'] ?? 'viewer');
        $this->assertAssignable($me, $role);
        $email = $this->str($b, 'email', 190);
        if ($email !== null && !filter_var($email, FILTER_VALIDATE_EMAIL)) throw new ApiException(422, 'validation_failed', 'Invalid email address.', ['email' => 'invalid']);
        $pw = (string)($b['password'] ?? '');
        Auth::checkPassword($pw, $username);
        $tenant = $role === 'super_admin' ? null : ($me['role'] === 'super_admin' ? (int)($b['tenant_id'] ?? 0) : (int)$me['tenant_id']);
        if ($role !== 'super_admin' && !Db::val('SELECT 1 FROM tenants WHERE id = ?', [$tenant])) throw new ApiException(422, 'validation_failed', 'Choose the company this user belongs to.', ['tenant_id' => 'required']);
        if (Db::val('SELECT 1 FROM admin_users WHERE username = ?', [$username])) throw new ApiException(409, 'duplicate', 'Username already exists.');
        Db::run('INSERT INTO admin_users (tenant_id, username, display_name, email, password_hash, role, password_changed_at) VALUES (?,?,?,?,?,?,UTC_TIMESTAMP())',
            [$tenant, $username, $this->str($b, 'display_name', 100) ?? $username, $email, Auth::hashPassword($pw), $role]);
        $id = Db::insertId();
        Audit::log($me['username'], 'user_created', $username, null, $tenant, null, ['username' => $username, 'role' => $role, 'tenant_id' => $tenant, 'email' => $email]);
        return $this->json($res, ['id' => $id], 201);
    }

    public function userUpdate(Request $req, Response $res, array $a): Response
    {
        $me = $this->user($req); $b = $this->body($req); $id = (int)$a['id'];
        $target = Db::one('SELECT * FROM admin_users WHERE id = ?', [$id]);
        if (!$target || !$this->manageable($me, $target)) throw new ApiException(404, 'not_found', 'Unknown user.');
        $self = $id === (int)$me['id'];
        $set = [];
        if (array_key_exists('display_name', $b)) $set['display_name'] = $this->str($b, 'display_name', 100) ?? $target['username'];
        if (array_key_exists('email', $b)) {
            $e = $this->str($b, 'email', 190);
            if ($e !== null && !filter_var($e, FILTER_VALIDATE_EMAIL)) throw new ApiException(422, 'validation_failed', 'Invalid email address.', ['email' => 'invalid']);
            $set['email'] = $e;
        }
        if (isset($b['role']) && $b['role'] !== $target['role']) {
            if ($self) throw new ApiException(409, 'self_change', 'You cannot change your own role.');
            $this->assertAssignable($me, (string)$b['role']);
            if ($target['role'] === 'super_admin' && $this->lastSuperAdmin($id)) throw new ApiException(409, 'last_super_admin', 'At least one active platform administrator must remain.');
            $set['role'] = $b['role'];
            if ($b['role'] === 'super_admin') $set['tenant_id'] = null;
        }
        if (array_key_exists('tenant_id', $b) && $me['role'] === 'super_admin' && ($set['role'] ?? $target['role']) !== 'super_admin') {
            if (!Db::val('SELECT 1 FROM tenants WHERE id = ?', [(int)$b['tenant_id']])) throw new ApiException(422, 'validation_failed', 'Unknown company.', ['tenant_id' => 'invalid']);
            $set['tenant_id'] = (int)$b['tenant_id'];
        }
        if (array_key_exists('active', $b) && (bool)$b['active'] !== (bool)$target['active']) {
            if ($self) throw new ApiException(409, 'self_lockout', 'You cannot deactivate your own account.');
            if (!$b['active'] && $target['role'] === 'super_admin' && $this->lastSuperAdmin($id)) throw new ApiException(409, 'last_super_admin', 'At least one active platform administrator must remain.');
            $set['active'] = $b['active'] ? 1 : 0;
        }
        if (array_key_exists('local_login', $b) && (bool)$b['local_login'] !== (bool)$target['local_login']) {
            if (!$b['local_login'] && $self) throw new ApiException(409, 'self_change', 'You cannot disable your own password sign-in.');
            if (!$b['local_login'] && !$target['google_sub'] && !\Saip\Security\GoogleAuth::enabled()) throw new ApiException(409, 'google_not_ready', 'Google sign-in must be enabled (and the user must be able to use it) before password sign-in can be turned off.');
            $set['local_login'] = $b['local_login'] ? 1 : 0;
        }
        if (!empty($b['unlink_google']) && $target['google_sub']) { $set['google_sub'] = null; $set['local_login'] = 1; }
        if (!empty($b['unlock'])) { $set['failed_logins'] = 0; $set['locked_until'] = null; }
        $pwChanged = false;
        if (!empty($b['password'])) {
            Auth::checkPassword((string)$b['password'], $target['username']);
            $set['password_hash'] = Auth::hashPassword((string)$b['password']); $set['password_changed_at'] = gmdate('Y-m-d H:i:s'); $set['failed_logins'] = 0; $set['locked_until'] = null;
            $pwChanged = true;
        }
        if (!$set) throw new ApiException(422, 'validation_failed', 'Nothing to update.');
        Db::run('UPDATE admin_users SET ' . implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($set))) . ' WHERE id = ?', array_merge(array_values($set), [$id]));
        $shown = array_diff_key($set, ['password_hash' => 1, 'password_changed_at' => 1]);
        Audit::log($me['username'], 'user_updated', $target['username'], ['password_reset' => $pwChanged], $target['tenant_id'] !== null ? (int)$target['tenant_id'] : null, array_intersect_key($target, $shown), $shown);
        return $this->json($res, ['status' => 'ok']);
    }

    public function userDelete(Request $req, Response $res): Response
    {
        $me = $this->user($req); $b = $this->body($req); $ids = $this->ids($b, 100);
        $rows = array_values(array_filter(Db::all('SELECT * FROM admin_users WHERE id IN (' . $this->in($ids) . ')', $ids), fn ($r) => $this->manageable($me, $r)));
        if (!$rows) throw new ApiException(404, 'not_found', 'No matching users.');
        foreach ($rows as $r) {
            if ((int)$r['id'] === (int)$me['id']) throw new ApiException(409, 'self_delete', 'You cannot delete your own account.');
            if ($r['role'] === 'super_admin' && $r['active'] && $this->lastSuperAdmin((int)$r['id'])) throw new ApiException(409, 'last_super_admin', 'At least one active platform administrator must remain.');
        }
        $impact = ['records' => count($rows), 'names' => array_column($rows, 'username')];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        $rid = array_map(static fn ($r) => (int)$r['id'], $rows);
        Db::run('DELETE FROM admin_users WHERE id IN (' . $this->in($rid) . ')', $rid);
        foreach ($rows as $r) Audit::log($me['username'], 'user_deleted', $r['username'], ['role' => $r['role']], $r['tenant_id'] !== null ? (int)$r['tenant_id'] : null, ['username' => $r['username'], 'role' => $r['role']], null);
        return $this->json($res, ['deleted' => $impact]);
    }

    // ---------------- companies ----------------
    public function tenants(Request $req, Response $res): Response
    {
        return $this->json($res, ['tenants' => Db::all(
            "SELECT t.id, t.name, t.slug, t.status, t.created_at,
                    (SELECT COUNT(*) FROM collectors c WHERE c.tenant_id = t.id) collectors,
                    (SELECT COUNT(*) FROM ai_usage_events e WHERE e.tenant_id = t.id) events,
                    (SELECT COUNT(*) FROM admin_users a WHERE a.tenant_id = t.id) users
             FROM tenants t ORDER BY t.name")]);
    }

    public function tenantCreate(Request $req, Response $res): Response
    {
        $b = $this->body($req);
        $name = $this->str($b, 'name', 150, true);
        $r = Tenants::create($name, $this->str($b, 'slug', 60));
        Audit::log($this->actor($req), 'tenant_created', $name, ['id' => $r['id']], $r['id'], null, ['name' => $name, 'slug' => $r['slug']]);
        return $this->json($res, ['id' => $r['id'], 'slug' => $r['slug'], 'enrollment_key' => $r['enrollment_key'], 'note' => "Shown once. Give it to the company's collector installer."], 201);
    }

    public function tenantUpdate(Request $req, Response $res, array $a): Response
    {
        $b = $this->body($req); $id = (int)$a['id'];
        $cur = Db::one('SELECT * FROM tenants WHERE id = ?', [$id]);
        if (!$cur) throw new ApiException(404, 'not_found', 'Unknown company.');
        $set = [];
        if (array_key_exists('name', $b)) $set['name'] = $this->str($b, 'name', 150, true);
        if (isset($b['status'])) {
            if (!in_array($b['status'], ['active', 'suspended'], true)) throw new ApiException(422, 'validation_failed', 'Invalid status.', ['status' => 'invalid']);
            $set['status'] = $b['status'];
        }
        if (!$set) throw new ApiException(422, 'validation_failed', 'Nothing to update.');
        Db::run('UPDATE tenants SET ' . implode(', ', array_map(static fn ($k) => "`$k` = ?", array_keys($set))) . ' WHERE id = ?', array_merge(array_values($set), [$id]));
        Audit::log($this->actor($req), 'tenant_updated', $cur['name'], null, $id, array_intersect_key($cur, $set), $set);
        return $this->json($res, ['status' => 'ok']);
    }

    /** POST tenants/delete {ids:[id], confirm: "<slug>", preview?}: removes a company and everything it owns (audit history is kept). */
    public function tenantDelete(Request $req, Response $res): Response
    {
        $b = $this->body($req); $ids = $this->ids($b, 1);
        $t = Db::one('SELECT * FROM tenants WHERE id = ?', [$ids[0]]);
        if (!$t) throw new ApiException(404, 'not_found', 'Unknown company.');
        $impact = ['records' => 1, 'names' => [$t['name']], 'collectors' => (int)Db::val('SELECT COUNT(*) FROM collectors WHERE tenant_id = ?', [$t['id']]),
            'events' => (int)Db::val('SELECT COUNT(*) FROM ai_usage_events WHERE tenant_id = ?', [$t['id']]), 'services' => (int)Db::val('SELECT COUNT(*) FROM ai_services WHERE tenant_id = ?', [$t['id']]),
            'users' => (int)Db::val('SELECT COUNT(*) FROM admin_users WHERE tenant_id = ?', [$t['id']]), 'slug' => $t['slug']];
        if (!empty($b['preview'])) return $this->json($res, ['preview' => $impact]);
        if (!hash_equals($t['slug'], (string)($b['confirm'] ?? ''))) throw new ApiException(422, 'confirmation_required', 'Type the company short name to confirm.', ['confirm' => 'mismatch']);
        if ((int)Db::val('SELECT COUNT(*) FROM tenants') <= 1) throw new ApiException(409, 'last_tenant', 'The last company cannot be deleted.');
        $pdo = Db::pdo(); $pdo->beginTransaction();
        try {
            $id = (int)$t['id'];
            Db::run('DELETE FROM ai_usage_events WHERE tenant_id = ?', [$id]);
            Db::run('DELETE FROM collectors WHERE tenant_id = ?', [$id]);          // heartbeats + connection events cascade
            Db::run('DELETE FROM ai_services WHERE tenant_id = ?', [$id]);         // domains cascade
            Db::run('DELETE FROM discovered_domain_hosts WHERE discovered_id IN (SELECT id FROM discovered_domains WHERE tenant_id = ?)', [$id]);
            foreach (['discovered_domains', 'access_requests', 'policies', 'iso_controls', 'employee_inventory', 'settings', 'admin_users'] as $tb) Db::run("DELETE FROM $tb WHERE tenant_id = ?", [$id]);
            Db::run('DELETE FROM tenants WHERE id = ?', [$id]);
            $pdo->commit();
        } catch (\Throwable $e) { $pdo->rollBack(); throw $e; }
        if ((int)($_SESSION['tenant_id'] ?? 0) === (int)$t['id']) $_SESSION['tenant_id'] = (int)Db::val("SELECT id FROM tenants WHERE status = 'active' ORDER BY id LIMIT 1");
        Audit::log($this->actor($req), 'tenant_deleted', $t['name'], $impact, null, $impact, null);   // history of the deleted company is retained in the audit log
        return $this->json($res, ['deleted' => $impact]);
    }

    // ---------------- audit ----------------
    private function auditQuery(Request $req): array
    {
        $u = $this->user($req);
        $all = $u['role'] === 'super_admin' && $this->q($req, 'scope') === 'all';
        $where = []; $args = [];
        if (!$all) { $where[] = 'tenant_id = ?'; $args[] = $this->tid($req); }
        foreach (['action' => 'action', 'actor' => 'administrator'] as $q => $col) {
            $v = $this->q($req, $q);
            if (is_string($v) && $v !== '') { $where[] = "$col = ?"; $args[] = $v; }
        }
        if (($s = $this->q($req, 'q')) && is_string($s)) { $where[] = '(affected_record LIKE ? OR details LIKE ?)'; $args[] = $args[] = '%' . addcslashes($s, '%_\\') . '%'; }
        foreach (['from' => '>=', 'to' => '<='] as $q => $op) {
            $v = $this->q($req, $q);
            if (is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) { $where[] = "timestamp $op ?"; $args[] = $v . ($q === 'to' ? ' 23:59:59' : ' 00:00:00'); }
        }
        $limit = max(1, min(5000, (int)$this->q($req, 'limit', 500)));
        return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $args, $limit];
    }

    public function audit(Request $req, Response $res): Response
    {
        [$w, $args, $limit] = $this->auditQuery($req);
        return $this->json($res, ['logs' => Db::all("SELECT id, tenant_id, administrator, action, affected_record, timestamp, details, before_json, after_json, ip_address, request_id FROM audit_logs $w ORDER BY id DESC LIMIT $limit", $args)]);
    }

    public function auditExport(Request $req, Response $res): Response
    {
        [$w, $args, $limit] = $this->auditQuery($req);
        $rows = Db::all("SELECT id, timestamp, administrator, action, affected_record, ip_address, request_id, details FROM audit_logs $w ORDER BY id DESC LIMIT $limit", $args);
        Audit::log($this->actor($req), 'export_audit', null, ['rows' => count($rows)], $this->tid($req));
        return $this->raw($res, $this->csv(['ID', 'Time (UTC)', 'Actor', 'Action', 'Record', 'IP', 'Request', 'Details'], array_map('array_values', $rows)), 'text/csv; charset=utf-8', 'audit-log.csv');
    }
}
