<?php
declare(strict_types=1);

namespace Saip\Security;

use Saip\Config;

/**
 * Encrypts stored secrets (OAuth client secret, webhook signing secrets, SIEM tokens) with libsodium secretbox.
 * The key comes from env SAIP_APP_KEY (base64, 32 bytes) or config/app.key, which is created on first use (chmod 600 where supported).
 * Keep config/app.key out of backups that travel with the database, or the encryption adds no protection.
 */
final class Secrets
{
    private static ?string $key = null;

    private static function key(): string
    {
        if (self::$key !== null) return self::$key;
        $env = getenv('SAIP_APP_KEY') ?: Config::get('app_key');
        if (is_string($env) && $env !== '') {
            $k = base64_decode($env, true);
            if ($k !== false && strlen($k) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES) return self::$key = $k;
        }
        $file = SAIP_ROOT . '/config/app.key';
        if (!is_file($file)) {
            file_put_contents($file, base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));
            @chmod($file, 0600);
        }
        $k = base64_decode(trim((string)file_get_contents($file)), true);
        if ($k === false || strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) throw new \RuntimeException('config/app.key is invalid.');
        return self::$key = $k;
    }

    public static function encrypt(string $plain): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return 'v1:' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, self::key()));
    }

    public static function decrypt(?string $blob): ?string
    {
        if ($blob === null || !str_starts_with($blob, 'v1:')) return null;
        $raw = base64_decode(substr($blob, 3), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) return null;
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), self::key());
        return $plain === false ? null : $plain;
    }
}
