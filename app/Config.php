<?php
declare(strict_types=1);

namespace Saip;

final class Config
{
    private static ?array $data = null;

    public static function get(string $path, mixed $default = null): mixed
    {
        if (self::$data === null) {
            $file = SAIP_ROOT . '/config/config.php';
            if (!is_file($file)) {
                $file = SAIP_ROOT . '/config/config.example.php';
            }
            self::$data = require $file;
        }
        $node = self::$data;
        foreach (explode('.', $path) as $part) {
            if (!is_array($node) || !array_key_exists($part, $node)) {
                return $default;
            }
            $node = $node[$part];
        }
        return $node;
    }
}
