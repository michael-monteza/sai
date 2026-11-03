<?php
declare(strict_types=1);

namespace Saip;

final class Validator
{
    public static function computerName(mixed $v): ?string
    {
        return is_string($v) && preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/', $v) ? strtoupper($v) : null;
    }

    public static function uuid(mixed $v): ?string
    {
        return is_string($v) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $v) ? strtolower($v) : null;
    }

    /** Returns MAC as AA:BB:CC:DD:EE:FF, or null. */
    public static function mac(mixed $v): ?string
    {
        if (!is_string($v) || !preg_match('/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/', $v)) {
            return null;
        }
        return strtoupper(str_replace('-', ':', $v));
    }

    public static function hostname(mixed $v): ?string
    {
        if (!is_string($v)) {
            return null;
        }
        $h = strtolower(rtrim(trim($v), '.'));
        if ($h === '' || strlen($h) > 253) {
            return null;
        }
        return preg_match('/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$/', $h) ? $h : null;
    }

    public static function version(mixed $v): ?string
    {
        return is_string($v) && preg_match('/^[0-9A-Za-z.+-]{1,20}$/', $v) ? $v : null;
    }

    /** ISO-8601 timestamp -> 'Y-m-d H:i:s.v' in UTC, or null. Rejects far-future values. */
    public static function utcTimestamp(mixed $v): ?string
    {
        if (!is_string($v) || strlen($v) > 40) {
            return null;
        }
        try {
            $dt = new \DateTimeImmutable($v);
        } catch (\Exception) {
            return null;
        }
        $dt = $dt->setTimezone(new \DateTimeZone('UTC'));
        if ($dt->getTimestamp() > time() + 86400 || $dt->getTimestamp() < strtotime('2015-01-01')) {
            return null;
        }
        return $dt->format('Y-m-d H:i:s.v');
    }
}
