<?php
declare(strict_types=1);

namespace Saip;

final class RateLimiter
{
    /** Counts a hit in a fixed window; throws 429 when the limit is exceeded. */
    public static function hit(string $bucket, int $limit, int $window = 60): void
    {
        $pdo = Db::pdo();
        $start = intdiv(time(), $window) * $window;
        $pdo->prepare('INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?, ?, 1)
                       ON DUPLICATE KEY UPDATE hits = hits + 1')->execute([$bucket, $start]);
        $st = $pdo->prepare('SELECT hits FROM rate_limits WHERE bucket = ? AND window_start = ?');
        $st->execute([$bucket, $start]);
        $hits = (int)$st->fetchColumn();

        if (random_int(1, 100) === 1) {
            $pdo->prepare('DELETE FROM rate_limits WHERE window_start < ?')->execute([time() - 3600]);
        }
        if ($hits > $limit) {
            $retry = $start + $window - time();
            throw new ApiException(429, 'rate_limited', 'Too many requests.', [], ['Retry-After' => (string)max(1, $retry)]);
        }
    }
}
