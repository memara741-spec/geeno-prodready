<?php

// prodready runtime profiler for Laravel 11+. Copy to app/Http/Middleware/ProdreadyProfile.php.
// Register in bootstrap/app.php:  $middleware->append(\App\Http\Middleware\ProdreadyProfile::class);
// Use it on a local or staging copy. It does nothing unless BOTH are set:
//   PRODREADY_PROFILE=true and PRODREADY_PROFILE_KEY=<long random value>
// and the request carries the same value in the X-Prodready-Profile header (scripts/profile_runtime.py does).
// It reports counts and query shapes with the values removed. It never reports data.

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

class ProdreadyProfile
{
    public function handle(Request $request, Closure $next): Response
    {
        $key = (string) env('PRODREADY_PROFILE_KEY', '');
        if (! filter_var(env('PRODREADY_PROFILE', false), FILTER_VALIDATE_BOOLEAN) || $key === ''
            || ! hash_equals($key, (string) $request->header('X-Prodready-Profile'))) {
            return $next($request);
        }

        $shapes = [];
        $count = 0;
        DB::listen(function ($query) use (&$shapes, &$count) {
            $count++;
            $shape = preg_replace(['/\'[^\']*\'/', '/"[^"]*"/', '/\b\d+\b/', '/\(\s*(\?\s*,\s*)+\?\s*\)/'], ['?', '?', '?', '(?...)'], $query->sql);
            $shapes[$shape] = ($shapes[$shape] ?? 0) + 1;
        });

        $start = microtime(true);
        $response = $next($request);
        arsort($shapes);

        $response->headers->set('X-Prodready-Queries', (string) $count);
        $response->headers->set('X-Prodready-Max-Repeat', (string) (reset($shapes) ?: 0));
        $response->headers->set('X-Prodready-Repeat-Sample', substr((string) key($shapes), 0, 160));
        $response->headers->set('X-Prodready-Time-Ms', (string) round((microtime(true) - $start) * 1000));
        $response->headers->set('X-Prodready-Memory-Kb', (string) round(memory_get_peak_usage(true) / 1024));

        return $response;
    }
}
