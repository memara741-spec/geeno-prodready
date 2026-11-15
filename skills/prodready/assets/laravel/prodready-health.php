<?php

// prodready read-only health report for Laravel 11+. Add to routes/web.php (or require this file there).
// Set PRODREADY_HEALTH_TOKEN to a long random value. The route returns counts and timestamps only, no data.
// verify_production.py --health-url https://your-site/prodready/health reads it with that token.

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Facades\Storage;

// In routes/console.php: a heartbeat the report reads. It proves the scheduler is really running.
Schedule::call(fn () => Cache::put('prodready:scheduler_last_run', time(), 3600))->everyMinute()->name('prodready-heartbeat');

Route::get('/prodready/health', function (\Illuminate\Http\Request $request) {
    $token = (string) env('PRODREADY_HEALTH_TOKEN', '');
    abort_unless($token !== '' && hash_equals($token, (string) $request->bearerToken()), 404);

    try {
        DB::select('select 1');
        $dbOk = true;
    } catch (\Throwable $e) {
        $dbOk = false;
    }

    $lastBackup = null;
    try {
        // spatie/laravel-backup stores files on the disk named in config/backup.php
        $disk = Storage::disk(config('backup.backup.destination.disks.0', 'local'));
        foreach ($disk->allFiles() as $file) {
            if (str_ends_with($file, '.zip')) {
                $lastBackup = max($lastBackup ?? 0, $disk->lastModified($file));
            }
        }
    } catch (\Throwable $e) {
        $lastBackup = null;
    }

    return response()->json([
        'database_ok' => $dbOk,
        'scheduler_last_run' => Cache::get('prodready:scheduler_last_run'),
        'queue_size' => rescue(fn () => Queue::size(), null, false),
        // Set this key yourself from a job-created-at lookup if you use the database queue, e.g. the age in seconds of the oldest row in `jobs`.
        'queue_oldest_job_age_s' => rescue(fn () => ($t = DB::table('jobs')->min('created_at')) ? time() - $t : 0, 0, false),
        'last_backup_at' => $lastBackup,
    ]);
});
