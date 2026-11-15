<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('reports:send')->hourly()->withoutOverlapping()->onOneServer()->pingOnFailure(env('HEALTHCHECK_FAIL_URL'));
Schedule::command('backup:run')->dailyAt('02:00')->onFailure(function () {
    report('Database backup failed');
});
