<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('reports:send')->everyMinute();
Schedule::command('invoices:remind')->daily();
