<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\WalletController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:5,1');

Route::middleware(['auth:sanctum', 'throttle:api'])->group(function () {
    Route::apiResource('invoices', InvoiceController::class);
    Route::post('/wallet/transfer', [WalletController::class, 'transfer'])->middleware('throttle:10,1');
});
