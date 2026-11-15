<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\BookingController;
use App\Http\Controllers\DocumentController;
use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\WalletController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login']);
Route::post('/password/forgot', [AuthController::class, 'forgot']);

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/invoices', [InvoiceController::class, 'index']);
    Route::get('/invoices/{invoice}', [InvoiceController::class, 'show']);
    Route::put('/invoices/{invoice}', [InvoiceController::class, 'update']);
    Route::post('/wallet/transfer', [WalletController::class, 'transfer']);
    Route::post('/wallet/withdraw', [WalletController::class, 'withdraw']);
    Route::post('/bookings', [BookingController::class, 'store']);
    Route::post('/users/{user}/role', [UserController::class, 'assignRole']);
    Route::post('/users/avatar', [UserController::class, 'avatar']);
    Route::post('/users/convert', [UserController::class, 'convert']);
    Route::get('/reports/summary', [ReportController::class, 'summary']);
    Route::get('/documents/{document}', [DocumentController::class, 'show']);
    Route::delete('/documents/{document}', [DocumentController::class, 'destroy']);
    Route::post('/switch-company', [ProjectController::class, 'switchCompany']);
});

Route::post('/projects/{id}/archive', [ProjectController::class, 'archive']);
