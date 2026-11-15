<?php

use App\Livewire\EditInvoice;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::middleware('auth')->group(function () {
    Route::get('/invoices/{invoiceId}/edit', EditInvoice::class);
});
