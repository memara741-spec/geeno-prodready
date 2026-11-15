<?php

use App\Livewire\EditInvoice;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('/invoices/{invoice}/edit', EditInvoice::class);
});
