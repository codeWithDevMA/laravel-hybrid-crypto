<?php

use Illuminate\Support\Facades\Route;
use Vendor\HybridCrypto\Http\Controllers\HybridCryptoDashboardController;

Route::prefix('hybrid-crypto')
    ->name('hybrid-crypto.')
    ->group(function (): void {
        Route::get('/dashboard', [HybridCryptoDashboardController::class, 'index'])->name('dashboard');
        Route::post('/dashboard', [HybridCryptoDashboardController::class, 'build'])->name('dashboard.build');
        Route::post('/decrypt', [HybridCryptoDashboardController::class, 'decrypt'])->name('dashboard.decrypt');
    });
