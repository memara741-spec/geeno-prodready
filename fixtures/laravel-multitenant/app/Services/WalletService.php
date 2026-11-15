<?php

namespace App\Services;

use App\Models\Wallet;

class WalletService
{
    public function sendMoney(Wallet $from, float $amount): void
    {
        $from->decrement('balance', $amount);
    }
}
