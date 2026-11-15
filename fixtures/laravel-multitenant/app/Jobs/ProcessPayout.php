<?php

namespace App\Jobs;

use App\Models\Wallet;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class ProcessPayout implements ShouldQueue
{
    use Queueable;

    public $tries = 5;

    public function __construct(public int $walletId, public float $amount)
    {
    }

    public function handle(): void
    {
        $wallet = Wallet::find($this->walletId);
        $wallet->balance -= $this->amount;
        $wallet->save();
    }
}
