<?php

namespace App\Jobs;

use App\Models\Wallet;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;

class ProcessPayout implements ShouldQueue, ShouldBeUnique
{
    use Queueable;

    public function __construct(public int $walletId, public int $payoutId)
    {
    }

    public function uniqueId(): string
    {
        return (string) $this->payoutId;
    }

    public function handle(): void
    {
        DB::transaction(function () {
            $wallet = Wallet::lockForUpdate()->findOrFail($this->walletId);
            $wallet->decrement('balance', 10);
        });
    }
}
