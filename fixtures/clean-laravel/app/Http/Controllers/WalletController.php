<?php

namespace App\Http\Controllers;

use App\Models\Wallet;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class WalletController extends Controller
{
    public function transfer(Request $request)
    {
        $data = $request->validate([
            'to' => 'required|integer|exists:wallets,id',
            'amount' => 'required|numeric|min:0.01|max:10000',
            'idempotency_key' => 'required|uuid|unique:transfers,idempotency_key',
        ]);

        DB::transaction(function () use ($request, $data) {
            $from = Wallet::where('user_id', $request->user()->id)->lockForUpdate()->firstOrFail();
            $to = Wallet::lockForUpdate()->findOrFail($data['to']);
            abort_if($from->balance < $data['amount'], 422, 'Insufficient funds');
            $from->decrement('balance', $data['amount']);
            $to->increment('balance', $data['amount']);
            DB::table('ledger_entries')->insert([['wallet_id' => $from->id, 'amount' => -$data['amount'], 'reason' => 'transfer'], ['wallet_id' => $to->id, 'amount' => $data['amount'], 'reason' => 'transfer']]);
            DB::table('transfers')->insert(['idempotency_key' => $data['idempotency_key'], 'from' => $from->id, 'to' => $to->id, 'amount' => $data['amount']]);
        });

        return ['ok' => true];
    }
}
