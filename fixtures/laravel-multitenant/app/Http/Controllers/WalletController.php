<?php

namespace App\Http\Controllers;

use App\Models\Wallet;
use Illuminate\Http\Request;

class WalletController extends Controller
{
    public function transfer(Request $request)
    {
        $request->validate([
            'to' => 'required|integer',
            'amount' => 'required|numeric',
        ]);

        $from = Wallet::where('user_id', $request->user()->id)->first();
        $to = Wallet::where('user_id', $request->to)->first();

        if ($from->balance >= $request->amount) {
            $from->balance = $from->balance - $request->amount;
            $from->save();
            $to->balance = $to->balance + $request->amount;
            $to->save();
        }

        return ['ok' => true];
    }

    public function withdraw(Request $request)
    {
        $request->validate(['amount' => 'required|numeric']);
        $wallet = Wallet::where('user_id', $request->user()->id)->first();
        $wallet->balance -= $request->amount;
        $wallet->save();

        return ['ok' => true];
    }
}
