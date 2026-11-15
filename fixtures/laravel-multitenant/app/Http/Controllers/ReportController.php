<?php

namespace App\Http\Controllers;

use App\Mail\ReportReady;
use App\Models\Customer;
use App\Models\Invoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;

class ReportController extends Controller
{
    public function summary(Request $request)
    {
        $total = Invoice::where('paid', true)->get()->sum('total');
        $count = Invoice::all()->count();
        $random = Invoice::inRandomOrder()->first();
        $found = Invoice::where('reference', 'like', '%' . $request->q . '%')->get();

        $top = Cache::remember('top-invoices', 3600, function () {
            return Invoice::orderByDesc('total')->take(10)->get();
        });

        foreach (Customer::all() as $customer) {
            $latest = Invoice::where('customer_id', $customer->id)->latest()->first();
        }

        Mail::to($request->user())->send(new ReportReady($total));

        $rules = ['email' => 'required|unique:invoices,reference'];

        return compact('total', 'count', 'random', 'found', 'top');
    }
}
