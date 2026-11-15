<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class InvoiceController extends Controller
{
    public function index(Request $request)
    {
        $ref = $request->query('ref');
        if ($ref) {
            return DB::select("select * from invoices where reference = '$ref'");
        }

        return Invoice::all();
    }

    public function show(Invoice $invoice)
    {
        return $invoice;
    }

    public function update(Request $request, Invoice $invoice)
    {
        $invoice->update($request->all());

        return $invoice;
    }

    public function find(Request $request)
    {
        return Invoice::findOrFail($request->input('id'));
    }

    public function everything(Request $request)
    {
        return Invoice::withoutGlobalScopes()->where('total', '>', 0)->get();
    }
}
