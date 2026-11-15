<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreInvoiceRequest;
use App\Models\Invoice;
use Illuminate\Http\Request;

class InvoiceController extends Controller
{
    public function index(Request $request)
    {
        return Invoice::with('customer')->paginate(25);
    }

    public function store(StoreInvoiceRequest $request)
    {
        return Invoice::create($request->validated());
    }

    public function show(Invoice $invoice)
    {
        $this->authorize('view', $invoice);

        return $invoice->load('customer');
    }

    public function update(StoreInvoiceRequest $request, Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        $invoice->update($request->validated());

        return $invoice;
    }

    public function destroy(Invoice $invoice)
    {
        $this->authorize('delete', $invoice);
        $invoice->delete();

        return response()->noContent();
    }
}
