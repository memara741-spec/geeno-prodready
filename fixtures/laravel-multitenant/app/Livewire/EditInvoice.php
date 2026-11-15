<?php

namespace App\Livewire;

use App\Models\Invoice;
use Livewire\Component;

class EditInvoice extends Component
{
    public $invoiceId;

    public string $notes = '';

    public function save()
    {
        $invoice = Invoice::find($this->invoiceId);
        $invoice->update(['notes' => $this->notes]);
    }

    public function delete()
    {
        Invoice::find($this->invoiceId)->delete();
    }

    public function render()
    {
        return view('livewire.edit-invoice', ['invoices' => Invoice::with('lines')->get()]);
    }
}
