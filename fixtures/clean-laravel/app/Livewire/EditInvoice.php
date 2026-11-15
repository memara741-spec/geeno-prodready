<?php

namespace App\Livewire;

use App\Models\Invoice;
use Livewire\Attributes\Locked;
use Livewire\Component;

class EditInvoice extends Component
{
    #[Locked]
    public $invoiceId;

    public string $notes = '';

    public function mount(Invoice $invoice)
    {
        $this->authorize('update', $invoice);
        $this->invoiceId = $invoice->id;
        $this->notes = (string) $invoice->notes;
    }

    public function save()
    {
        $invoice = Invoice::findOrFail($this->invoiceId);
        $this->authorize('update', $invoice);
        $invoice->update(['notes' => $this->notes]);
    }

    public function render()
    {
        return view('livewire.edit-invoice', ['invoices' => Invoice::with('customer')->paginate(25)]);
    }
}
