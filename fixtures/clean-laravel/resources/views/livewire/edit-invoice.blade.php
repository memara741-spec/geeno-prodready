<div>
    <h1>Invoice</h1>
    <p>{{ $notes }}</p>
    <ul>
        @foreach ($invoices as $invoice)
            <li>{{ $invoice->reference }} - {{ $invoice->customer->name }}</li>
        @endforeach
    </ul>
    {{ $invoices->links() }}
    <button wire:click="save">Save</button>
</div>
