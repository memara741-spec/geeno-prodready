<div>
    <h1>Invoice</h1>
    <div>{!! $notes !!}</div>
    <ul>
        @foreach ($invoices as $invoice)
            <li>{{ $invoice->reference }} - {{ $invoice->customer->name }}</li>
        @endforeach
    </ul>
    <button wire:click="save">Save</button>
</div>
