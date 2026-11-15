<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreInvoiceRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'reference' => ['required', 'string', 'max:40', Rule::unique('invoices', 'reference')->where('company_id', $this->user()->company_id)],
            'customer_id' => ['required', 'integer', Rule::exists('customers', 'id')->where('company_id', $this->user()->company_id)],
            'notes' => ['nullable', 'string', 'max:2000'],
        ];
    }
}
