<?php

namespace App\Models;

use App\Models\Concerns\BelongsToTenant;
use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    use BelongsToTenant;

    protected $fillable = ['reference', 'customer_id', 'notes'];

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }
}
