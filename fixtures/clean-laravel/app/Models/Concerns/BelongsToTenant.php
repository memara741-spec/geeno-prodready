<?php

namespace App\Models\Concerns;

use Illuminate\Database\Eloquent\Builder;

trait BelongsToTenant
{
    protected static function bootBelongsToTenant(): void
    {
        static::addGlobalScope('tenant', function (Builder $query) {
            $query->where($query->getModel()->getTable().'.company_id', auth()->user()?->company_id);
        });

        static::creating(function ($model) {
            $model->company_id ??= auth()->user()?->company_id;
        });
    }
}
