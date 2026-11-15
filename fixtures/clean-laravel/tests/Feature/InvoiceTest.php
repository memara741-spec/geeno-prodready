<?php

namespace Tests\Feature;

use Tests\TestCase;

class InvoiceTest extends TestCase
{
    public function test_guests_cannot_list_invoices(): void
    {
        $this->getJson('/api/invoices')->assertStatus(401);
    }
}
