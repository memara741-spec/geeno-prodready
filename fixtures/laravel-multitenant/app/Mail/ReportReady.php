<?php

namespace App\Mail;

use Illuminate\Mail\Mailable;

class ReportReady extends Mailable
{
    public function __construct(public $total)
    {
    }

    public function build()
    {
        return $this->view('mail.report');
    }
}
