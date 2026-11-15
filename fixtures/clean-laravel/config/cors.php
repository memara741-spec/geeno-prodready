<?php

return [
    'paths' => ['api/*'],
    'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE'],
    'allowed_origins' => ['https://app.acme.example'],
    'allowed_headers' => ['Content-Type', 'Authorization'],
    'supports_credentials' => true,
];
