<?php

return [
    'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', 'localhost')),
    'guard' => ['web'],
    'expiration' => 60 * 24 * 30,
    'token_prefix' => env('SANCTUM_TOKEN_PREFIX', ''),
];
