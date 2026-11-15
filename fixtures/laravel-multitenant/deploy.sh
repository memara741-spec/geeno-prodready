#!/bin/sh
set -e
git pull origin main
composer install
php artisan migrate --force
curl -k https://internal.acme.example/notify
