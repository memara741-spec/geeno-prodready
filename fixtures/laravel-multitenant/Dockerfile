FROM php:8.3-apache

COPY . /var/www/html
WORKDIR /var/www/html

RUN composer install
RUN chmod -R 777 storage bootstrap/cache
