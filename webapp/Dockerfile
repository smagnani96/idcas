FROM php:7-apache
MAINTAINER simonemagnani.96@gmail.com

COPY 000-default.conf /etc/apache2/sites-available/000-default.conf

# Copy application source
COPY index.php /var/www/html
RUN chown -R www-data:www-data /var/www