# Ubuntu LAMP Setup Script

Bash scripts to automatically setup LAMP server following best practices.

Current version: `lamp-ubuntu20.sh`

## How to use

  * Log in to your fresh Ubuntu server as root
  * Download the most recent version of the script: `wget https://raw.githubusercontent.com/Lyquix/ubuntu-lamp/master/lamp-ubuntu22.sh`
  * Change permissions: `chmod 755 lamp-ubuntu22.sh`
  * Run and follow prompts: `./lamp-ubuntu22.sh`

## What does this script do?

  * Checks that you are root
  * Set the hostname. In general it is a good idea to use the real domain for your site as hostname.
  * Update packages from repo
  * Install utility software, Apache, PHP and MySQL (see detailed list below)
  * Setup unattended upgrades
  * Change www-data user password, and allow shell access
  * Apache configuration (see details below)
  * PHP configuration
  * MySQL configuration
  * Configure log rotation
  * Setup automatic daily database dump and rotation
  * Setup basic firewall rules
  * Setup fail2ban
  * Setup mod_security

## Installed Software

  * Utility software:
    * curl
    * vim
    * openssl
    * git
    * htop
    * nload
    * nethogs
    * zip
    * unzip
    * sendmail
    * sendmail-bin
    * libcurl3-openssl-dev
    * psmisc
    * build-essential
    * zlib1g-dev
    * libpcre3
    * libpcre3-dev
    * memcached
    * fail2ban
    * iptables-persistent
  * Apache and modules
    * apache2
    * apache2-doc
    * apachetop
    * libapache2-mod-php
    * libapache2-mod-fcgid
    * apache2-suexec-pristine
    * libapache2-mod-security2
  * PHP 8.1
    * mcrypt
    * imagemagick
    * php8.1
    * php8.1-common
    * php8.1-gd
    * php8.1-imap
    * php8.1-mysql
    * php8.1-mysqli
    * php8.1-cli
    * php8.1-cgi
    * php8.1-zip
    * php-pear
    * php-auth
    * php-mcrypt
    * php-imagick
    * php8.1-curl
    * php8.1-mbstring
    * php8.1-bcmath
    * php8.1-xml
    * php8.1-soap
    * php8.1-opcache
    * php8.1-intl
    * php-apcu
    * php-mail
    * php-mail-mime
    * php8.1-memcached
    * php-all-dev
    * php8.1-dev
    * libapache2-mod-php8.1
  * MySQL
  * NodeJS 12

## Apache Configuration

  * Change maximum number of concurrent request to unlimited: `MaxKeepAliveRequests 0`
  * Change the default timeout: `Timeout 60`
  * Add global settings for /srv/www directory, security settings, and caching:

```
<Directory /srv/www/>
    Options FollowSymLinks -Indexes -Includes
    AllowOverride all
    Require all granted
    Header set Access-Control-Allow-Origin "*"
    Header set Timing-Allow-Origin: "*"
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options sameorigin
    Header unset X-Powered-By
    Header set X-UA-Compatible "IE=edge"
    Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
    Header set X-XSS-Protection "1; mode=block"
</Directory>

# Disable HTTP 1.0
RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1.1$
RewriteRule .* - [F]

# Disable unused HTTP request methods
<LimitExcept GET POST HEAD>
deny from all
</LimitExcept>

# Disable Trace HTTP request
TraceEnable off

# Disable SSL v2 & v3
SSLProtocol –ALL +TLSv1.2 +TLSv1.3

# Disable server signature
ServerSignature Off
ServerTokens Prod

# Browser Caching #
ExpiresActive On
ExpiresDefault "access plus 30 days"
ExpiresByType text/html "access plus 15 minutes"
Header unset Last-Modified
Header unset ETag
FileETag None
```

  * Configure compression of svg images and font files
  * Set correct mime type for font files
  * Set correct priority of index files extensions
  * Configure memory limits based on actual server memory
  * Install ModPageSpeed and set CoreFilters
  * Virtual servers configuration
  * Log rotation and compression

## PHP Configuration

```
output_buffering = Off
max_execution_time = 60
max_input_vars = 5000
memory_limit = 256M
error_reporting = E_ALL & ~E_NOTICE & ~E_STRICT & ~E_DEPRECATED
log_errors_max_len = 0
post_max_size = 20M
upload_max_filesize = 20M
```

## MySQL Configuration

```
key_buffer = 16M
max_allowed_packet = 16M
thread_stack = 192K
thread_cache_size = 8
table_cache = 64
log_slow_queries = /var/log/mysql/mysql-slow.log
long_query_time = 1
```
