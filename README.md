# Ubuntu LAMP Setup Script

Bash scripts to automatically setup LAMP server following best practices.

Current version: `lamp-ubuntu24.sh`

## How to use

  * Log in to your fresh Ubuntu server as root
  * Download the most recent version of the script: `wget https://raw.githubusercontent.com/Lyquix/ubuntu-lamp/master/lamp-ubuntu24.sh`
  * Change permissions: `chmod +x lamp-ubuntu24.sh`
  * Run and follow prompts: `./lamp-ubuntu24.sh`

## What does this script do?

  * Checks that you are root
  * Set the hostname
  * Set the time zone
  * Update packages from repo
  * Install utility software, Apache, PHP, PHP-FPM and MySQL (see detailed list below)
  * Setup unattended upgrades
  * Change www-data user password, and allow shell access
  * Apache configuration (see details below)
  * PHP configuration
  * PHP-FPM configuration
  * MySQL configuration
  * Sets up production, staging and development environments and databases
  * Encrypts database and other credentials
  * Configure log rotation
  * Automatic service restart for Apache and MySQL
  * Setup automatic daily database dump and rotation
  * Setup basic firewall rules
  * Setup fail2ban
  * Setup mod_security
  * Setup bad bots blocker
  * Automatically generates wp-config.php, wp-secrets.php, .htaccess, .htpassword, and deploy-config.php

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
    * apachetop
    * libapache2-mod-php
    * libapache2-mod-fcgid
    * apache2-suexec-pristine
    * libapache2-mod-security2
  * PHP 8.3
    * mcrypt
    * imagemagick
    * php8.3
    * php8.3-common
    * php8.3-gd
    * php8.3-imap
    * php8.3-mysql
    * php8.3-mysqli
    * php8.3-cli
    * php8.3-cgi
    * php8.3-zip
    * php-pear
    * php-auth
    * php-mcrypt
    * php-imagick
    * php8.3-curl
    * php8.3-mbstring
    * php8.3-bcmath
    * php8.3-xml
    * php8.3-soap
    * php8.3-opcache
    * php8.3-intl
    * php-apcu
    * php-mail
    * php-mail-mime
    * php8.3-memcached
    * php-all-dev
    * php8.3-dev
    * libapache2-mod-php8.3
  * MySQL

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
    Header set Access-Control-Allow-Methods "GET, POST, HEAD, OPTIONS"
    Header set Timing-Allow-Origin: "*"
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "sameorigin"
    Header unset X-Powered-By
    Header unset Server
    Header set X-XSS-Protection "1; mode=block"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header set Referrer-Policy "same-origin"
    SetEnv WPCONFIG_ENCKEY ENC_KEY
    SetEnv WPCONFIG_ENCIV ENC_IV

    # Disable unused HTTP request methods
    <LimitExcept GET POST HEAD OPTIONS>
      deny from all
    </LimitExcept>
</Directory>

# Disable Trace HTTP request
TraceEnable off

# Disable SSL and TLS under v1.2
SSLProtocol TLSv1.2

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

Uses optimized MySQL configuration from [Fotis Evangelou](https://gist.github.com/fevangelou)
[https://gist.github.com/fevangelou/0da9941e67a9c9bb2596](https://gist.github.com/fevangelou/0da9941e67a9c9bb2596)
