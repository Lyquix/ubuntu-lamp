<?php

$_WP_SECRETS = (function () {
    // Allowed salt characters
    $salt_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_ []{}<>~`+=,.;:/?|';

    // Map domains to environment names
    $environment = [
        'example.com' => 'production',
        'www.example.com' => 'production',
        'stg.example.com' => 'staging',
        'dev.example.com' => 'development',
        'example.test' => 'local'
    ];

    // Configuration of all environments
    // - use arrays to map environments to different values
    // - use strings when the value doesn't change between environments
    // 'local' environment values, DB_HOST and WP_DEBUG_DISPLAY are never encrypted
    $config = [
        'DB_NAME' => [
            'production' => '{{DB_NAME}}',
            'staging' => '{{STGDB_NAME}}',
            'development' => '{{DEVDB_NAME}}',
            'local' => 'dbname' // local environment is never encrypted
        ],
        'DB_USER' => [
            'production' => '{{DB_USER}}',
            'staging' => '{{STGDB_USER}}',
            'development' => '{{DEVDB_USER}}',
            'local' => 'dbuser' // local environment is never encrypted
        ],
        'DB_PASSWORD' => [
            'production' => '{{DB_PASSWORD}}',
            'staging' => '{{STGDB_PASSWORD}}',
            'development' => '{{DEVDB_PASSWORD}}',
            'local' => 'dbpassword' // local environment is never encrypted
        ],
        // DB_HOST is never encrypted
        'DB_HOST' => [
            'production' => 'localhost',
            'staging' => 'localhost',
            'development' => 'localhost',
            'local' => 'localhost'
        ],
        // WordPress keys and salts
        'AUTH_KEY' => '{{AUTH_KEY_ENC}}',
        'SECURE_AUTH_KEY' => '{{SECURE_AUTH_KEY_ENC}}',
        'LOGGED_IN_KEY' => '{{LOGGED_IN_KEY_ENC}}',
        'NONCE_KEY' => '{{NONCE_KEY_ENC}}',
        'AUTH_SALT' => '{{AUTH_SALT_ENC}}',
        'SECURE_AUTH_SALT' => '{{SECURE_AUTH_SALT_ENC}}',
        'LOGGED_IN_SALT' => '{{LOGGED_IN_SALT_ENC}}',
        'NONCE_SALT' => '{{NONCE_SALT_ENC}}',
        // WP_DEBUG_DISPLAY is never encrypted
        'WP_DEBUG_DISPLAY' => [
            'production' => false,
            'staging' => false,
            'development' => true,
            'local' => true
        ]
    ];

    // Determine the current environment
    // - default to local
    $env = 'local';
    if (array_key_exists(strtolower($_SERVER['HTTP_HOST']), $environment)) {
        $env = $environment[strtolower($_SERVER['HTTP_HOST'])];
    }

    // Get encryption key
    $key = base64_decode(getenv('WPCONFIG_ENCKEY'));
    $iv = base64_decode(getenv('WPCONFIG_IV'));

    // Decrypt secrets (except for local environment)
    $secrets = [];
    foreach ($config as $var => $val) {
        $secrets[$var] = is_array($val) ? $val[$env] : $val;
        // Decrypt the value
        if (!in_array($var, ['DB_HOST', 'WP_DEBUG_DISPLAY']) || $env !== 'local') {
            $secrets[$var] = openssl_decrypt($secrets[$var], "AES-256-CBC", $key, 0, $iv);
        }
        // Generate the WordPress keys and salts for local environment
        if ((strpos($var, '_KEY') !== false || strpos($var, '_SALT') !== false) && $env === 'local') {
            // Generate a hash of the key name
            $hash = hash('sha256', $key);
            $hash .= hash('sha256', $hash);

            // Convert the hash to the allowed characters
            $secrets[$key] = '';
            for ($i = 0; $i < 128; $i += 2) {
                $hex = substr($hash, $i, 2);
                $index = hexdec($hex) % 92;
                $secrets[$key] .= $salt_chars[$index];
            }
        }
    }

    return $secrets;
})();