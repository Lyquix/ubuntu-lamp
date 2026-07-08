<?php
// Load the encryption key/iv into the env before WordPress (wp-config -> wp-secrets) loads.
$envFile = getenv('WPCLI_ENV_FILE') ?: '/etc/wpconfig/wpcli.env';
if (is_readable($envFile)) {
	foreach (parse_ini_file($envFile) as $k => $v) {
		if (getenv($k) === false) putenv("$k=$v");
	}
}
