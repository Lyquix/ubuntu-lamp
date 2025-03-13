#!/bin/bash

# Site Setup script for Ubuntu LAMP
# https://github.com/Lyquix/ubuntu-lamp

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root!"
	exit 1
fi

DIVIDER="\n***************************************\n\n"

# Welcome and instructions
printf $DIVIDER
echo "Lyquix LAMP server Add Site script"
printf $DIVIDER

# Prompt to continue
while true; do
	read -p "Continue [Y/N]? " cnt1
	case $cnt1 in
	[Yy]*) break ;;
	[Nn]*) exit ;;
	*) echo "Please answer Y or N" ;;
	esac
done

# Virtual Hosts
printf $DIVIDER
echo "VIRTUAL HOSTS"
echo "The script will setup the base virtual hosts configuration. Using the main domain name it will:"
echo " * Setup configuration files for the production site, e.g. example.com with alias www.example.com"
echo " * Setup staging and development environments e.g. stg.example.com and dev.example.com"
echo " * Setup the necessary directories"

while true; do
	read -p "Please enter the main domain (e.g. example.com, without www): " domain
	case $domain in
	"") echo "Domain may not be left blank" ;;
	*) break ;;
	esac
done

stg_domain="stg.$domain"
echo "Suggested staging domain: $stg_domain"
while true; do
	read -p "Would you like to keep this as your staging domain? [Y/n] " answer
	case "$answer" in
	[Yy]* | "") # Accept default or yes
		break ;;
	[Nn]*) # Enter a new value
		read -p "Enter your staging domain: " stg_domain
		break
		;;
	*) echo "Please answer yes or no." ;;
	esac
done

dev_domain="dev.$domain"
echo "Suggested development domain: $dev_domain"
while true; do
	read -p "Would you like to keep this as your development domain? [Y/n] " answer
	case "$answer" in
	[Yy]* | "") # Accept default or yes
		break ;;
	[Nn]*) # Enter a new value
		read -p "Enter your development domain: " dev_domain
		break
		;;
	*) echo "Please answer yes or no." ;;
	esac
done

echo "Main domain: $domain"
echo "Staging domain: $stg_domain"
echo "Development domain: $dev_domain"

# Declare associative array of domains
declare -A domains=(
	[production]=$domain
	[staging]=$stg_domain
	[development]=$dev_domain
)

# Backup previous virtual host files
if [ -f /etc/apache2/sites-available/$domain.conf ]; then
	echo "Backing up existing virtual host configuration file to /etc/apache2/sites-available/$domain.conf.bak"
	cp /etc/apache2/sites-available/$domain.conf /etc/apache2/sites-available/$domain.conf.bak
fi
if [ -f /etc/apache2/sites-available/$stg_domain.conf ]; then
	echo "Backing up existing virtual host configuration file to /etc/apache2/sites-available/$stg_domain.conf.bak"
	cp /etc/apache2/sites-available/$stg_domain.conf /etc/apache2/sites-available/$stg_domain.conf.bak
fi
if [ -f /etc/apache2/sites-available/$dev_domain.conf ]; then
	echo "Backing up existing virtual host configuration file to /etc/apache2/sites-available/$dev_domain.conf.bak"
	cp /etc/apache2/sites-available/$dev_domain.conf /etc/apache2/sites-available/$dev_domain.conf.bak
fi

# Production
VIRTUALHOST="<VirtualHost *:80>
	ServerName $domain
	ServerAlias www.$domain
	DocumentRoot /srv/www/$domain/public_html/
	ErrorLog /srv/www/$domain/logs/error.log
	CustomLog /srv/www/$domain/logs/access.log combined
	SetEnv WPCONFIG_ENVNAME production
</VirtualHost>\n"
echo -e "$VIRTUALHOST" >/etc/apache2/sites-available/$domain.conf

# Staging
VIRTUALHOST="<VirtualHost *:80>
	ServerName $stg_domain
	DocumentRoot /srv/www/$stg_domain/public_html/
	ErrorLog /srv/www/$stg_domain/logs/error.log
	CustomLog /srv/www/$stg_domain/logs/access.log combined
	SetEnv WPCONFIG_ENVNAME staging
</VirtualHost>\n"
echo -e "$VIRTUALHOST" >/etc/apache2/sites-available/$stg_domain.conf

# Development
VIRTUALHOST="<VirtualHost *:80>
	ServerName dev.$domain
	DocumentRoot /srv/www/dev.$domain/public_html/
	ErrorLog /srv/www/dev.$domain/logs/error.log
	CustomLog /srv/www/dev.$domain/logs/access.log combined
	SetEnv WPCONFIG_ENVNAME development
</VirtualHost>\n"
echo -e "$VIRTUALHOST" >/etc/apache2/sites-available/$dev_domain.conf

# Create directories
mkdir -p /srv/www/$domain/public_html
mkdir -p /srv/www/$domain/logs
mkdir -p /srv/www/$stg_domain/public_html
mkdir -p /srv/www/$stg_domain/logs
mkdir -p /srv/www/$dev_domain/public_html
mkdir -p /srv/www/$dev_domain/logs
chown -R www-data:www-data /srv/www

# Enable sites
a2ensite $domain
a2ensite $stg_domain
a2ensite $dev_domain
service apache2 reload

# MySQL
printf $DIVIDER
echo "MYSQL"
echo "Setup databases and users"
while true; do
	read -sp "Enter password for MySQL root: " mysqlrootpsw
	case $mysqlrootpsw in
	"") echo "Password may not be left blank" ;;
	*) break ;;
	esac
done
echo "\nPlease set name for databases, users and passwords"
while true; do
	read -p "Production database name (recommended: use domain without TLD, for mydomain.com use mydomain): " dbname
	case $dbname in
	"") echo "Database name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -p "Production database user (recommended: use same as database name, max 16 characters): " dbuser
	case $dbuser in
	"") echo "User name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -sp "Production database password: " dbpass
	case $dbpass in
	"") echo "\nPassword may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	printf "\n"
	read -p "Staging database name (recommended: use domain without TLD followed by _stg, for mydomain.com use mydomain_stg): " stgdbname
	case $stgdbname in
	"") echo "Database name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -p "Staging database user (recommended: use same as database name, max 16 characters): " stgdbuser
	case $stgdbuser in
	"") echo "User name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -sp "Staging database password: " stgdbpass
	case $stgdbpass in
	"") echo "\nPassword may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	printf "\n"
	read -p "Development database name (recommended: use domain without TLD followed by _dev, for mydomain.com use mydomain_dev): " devdbname
	case $devdbname in
	"") echo "Database name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -p "Development database user (recommended: use same as database name, max 16 characters): " devdbuser
	case $devdbuser in
	"") echo "User name may not be left blank" ;;
	*) break ;;
	esac
done
while true; do
	read -sp "Development database password: " devdbpass
	case $devdbpass in
	"") echo "\nPassword may not be left blank" ;;
	*) break ;;
	esac
done

# Declare associative arrays of credentials
declare -A dbnames=(
	[production]=$dbname
	[staging]=$stgdbname
	[development]=$devdbname
)
declare -A dbusers=(
	[production]=$dbuser
	[staging]=$stgdbuser
	[development]=$devdbuser
)
declare -A dbpasss=(
	[production]=$dbpass
	[staging]=$stgdbpass
	[development]=$devdbpass
)

# Array of environment names
environments=(production staging development)

# Loop through each environment
for env in "${environments[@]}"; do
	# Create database
	echo "Create database ${dbnames[$env]}..."
	mysql -u root -p"$mysqlrootpsw" -e "CREATE DATABASE ${dbnames[$env]};"
	# Create user with the original password
	echo "Create user ${dbusers[$env]}..."
	mysql -u root -p"$mysqlrootpsw" -e "CREATE USER '${dbusers[$env]}'@'localhost' IDENTIFIED BY '${dbpasss[$env]}';"

	# Grant privileges
	echo "Grant ${dbusers[$env]} all privileges on ${dbnames[$env]}..."
	mysql -u root -p"$mysqlrootpsw" -e "GRANT ALL PRIVILEGES ON ${dbnames[$env]}.* TO '${dbusers[$env]}'@'localhost';"
done

echo "Restart MySQL..."
service mysql restart

# Extract the values of WPCONFIG_ENCKEY and WPCONFIG_ENCIV from apache2.conf
ENC_KEY=$(grep 'SetEnv WPCONFIG_ENCKEY' /etc/apache2/apache2.conf | awk '{print $3}')
ENC_IV=$(grep 'SetEnv WPCONFIG_ENCIV' /etc/apache2/apache2.conf | awk '{print $3}')

# If ENC_KEY or ENC_IV are missing, prompt the user
if [ -z "$ENC_KEY" ] || [ -z "$ENC_IV" ]; then
	printf $DIVIDER
	echo "WARNING: Encryption keys (ENC_KEY and/or ENC_IV) could not be extracted from apache2.conf."

	while true; do
		echo "Would you like to:"
		echo "  [1] Enter ENC_KEY and ENC_IV manually"
		echo "  [2] Skip creation of wp-secrets, wp-config, htaccess, htpasswd, and deploy files"
		read -p "Enter your choice [1-2]: " ENC_MANUAL

		case $ENC_MANUAL in
			1)  # Manually enter encryption keys
				while true; do
					read -p "Please enter the Encryption Key: " ENC_KEY
					case $ENC_KEY in
					"") echo "Encryption Key may not be left blank" ;;
					*) break ;;
					esac
				done

				while true; do
					read -p "Please enter the Encryption Initialization Vector: " ENC_IV
					case $ENC_IV in
					"") echo "Encryption Initialization Vector may not be left blank" ;;
					*) break ;;
					esac
				done

				break
				;;
			2)  # Skip file creation
				echo "Skipping the creation of wp-secrets, wp-config, htaccess, htpasswd, and deploy files."
				break
				;;
			*)  
				echo "Invalid choice. Please enter 1 or 2."
				;;
		esac
	done
fi

# Check if both ENC_KEY and ENC_IV were found
if [ -z "$ENC_KEY" ] || [ -z "$ENC_IV" ]; then
	# Create setup directory to store log file and generated configuration files
	SETUP_DIR="/srv/www/setup-$(date +"%Y%m%d-%H%M%S")"
	echo "Creating setup directory $SETUP_DIR to store log and generated configuration files"
	mkdir -p "$SETUP_DIR"

	# Create wp-secrets.php file
	echo "Create $SETUP_DIR/wp-secrets.php file"
	WP_SECRETS="$(
		cat <<'EOF'
<?php
// Generated by Lyquix Ubuntu LAMP Setup Script
// https://github.com/Lyquix/ubuntu-lamp

$_WP_SECRETS = (function () {
	// Map domains to environment names
	$environment = [
		'{{production_domain}}' => 'production',
		'www.{{production_domain}}' => 'production',
		'{{staging_domain}}' => 'staging',
		'{{development_domain}}' => 'development'
	];

	// Configuration of all environments
	// - use arrays to map environments to different values
	// - use strings when the value doesn't change between environments
	// 'local' environment values, DB_HOST and WP_DEBUG_DISPLAY are never encrypted
	$config = [
		'DB_NAME' => [
			'production' => '{{production_dbname}}',
			'staging' => '{{staging_dbname}}',
			'development' => '{{development_dbname}}',
			'local' => 'dbname' // local environment is never encrypted
		],
		'DB_USER' => [
			'production' => '{{production_dbuser}}',
			'staging' => '{{staging_dbuser}}',
			'development' => '{{development_dbuser}}',
			'local' => 'dbuser' // local environment is never encrypted
		],
		'DB_PASSWORD' => [
			'production' => '{{production_dbpass}}',
			'staging' => '{{staging_dbpass}}',
			'development' => '{{development_dbpass}}',
			'local' => 'dbpassword' // local environment is never encrypted
		],
		// DB_HOST is never encrypted
		'DB_HOST' => [
			'production' => 'localhost',
			'staging' => 'localhost',
			'development' => 'localhost',
			'local' => '127.0.0.1'
		],
		// WordPress keys and salts
		'AUTH_KEY' => '{{AUTH_KEY}}',
		'SECURE_AUTH_KEY' => '{{SECURE_AUTH_KEY}}',
		'LOGGED_IN_KEY' => '{{LOGGED_IN_KEY}}',
		'NONCE_KEY' => '{{NONCE_KEY}}',
		'AUTH_SALT' => '{{AUTH_SALT}}',
		'SECURE_AUTH_SALT' => '{{SECURE_AUTH_SALT}}',
		'LOGGED_IN_SALT' => '{{LOGGED_IN_SALT}}',
		'NONCE_SALT' => '{{NONCE_SALT}}',
		// WP_DEBUG_DISPLAY is never encrypted
		'WP_DEBUG_DISPLAY' => [
			'production' => false,
			'staging' => false,
			'development' => true,
			'local' => true
		]
	];

	// Determine the current environment, default to local
	$domain = strtolower($_SERVER['HTTP_HOST']);
	$env = 'local';
	if (array_key_exists($domain, $environment)) {
		$env = $environment[$domain];
	} elseif (preg_match('#/srv/www/([^/]+)/public_html#', __DIR__, $matches)) {
		$dir = $matches[1];
		if (array_key_exists($dir, $environment)) {
			$env = $environment[$dir];
		}
	}

	// Get encryption key
	$key = hex2bin(getenv('WPCONFIG_ENCKEY'));
	$iv = hex2bin(getenv('WPCONFIG_ENCIV'));

	// Decrypt secrets (except for local environment)
	$salt_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_ []{}<>~`+=,.;:/?|';
	$secrets = [];
	foreach ($config as $var => $val) {
		$secrets[$var] = is_array($val) ? $val[$env] : $val;
		// Decrypt the value
		if (!in_array($var, ['DB_HOST', 'WP_DEBUG_DISPLAY']) && $env !== 'local') {
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
EOF
	)"
	echo -e "$WP_SECRETS" >$SETUP_DIR/wp-secrets.php

	# Loop through each environment
	echo "Save encrypted database credentials"
	for env in "${environments[@]}"; do
		echo "Processing $env"

		# Update domains
		FIND="{{${env}_domain}}"
		REPLACE=$(printf '%s\n' "${domains[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/wp-secrets.php

		# Update database names
		FIND="{{${env}_dbname}}"
		REPLACE=$(printf '%s\n' "${dbnames[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/wp-secrets.php

		# Update database users
		FIND="{{${env}_dbuser}}"
		REPLACE=$(printf '%s\n' "${dbusers[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/wp-secrets.php

		# Update database passwords
		FIND="{{${env}_dbpass}}"
		REPLACE=$(printf '%s\n' "${dbpasss[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/wp-secrets.php
	done

	# Declare an associative array to hold the salt names
	echo "Get WordPress salts"
	salt_names=("AUTH_KEY" "SECURE_AUTH_KEY" "LOGGED_IN_KEY" "NONCE_KEY" "AUTH_SALT" "SECURE_AUTH_SALT" "LOGGED_IN_SALT" "NONCE_SALT")

	# Generate WordPress salts
	SALTS=$({ curl -s https://api.wordpress.org/secret-key/1.1/salt/; })

	# Loop through the salt names and process each one
	for salt in "${salt_names[@]}"; do
		# Extract the salt value
		value=$(echo "$SALTS" | grep "'$salt'" | awk -F"'" '{print $4}')

		log_msg "$salt: $value"

		# Encrypt the value
		encrypted_value=$(echo $value | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $ENC_KEY -iv $ENC_IV | tr -d '\n')

		FIND="{{${salt}}}"
		REPLACE=$(printf '%s\n' "$encrypted_value" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/wp-secrets.php
	done

	# Change file ownership
	chown www-data:www-data $SETUP_DIR/wp-secrets.php

	# Create wp-config.php file
	printf $DIVIDER
	echo "Create $SETUP_DIR/wp-config.php file"
	WP_CONFIG="$(
		cat <<'EOF'
<?php
// Generated by Lyquix Ubuntu LAMP Setup Script
// https://github.com/Lyquix/ubuntu-lamp

/** Get the WordPress secrets for the current environment */
require_once(dirname(__FILE__) . '/wp-secrets.php');

/** MySQL settings */
define('DB_NAME', $_WP_SECRETS['DB_NAME']);
define('DB_USER', $_WP_SECRETS['DB_USER']);
define('DB_PASSWORD', $_WP_SECRETS['DB_PASSWORD']);
define('DB_HOST', $_WP_SECRETS['DB_HOST']);

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**
 * Authentication Unique Keys and Salts.
 */
define('AUTH_KEY', $_WP_SECRETS['AUTH_KEY']);
define('SECURE_AUTH_KEY', $_WP_SECRETS['SECURE_AUTH_KEY']);
define('LOGGED_IN_KEY', $_WP_SECRETS['LOGGED_IN_KEY']);
define('NONCE_KEY', $_WP_SECRETS['NONCE_KEY']);
define('AUTH_SALT', $_WP_SECRETS['AUTH_SALT']);
define('SECURE_AUTH_SALT', $_WP_SECRETS['SECURE_AUTH_SALT']);
define('LOGGED_IN_SALT', $_WP_SECRETS['LOGGED_IN_SALT']);
define('NONCE_SALT', $_WP_SECRETS['NONCE_SALT']);

/**
 * WordPress Database Table prefix.
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 */
define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', $_WP_SECRETS['WP_DEBUG_DISPLAY']);
define('WP_DEBUG_LOG', !$_WP_SECRETS['WP_DEBUG_DISPLAY']);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') ) define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');
EOF
	)"
	echo -e "$WP_CONFIG" >$SETUP_DIR/wp-config.php

	# Change file ownership
	chown www-data:www-data $SETUP_DIR/wp-config.php

	# Create .htaccess file
	printf $DIVIDER
	echo "Create $SETUP_DIR/.htaccess file"
	HTACCESS="$(
		cat <<'EOF'
# Generated by Lyquix Ubuntu LAMP Setup Script
# https://github.com/Lyquix/ubuntu-lamp

<If "%{ENV:WPCONFIG_ENVNAME} == 'production'">
# Redirect domain and force SSL #
RewriteEngine On
RewriteCond %{HTTP_HOST} !^www.{{production_domain}}$ [OR,NC]
RewriteCond %{SERVER_PORT} 80
RewriteRule ^(.*)$ https://www.{{production_domain}}/$1 [R=301,L]
</If>

<If "%{ENV:WPCONFIG_ENVNAME} == 'staging'">
# Redirect domain and force SSL #
RewriteEngine On
RewriteCond %{HTTP_HOST} !^{{staging_domain}}$ [OR,NC]
RewriteCond %{SERVER_PORT} 80
RewriteRule ^(.*)$ https://{{staging_domain}}/$1 [R=301,L]
  <If "%{HTTPS} == 'on'">
  # Password Protect Directory #
  AuthUserFile /srv/www/{{staging_domain}}/.htpasswd
  AuthName "Enter username and password"
  AuthType Basic
  Require valid-user
  </If>
</If>

<If "%{ENV:WPCONFIG_ENVNAME} == 'development'">
# Redirect domain and force SSL #
RewriteEngine On
RewriteCond %{HTTP_HOST} !^{{development_domain}}$ [OR,NC]
RewriteCond %{SERVER_PORT} 80
RewriteRule ^(.*)$ https://{{development_domain}}/$1 [R=301,L]
  <If "%{HTTPS} == 'on'">
  # Password Protect Directory #
  AuthUserFile /srv/www/{{development_domain}}/.htpasswd
  AuthName "Enter username and password"
  AuthType Basic
  Require valid-user
  </If>
</If>

# BEGIN WordPress
# The directives (lines) between "BEGIN WordPress" and "END WordPress" are
# dynamically generated, and should only be modified via WordPress filters.
# Any changes to the directives between these markers will be overwritten.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF
	)"
	echo -e "$HTACCESS" >$SETUP_DIR/.htaccess

	# Loop through each environment
	for env in "${environments[@]}"; do
		echo "Processing $env"
		# Update domains
		FIND="{{${env}_domain}}"
		REPLACE=$(printf '%s\n' "${domains[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/.htaccess
	done

	# Change file ownership
	chown www-data:www-data $SETUP_DIR/.htaccess

	# Create .htpasswd file
	printf $DIVIDER
	echo "Create .htpasswd file"
	# Remove any subdomains and the TLD from the username
	HTUSER=$(echo $domain | awk -F'.' '{print $(NF-1)}')
	htpasswd -bc $SETUP_DIR/.htpasswd $HTUSER review

	log_msg "HTUSER: $HTUSER"
	log_msg "HTPASSWD: review"

	# Change file ownership
	chown www-data:www-data $SETUP_DIR/.htpasswd

	# PHP Deploy script config
	printf $DIVIDER
	echo "Enter the git repository address"
	echo "You may use HTTPS URL like https://github.com/username/reponame.git"
	echo "or SSH address like git@bitbucket.org:username/reponame.git"

	while true; do
		read -p "Enter git repository address: " gitaddr
		case $gitaddr in
		"") echo "Git address may not be left blank" ;;
		*) break ;;
		esac
	done

	while true; do
		read -p "Enter the production branch name (e.g. master, or main): " branch
		case $branch in
		"") echo "Branch name may not be left blank" ;;
		*) break ;;
		esac
	done

	while true; do
		read -p "Enter the staging branch name (e.g. staging): " stg_branch
		case $stg_branch in
		"") echo "Branch name may not be left blank" ;;
		*) break ;;
		esac
	done

	while true; do
		read -p "Enter the development branch name (e.g. development): " dev_branch
		case $dev_branch in
		"") echo "Branch name may not be left blank" ;;
		*) break ;;
		esac
	done

	# Declare associative array of branches
	declare -A branches=(
		[production]=$branch
		[staging]=$stg_branch
		[development]=$dev_branch
	)

	echo "Create $SETUP_DIR/deploy-config.php file"
	DEPLOYCONFIG="$(
		cat <<'EOF'
<?php

$_DEPLOY_SECRETS = (function () {
	// Map domains to environment names
	$environment = [
		'{{production_domain}}' => 'production',
		'www.{{production_domain}}' => 'production',
		'{{staging_domain}}' => 'staging',
		'{{development_domain}}' => 'development'
	];

	// Configuration of all environments
	// - use arrays to map environments to different values
	// - use strings when the value doesn't change between environments
	$config = [
		'BRANCH' => [ // Branch is never encrypted
			'production' => '{{production_branch}}',
			'staging' => '{{staging_branch}}',
			'development' => '{{development_branch}}',
		],
		'ACCESS_TOKEN' => [
			'production' => '{{production_token}}',
			'staging' => '{{staging_token}}',
			'development' => '{{development_token}}',
		],
		'BASE_DIR' => [ // Base directory is never encrypted
			'production' => '/srv/www/{{production_domain}}',
			'staging' => '/srv/www/{{staging_domain}}',
			'development' => '/srv/www/{{development_domain}}',
		]
	];

	// Determine the current environment, default to local
	$env = 'local';
	if (array_key_exists(strtolower($_SERVER['HTTP_HOST']), $environment)) {
		$env = $environment[strtolower($_SERVER['HTTP_HOST'])];
	}

	// Get encryption key
	$key = hex2bin(getenv('WPCONFIG_ENCKEY'));
	$iv = hex2bin(getenv('WPCONFIG_ENCIV'));

	// Decrypt secrets
	$secrets = [];
	foreach ($config as $var => $val) {
		$secrets[$var] = $val[$env];
		// Decrypt the value
		if ($var == 'ACCESS_TOKEN') {
			$secrets[$var] = openssl_decrypt($secrets[$var], "AES-256-CBC", $key, 0, $iv);
		}
	}

	return $secrets;
})();

define('DISABLED', false);
define('IP_ALLOW', serialize([]));
define('REMOTE_REPOSITORY', '{{gitaddr}}');
define('BRANCH', serialize([$_DEPLOY_SECRETS['BRANCH']]));
define('ACCESS_TOKEN', $_DEPLOY_SECRETS['ACCESS_TOKEN']);
define('GIT_DIR', $_DEPLOY_SECRETS['BASE_DIR'] . '/git/');
define('TARGET_DIR', $_DEPLOY_SECRETS['BASE_DIR'] . '/public_html/');
define('LOG_FILE', $_DEPLOY_SECRETS['BASE_DIR'] . '/logs/deploy.log');
define('EMAIL_NOTIFICATIONS', '');
define('TIME_LIMIT', 60);
define('EXCLUDE_FILES', serialize(['.git']));
define('RSYNC_FLAGS', '-rltgoDzvO');
define('COMMANDS_BEFORE_RSYNC', serialize([]));
define('COMMANDS_AFTER_RSYNC', serialize([]));
define('CLEANUP_WORK_TREE', false);
define('CALLBACK_CLASSES', []);
define('PLUGINS_FOLDER','plugins/');
EOF
	)"
	echo -e "$DEPLOYCONFIG" >$SETUP_DIR/deploy-config.php

	# Loop through each environment
	for env in "${environments[@]}"; do
		echo "Processing $env"

		# Update domains
		FIND="{{${env}_domain}}"
		REPLACE=$(printf '%s\n' "${domains[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/deploy-config.php

		# Update branches
		FIND="{{${env}_branch}}"
		REPLACE=$(printf '%s\n' "${branches[$env]}" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/deploy-config.php

		# Generate and update access tokens and encrypt it
		ACCESS_TOKEN=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9')
		if [ "$env" == "production" ]; then
			log_msg "$env webhook: https://${domains[$env]}/deploy.php?t=$ACCESS_TOKEN&b=${branches[$env]}"
		else
			log_msg "$env webhook: https://$HTUSER:review@${domains[$env]}/deploy.php?t=$ACCESS_TOKEN&b=${branches[$env]}"
		fi
		ACCESS_TOKEN=$(printf "%s" "$ACCESS_TOKEN" | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $ENC_KEY -iv $ENC_IV | tr -d '\n')
		FIND="{{${env}_token}}"
		REPLACE=$(printf '%s\n' "$ACCESS_TOKEN" | sed 's/[\&/]/\\&/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/deploy-config.php

		# Update the GIT address
		FIND="{{gitaddr}}"
		REPLACE=$(printf '%s\n' "$gitaddr" | sed 's/[\&/]/\\&/g; s/@/\\@/g')
		perl -pi -e "s/\Q$FIND\E/$REPLACE/g" $SETUP_DIR/deploy-config.php
	done

	echo "Download php-git-deploy script..."
	wget https://raw.githubusercontent.com/Lyquix/php-git-deploy/master/deploy.php -O $SETUP_DIR/deploy.php

	# Change file ownership
	chown www-data:www-data $SETUP_DIR/deploy*

	echo "You will need to copy files in $SETUP_DIR to each site and your local environment"
fi

# The End
printf $DIVIDER
echo "The script executing has finished. Please check messages for any errors."
read -p "Press ENTER to continue"

exit
