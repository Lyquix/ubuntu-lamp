#!/bin/bash

# Ubuntu LAMP Setup Script
# https://github.com/Lyquix/ubuntu-lamp

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root!"
	exit 1
fi

DIVIDER="\n\n********************************************************************************\n\n"

# Echo to the console and save to a file
LOGMSG=("$DIVIDER" "$(date '+%Y-%m-%d %H:%M:%S')")
log_msg() {
	local MSG="$1"
	printf "%s\n" "$MSG"
	LOGMSG+=("$MSG")
	return 0
}

# Trap errors and save them to log file
trap_error() {
	local status=$?
	if [ $status -ne 0 ]; then
		local source="${BASH_COMMAND}"
		LOGMSG+=("[Exit Code: $status] $source")
	fi
}
trap 'trap_error' DEBUG

# Welcome and instructions
printf $DIVIDER
log_msg "Lyquix LAMP server setup on Ubuntu 24.04"
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

printf $DIVIDER
echo "Generating AES-256-CBC encryption key and initialization vector in hexadecimal"
ENC_KEY=$(openssl rand -hex 32)
log_msg "Encryption Key: $ENC_KEY"
ENC_IV=$(openssl rand -hex 16)
log_msg "Encryption IV: $ENC_IV"

# Create setup directory to store log file and generated configuration files
SETUP_DIR="/srv/www/setup-$(date +"%Y%m%d-%H%M%S")"
echo "Creating setup directory $SETUP_DIR to store log and generated configuration files"
mkdir -p "$SETUP_DIR"

# Change the swappiness to 10
printf $DIVIDER
echo "Change swappiness to 10"
echo "vm.swappiness = 10" >>/etc/sysctl.conf
sysctl -p

# Set the hostname
printf $DIVIDER
echo "HOSTNAME"
echo "Pick a hostname that identifies this server."
while true; do
	read -p "Hostname: " host
	case $host in
	"") echo "Hostname may not be left blank" ;;
	*) break ;;
	esac
done
echo "$host" >/etc/hostname
hostname -F /etc/hostname
printf "127.2.1       $host\n::1             $host\n" >>/etc/hosts

# Set the time zone
printf $DIVIDER
echo "TIME ZONE"
echo "Please select the correct time zone. e.g. US > Eastern Time"
read -p "Please ENTER to continue "
dpkg-reconfigure tzdata

# Install and update software
printf $DIVIDER
echo "INSTALL AND UPDATE SOFTWARE"
echo "Now the script will update Ubuntu and install all the necessary software."
read -p "Please ENTER to continue "

# Do not prompt asking about restarting
export NEEDRESTART_MODE=a
echo "Repository update..."
apt-get -y -q --fix-missing update
echo "Upgrade installed packages..."
apt-get -y -q upgrade
echo "Installing utilities..."
PCKGS=("curl" "vim" "openssl" "git" "htop" "nload" "nethogs" "zip" "unzip" "sendmail" "sendmail-bin" "mysqltuner" "libcurl3-openssl-dev" "psmisc" "build-essential" "zlib1g-dev" "libpcre3" "libpcre3-dev" "memcached" "redis-server" "redis-tools" "fail2ban" "iptables-persistent" "software-properties-common")
for PCKG in "${PCKGS[@]}"; do
	echo " * Installing $PCKG..."
	apt-get -y -q --no-install-recommends install ${PCKG}
done
echo "Installing Apache..."
PCKGS=("apache2" "apachetop" "libapache2-mod-php" "libapache2-mod-fcgid" "apache2-suexec-pristine" "libapache2-mod-security2")
for PCKG in "${PCKGS[@]}"; do
	echo " * Installing $PCKG..."
	apt-get -y -q --no-install-recommends install ${PCKG}
done
echo "Installing PHP..."
PCKGS=("mcrypt" "imagemagick" "php8.3" "php8.3-common" "php8.3-gd" "php8.3-imap" "php8.3-mysql" "php8.3-mysqli" "php8.3-cli" "php8.3-cgi" "php8.3-fpm" "php8.3-zip" "php-pear" "php-imagick" "php8.3-curl" "php8.3-mbstring" "php8.3-bcmath" "php8.3-xml" "php8.3-soap" "php8.3-opcache" "php8.3-intl" "php-apcu" "php-mail" "php-mail-mime" "php-all-dev" "php8.3-dev" "libapache2-mod-php8.3" "php8.3-memcached" "php8.3-redis" "composer")
for PCKG in "${PCKGS[@]}"; do
	echo " * Installing $PCKG..."
	apt-get -y -q --no-install-recommends install ${PCKG}
done

# Install CertBot
printf $DIVIDER
echo "Install CertBot..."
snap install core
snap refresh core
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot

# Set up unattended upgrades
printf $DIVIDER
echo "Set up unattended Upgrades..."
apt-get -y -q --no-install-recommends install unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# Set password for www-data user and allow shell access
printf $DIVIDER
echo "WWW-DATA USER"
echo "Set password for www-data user, set home directory permissions, and allow shell access."
passwd -u www-data
passwd www-data
mkdir /var/www
chown -R www-data:www-data /var/www
chsh -s /bin/bash www-data

# APACHE configuration
printf $DIVIDER
echo "APACHE CONFIGURATION"

# Create the systemd override directory for apache2.service if it doesn't already exist
echo "Automatic Apache server restart configuration"
mkdir -p /etc/systemd/system/apache2.service.d

# Write the override configuration to restart Apache automatically
cat <<EOF >/etc/systemd/system/apache2.service.d/override.conf
[Service]
Restart=always
RestartSec=5s
EOF

# Reload the systemd daemon to apply changes
systemctl daemon-reload

# Ensure Apache service is enabled to start on boot
systemctl enable apache2

# Restart Apache
systemctl restart apache2

echo "Apache modules..."
a2dismod php8.3 mpm_prefork
a2enmod expires headers rewrite ssl suphp proxy_fcgi setenvif mpm_event http2 security2

echo "Apache configurations..."
a2enconf php8.3-fpm
a2disconf security apache2-conf

if [ ! -f /etc/apache2/apache2.conf.orig ]; then
	echo "Backing up original configuration file to /etc/apache2/apache2.conf.orig"
	cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.orig
fi

echo "Changing MaxKeepAliveRequests to 0..."
FIND="^\s*MaxKeepAliveRequests \s*\d*"
REPLACE="MaxKeepAliveRequests 0"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

echo "Changing Timeout to 60..."
FIND="^\s*Timeout \s*\d*"
REPLACE="Timeout 60"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

echo "Adding security settings and caching..."
FIND="#<\/Directory>"
REPLACE="$(
	cat <<'EOF'
#</Directory>

# Disable Trace HTTP request
TraceEnable off

# Disable SSL and TSL under v1.2
SSLProtocol TLSv1.2

# Disable server signature
ServerSignature Off
ServerTokens Prod

# Browser Caching
ExpiresActive On
ExpiresDefault "access plus 1 year"
ExpiresByType text/html "access plus 15 minutes"
Header unset Last-Modified
Header unset ETag
FileETag None
EOF
)"
REPLACE=${REPLACE//\//\\\/}   # Escape the / characters
REPLACE=${REPLACE//$'\n'/\\n} # Escape the new line characters
REPLACE=${REPLACE//\$/\\$}    # Escape the $ characters
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

echo "Adding <Directory /srv/www/> configuration for /srv/www..."
FIND="#<\/Directory>"
REPLACE="$(
	cat <<'EOF'
#</Directory>

<Directory /srv/www/>
	Options +FollowSymLinks -Indexes -Includes
	AllowOverride all
	Require all granted
	IncludeOptional /etc/apache2/custom.d/globalblacklist.conf
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
EOF
)"
# Replace the placeholders with actual values
REPLACE=${REPLACE//ENC_KEY/$ENC_KEY}
REPLACE=${REPLACE//ENC_IV/$ENC_IV}
REPLACE=${REPLACE//\//\\\/}   # Escape the / characters
REPLACE=${REPLACE//$'\n'/\\n} # Escape the new line characters
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

if [ ! -f /etc/apache2/mods-available/deflate.conf.orig ]; then
	echo "Backing up original compression configuration file to /etc/apache2/mods-available/deflate.conf.orig"
	cp /etc/apache2/mods-available/deflate.conf /etc/apache2/mods-available/deflate.conf.orig
fi

echo "Adding compression for SVG and fonts..."
FIND="<\/IfModule>"
REPLACE="\t# Add SVG images\n\t\tAddOutputFilterByType DEFLATE image\/svg+xml\n\t\t# Add font files\n\t\tAddOutputFilterByType DEFLATE application\/x-font-woff\n\t\tAddOutputFilterByType DEFLATE application\/x-font-woff2\n\t\tAddOutputFilterByType DEFLATE application\/vnd.ms-fontobject\n\t\tAddOutputFilterByType DEFLATE application\/x-font-ttf\n\t\tAddOutputFilterByType DEFLATE application\/x-font-otf\n\t<\/IfModule>"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/deflate.conf

if [ ! -f /etc/apache2/mods-available/mime.conf.orig ]; then
	echo "Backing up original MIME configuration file to /etc/apache2/mods-available/mime.conf.orig"
	cp /etc/apache2/mods-available/mime.conf /etc/apache2/mods-available/mime.conf.orig
fi

echo "Adding MIME types for font files..."
FIND="<IfModule mod_mime\.c>"
REPLACE="<IfModule mod_mime\.c>\n\n\t# Add font files\n\tAddType application\/x-font-woff2 \.woff2\n\tAddType application\/x-font-otf \.otf\n\tAddType application\/x-font-ttf \.ttf\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mime.conf

if [ ! -f /etc/apache2/mods-available/dir.conf.orig ]; then
	echo "Backing up original directory listing configuration file to /etc/apache2/mods-available/dir.conf.orig"
	cp /etc/apache2/mods-available/dir.conf /etc/apache2/mods-available/dir.conf.orig
fi

echo "Making index.php the default file for directory listing..."
FIND="index\.php "
REPLACE=""
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/dir.conf

FIND="DirectoryIndex"
REPLACE="DirectoryIndex index\.php"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/dir.conf

if [ ! -f /etc/apache2/mods-available/mpm_event.conf.orig ]; then
	echo "Backing up original mpm_event configuration file to /etc/apache2/mods-available/mpm_event.conf.orig"
	cp /etc/apache2/mods-available/mpm_event.conf /etc/apache2/mods-available/mpm_event.conf.orig
fi

# APACHE memory settings
CPUS=$(nproc)                                                          # Number of CPUs
PROCMEM=32                                                             # Average amount of memory used by each request
SYSMEM=$(grep MemTotal /proc/meminfo | awk '{ printf "%d", $2/1024 }') # System memory in MB (rounded down)
AVAILMEM=$(((SYSMEM - 256) * 75 / 100))                                # Memory available to Apache: (Total - 256MB) x 75%
MAXWORKERS=$((AVAILMEM / PROCMEM))                                     # Max number of request workers: available memory / average request memory
MAXTHREADS=$((MAXWORKERS / CPUS))                                      # Max number of threads
MAXSPARETHREADS=$((MAXTHREADS * 2))                                    # Max number of spare threads

echo "Updating memory settings..."
FIND="^\s*StartServers\s*[0-9]*"
REPLACE="\tStartServers\t\t\t1\n\tServerLimit\t\t\t$CPUS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*MinSpareThreads\s*[0-9]*"
REPLACE="\tMinSpareThreads\t\t $MAXTHREADS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*MaxSpareThreads\s*[0-9]*"
REPLACE="\tMaxSpareThreads\t\t $MAXSPARETHREADS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*ThreadLimit\s*[0-9]*"
REPLACE="\tThreadLimit\t\t$MAXTHREADS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*ThreadsPerChild\s*[0-9]*"
REPLACE="\tThreadsPerChild\t\t$MAXTHREADS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*MaxRequestWorkers\s*[0-9]*"
REPLACE="\tMaxRequestWorkers\t\t$MAXWORKERS"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf
FIND="^\s*MaxConnectionsPerChild\s*[0-9]*"
REPLACE="\tMaxConnectionsPerChild  0"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mpm_event.conf

# Apache logs rotation and compression
if ! grep -q /srv/www/*/logs/ "/etc/logrotate.d/apache2"; then
	LOGROTATE="/srv/www/*/logs/access.log {
	monthly
	missingok
	rotate 12
	compress
	notifempty
	create 644 www-data www-data
}
/srv/www/*/logs/error.log {
	size 100M
	missingok
	rotate 4
	compress
	notifempty
	create 644 www-data www-data
}
"
	echo -e "$LOGROTATE" >>/etc/logrotate.d/apache2
fi

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

log_msg "Main domain: $domain"
log_msg "Staging domain: $stg_domain"
log_msg "Development domain: $dev_domain"

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

# PHP
printf $DIVIDER
echo "PHP"
echo "The script will update PHP configuration"

if [ ! -f /etc/php/8.3/fpm/php.ini.orig ]; then
	echo "Backing up PHP.ini configuration file to /etc/php/8.3/fpm/php.ini.orig"
	cp /etc/php/8.3/fpm/php.ini /etc/php/8.3/fpm/php.ini.orig
fi

FIND="^\s*output_buffering\s*=\s*.*"
REPLACE="output_buffering = Off"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*max_execution_time\s*=\s*.*"
REPLACE="max_execution_time = 60"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*error_reporting\s*=\s*.*"
REPLACE="error_reporting = E_ALL \& ~E_NOTICE \& ~E_STRICT \& ~E_DEPRECATED"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*log_errors_max_len\s*=\s*.*"
REPLACE="log_errors_max_len = 0"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*post_max_size\s*=\s*.*"
REPLACE="post_max_size = 50M"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*upload_max_filesize\s*=\s*.*"
REPLACE="upload_max_filesize = 50M"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*short_open_tag\s*=\s*.*"
REPLACE="short_open_tag = On"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

FIND="^\s*;\s*max_input_vars\s*=\s*.*" # this is commented in the original file
REPLACE="max_input_vars = 10000"
echo "php.ini: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/php.ini

if [ ! -f /etc/php/8.3/fpm/pool.d/www.conf.orig ]; then
	echo "Backing up PHP-FPM Pool configuration file to /etc/php/8.3/fpm/pool.d/www.conf.orig"
	cp /etc/php/8.3/fpm/pool.d/www.conf /etc/php/8.3/fpm/pool.d/www.conf.orig
fi

MAXCHILDREN=$((MAXWORKERS / 8)) # Max number of PHP-FPM processes
STARTSERVERS=$((CPUS * 4))
MINSPARESERVERS=$((CPUS * 2))

FIND="^\s*pm\.max_children\s*=\s*.*"
REPLACE="pm.max_children = $MAXCHILDREN"
echo "www.conf: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/pool.d/www.conf
FIND="^\s*pm\.start_servers\s*=\s*.*"
REPLACE="pm.start_servers = $STARTSERVERS"
echo "www.conf: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/pool.d/www.conf
FIND="^\s*pm\.min_spare_servers\s*=\s*.*"
REPLACE="pm.min_spare_servers = $MINSPARESERVERS"
echo "www.conf: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/pool.d/www.conf
FIND="^\s*pm\.max_spare_servers\s*=\s*.*"
REPLACE="pm.max_spare_servers = $STARTSERVERS"
echo "www.conf: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/pool.d/www.conf
FIND="^\s*;\s*pm\.max_requests\s*=\s*.*"
REPLACE="pm.max_requests = $STARTSERVERS"
echo "www.conf: $REPLACE"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/8.3/fpm/pool.d/www.conf

# Enable PHP-FPM
systemctl enable php8.3-fpm

# Restart Apache
echo "Restarting PHP-FPM and Apache..."
service php8.3-fpm start
service apache2 restart

# Install MySQL
printf $DIVIDER
echo "Install MySQL"

echo "Installing MySQL server and client..."
apt-get -y -q --no-install-recommends install mysql-server mysql-client
if [ ! -f /etc/mysql/mysql.conf.d/mysqld.cnf.orig ]; then
	echo "Backing up my.cnf configuration file to /etc/mysql/mysql.conf.d/mysqld.cnf.orig"
	cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.orig
fi

echo "Download optimized MySQL configuration to /etc/mysql/conf.d/my.cnf"
wget -O /etc/mysql/conf.d/my.cnf https://gist.github.com/fevangelou/fb72f36bbe333e059b66/raw/d1a8410c7a187f5142b7a15fcabdc445587dfe91/my.cnf

# Create the systemd override directory for mysql.service if it doesn't already exist
mkdir -p /etc/systemd/system/mysql.service.d

# Write the override configuration to restart MySQL automatically
echo "Automatic MySQL server restart configuration"
cat <<EOF >/etc/systemd/system/mysql.service.d/override.conf
[Service]
Restart=always
RestartSec=5s
EOF

# Reload the systemd daemon to apply changes
systemctl daemon-reload

# Ensure MySQL service is enabled to start on boot
systemctl enable mysql

# Restart MySQL
systemctl restart mysql

while true; do
	read -sp "Enter NEW password for MySQL root: " mysqlrootpsw
	case $mysqlrootpsw in
	"") echo "Password may not be left blank" ;;
	*) break ;;
	esac
done
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$mysqlrootpsw';"

echo "Secure MySQL installation"
echo "Make sure you answer the questions that will be prompted as follows:"
echo " - Validate password component: No"
echo " - Change password for root: No"
echo " - Remove anonymous users: Yes"
echo " - Disallow root login remotely: Yes"
echo " - Remove test database: Yes"
echo " - Reload the privilege tables now: Yes"
read -p "Please ENTER to continue "
mysql_secure_installation

printf $DIVIDER
echo "Setup databases and users"

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
	echo "Processing environment: $env"

	# Encrypt and handle database name
	dbname_value="${dbnames[$env]}"
	encrypted_dbname_value=$(echo -n "$dbname_value" | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $ENC_KEY -iv $ENC_IV | tr -d '\n')
	dbnames[$env]=$encrypted_dbname_value
	log_msg "$env dbname: $dbname_value"

	# Encrypt and handle database user
	dbuser_value="${dbusers[$env]}"
	encrypted_dbuser_value=$(echo -n "$dbuser_value" | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $ENC_KEY -iv $ENC_IV | tr -d '\n')
	dbusers[$env]=$encrypted_dbuser_value
	log_msg "$env dbuser: $dbuser_value"

	# Encrypt and handle database password
	dbpass_value="${dbpasss[$env]}"
	encrypted_dbpass_value=$(echo -n "$dbpass_value" | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $ENC_KEY -iv $ENC_IV | tr -d '\n')
	dbpasss[$env]=$encrypted_dbpass_value
	log_msg "$env dbpass: $dbpass_value"

	# Create database
	echo "Create database $dbname_value..."
	mysql -u root -p"$mysqlrootpsw" -e "CREATE DATABASE $dbname_value;"
	# Create user with the original password
	echo "Create user $dbuser_value..."
	mysql -u root -p"$mysqlrootpsw" -e "CREATE USER '$dbuser_value'@'localhost' IDENTIFIED BY '$dbpass_value';"

	# Grant privileges
	echo "Grant $dbuser_value all privileges on $dbname_value..."
	mysql -u root -p"$mysqlrootpsw" -e "GRANT ALL PRIVILEGES ON $dbname_value.* TO '$dbuser_value'@'localhost';"
done

echo "Restart MySQL..."
service mysql restart

echo "Add automatic database dump and rotation..."
#write out current crontab
crontab -l >mycron.txt
#echo new cron into cron file
cat >>mycron.txt <<EOL
# Daily 00:00 - database check and optimization
0 0 * * * mysqlcheck -Aos -u root -p'$mysqlrootpsw' > /dev/null 2>&1

# Daily 01:00 - database dump
0 1 * * * mysqldump -u root -p'$mysqlrootpsw' --all-databases --single-transaction --quick > /var/lib/mysql/daily.sql

# Mondays 02:00 - copy daily database dump to weekly
0 2 * * 0 cp /var/lib/mysql/daily.sql /var/lib/mysql/weekly.sql

# First Day of the Month 02:00 - copy daily database dump to monthly
0 2 1 * * cp /var/lib/mysql/daily.sql /var/lib/mysql/monthly.sql

# Daily 05:00 update apache bad bot blocker definitions
0 5 * * * /usr/sbin/apache-bad-bot-blocker.sh

# Sundays 03:00 - restart Apache and MySQL
0 3 * * 0 service apache2 restart
0 3 * * 0 service mysql restart

# Sundays 03:15 - Update and upgrade OS
15 3 * * 0 apt-get update && apt-get -y upgrade

# First Day of the Month  04:00 - restart server
0 4 1 * * /sbin/shutdown -r now

# Twice Daily 06:00, 18:00 - check and update ssl certificates
0 6,18 * * * /usr/bin/certbot renew --quiet

EOL
#install new cron file
crontab mycron.txt
rm mycron.txt

if [ ! -f /etc/logrotate.d/mysql-backup ]; then
	echo "Creating database backup rotation and compression file"
	printf "# Daily\n/var/lib/mysql/daily.sql {\n\t daily\n\t missingok\n\t rotate 7\n\t compress\n\t copy\n}\n\n# Weekly\n/var/lib/mysql/weekly.sql {\n\t weekly\n\t missingok\n\t rotate 4\n\t compress\n\t copy\n}\n\n# Monthly\n/var/lib/mysql/monthly.sql {\n\t monthly\n\t missingok\n\t rotate 12\n\t compress\n\t copy\n}\n" >/etc/logrotate.d/mysql-backup
fi

# Create wp-secrets.php file
printf $DIVIDER
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
			$secrets[$var] = trim(openssl_decrypt($secrets[$var], "AES-256-CBC", $key, 0, $iv));
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
echo "Create .htaccess file"
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
echo "PHP Deploy script config"

# Prompt to continue
while true; do
	read -p "Do you want to setup PHP Deploy script? [Y/N]? " cnt2
	case $cnt2 in
	[Yy]*)
		# Get the home directory of www-data
		WWW_DATA_HOME=$(getent passwd www-data | cut -d: -f6)

		# Create ~/.ssh directory for www-data user
		echo "Creating $WWW_DATA_HOME/.ssh directory for www-data user"
		sudo -u www-data mkdir $WWW_DATA_HOME/.ssh

		echo "Creating the deployment key..."
		sudo -u www-data ssh-keygen -t rsa -N '' -f $WWW_DATA_HOME/.ssh/php-git-deploy_key

		echo "Creating a SSH config file..."
		sudo -u www-data printf "Host github.com\n\tIdentityFile ~/.ssh/php-git-deploy_key\nHost bitbucket.org\n\tIdentityFile ~/.ssh/php-git-deploy_key\n" >$WWW_DATA_HOME/.ssh/config

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

		# Clone the repository
		echo "You must copy this deployment key in your repository settings in GitHub or Bitbucket"
		log_msg "Deployment key:"
		log_msg "$(cat $WWW_DATA_HOME/.ssh/php-git-deploy_key.pub)"
		read -p "Press Enter when ready to continue..."
		echo "Cloning the repository to establish SSH keys"
		echo "Answer Yes when prompted and ignore the permission denied error message"
		sudo -u www-data mkdir -p $WWW_DATA_HOME/git
		sudo -u www-data git clone --depth=1 --branch $branch $gitaddr $WWW_DATA_HOME/git
		sudo -u www-data rm -rf $WWW_DATA_HOME/git

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
			$secrets[$var] = trim(openssl_decrypt($secrets[$var], "AES-256-CBC", $key, 0, $iv));
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
				log_msg "$env webhook: https://${domains[$env]}/deploy.php?t=$ACCESS_TOKEN&b=${branches[$env]}\n"
			else
				log_msg "$env webhook: https://$HTUSER:review@${domains[$env]}/deploy.php?t=$ACCESS_TOKEN&b=${branches[$env]}\n"
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

		break
		;;
	[Nn]*) break ;;
	*) echo "Please answer Y or N" ;;
	esac
done

echo "Download site-setup.sh script..."
wget https://raw.githubusercontent.com/Lyquix/ubuntu-lamp/master/site-setup.sh -O /srv/www/site-setup.sh
chown www-data:www-data /srv/www/site-setup.sh
chmod +x /srv/www/site-setup.sh

echo "Download file-permissions.sh script..."
wget https://raw.githubusercontent.com/Lyquix/ubuntu-lamp/master/file-permissions.sh -O /srv/www/file-permissions.sh
chown www-data:www-data /srv/www/file-permissions.sh
chmod +x /srv/www/file-permissions.sh

# Set firewall rules
printf $DIVIDER
echo "Setting up firewall rules..."
iptables -F
iptables -P INPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP
ip6tables -F
ip6tables -P INPUT ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -j DROP
ip6tables -P OUTPUT ACCEPT
ip6tables -P FORWARD DROP

echo "Saving firewall rules..."
mkdir /etc/iptables
iptables-save >/etc/iptables/rules.v4
ip6tables-save >/etc/iptables/rules.v6

# Set fail2ban jails
printf $DIVIDER
echo "Setting up fail2ban jails rules..."
FAIL2BANJAILS="[sshd]\nenabled = true

[sshd-ddos]
enabled = true

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true

[apache-nohome]
enabled = true

[apache-botsearch]
enabled = true

[apache-fakegooglebot]
enabled = true

[apache-modsecurity]
enabled = true

[apache-shellshock]
enabled = true

[php-url-fopen]
enabled = true
"
echo -e "$FAIL2BANJAILS" >/etc/fail2ban/jail.local
service fail2ban restart

# Get OWASP rules for ModSecurity
printf $DIVIDER
echo "Downloading OWASP rules for ModSecurity..."
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.2/master.zip -O /tmp/owasp-modsecurity-crs.zip
unzip -q /tmp/owasp-modsecurity-crs.zip -d /tmp
rm /tmp/owasp-modsecurity-crs.zip
mv /tmp/owasp-modsecurity-crs-3.2-master/crs-setup.conf.example /etc/modsecurity/owasp-crs-setup.conf
mv /tmp/owasp-modsecurity-crs-3.2-master/rules /etc/modsecurity/
rm -r /tmp/owasp-modsecurity-crs-3.2-master

if [ ! -f /etc/apache2/mods-available/security2.conf.orig ]; then
	echo "Backing up original ModSecurity configuration file to /etc/apache2/mods-available/security2.conf.orig"
	cp /etc/apache2/mods-available/security2.conf /etc/apache2/mods-available/security2.conf.orig
fi

echo "Adding OWASP rules in ModSecurity configuration..."
FIND="^\s*IncludeOptional"
REPLACE="\t# IncludeOptional"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/security2.conf
# Replace again
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/security2.conf
FIND="<\/IfModule>"
REPLACE="\tIncludeOptional \/etc\/modsecurity\/owasp-crs-setup.conf\n\tIncludeOptional \/etc\/modsecurity\/rules\/\*.conf\n<\/IfModule>"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/security2.conf

# Set up Bad Bots Blocker
printf $DIVIDER
echo "Set up Bad Bot Blocker..."
echo "$(
	cat <<'EOF'
#!/bin/bash

REPO="https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/Apache_2.4/custom.d"
DIR="/etc/apache2/custom.d"

mkdir -p $DIR

wget -q $REPO/globalblacklist.conf -O $DIR/globalblacklist.conf

if [ ! -f $DIR/bad-referrer-words.conf ]; then
	echo "SetEnvIfNoCase Referer ~*badreferrername spam_ref" >  $DIR/bad-referrer-words.conf
fi
if [ ! -f $DIR/blacklist-ips.conf ]; then
	echo "Require not ip 0.0.0.0" > $DIR/blacklist-ips.conf
fi
if [ ! -f $DIR/blacklist-user-agents.conf ]; then
	echo "BrowserMatchNoCase \"^(.*?)(\bBadUserAgentName\b)(.*)$\" bad_bot" > $DIR/blacklist-user-agents.conf
fi
if [ ! -f $DIR/whitelist-domains.conf ]; then
	echo "SetEnvIfNoCase Referer \"~*example\.com\" good_ref" > $DIR/whitelist-domains.conf
fi
if [ ! -f $DIR/whitelist-ips.conf ]; then
	echo "Require ip 127.0.0.1" > $DIR/whitelist-ips.conf
fi

service apache2 reload

exit 0
EOF
)" >/usr/sbin/apache-bad-bot-blocker.sh
chmod 744 /usr/sbin/apache-bad-bot-blocker.sh
/usr/sbin/apache-bad-bot-blocker.sh

# The End
printf $DIVIDER
echo "The script executing has finished!"
echo "Please check the log file $SETUP_DIR/lamp-ubuntu24.log for important information and any errors."
echo "You will need to copy files in $SETUP_DIR to each site and your local environment"

# Save the log at the end
printf "%s\n" "${LOGMSG[@]}" >>$SETUP_DIR/lamp-ubuntu24.log

exit
