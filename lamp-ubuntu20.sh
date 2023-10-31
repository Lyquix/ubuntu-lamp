#!/bin/bash

# Ubuntu LAMP Setup Script
# https://github.com/Lyquix/ubuntu-lamp

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
   printf "This script must be run as root!\n"
   exit 1
fi

DIVIDER="\n***************************************\n\n"
NEEDRESTART_MODE=a

# Welcome and instructions
printf $DIVIDER
printf "Lyquix LAMP server setup on Ubuntu 20.04\n"
printf $DIVIDER

# Prompt to continue
while true; do
	read -p "Continue [Y/N]? " cnt1
	case $cnt1 in
		[Yy]* ) break;;
		[Nn]* ) exit;;
		* ) printf "Please answer Y or N\n";;
	esac
done

# Change the swappiness to 10
echo "vm.swappiness = 10" >> /etc/sysctl.conf
sysctl -p

# Set the hostname
printf $DIVIDER
printf "HOSTNAME\n"
printf "Pick a hostname that identify this server.\nRecommended: use the main domain, e.g. example.com\n"
while true; do
	read -p "Hostname: " host
	case $host in
		"" ) printf "Hostname may not be left blank\n";;
		* ) break;;
	esac
done
echo "$host" > /etc/hostname
hostname -F /etc/hostname
printf "127.2.1       $host\n::1             $host\n" >> /etc/hosts;

# Set the time zone
printf $DIVIDER
printf "TIME ZONE\n"
printf "Please select the correct time zone. e.g. US > Eastern Time\n"
read -p "Please ENTER to continue "
dpkg-reconfigure tzdata

# Install and update software
printf $DIVIDER
printf "INSTALL AND UPDATE SOFTWARE\n"
printf "Now the script will update Ubuntu and install all the necessary software.\n"
printf " * You will be prompted to enter the password for the MySQL root user\n"
read -p "Please ENTER to continue "
printf "Repository update...\n"
apt-get update --fix-missing
printf "Upgrade installed packages...\n"
apt-get -y upgrade
printf "Install utilities...\n"
NEEDRESTART_MODE=a
PCKGS=("curl" "vim" "openssl" "git" "htop" "nload" "nethogs" "zip" "unzip" "sendmail" "sendmail-bin" "mysqltuner" "libcurl3-openssl-dev" "psmisc" "build-essential" "zlib1g-dev" "libpcre3" "libpcre3-dev" "memcached" "fail2ban" "iptables-persistent" "software-properties-common")
for PCKG in "${PCKGS[@]}"
do
	echo "$PCKG"
	apt-get -y -q=2 install ${PCKG}
done
printf "Install Apache...\n"
PCKGS=("apache2" "apache2-doc" "apachetop" "libapache2-mod-php" "libapache2-mod-fcgid" "apache2-suexec-pristine" "libapache2-mod-security2")
for PCKG in "${PCKGS[@]}"
do
	echo "$PCKG"
	apt-get -y -q=2 install ${PCKG}
done
printf "Install PHP...\n"
PCKGS=("mcrypt" "imagemagick" "php7.4" "php7.4-common" "php7.4-gd" "php7.4-imap" "php7.4-mysql" "php7.4-mysqli" "php7.4-cli" "php7.4-cgi" "php7.4-fpm" "php7.4-zip" "php-pear" "php-imagick" "php7.4-curl" "php7.4-mbstring" "php7.4-bcmath" "php7.4-xml" "php7.4-soap" "php7.4-opcache" "php7.4-intl" "php-apcu" "php-mail" "php-mail-mime" "php-all-dev" "php7.4-dev" "libapache2-mod-php7.4" "php7.4-memcached" "php-auth" "php-mcrypt" "composer")
for PCKG in "${PCKGS[@]}"
do
	echo "$PCKG"
	apt-get -y -q=2 install ${PCKG}
done

# Install MySQL
printf "Install MySQL...\n"
apt-get -y -q=2 install mysql-server mysql-client

# Install CertBot
printf "Install CertBot...\n"
snap install core
snap refresh core
snap install --classic certbot
ln -s /snap/bin/certbot /usr/bin/certbot

# Set up unattended upgrades
printf "Set up unattended Upgrades...\n"
apt-get -y -q=2 install unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# Set password for www-data user and allow shell access
printf $DIVIDER
printf "WWW-DATA USER\n"
printf "Set password for www-data user, set home directory permissions, and allow shell access.\n"
passwd -u www-data
passwd www-data
mkdir /var/www
chown -R www-data:www-data /var/www
chsh -s /bin/bash www-data

# APACHE configuration
printf $DIVIDER
printf "APACHE CONFIGURATION\n"
read -p "Please ENTER to continue "

printf "Apache modules...\n"
a2dismod php7.4
a2enmod expires headers rewrite ssl suphp proxy_fcgi setenvif mpm_event http2 security2

printf "Apache configurations...\n"
a2enconf php7.4-fpm
a2disconf security

if [ ! -f /etc/apache2/apache2.conf.orig ]; then
	printf "Backing up original configuration file to /etc/apache2/apache2.conf.orig\n"
	cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.orig
fi

printf "Changing MaxKeepAliveRequests to 0...\n"
FIND="^\s*MaxKeepAliveRequests \s*\d*"
REPLACE="MaxKeepAliveRequests 0"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

printf "Changing Timeout to 60...\n"
FIND="^\s*Timeout \s*\d*"
REPLACE="Timeout 60"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

printf "Adding security settings and caching...\n"
FIND="#<\/Directory>"
REPLACE="$(cat << 'EOF'
#</Directory>

# Disable Trace HTTP request
TraceEnable off

# Disable SSL v2 & v3
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
REPLACE=${REPLACE//\//\\\/} # Escape the / characters
REPLACE=${REPLACE//$'\n'/\\n} # Escape the new line characters
REPLACE=${REPLACE//\$/\\$} # Escape the $ characters
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

printf "Adding <Directory /srv/www/> configuration for /srv/www...\n"
FIND="#<\/Directory>"
REPLACE="$(cat << 'EOF'
#</Directory>

<Directory /srv/www/>
    Options +FollowSymLinks -Indexes -Includes
    AllowOverride all
    Require all granted
    IncludeOptional /etc/apache2/custom.d/globalblacklist.conf
    Header set Access-Control-Allow-Origin "*"
    Header set Timing-Allow-Origin: "*"
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options sameorigin
    Header unset X-Powered-By
    Header set X-XSS-Protection "1; mode=block"

    # Disable unused HTTP request methods
    <LimitExcept GET POST HEAD OPTIONS>
      deny from all
    </LimitExcept>
</Directory>
EOF
)"
REPLACE=${REPLACE//\//\\\/} # Escape the / characters
REPLACE=${REPLACE//$'\n'/\\n} # Escape the new line characters
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/apache2.conf

if [ ! -f /etc/apache2/mods-available/deflate.conf.orig ]; then
	printf "Backing up original compression configuration file to /etc/apache2/mods-available/deflate.conf.orig\n"
	cp /etc/apache2/mods-available/deflate.conf /etc/apache2/mods-available/deflate.conf.orig
fi

printf "Adding compression for SVG and fonts...\n"
FIND="<\/IfModule>"
REPLACE="\t# Add SVG images\n\t\tAddOutputFilterByType DEFLATE image\/svg+xml\n\t\t# Add font files\n\t\tAddOutputFilterByType DEFLATE application\/x-font-woff\n\t\tAddOutputFilterByType DEFLATE application\/x-font-woff2\n\t\tAddOutputFilterByType DEFLATE application\/vnd.ms-fontobject\n\t\tAddOutputFilterByType DEFLATE application\/x-font-ttf\n\t\tAddOutputFilterByType DEFLATE application\/x-font-otf\n\t<\/IfModule>"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/deflate.conf

if [ ! -f /etc/apache2/mods-available/mime.conf.orig ]; then
	printf "Backing up original MIME configuration file to /etc/apache2/mods-available/mime.conf.orig\n"
	cp /etc/apache2/mods-available/mime.conf /etc/apache2/mods-available/mime.conf.orig
fi

printf "Adding MIME types for font files...\n"
FIND="<IfModule mod_mime\.c>"
REPLACE="<IfModule mod_mime\.c>\n\n\t# Add font files\n\tAddType application\/x-font-woff2 \.woff2\n\tAddType application\/x-font-otf \.otf\n\tAddType application\/x-font-ttf \.ttf\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/mime.conf

if [ ! -f /etc/apache2/mods-available/dir.conf.orig ]; then
	printf "Backing up original directory listing configuration file to /etc/apache2/mods-available/dir.conf.orig\n"
	cp /etc/apache2/mods-available/dir.conf /etc/apache2/mods-available/dir.conf.orig
fi

printf "Making index.php the default file for directory listing...\n"
FIND="index\.php "
REPLACE=""
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/dir.conf

FIND="DirectoryIndex"
REPLACE="DirectoryIndex index\.php"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/dir.conf

if [ ! -f /etc/apache2/mods-available/mpm_event.conf.orig ]; then
	printf "Backing up original mpm_event configuration file to /etc/apache2/mods-available/mpm_event.conf.orig\n"
	cp /etc/apache2/mods-available/mpm_event.conf /etc/apache2/mods-available/mpm_event.conf.orig
fi

# APACHE memory settings
CPUS=$(nproc) # Number of CPUs
PROCMEM=32 # Average amount of memory used by each request
SYSMEM=$(grep MemTotal /proc/meminfo | awk '{ printf "%d", $2/1024 }') # System memory in MB (rounded down)
AVAILMEM=$(( (SYSMEM-256)*75/100 )) # Memory available to Apache: (Total - 256MB) x 75%
MAXWORKERS=$(( AVAILMEM/PROCMEM )) # Max number of request workers: available memory / average request memory
MAXTHREADS=$(( MAXWORKERS/CPUS )) # Max number of threads
MAXSPARETHREADS=$(( MAXTHREADS*2 )) # Max number of spare threads

printf "Updating memory settings...\n"
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
	echo -e "$LOGROTATE" >> /etc/logrotate.d/apache2
fi

#ModPageSpeed
printf $DIVIDER
printf "MODPAGESPEED\n"
printf "Please answer Yes when prompted\n"
read -p "Press ENTER to continue"
wget https://dl-ssl.google.com/dl/linux/direct/mod-pagespeed-stable_current_amd64.deb
dpkg -i mod-pagespeed*.deb
rm mod-pagespeed*.deb
apt-get -f install

if [ ! -f /etc/apache2/mods-available/pagespeed.conf.orig ]; then
	printf "Backing up original ModPagespeed configuration file to /etc/apache2/mods-available/pagespeed.conf.orig\n"
	cp /etc/apache2/mods-available/pagespeed.conf /etc/apache2/mods-available/pagespeed.conf.orig
fi
printf "Set ModPagespeed filters to CoreFilters...\n"
FIND="^\s*#*\s*ModPagespeedRewriteLevel\s+PassThrough"
REPLACE="\tModPagespeedRewriteLevel CoreFilters"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/apache2/mods-available/pagespeed.conf

# Virtual Hosts
printf $DIVIDER
printf "VIRTUAL HOSTS\n"
printf "The script will setup the base virtual hosts configuration. Using the main domain name it will:\n"
printf " * Setup configuration files for example.com (with alias www.example.com), and dev.example.com\n"
printf " * Setup the necessary directories\n"
while true; do
	read -p "Please enter the main domain (e.g. example.com): " domain
	case $domain in
		"" ) printf "Domain may not be left blank\n";;
		* ) break;;
	esac
done

# Get IPv4
IPV4=$(ip -4 addr | grep inet | grep -v '127.0.0.1' | awk -F '[ \t]+|/' '{print $3}' | grep -v ^127.2.1)

# Backup previous virtual host files
if [ -f /etc/apache2/sites-available/$domain.conf ]; then
	printf "Backing up existing virtual host configuration file to /etc/apache2/sites-available/$domain.conf.bak\n"
	cp /etc/apache2/sites-available/$domain.conf /etc/apache2/sites-available/$domain.conf.bak
fi

# Production
VIRTUALHOST="<VirtualHost $IPV4:80>
	ServerName $domain
	ServerAlias www.$domain
	DocumentRoot /srv/www/$domain/public_html/
	ErrorLog /srv/www/$domain/logs/error.log
	CustomLog /srv/www/$domain/logs/access.log combined
</VirtualHost>\n";
echo -e "$VIRTUALHOST" > /etc/apache2/sites-available/$domain.conf

# Development
VIRTUALHOST="<VirtualHost $IPV4:80>
	ServerName dev.$domain
	DocumentRoot /srv/www/dev.$domain/public_html/
	ErrorLog /srv/www/dev.$domain/logs/error.log
	CustomLog /srv/www/dev.$domain/logs/access.log combined
</VirtualHost>\n";
echo -e "$VIRTUALHOST" > /etc/apache2/sites-available/dev.$domain.conf

# Create directories
mkdir -p /srv/www/$domain/public_html
mkdir -p /srv/www/$domain/logs
mkdir -p /srv/www/dev.$domain/public_html
mkdir -p /srv/www/dev.$domain/logs
chown -R www-data:www-data /srv/www

# Enable sites
a2ensite $domain
a2ensite dev.$domain
service apache2 reload

# PHP
printf $DIVIDER
printf "PHP\n"
printf "The script will update PHP configuration\n"
read -p "Press ENTER to continue"

if [ ! -f /etc/php/7.4/fpm/php.ini.orig ]; then
	printf "Backing up PHP.ini configuration file to /etc/php/7.4/fpm/php.ini.orig\n"
	cp /etc/php/7.4/fpm/php.ini /etc/php/7.4/fpm/php.ini.orig
fi

FIND="^\s*output_buffering\s*=\s*.*"
REPLACE="output_buffering = Off"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*max_execution_time\s*=\s*.*"
REPLACE="max_execution_time = 60"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*error_reporting\s*=\s*.*"
REPLACE="error_reporting = E_ALL \& ~E_NOTICE \& ~E_STRICT \& ~E_DEPRECATED"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*log_errors_max_len\s*=\s*.*"
REPLACE="log_errors_max_len = 0"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*post_max_size\s*=\s*.*"
REPLACE="post_max_size = 20M"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*upload_max_filesize\s*=\s*.*"
REPLACE="upload_max_filesize = 20M"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*short_open_tag\s*=\s*.*"
REPLACE="short_open_tag = On"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

FIND="^\s*;\s*max_input_vars\s*=\s*.*" # this is commented in the original file
REPLACE="max_input_vars = 5000"
printf "php.ini: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/php.ini

if [ ! -f /etc/php/7.4/fpm/pool.d/www.conf.orig ]; then
	printf "Backing up PHP-FPM Pool configuration file to /etc/php/7.4/fpm/pool.d/www.conf.orig\n"
	cp /etc/php/7.4/fpm/pool.d/www.conf /etc/php/7.4/fpm/pool.d/www.conf.orig
fi

MAXCHILDREN=$(( MAXWORKERS/8 )) # Max number of PHP-FPM processes
STARTSERVERS=$(( CPUS*4 ))
MINSPARESERVERS=$(( CPUS*2 ))

FIND="^\s*pm\.max_children\s*=\s*.*"
REPLACE="pm.max_children = $MAXCHILDREN"
printf "www.conf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/pool.d/www.conf
FIND="^\s*pm\.start_servers\s*=\s*.*"
REPLACE="pm.start_servers = $STARTSERVERS"
printf "www.conf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/pool.d/www.conf
FIND="^\s*pm\.min_spare_servers\s*=\s*.*"
REPLACE="pm.min_spare_servers = $MINSPARESERVERS"
printf "www.conf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/pool.d/www.conf
FIND="^\s*pm\.max_spare_servers\s*=\s*.*"
REPLACE="pm.max_spare_servers = $STARTSERVERS"
printf "www.conf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/pool.d/www.conf
FIND="^\s*;\s*pm\.max_requests\s*=\s*.*"
REPLACE="pm.max_requests = $STARTSERVERS"
printf "www.conf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/php/7.4/fpm/pool.d/www.conf

# Enable PHP-FPM
systemctl enable php7.4-fpm

# Restart Apache
printf "Restarting PHP-FPM and Apache...\n"
service php7.4-fpm start
service apache2 restart


# MySQL
printf $DIVIDER
printf "MYSQL\n"
printf "The script will update MySQL and setup intial databases\n"
read -p "Press ENTER to continue"

if [ ! -f /etc/mysql/mysql.conf.d/mysqld.cnf.orig ]; then
	printf "Backing up my.cnf configuration file to /etc/mysql/mysql.conf.d/mysqld.cnf.orig\n"
	cp /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mysql.conf.d/mysqld.cnf.orig
fi

printf "Updating configuration\n"

FIND="^\s*key_buffer\s*=\s*.*"
REPLACE="key_buffer=16M"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*max_allowed_packet\s*=\s*.*"
REPLACE="max_allowed_packet=16M"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*thread_stack\s*=\s*.*"
REPLACE="thread_stack=192K"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*thread_cache_size\s*=\s*.*"
REPLACE="thread_cache_size=8"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*#\s*table_cache\s*=\s*.*" # commented by default
REPLACE="table_cache=64"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*#\s*log_slow_queries\s*=\s*.*" # commented by default
REPLACE="log_slow_queries = /var/log/mysql/mysql-slow.log"
printf "my.cnf: $REPLACE\n"
REPLACE=${REPLACE//\//\\\/} # Escape the / characters
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

FIND="^\s*#\s*long_query_time\s*=\s*.*" # commented by default
REPLACE="long_query_time=1"
printf "my.cnf: $REPLACE\n"
perl -pi -e "s/$FIND/$REPLACE/m" /etc/mysql/mysql.conf.d/mysqld.cnf

while true; do
	read -sp "Enter password for MySQL root: " mysqlrootpsw
	case $mysqlrootpsw in
		"" ) printf "Password may not be left blank\n";;
		* ) break;;
	esac
done
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$mysqlrootpsw';"

printf "Secure MySQL installation\n"
printf "Make sure you answer the questions that will be prompted as follows:\n"
printf " - Validate password component: No\n"
printf " - Change password for root: No\n"
printf " - Disallow root login remotely: Yes\n"
printf " - Remove anonymous users: Yes\n"
printf " - Remove test database: Yes\n"
printf " - Reload the privilege tables now: Yes\n"
read -p "Please ENTER to continue "
mysql_secure_installation

printf "Setup databases and users\n"

printf "\nPlease set name for databases, users and passwords\n"
while true; do
	read -p "Production database name (recommended: use domain without TLD, for mydomain.com use mydomain): " dbname
	case $dbname in
		"" ) printf "Database name may not be left blank\n";;
		* ) break;;
	esac
done
while true; do
	read -p "Production database user (recommended: use same as database name, max 16 characters): " dbuser
	case $dbuser in
		"" ) printf "User name may not be left blank\n";;
		* ) break;;
	esac
done
while true; do
	read -sp "Production database password: " dbpass
	case $dbpass in
		"" ) printf "\nPassword may not be left blank\n";;
		* ) break;;
	esac
done
while true; do
	printf "\n"
	read -p "Development database name (recommended: use domain without TLD followed by _dev, for mydomain.com use mydomain_dev): " devdbname
	case $devdbname in
		"" ) printf "Database name may not be left blank\n";;
		* ) break;;
	esac
done
while true; do
	read -p "Development database user (recommended: use same as database name, max 16 characters): " devdbuser
	case $devdbuser in
		"" ) printf "User name may not be left blank\n";;
		* ) break;;
	esac
done
while true; do
	read -sp "Development database password: " devdbpass
	case $devdbpass in
		"" ) printf "\nPassword may not be left blank\n";;
		* ) break;;
	esac
done

printf "Create database $dbname...\n"
mysql -u root -p$mysqlrootpsw -e "CREATE DATABASE $dbname;"
printf "Create user $dbuser...\n"
mysql -u root -p$mysqlrootpsw -e "CREATE USER '$dbuser'@localhost IDENTIFIED BY '$dbpass';"
printf "Grant $dbuser all privileges on $dbname...\n"
mysql -u root -p$mysqlrootpsw -e "GRANT ALL PRIVILEGES ON $dbname.* TO '$dbuser'@localhost;"
printf "Create database $devdbname...\n"
mysql -u root -p$mysqlrootpsw -e "CREATE DATABASE $devdbname;"
printf "Create user $devdbuser...\n"
mysql -u root -p$mysqlrootpsw -e "CREATE USER '$devdbuser'@localhost IDENTIFIED BY '$devdbpass';"
printf "Grant $devdbuser all privileges on $devdbname...\n"
mysql -u root -p$mysqlrootpsw -e "GRANT ALL PRIVILEGES ON $devdbname.* TO '$devdbuser'@localhost;"

printf "Restart MySQL...\n"
service mysql restart

printf "Add automatic database dump and rotation...\n"
#write out current crontab
crontab -l > mycron.txt
#echo new cron into cron file
cat >> mycron.txt <<EOL
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
	printf "Creating database backup rotation and compression file\n"
	printf "# Daily\n/var/lib/mysql/daily.sql {\n\t daily\n\t missingok\n\t rotate 7\n\t compress\n\t copy\n}\n\n# Weekly\n/var/lib/mysql/weekly.sql {\n\t weekly\n\t missingok\n\t rotate 4\n\t compress\n\t copy\n}\n\n# Monthly\n/var/lib/mysql/monthly.sql {\n\t monthly\n\t missingok\n\t rotate 12\n\t compress\n\t copy\n}\n" > /etc/logrotate.d/mysql-backup
fi

# Set firewall rules
printf $DIVIDER
printf "Setting up firewall rules...\n"
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

printf "Saving firewall rules...\n"
mkdir /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Set fail2ban jails
printf $DIVIDER
printf "Setting up fail2ban jails rules...\n"
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
";
echo -e "$FAIL2BANJAILS" > /etc/fail2ban/jail.local
service fail2ban restart

# Get OWASP rules for ModSecurity
printf $DIVIDER
printf "Downloading OWASP rules for ModSecurity...\n"
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.2/master.zip -O /tmp/owasp-modsecurity-crs.zip
unzip -q /tmp/owasp-modsecurity-crs.zip -d /tmp
rm /tmp/owasp-modsecurity-crs.zip
mv /tmp/owasp-modsecurity-crs-3.2-master/crs-setup.conf.example /etc/modsecurity/owasp-crs-setup.conf
mv /tmp/owasp-modsecurity-crs-3.2-master/rules /etc/modsecurity/
rm -r /tmp/owasp-modsecurity-crs-3.2-master

if [ ! -f /etc/apache2/mods-available/security2.conf.orig ]; then
	printf "Backing up original ModSecurity configuration file to /etc/apache2/mods-available/security2.conf.orig\n"
	cp /etc/apache2/mods-available/security2.conf /etc/apache2/mods-available/security2.conf.orig
fi

printf "Adding OWASP rules in ModSecurity configuration...\n"
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
printf "Set up Bad Bot Blocker...\n"
echo "$(cat << 'EOF'
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
)" > /usr/sbin/apache-bad-bot-blocker.sh
chmod 744 /usr/sbin/apache-bad-bot-blocker.sh
/usr/sbin/apache-bad-bot-blocker.sh

# The End
printf $DIVIDER
printf "The script executing has finished. Please check messages for any errors.\n"
read -p "Press ENTER to continue"

exit
