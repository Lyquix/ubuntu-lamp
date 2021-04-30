#!/bin/bash

# Ubuntu Add Site
# https://github.com/Lyquix/ubuntu-lamp

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
   printf "This script must be run as root!\n"
   exit 1
fi

DIVIDER="\n***************************************\n\n"

# Welcome and instructions
printf $DIVIDER
printf "Lyquix LAMP server Add Site script\n"
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
VIRTUALHOST="<VirtualHost $IPV4:80>\n\tServerName $domain\n\tServerAlias www.$domain\n\tDocumentRoot /srv/www/$domain/public_html/\n\tErrorLog /srv/www/$domain/logs/error.log\n\tCustomLog /srv/www/$domain/logs/access.log combined\n</VirtualHost>\n";
printf "$VIRTUALHOST" > /etc/apache2/sites-available/$domain.conf

# Development
VIRTUALHOST="<VirtualHost $IPV4:80>\n\tServerName dev.$domain\n\tDocumentRoot /srv/www/dev.$domain/public_html/\n\tErrorLog /srv/www/dev.$domain/logs/error.log\n\tCustomLog /srv/www/dev.$domain/logs/access.log combined\n</VirtualHost>\n";
printf "$VIRTUALHOST" > /etc/apache2/sites-available/dev.$domain.conf

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


# MySQL
printf $DIVIDER
printf "MYSQL\n"
printf "Setup databases and users\n"

while true; do
	read -sp "Enter password for MySQL root: " mysqlrootpsw
	case $mysqlrootpsw in
		"" ) printf "Password may not be left blank\n";;
		* ) break;;
	esac
done

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



# The End
printf $DIVIDER
printf "The script executing has finished. Please check messages for any errors.\n"
read -p "Press ENTER to continue"

exit
