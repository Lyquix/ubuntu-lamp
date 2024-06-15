#!/bin/bash

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root!"
	exit 1
fi

DIVIDER="\n***************************************\n\n"
CURRDIR="${PWD}"
cd /srv/www

# Welcome and instructions
printf $DIVIDER
printf "Lyquix file permissions script\n"
printf $DIVIDER

# Prompt whether to do all sites or a specific one
while true; do
	read -p "Fix ALL sites? [Y/N] " FIXALL
	case $FIXALL in
	[YyNn]*) break ;;
	*) printf "Please answer Y or N\n" ;;
	esac
done

# Prompt whether to do the whole site or just the theme/template folder
while true; do
	read -p "Fix ONLY the theme/template files? [Y/N] " FIXTHEME
	case $FIXTHEME in
	[YyNn]*) break ;;
	*) printf "Please answer Y or N\n" ;;
	esac
done

if [[ $FIXALL =~ ^[Yy]$ ]]; then
	WP="$(find /srv/www/*/public_html/wp-content/themes/* -maxdepth 0 -type d 2>/dev/null | wc -l)"
	JOOMLA="$(find /srv/www/*/public_html/templates/* -maxdepth 0 -type d 2>/dev/null | wc -l)"

	if [[ $FIXTHEME =~ ^[Nn]$ ]]; then
		printf "Updating ALL sites\n"
		printf "Set www-data as owner\n"
		chown -R www-data:www-data /srv/www/*
		printf "Set permissions of files to 666\n"
		find /srv/www/*/public_html -type f -exec chmod 666 {} \;
		printf "Set permissions of directories to 777\n"
		find /srv/www/*/public_html -type d -exec chmod 777 {} \;
	else
		printf "Updating ALL sites, ONLY theme/template files\n"
		printf "Set www-data as owner\n"
		if [ "$WP" != "0" ]; then
			chown -R www-data:www-data /srv/www/*/public_html/wp-content/themes/*
		fi
		if [ "$JOOMLA" != "0" ]; then
			chown -R www-data:www-data /srv/www/*/public_html/templates/*
		fi
		printf "Set permissions of files to 666\n"
		if [ "$WP" != "0" ]; then
			find /srv/www/*/public_html/wp-content/themes/* -type f -exec chmod 644 {} \;
		fi
		if [ "$JOOMLA" != "0" ]; then
			find /srv/www/*/public_html/templates/* -type f -exec chmod 644 {} \;
		fi
		printf "Set permissions of config files to 440\n"
		if [ "$WP" != "0" ]; then
			chmod 440 /srv/www/*/public_html/wp-content/themes/*/wp-config.php
		fi
		if [ "$JOOMLA" != "0" ]; then
			chmod 440 /srv/www/*/public_html/templates/*/configuration.php
		fi
		printf "Set permissions of directories to 777\n"
		if [ "$WP" != "0" ]; then
			find /srv/www/*/public_html/wp-content/themes/* -type d -exec chmod 755 {} \;
		fi
		if [ "$JOOMLA" != "0" ]; then
			find /srv/www/*/public_html/templates/* -type d -exec chmod 755 {} \;
		fi
	fi
	printf "Set execution permissions to node_modules/.bin\n"
	if [ "$WP" != "0" ]; then
		chmod +x /srv/www/*/public_html/wp-content/themes/*/node_modules/.bin/*
	fi
	if [ "$JOOMLA" != "0" ]; then
		chmod +x /srv/www/*/public_html/templates/*/node_modules/.bin/*
	fi
	printf "Set execution permissions to shell scripts\n"
	if [ "$WP" != "0" ]; then
		find /srv/www/*/public_html/wp-content/themes/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
	if [ "$JOOMLA" != "0" ]; then
		find /srv/www/*/public_html/templates/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
else
	printf "Please select folder:\n"
	select DIR in */; do
		test -n "$DIR" && break
		echo ">>> Invalid Selection"
	done

	WP="$(find /srv/www/$DIR/public_html/wp-content/themes/* -maxdepth 0 -type d 2>/dev/null | wc -l)"
	JOOMLA="$(find /srv/www/$DIR/public_html/templates/* -maxdepth 0 -type d 2>/dev/null | wc -l)"

	if [[ $FIXTHEME =~ ^[Nn]$ ]]; then
		printf "Updating /srv/www/$DIR\n"
		printf "Set www-data as owner\n"
		chown -R www-data:www-data /srv/www/$DIR
		printf "Set permissions of files to 666\n"
		find /srv/www/$DIR/public_html -type f -exec chmod 666 {} \;
		printf "Set permissions of directories to 777\n"
		find /srv/www/$DIR/public_html -type d -exec chmod 777 {} \;
	else
		printf "Updating /srv/www/$DIR, ONLY theme/template files\n"
		printf "Set www-data as owner\n"
		if [ "$WP" != "0" ]; then
			chown -R www-data:www-data /srv/www/$DIR/public_html/wp-content/themes/*
		fi
		if [ "$JOOMLA" != "0" ]; then
			chown -R www-data:www-data /srv/www/$DIR/public_html/templates/*
		fi
		printf "Set permissions of files to 666\n"
		if [ "$WP" != "0" ]; then
			find /srv/www/$DIR/public_html/wp-content/themes/* -type f -exec chmod 644 {} \;
		fi
		if [ "$JOOMLA" != "0" ]; then
			find /srv/www/$DIR/public_html/templates/* -type f -exec chmod 644 {} \;
		fi
		printf "Set permissions of config files to 440\n"
		if [ "$WP" != "0" ]; then
			chmod 440 /srv/www/$DIR/public_html/wp-content/themes/*/wp-config.php
		fi
		if [ "$JOOMLA" != "0" ]; then
			chmod 440 /srv/www/$DIR/public_html/templates/*/configuration.php
		fi
		printf "Set permissions of directories to 777\n"
		if [ "$WP" != "0" ]; then
			find /srv/www/$DIR/public_html/wp-content/themes/* -type d -exec chmod 755 {} \;
		fi
		if [ "$JOOMLA" != "0" ]; then
			find /srv/www/$DIR/public_html/templates/* -type d -exec chmod 755 {} \;
		fi
	fi
	printf "Set execution permissions to node_modules/.bin\n"
	if [ "$WP" != "0" ]; then
		chmod +x /srv/www/$DIR/public_html/wp-content/themes/*/node_modules/.bin/*
	fi
	if [ "$JOOMLA" != "0" ]; then
		chmod +x /srv/www/$DIR/public_html/templates/*/node_modules/.bin/*
	fi
	printf "Set execution permissions to shell scripts\n"
	if [ "$WP" != "0" ]; then
		find /srv/www/$DIR/public_html/wp-content/themes/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
	if [ "$JOOMLA" != "0" ]; then
		find /srv/www/$DIR/public_html/templates/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
fi

cd $CURRDIR
printf "Done\n"

exit
