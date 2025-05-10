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
	read -p "Fix ONLY the WordPress themes files? [Y/N] " FIXTHEME
	case $FIXTHEME in
	[YyNn]*) break ;;
	*) printf "Please answer Y or N\n" ;;
	esac
done

if [[ $FIXALL =~ ^[Yy]$ ]]; then
	WP="$(find /srv/www/*/public_html/wp-content/themes/* -maxdepth 0 -type d 2>/dev/null | wc -l)"

	if [[ $FIXTHEME =~ ^[Nn]$ ]]; then
		printf "Updating ALL sites\n"
		printf "Set www-data as owner\n"
		chown -R www-data:www-data /srv/www/*

		printf "Set permissions of files to 644\n"
		find /srv/www/*/public_html -type f -exec chmod 644 {} \;

		printf "Set permissions of directories to 755\n"
		find /srv/www/*/public_html -type d -exec chmod 755 {} \;
	else
		if [ "$WP" != "0" ]; then
			printf "Updating ALL sites, ONLY theme/template files\n"
			printf "Set www-data as owner\n"
			chown -R www-data:www-data /srv/www/*/public_html/wp-content/themes/*

			printf "Set permissions of files to 644\n"
			find /srv/www/*/public_html/wp-content/themes/* -type f -exec chmod 644 {} \;

			printf "Set permissions of directories to 755\n"
			find /srv/www/*/public_html/wp-content/themes/* -type d -exec chmod 755 {} \;
		else
			printf "WARNING: No WordPress themes found in /srv/www/*/public_html/wp-content/themes\n"
		fi
	fi
	
	printf "Set permissions of config files to 440\n"
	chmod 440 /srv/www/*/public_html/wp-config.php
	chmod 440 /srv/www/*/public_html/wp-secrets.php
	chmod 440 /srv/www/*/public_html/deploy-config.php

	if [ "$WP" != "0" ]; then
		printf "Set execution permissions to node_modules/.bin\n"
		chmod +x /srv/www/*/public_html/wp-content/themes/*/node_modules/.bin/*

		printf "Set execution permissions to shell scripts\n"
		find /srv/www/*/public_html/wp-content/themes/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
else
	printf "Please select folder:\n"
	select DIR in */; do
		test -n "$DIR" && break
		echo ">>> Invalid Selection"
	done

	WP="$(find /srv/www/$DIR/public_html/wp-content/themes/* -maxdepth 0 -type d 2>/dev/null | wc -l)"

	if [[ $FIXTHEME =~ ^[Nn]$ ]]; then
		printf "Updating /srv/www/$DIR\n"
		printf "Set www-data as owner\n"
		chown -R www-data:www-data /srv/www/$DIR

		printf "Set permissions of files to 644\n"
		find /srv/www/$DIR/public_html -type f -exec chmod 644 {} \;

		printf "Set permissions of directories to 755\n"
		find /srv/www/$DIR/public_html -type d -exec chmod 755 {} \;
	else
		if [ "$WP" != "0" ]; then
			printf "Updating /srv/www/$DIR, ONLY theme/template files\n"
			printf "Set www-data as owner\n"
			chown -R www-data:www-data /srv/www/$DIR/public_html/wp-content/themes/*

			printf "Set permissions of files to 644\n"
			find /srv/www/$DIR/public_html/wp-content/themes/* -type f -exec chmod 644 {} \;

			printf "Set permissions of directories to 755\n"
			find /srv/www/$DIR/public_html/wp-content/themes/* -type d -exec chmod 755 {} \;
		else 
			printf "WARNING: No WordPress themes found in /srv/www/$DIR/public_html/wp-content/themes\n"
		fi
	fi

	printf "Set permissions of config files to 440\n"
	chmod 440 /srv/www/$DIR/public_html/wp-config.php
	chmod 440 /srv/www/$DIR/public_html/wp-secrets.php
	chmod 440 /srv/www/$DIR/public_html/deploy-config.php

	if [ "$WP" != "0" ]; then
		printf "Set execution permissions to node_modules/.bin\n"
		chmod +x /srv/www/$DIR/public_html/wp-content/themes/*/node_modules/.bin/*
	
		printf "Set execution permissions to shell scripts\n"
		find /srv/www/$DIR/public_html/wp-content/themes/* -name "*.sh" -type f -exec chmod +x {} \;
	fi
fi

cd $CURRDIR
printf "Done\n"

exit
