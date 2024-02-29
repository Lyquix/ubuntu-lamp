#!/bin/bash

# wp-secrets.php Setup Script
# https://github.com/Lyquix/ubuntu-lamp

# Check if script is being run by root
if [[ $EUID -ne 0 ]]; then
   printf "This script must be run as root!\n"
   exit 1
fi

DIVIDER="\n***************************************\n\n"

# Welcome and instructions
printf $DIVIDER
printf "Lyquix wp-secrets.php Setup Script\n"
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

CREDENTIALS_FILE="./encrypted_credentials.txt"
# Path to the apache2.conf file
apache_conf="/etc/apache2/apache2.conf"

# Extract the ENCRYPTION_KEY
ENCRYPTION_KEY=$(grep -oP 'SetEnv WPCONFIG_ENCKEY \K.*' $apache_conf)

# Extract the ENCRYPTION_IV
ENCRYPTION_IV=$(grep -oP 'SetEnv WPCONFIG_IV \K.*' $apache_conf)

while IFS='=' read -r key value; do
    case "$key" in
        DB_NAME) DB_NAME="$value" ;;
        DB_USER) DB_USER="$value" ;;
        DB_PASSWORD) DB_PASSWORD="$value" ;;
        STGDB_NAME) STGDB_NAME="$value" ;;
        STGDB_USER) STGDB_USER="$value" ;;
        STGDB_PASSWORD) STGDB_PASSWORD="$value" ;;
        DEVDB_NAME) DEVDB_NAME="$value" ;;
        DEVDB_USER) DEVDB_USER="$value" ;;
        DEVDB_PASSWORD) DEVDB_PASSWORD="$value" ;;
    esac
done < encrypted_credentials.txt

SALTS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)

# Declare an associative array to hold the salt names
declare -A salt_names=(
    [AUTH_KEY]="AUTH_KEY"
    [SECURE_AUTH_KEY]="SECURE_AUTH_KEY"
    [LOGGED_IN_KEY]="LOGGED_IN_KEY"
    [NONCE_KEY]="NONCE_KEY"
    [AUTH_SALT]="AUTH_SALT"
    [SECURE_AUTH_SALT]="SECURE_AUTH_SALT"
    [LOGGED_IN_SALT]="LOGGED_IN_SALT"
    [NONCE_SALT]="NONCE_SALT"
)

key_hex=$(echo -n $ENCRYPTION_KEY | base64 -d | xxd -p -c 32)
iv_hex=$(echo -n $ENCRYPTION_IV | base64 -d | xxd -p -c 16)

# Loop through the salt names and process each one
for salt in "${!salt_names[@]}"; do
    # Extract the salt value
    value=$(echo "$SALTS" | grep "$salt" | awk -F"'" '{print $4}')

    # Encrypt the value
    encrypted_value=$(echo $value | openssl enc -aes-256-cbc -a -pbkdf2 -iter 10000 -K $key_hex -iv $iv_hex)

    # Dynamically assign the encrypted value to the variable intended for the placeholder
    declare ${salt_names[$salt]}="$encrypted_value"
done

# Path to your template and the output file
template_file="./wp-secrets.dist.php"
output_file="./wp-secrets.php"

# Update the placeholders associative array with the newly assigned encrypted salt values
declare -A placeholders=(
    ["{{DB_NAME}}"]=$DB_NAME
    ["{{DB_USER}}"]=$DB_USER
    ["{{DB_PASSWORD}}"]=$DB_PASSWORD
    ["{{STGDB_NAME}}"]=$STGDB_NAME
    ["{{STGDB_USER}}"]=$STGDB_USER
    ["{{STGDB_PASSWORD}}"]=$STGDB_PASSWORD
    ["{{DEVDB_NAME}}"]=$DEVDB_NAME
    ["{{DEVDB_USER}}"]=$DEVDB_USER
    ["{{DEVDB_PASSWORD}}"]=$DEVDB_PASSWORD
    ["{{AUTH_KEY_ENC}}"]=$AUTH_KEY
    ["{{SECURE_AUTH_KEY_ENC}}"]=$SECURE_AUTH_KEY
    ["{{LOGGED_IN_KEY_ENC}}"]=$LOGGED_IN_KEY
    ["{{NONCE_KEY_ENC}}"]=$NONCE_KEY
    ["{{AUTH_SALT_ENC}}"]=$AUTH_SALT
    ["{{SECURE_AUTH_SALT_ENC}}"]=$SECURE_AUTH_SALT
    ["{{LOGGED_IN_SALT_ENC}}"]=$LOGGED_IN_SALT
    ["{{NONCE_SALT_ENC}}"]=$NONCE_SALT
)

# Prepare the output file by clearing its contents or creating it if it doesn't exist
> "$output_file"

# Read template and replace placeholders
while IFS= read -r line || [[ -n "$line" ]]; do
    for placeholder in "${!placeholders[@]}"; do
        line="${line//${placeholder}/${placeholders[$placeholder]}}"
    done
    # Append the processed line to the output file
    echo "$line" >> "$output_file"
done < "$template_file"

printf "wp-secrets.php has been generated successfully.\n"
