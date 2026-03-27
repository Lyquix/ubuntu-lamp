#!/bin/bash

# Daily Backup Script for LAMP Server
# Handles database dumps, file backups, compression, and optional S3 sync
# S3 backup is enabled if /s3backup mount point exists

set -e

# Configuration
MYSQL_DIR="/var/lib/mysql"
WEB_DIR="/srv/www"
S3_MOUNT_POINT="/s3backup"
LOCK_FILE="/var/run/daily-backup.lock"
MY_CNF="$HOME/.my.cnf"

# Set up cleanup to always run on exit
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# Prevent concurrent executions
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "ERROR: Backup already running (PID: $pid)" >&2
        exit 1
    fi
fi
echo $$ > "$LOCK_FILE"

# Verify .my.cnf exists and has correct permissions (600)
if [ ! -f "$MY_CNF" ]; then
    echo "ERROR: .my.cnf not found at $MY_CNF" >&2
    echo "Create it with: cp .my.cnf.example $MY_CNF && chmod 600 $MY_CNF" >&2
    exit 1
fi

perms=$(stat -c %a "$MY_CNF")
if [ "$perms" != "600" ]; then
    echo "ERROR: .my.cnf has incorrect permissions ($perms). Should be 600." >&2
    echo "Fix with: chmod 600 $MY_CNF" >&2
    exit 1
fi

# Verify required directories exist
if [ ! -d "$MYSQL_DIR" ]; then
    echo "ERROR: Backup directory not found: $MYSQL_DIR" >&2
    exit 1
fi

if [ ! -d "$WEB_DIR" ]; then
    echo "ERROR: Web root not found: $WEB_DIR" >&2
    exit 1
fi

# Verify MySQL is responding
if ! mysqladmin ping > /dev/null; then
    echo "ERROR: MySQL is not responding" >&2
    exit 1
fi

# Optimize all databases
mysqlcheck -Aos > /dev/null || exit 1

# Create daily dump of all databases
mysqldump --all-databases --single-transaction --quick > "$MYSQL_DIR/daily.sql" || exit 1

# Create compressed archive of all public_html directories
tar -czf "$WEB_DIR/daily.tar.gz" "$WEB_DIR"/*/public_html || exit 1

# If today is Sunday, create weekly backups
if [ "$(date +%w)" -eq 0 ]; then
    cp "$MYSQL_DIR/daily.sql" "$MYSQL_DIR/weekly.sql" || exit 1
    cp "$WEB_DIR/daily.tar.gz" "$WEB_DIR/weekly.tar.gz" || exit 1
fi

# If today is the first day of the month, create monthly backups
if [ "$(date +%d)" -eq 01 ]; then
    cp "$MYSQL_DIR/daily.sql" "$MYSQL_DIR/monthly.sql" || exit 1
    cp "$WEB_DIR/daily.tar.gz" "$WEB_DIR/monthly.tar.gz" || exit 1
fi

# If S3 mount point exists, copy backups to S3
if [ -d "$S3_MOUNT_POINT" ]; then
    # Attempt to mount if not already mounted
    if ! mountpoint -q "$S3_MOUNT_POINT"; then
        mount "$S3_MOUNT_POINT" || {
            echo "ERROR: Failed to mount S3 bucket at $S3_MOUNT_POINT" >&2
        }
    fi
    
    # If mount point is now mounted, proceed with S3 backup
    if mountpoint -q "$S3_MOUNT_POINT"; then
        # Compress the database dump
        tar -czf "$MYSQL_DIR/daily.sql.tar.gz" "$MYSQL_DIR/daily.sql" || exit 1
        
        # Copy daily backups to S3
        cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/daily.sql.tar.gz" || exit 1
        cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/daily.tar.gz" || exit 1
        
        # If today is Sunday, copy weekly backups to S3
        if [ "$(date +%w)" -eq 0 ]; then
            cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/weekly.sql.tar.gz" || exit 1
            cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/weekly.tar.gz" || exit 1
        fi
        
        # If today is the first day of the month, copy monthly backups to S3
        if [ "$(date +%d)" -eq 01 ]; then
            cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/monthly.sql.tar.gz" || exit 1
            cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/monthly.tar.gz" || exit 1
        fi
    fi
fi