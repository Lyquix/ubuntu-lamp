#!/bin/bash

# Daily Backup Script for LAMP Server
# Handles database dumps, file backups, compression, and optional S3 sync.
# Writes a structured log consumed by the Lyquix AI Security plugin.
# Steps are independent: a failure is logged and the run continues.

set -u

MYSQL_DIR="${MYSQL_DIR:-/var/lib/mysql}"
WEB_DIR="${WEB_DIR:-/srv/www}"
S3_MOUNT_POINT="${S3_MOUNT_POINT:-/s3backup}"
LOCK_FILE="${LOCK_FILE:-/var/run/daily-backup.lock}"
MY_CNF="${MY_CNF:-$HOME/.my.cnf}"
LOG_FILE="${LOG_FILE:-}"
SITES_ENABLED_DIR="${SITES_ENABLED_DIR:-/etc/apache2/sites-enabled}"
SEPARATOR="$(printf '=%.0s' {1..80})"

# --- Log path: same discovery as certbot-renew.sh ---------------------------
# Logging is diagnostic and must never stop a backup. If the path cannot be
# resolved or written, warn on stderr and continue with logging disabled.
LOG_ENABLED=1

if [[ -z "$LOG_FILE" ]]; then
    for conf in "$SITES_ENABLED_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        if grep -q 'SetEnv WPCONFIG_ENVNAME production' "$conf" 2>/dev/null; then
            custom_log=$(awk '/^[[:space:]]*CustomLog[[:space:]]/{print $2; exit}' "$conf")
            [[ -n "$custom_log" ]] && LOG_FILE="$(dirname "$custom_log")/daily-backup.log"
            break
        fi
    done
fi

if [[ -z "$LOG_FILE" ]]; then
    echo "WARNING: Cannot determine the backup log path (no production vhost with a CustomLog under $SITES_ENABLED_DIR). The backup will run without a structured log." >&2
    LOG_ENABLED=0
elif ! mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null; then
    echo "WARNING: Cannot create the backup log directory for $LOG_FILE. The backup will run without a structured log." >&2
    LOG_ENABLED=0
elif { [[ -f "$LOG_FILE" ]] && [[ ! -w "$LOG_FILE" ]]; } || { [[ ! -f "$LOG_FILE" ]] && [[ ! -w "$(dirname "$LOG_FILE")" ]]; }; then
    echo "WARNING: The backup log destination is not writable: $LOG_FILE. The backup will run without a structured log." >&2
    LOG_ENABLED=0
fi

overall_status="ok"
run_ts=$(date -Iseconds)
start_epoch=$(date +%s)

log() {
    [[ $LOG_ENABLED -eq 1 ]] || return 0
    printf '%s\n' "$*" >> "$LOG_FILE"
}

raise() {
    case "$1:$overall_status" in
        error:*)    overall_status="error" ;;
        warning:ok) overall_status="warning" ;;
    esac
}

step_ok() { # name [duration_seconds] [size_bytes]
    local line="step=$1 status=ok"
    [[ -n "${2:-}" ]] && line+=" duration_seconds=$2"
    [[ -n "${3:-}" ]] && line+=" size_bytes=$3"
    log "$line"
}

step_error() { # name exit_code [duration_seconds] [error]
    local line="step=$1 status=error exit_code=$2"
    [[ -n "${3:-}" ]] && line+=" duration_seconds=$3"
    [[ -n "${4:-}" ]] && line+=" error=\"$(printf '%s' "$4" | tr '\n' ' ' | cut -c1-300)\""
    log "$line"
}

step_skipped() { log "step=$1 status=skipped reason=$2"; }

step_disabled() { log "step=$1 status=disabled reason=$2"; }

cleanup() { rm -f "$LOCK_FILE"; }

# --- Lock: the only hard stop ----------------------------------------------
if [[ -f "$LOCK_FILE" ]]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        # Never touch the active run's log block: write the skip notice beside
        # the main log so the collector, which reads only $LOG_FILE, cannot see
        # an interleaved block. If logging is unavailable, the notice goes to stderr.
        notice="run_status=skipped reason=already_running pid=$pid"
        if [[ $LOG_ENABLED -eq 1 ]]; then
            {
                echo "$SEPARATOR"
                echo "[$run_ts]"
                echo "$notice"
                echo "[$(date -Iseconds)] END"
                echo "$SEPARATOR"
            } >> "${LOG_FILE}.skipped" 2>/dev/null || echo "$notice" >&2
        else
            echo "$notice" >&2
        fi
        exit 0
    fi
fi
echo $$ > "$LOCK_FILE"
trap cleanup EXIT
log "$SEPARATOR"
log "[$run_ts]"
step_ok lock

# --- Preconditions ----------------------------------------------------------
my_cnf_ok=0
my_cnf_mode=$(stat -c %a "$MY_CNF" 2>/dev/null || true)
if [[ -f "$MY_CNF" ]] && [[ "$my_cnf_mode" == "600" || "$my_cnf_mode" == "400" ]]; then
    my_cnf_ok=1; step_ok my_cnf
else
    step_error my_cnf 1 "" "missing or permissions are not 600 or 400"; raise error
fi

mysql_dir_ok=0
if [[ -d "$MYSQL_DIR" ]]; then
    mysql_dir_ok=1; step_ok mysql_dir
else
    step_error mysql_dir 1 "" "directory not found"; raise error
fi

web_dir_ok=0
if [[ -d "$WEB_DIR" ]]; then
    web_dir_ok=1; step_ok web_dir
else
    step_error web_dir 1 "" "directory not found"; raise error
fi

mysql_ok=0
if [[ $my_cnf_ok -eq 1 ]]; then
    if mysqladmin ping >/dev/null 2>&1; then
        mysql_ok=1; step_ok mysql_ping
    else
        step_error mysql_ping 1 "" "mysqladmin ping failed"; raise error
    fi
else
    step_skipped mysql_ping my_cnf_invalid
fi

# Root cause for skipping DB steps while MySQL is not usable.
db_skip_reason=""
if [[ $mysql_ok -ne 1 ]]; then
    if [[ $my_cnf_ok -ne 1 ]]; then
        db_skip_reason="my_cnf_invalid"
    else
        db_skip_reason="mysql_unreachable"
    fi
fi

# --- Optimize (secondary) ---------------------------------------------------
if [[ $mysql_ok -eq 1 ]]; then
    t=$(date +%s)
    mysqlcheck -Aos >/dev/null 2>&1; rc=$?
    if [[ $rc -eq 0 ]]; then
        step_ok mysqlcheck $(( $(date +%s) - t ))
    else
        step_error mysqlcheck "$rc" $(( $(date +%s) - t )) "mysqlcheck failed"; raise warning
    fi
else
    step_skipped mysqlcheck "$db_skip_reason"
fi

# --- Database dump (primary) ------------------------------------------------
dump_ok=0
if [[ $mysql_ok -eq 1 && $mysql_dir_ok -eq 1 ]]; then
    t=$(date +%s)
    err=$(mysqldump --all-databases --single-transaction --quick 2>&1 > "$MYSQL_DIR/daily.sql"); rc=$?
    d=$(( $(date +%s) - t ))
    if [[ $rc -eq 0 ]]; then
        dump_ok=1
        step_ok mysqldump "$d" "$(stat -c %s "$MYSQL_DIR/daily.sql" 2>/dev/null || echo 0)"
    else
        step_error mysqldump "$rc" "$d" "$err"; raise error
    fi
else
    if [[ $mysql_ok -ne 1 ]]; then step_skipped mysqldump "$db_skip_reason"
    else step_skipped mysqldump mysql_dir_missing; fi
    raise error
fi

# --- Web archive (primary) --------------------------------------------------
web_ok=0
if [[ $web_dir_ok -eq 1 ]]; then
    t=$(date +%s)
    err=$(tar -czf "$WEB_DIR/daily.tar.gz" "$WEB_DIR"/*/public_html 2>&1); rc=$?
    d=$(( $(date +%s) - t ))
    if [[ $rc -eq 0 ]]; then
        web_ok=1
        step_ok web_archive "$d" "$(stat -c %s "$WEB_DIR/daily.tar.gz" 2>/dev/null || echo 0)"
    else
        step_error web_archive "$rc" "$d" "$err"; raise error
    fi
else
    step_skipped web_archive web_dir_missing; raise error
fi

# --- Weekly / monthly retention copies (secondary) --------------------------
copy_period() { # weekly|monthly
    local period="$1" attempted=0 failed=0
    if [[ $dump_ok -eq 1 ]]; then
        attempted=$(( attempted + 1 ))
        cp "$MYSQL_DIR/daily.sql" "$MYSQL_DIR/$period.sql" || failed=$(( failed + 1 ))
    fi
    if [[ $web_ok -eq 1 ]]; then
        attempted=$(( attempted + 1 ))
        cp "$WEB_DIR/daily.tar.gz" "$WEB_DIR/$period.tar.gz" || failed=$(( failed + 1 ))
    fi
    if [[ $attempted -eq 0 ]]; then
        step_skipped "$period" daily_artifact_missing
    elif [[ $failed -gt 0 ]]; then
        step_error "$period" 1 "" "$failed copy(ies) failed"; raise warning
    else
        step_ok "$period"
    fi
}
if [[ "$(date +%w)" -eq 0 ]]; then copy_period weekly; else step_skipped weekly not_sunday; fi
if [[ "$(date +%d)" == "01" ]]; then copy_period monthly; else step_skipped monthly not_first_of_month; fi

# --- Offsite copy (primary when configured) ---------------------------------
if [[ -d "$S3_MOUNT_POINT" ]]; then
    s3_ok=1
    s3_synced=0
    mountpoint -q "$S3_MOUNT_POINT" || mount "$S3_MOUNT_POINT" 2>/dev/null || s3_ok=0
    mountpoint -q "$S3_MOUNT_POINT" || s3_ok=0

    if [[ $s3_ok -eq 1 && $dump_ok -eq 1 ]]; then
        tar -czf "$MYSQL_DIR/daily.sql.tar.gz" "$MYSQL_DIR/daily.sql" 2>/dev/null || s3_ok=0
        if [[ $s3_ok -eq 1 ]]; then
            cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/daily.sql.tar.gz" && s3_synced=1 || s3_ok=0
            [[ "$(date +%w)" -eq 0 ]] && { cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/weekly.sql.tar.gz" && s3_synced=1 || s3_ok=0; }
            [[ "$(date +%d)" == "01" ]] && { cp "$MYSQL_DIR/daily.sql.tar.gz" "$S3_MOUNT_POINT/monthly.sql.tar.gz" && s3_synced=1 || s3_ok=0; }
        fi
    fi
    if [[ $s3_ok -eq 1 && $web_ok -eq 1 ]]; then
        cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/daily.tar.gz" && s3_synced=1 || s3_ok=0
        [[ "$(date +%w)" -eq 0 ]] && { cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/weekly.tar.gz" && s3_synced=1 || s3_ok=0; }
        [[ "$(date +%d)" == "01" ]] && { cp "$WEB_DIR/daily.tar.gz" "$S3_MOUNT_POINT/monthly.tar.gz" && s3_synced=1 || s3_ok=0; }
    fi

    if [[ $s3_ok -eq 1 && $s3_synced -eq 1 ]]; then
        step_ok s3
    elif [[ $s3_ok -eq 1 ]]; then
        # Mount is usable but there was nothing to copy: primary steps already
        # raised the error, so do not raise again.
        step_skipped s3 daily_artifact_missing
    else
        step_error s3 1 "" "mount or copy failed"; raise error
    fi
else
    step_disabled s3 no_mount_point
fi

# --- Summary ----------------------------------------------------------------
log "run_status=$overall_status"
log "finished_at=$(date -Iseconds) duration_seconds=$(( $(date +%s) - start_epoch ))"
log "[END]"
log "$SEPARATOR"
log ""

[[ "$overall_status" == "error" ]] && exit 1
exit 0
