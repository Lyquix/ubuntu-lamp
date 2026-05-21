#!/bin/bash
#
# certbot-renew.sh
# SSL certificate renewal for LAMP servers using the Apache plugin.
# Outputs a structured log consumed by the Lyquix AI Security plugin.
#
# Usage: Replace `certbot renew` in your cron with this script.
#   Example cron: 0 */12 * * * root /path/to/certbot-renew.sh
#
# Behavior:
#   1. Discovers certificates referenced in active Apache vhost configs
#   2. For each certificate:
#      a. Checks days until expiry and whether the cert chain is currently valid
#      b. Runs a certbot dry-run to test ACME validation
#      c. If dry-run passes:  runs real renewal (certbot's own 30-day window applies)
#      d. If dry-run fails:   logs the failure and failing domains; no cert changes
#                             unless days <= REISSUE_DAYS, in which case the cert is
#                             reissued excluding the failing domains
#   3. Appends a structured block to LOG_FILE after every run

# =============================================================================
# CONFIGURATION — edit these values for your server
# =============================================================================

CERTBOT="/usr/bin/certbot"

# Days before expiry at which a failing dry-run triggers an emergency reissue
# (cert is reissued immediately, excluding the failing domains).
# Set to 3 to allow several more cron attempts before expiry.
REISSUE_DAYS=3

# =============================================================================

SEPARATOR="$(printf '=%.0s' {1..80})"

# Returns the certificate expiry date as YYYY-MM-DD, or "unknown".
# Called multiple times per cert (initial display, before/after renewal).
_expiry_date() {
    local pem="/etc/letsencrypt/live/$1/cert.pem"
    [[ -f "$pem" ]] || { echo "unknown"; return; }
    local enddate
    enddate=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    [[ -z "$enddate" ]] && { echo "unknown"; return; }
    date -d "$enddate" "+%Y-%m-%d" 2>/dev/null || echo "unknown"
}

# --- Auto-detect log path from the production Apache vhost ------------------
# Finds the vhost containing 'SetEnv WPCONFIG_ENVNAME production' and places
# certbot-renew.log in the same directory as its CustomLog file.

LOG_FILE=""
for conf in /etc/apache2/sites-enabled/*.conf; do
    [[ -f "$conf" ]] || continue
    if grep -q 'SetEnv WPCONFIG_ENVNAME production' "$conf" 2>/dev/null; then
        custom_log=$(awk '/^[[:space:]]*CustomLog[[:space:]]/{print $2; exit}' "$conf")
        [[ -n "$custom_log" ]] && LOG_FILE="$(dirname "$custom_log")/certbot-renew.log"
        break
    fi
done

if [[ -z "$LOG_FILE" ]]; then
    echo "ERROR: Cannot determine log path. No vhost with 'SetEnv WPCONFIG_ENVNAME production' found in /etc/apache2/sites-enabled/." >&2
    exit 1
fi

# --- Discover active certificates from Apache vhosts ------------------------

mkdir -p "$(dirname "$LOG_FILE")"

mapfile -t cert_names < <(
    grep -rh "SSLCertificateFile" /etc/apache2/sites-enabled/*.conf 2>/dev/null \
        | grep -o '/etc/letsencrypt/live/[^/]*' \
        | sed 's|/etc/letsencrypt/live/||' \
        | sort -u
)

[[ ${#cert_names[@]} -eq 0 ]] && exit 0

# --- Main run ----------------------------------------------------------------

run_ts=$(date -Iseconds)
overall_status="ok"

{
    echo "$SEPARATOR"
    echo "[$run_ts]"
    echo ""

    for cert_name in "${cert_names[@]}"; do

        expiry=$(_expiry_date "$cert_name")
        if [[ "$expiry" == "unknown" ]]; then
            days=9999
        else
            days=$(( ( $(date -d "$expiry" +%s) - $(date +%s) ) / 86400 ))
        fi

        chain_pem="/etc/letsencrypt/live/$cert_name/fullchain.pem"
        if [[ -f "$chain_pem" ]] && openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "$chain_pem" &>/dev/null; then
            chain_valid="true"
        else
            chain_valid="false"
        fi

        renewal_due="no"
        (( days <= 30 )) && renewal_due="yes"

        # Status based on expiry and chain validity
        if   (( days <= 0 ));            then cert_status="expired";  overall_status="critical"
        elif (( days <= REISSUE_DAYS )); then cert_status="critical"; overall_status="critical"
        elif [[ "$chain_valid" == "false" ]]; then cert_status="critical"; overall_status="critical"
        else cert_status="ok"
        fi

        # --- Domains on this cert -------------------------------------------
        mapfile -t all_domains < <(
            $CERTBOT certificates --cert-name "$cert_name" 2>/dev/null \
                | grep -E '^\s+Domains:' \
                | head -1 \
                | sed 's/^\s*Domains:\s*//' \
                | tr ' ' '\n' \
                | grep -v '^$'
        )

        # --- Emit cert block header ------------------------------------------
        echo "cert=$cert_name expires=$expiry days=$days renewal_due=$renewal_due chain_valid=$chain_valid"
        [[ ${#all_domains[@]} -gt 0 ]] && echo "  domains: ${all_domains[*]}"

        # --- Dry run ---------------------------------------------------------
        dry_run_output=$($CERTBOT renew --dry-run --cert-name "$cert_name" --apache 2>&1)
        dry_run_exit=$?

        # Domains certbot identified as failing ACME validation (if any)
        mapfile -t acme_bad_domains < <(
            echo "$dry_run_output" | grep -oP '(?<=Domain: )\S+'
        )

        if [[ $dry_run_exit -eq 0 ]]; then
            # ----------------------------------------------------------------
            # Dry run passed — run real renewal.
            # certbot will skip if the cert is not yet within its 30-day window.
            # Compare expiry dates before and after to detect whether a renewal
            # actually occurred.
            # ----------------------------------------------------------------
            echo "  dry_run=pass"

            expiry_before=$(_expiry_date "$cert_name")
            renew_output=$($CERTBOT renew --cert-name "$cert_name" --apache --quiet 2>&1)
            renew_exit=$?
            expiry_after=$(_expiry_date "$cert_name")

            if [[ $renew_exit -ne 0 ]]; then
                echo "  action=renewal_attempted"
                echo "  result=error"
                echo "  error: $(echo "$renew_output" | tail -5 | tr '\n' ' ')"
                cert_status="critical"
                overall_status="critical"
            elif [[ "$expiry_after" != "$expiry_before" ]]; then
                echo "  action=renewed"
                echo "  result=success new_expiry=$expiry_after"
            else
                echo "  action=none"
            fi

        else
            # ----------------------------------------------------------------
            # Dry run failed — always log the failure.
            # Only attempt an emergency reissue (excluding failing domains)
            # when the cert is within REISSUE_DAYS of expiry.
            # ----------------------------------------------------------------
            echo "  dry_run=fail"
            [[ ${#acme_bad_domains[@]} -gt 0 ]] && echo "  failing_domains: ${acme_bad_domains[*]}"

            if (( days <= REISSUE_DAYS )); then
                # =============================================================
                # REISSUE WINDOW: reissue the cert, excluding failing domains.
                # =============================================================
                if [[ ${#acme_bad_domains[@]} -eq 0 ]]; then
                    # Dry run failed but no per-domain error was parsed
                    # (e.g. CAA record, rate limit, or a non-domain-specific error).
                    # Removing domains won't fix this; flag for manual review.
                    echo "  action=none"
                    echo "  reason=dry_run_failed_no_per_domain_error_manual_review_required"
                    cert_status="critical"
                    overall_status="critical"
                else
                    good_domains=()
                    for domain in "${all_domains[@]}"; do
                        [[ ! " ${acme_bad_domains[*]} " =~ " ${domain} " ]] \
                            && good_domains+=("$domain")
                    done

                    if [[ ${#good_domains[@]} -ge 1 ]]; then
                        d_flags=()
                        for domain in "${good_domains[@]}"; do d_flags+=(-d "$domain"); done

                        reissue_output=$($CERTBOT certonly \
                            --apache \
                            --cert-name "$cert_name" \
                            "${d_flags[@]}" \
                            --non-interactive \
                            --force-renewal \
                            2>&1)
                        reissue_exit=$?

                        echo "  action=reissue_without_failing_domains"
                        echo "  reissue_domains: ${good_domains[*]}"
                        if [[ $reissue_exit -eq 0 ]]; then
                            echo "  result=success new_expiry=$(_expiry_date "$cert_name")"
                        else
                            echo "  result=error"
                            echo "  error: $(echo "$reissue_output" | tail -5 | tr '\n' ' ')"
                            overall_status="critical"
                        fi
                    else
                        # Every domain on the cert is failing — cannot reissue with zero domains.
                        echo "  action=none"
                        echo "  reason=all_domains_failing_manual_intervention_required"
                        cert_status="critical"
                        overall_status="critical"
                    fi
                fi

            else
                # =============================================================
                # Outside the reissue window — log the failure and move on.
                # The dry_run=fail and failing_domains fields are sufficient for
                # the security plugin and admins to act on.
                # =============================================================
                echo "  action=none"
                [[ "$cert_status" == "ok" ]] && cert_status="warning"
                [[ "$overall_status" == "ok" ]] && overall_status="warning"
            fi
        fi

        # Final resolved status for this cert
        echo "  status=$cert_status"
        echo ""
    done

    echo "run_status=$overall_status"
    echo "[$( date -Iseconds )] END"
    echo "$SEPARATOR"
    echo ""

} >> "$LOG_FILE"
