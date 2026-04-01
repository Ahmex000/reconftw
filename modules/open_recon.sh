#!/bin/bash
# shellcheck disable=SC2154
# reconFTW - Open Mode (Horizontal Recon) module
# Horizontal asset discovery: TLDs, ASNs, CIDRs, IPs, vhosts, cloud assets
[[ -z "${SCRIPTPATH:-}" ]] && { echo "Error: This module must be sourced by reconftw.sh" >&2; exit 1; }

# Send Discord notification
discord_notify() {
    local message="$1"
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"content\": \"$message\"}" \
            "${DISCORD_WEBHOOK}" >/dev/null 2>&1 || true
    fi
}

# Phase 1: Collect TLDs via crt.sh
function open_tld_collect() {
    start_func "${FUNCNAME[0]}" "TLD Collection via crt.sh"
    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')
    mkdir -p "${dir}/open/TLD" "${dir}/open/subdomains" "${dir}/open/ips" "${dir}/open/asns" "${dir}/open/cidrs" "${dir}/open/vhosts" "${dir}/open/ports"

    notification "Collecting TLDs for ${base_domain}" info
    curl -s "https://crt.sh/?q=%25.${base_domain}&output=json" 2>/dev/null \
        | jq -r '.[].name_value' 2>/dev/null \
        | tr '\n' '\n' | sed 's/^\*\.//' | sort -u \
        > "${dir}/open/TLD/${base_domain}_TLD.txt" 2>/dev/null || true
    echo "$domain" >> "${dir}/open/TLD/${base_domain}_TLD.txt"
    sort -u -o "${dir}/open/TLD/${base_domain}_TLD.txt" "${dir}/open/TLD/${base_domain}_TLD.txt"
    local count
    count=$(wc -l < "${dir}/open/TLD/${base_domain}_TLD.txt" 2>/dev/null || echo 0)
    notification "TLD collection complete: ${count} domains found" good
    end_func "${dir}/open/TLD/${base_domain}_TLD.txt" "${FUNCNAME[0]}"
}

# Phase 2: Reverse WHOIS & WHOIS
function open_whois_enum() {
    start_func "${FUNCNAME[0]}" "WHOIS & Reverse WHOIS"
    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

    if command -v amass >/dev/null 2>&1; then
        notification "Running Amass WHOIS/reverse-whois for ${domain}" info
        amass intel -whois -d "$domain" 2>/dev/null \
            | sort -u >> "${dir}/open/TLD/${base_domain}_TLD.txt" || true
        sort -u -o "${dir}/open/TLD/${base_domain}_TLD.txt" "${dir}/open/TLD/${base_domain}_TLD.txt"
    fi

    if command -v whois >/dev/null 2>&1; then
        notification "Running WHOIS for ${domain}" info
        whois "$domain" 2>/dev/null > "${dir}/open/whois_${domain}.txt" || true
    fi
    end_func "${dir}/open/TLD/${base_domain}_TLD.txt" "${FUNCNAME[0]}"
}

# Phase 3: ASN Enumeration
function open_asn_enum() {
    start_func "${FUNCNAME[0]}" "ASN Enumeration"
    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

    if command -v asnmap >/dev/null 2>&1 && [[ -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "Running asnmap for ASN discovery" info
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            asnmap -d "$d" 2>/dev/null | grep -Eo 'AS[0-9]+' >> "${dir}/open/asns/asns_asnmap.txt" || true
        done < "${dir}/open/TLD/${base_domain}_TLD.txt"
        sort -u -o "${dir}/open/asns/asns_asnmap.txt" "${dir}/open/asns/asns_asnmap.txt"
    fi

    # Also query via SHODAN API
    if [[ -n "${SHODAN_API_KEY:-}" ]] && [[ -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "Querying Shodan API for ASNs/IPs" info
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=hostname:${d}" 2>/dev/null \
                | jq -r '.matches[].asn? // empty' 2>/dev/null >> "${dir}/open/asns/asns_shodan.txt" || true
            curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=hostname:${d}" 2>/dev/null \
                | jq -r '.matches[].ip_str? // empty' 2>/dev/null >> "${dir}/open/ips/ips_shodan.txt" || true
            curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=hostname:${d}" 2>/dev/null \
                | jq -r '.matches[] | "\(.ip_str):\(.port)"' 2>/dev/null >> "${dir}/open/ports/shodan_ports.txt" || true
        done < "${dir}/open/TLD/${base_domain}_TLD.txt"
        sort -u -o "${dir}/open/asns/asns_shodan.txt" "${dir}/open/asns/asns_shodan.txt" 2>/dev/null || true
        sort -u -o "${dir}/open/ips/ips_shodan.txt" "${dir}/open/ips/ips_shodan.txt" 2>/dev/null || true
    fi

    # Consolidate ASNs
    cat "${dir}/open/asns/"*.txt 2>/dev/null | grep -Eo 'AS[0-9]+' | sort -u > "${dir}/open/asns/unique_asns.txt" || true
    local count
    count=$(wc -l < "${dir}/open/asns/unique_asns.txt" 2>/dev/null || echo 0)
    notification "ASN enumeration complete: ${count} ASNs found" good
    end_func "${dir}/open/asns/unique_asns.txt" "${FUNCNAME[0]}"
}

# Phase 4: ASN to CIDR conversion
function open_asn_to_cidr() {
    start_func "${FUNCNAME[0]}" "ASN to CIDR Conversion"

    if [[ ! -s "${dir}/open/asns/unique_asns.txt" ]]; then
        notification "No ASNs found, skipping CIDR conversion" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    # Use whois.radb.net
    if command -v whois >/dev/null 2>&1; then
        notification "Converting ASNs to CIDRs via whois.radb.net" info
        while IFS= read -r asn; do
            [[ -z "$asn" ]] && continue
            whois -h whois.radb.net -- "-i origin ${asn}" 2>/dev/null \
                | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' \
                >> "${dir}/open/cidrs/cidrs_from_asns.txt" || true
        done < "${dir}/open/asns/unique_asns.txt"
        sort -u -o "${dir}/open/cidrs/cidrs_from_asns.txt" "${dir}/open/cidrs/cidrs_from_asns.txt" 2>/dev/null || true
    fi

    # Use asnmap for CIDR extraction too
    if command -v asnmap >/dev/null 2>&1; then
        cat "${dir}/open/asns/unique_asns.txt" 2>/dev/null \
            | asnmap 2>/dev/null \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+' \
            >> "${dir}/open/cidrs/cidrs_from_asnmap.txt" || true
        sort -u -o "${dir}/open/cidrs/cidrs_from_asnmap.txt" "${dir}/open/cidrs/cidrs_from_asnmap.txt" 2>/dev/null || true
    fi

    # Combine all CIDRs
    cat "${dir}/open/cidrs/"*.txt 2>/dev/null | sort -u > "${dir}/open/cidrs/unique_cidrs.txt" || true
    local count
    count=$(wc -l < "${dir}/open/cidrs/unique_cidrs.txt" 2>/dev/null || echo 0)
    notification "CIDR conversion complete: ${count} CIDRs found" good
    end_func "${dir}/open/cidrs/unique_cidrs.txt" "${FUNCNAME[0]}"
}

# Phase 5: IP Expansion & Reverse DNS
function open_ip_expansion() {
    start_func "${FUNCNAME[0]}" "IP Expansion & Reverse DNS"

    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

    if command -v dnsx >/dev/null 2>&1 && [[ -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "Resolving TLD domains to IPs with dnsx" info
        dnsx -l "${dir}/open/TLD/${base_domain}_TLD.txt" -a -resp-only -silent 2>/dev/null \
            >> "${dir}/open/ips/ips_from_tlds.txt" || true
        sort -u -o "${dir}/open/ips/ips_from_tlds.txt" "${dir}/open/ips/ips_from_tlds.txt" 2>/dev/null || true
    fi

    # Also resolve via ZDNS if available
    if command -v zdns >/dev/null 2>&1 && [[ -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "Resolving IPs with zdns" info
        cat "${dir}/open/TLD/${base_domain}_TLD.txt" \
            | zdns A 2>/dev/null \
            | jq -r '.results.A.data.answers[].answer' 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
            >> "${dir}/open/ips/ips_zdns.txt" || true
        sort -u -o "${dir}/open/ips/ips_zdns.txt" "${dir}/open/ips/ips_zdns.txt" 2>/dev/null || true
    fi

    # Consolidate IPs
    cat "${dir}/open/ips/"*.txt 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "${dir}/open/ips/unique_ips.txt" || true

    # Reverse DNS on IPs
    if [[ -s "${dir}/open/ips/unique_ips.txt" ]] && command -v dnsx >/dev/null 2>&1; then
        notification "Running reverse DNS on collected IPs" info
        dnsx -l "${dir}/open/ips/unique_ips.txt" -ptr -resp-only -silent 2>/dev/null \
            > "${dir}/open/subdomains/subdomains_rdns.txt" || true
    fi

    # CIDR expansion (sample only for large ranges)
    if command -v mapcidr >/dev/null 2>&1 && [[ -s "${dir}/open/cidrs/unique_cidrs.txt" ]]; then
        notification "Expanding CIDRs to IPs (sampled)" info
        mapcidr -cidr "${dir}/open/cidrs/unique_cidrs.txt" -skip-base-broadcast 2>/dev/null \
            | head -50000 \
            >> "${dir}/open/ips/ips_from_cidrs.txt" || true
        sort -u -o "${dir}/open/ips/ips_from_cidrs.txt" "${dir}/open/ips/ips_from_cidrs.txt" 2>/dev/null || true
    fi

    # Shodan reverse IP lookup
    if [[ -n "${SHODAN_API_KEY:-}" ]] && [[ -s "${dir}/open/ips/unique_ips.txt" ]]; then
        notification "Running Shodan reverse IP lookups" info
        head -20 "${dir}/open/ips/unique_ips.txt" | while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            curl -s "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null \
                | jq -r '.data[].domains[]? // empty' 2>/dev/null \
                >> "${dir}/open/subdomains/subdomains_shodan_rdns.txt" || true
            curl -s "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" 2>/dev/null \
                | jq -r '.asn? // empty' 2>/dev/null \
                >> "${dir}/open/asns/asns_shodan.txt" || true
        done
        sort -u -o "${dir}/open/subdomains/subdomains_shodan_rdns.txt" "${dir}/open/subdomains/subdomains_shodan_rdns.txt" 2>/dev/null || true
    fi

    local count
    count=$(wc -l < "${dir}/open/ips/unique_ips.txt" 2>/dev/null || echo 0)
    notification "IP expansion complete: ${count} unique IPs found" good
    end_func "${dir}/open/ips/unique_ips.txt" "${FUNCNAME[0]}"
}

# Phase 6: Virtual Host Fuzzing (for domains with different IPs)
function open_vhost_fuzz() {
    start_func "${FUNCNAME[0]}" "Virtual Host Fuzzing"

    if [[ "${OPEN_VHOST_FUZZ:-true}" != "true" ]]; then
        notification "Virtual host fuzzing disabled (OPEN_VHOST_FUZZ=false)" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local vhost_wl="${VHOST_WORDLIST:-${tools}/SecLists/Discovery/DNS/subdomains-top1million-5000.txt}"
    if [[ ! -f "$vhost_wl" ]]; then
        vhost_wl="${fuzz_wordlist:-${WORDLISTS_DIR}/fuzz_wordlist.txt}"
    fi

    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

    if ! command -v ffuf >/dev/null 2>&1; then
        notification "ffuf not found, skipping vhost fuzzing" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    if [[ ! -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "No TLD domains found for vhost fuzzing" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    notification "Starting Virtual Host fuzzing on discovered domains" info
    > "${dir}/open/vhosts/vhosts_ffuf.txt"

    # Run vhost fuzzing in a new tmux window if available
    local tmux_session
    tmux_session=$(tmux display-message -p '#S' 2>/dev/null || echo "")

    while IFS= read -r tld_domain; do
        [[ -z "$tld_domain" ]] && continue
        local window_name="vhost-${tld_domain//\./-}"
        local ffuf_cmd="ffuf -w '${vhost_wl}' -u 'https://${tld_domain}' -H 'Host: FUZZ.${tld_domain}' -fs 0 -o '/tmp/vhosts_temp_${tld_domain}.json' -of json -noninteractive -silent && jq -r '.results[].input.Host' '/tmp/vhosts_temp_${tld_domain}.json' >> '${dir}/open/vhosts/vhosts_ffuf.txt' 2>/dev/null || true"

        if [[ -n "$tmux_session" ]] && command -v tmux >/dev/null 2>&1; then
            tmux new-window -t "${tmux_session}" -n "${window_name}" 2>/dev/null || true
            tmux send-keys -t "${tmux_session}:${window_name}" "$ffuf_cmd" C-m 2>/dev/null || true
        else
            # Run inline (sequential)
            ffuf -w "${vhost_wl}" -u "https://${tld_domain}" -H "Host: FUZZ.${tld_domain}" \
                -fs 0 -o "/tmp/vhosts_temp_${tld_domain}.json" -of json -noninteractive -silent 2>/dev/null || true
            jq -r '.results[].input.Host' "/tmp/vhosts_temp_${tld_domain}.json" 2>/dev/null \
                >> "${dir}/open/vhosts/vhosts_ffuf.txt" || true
        fi
    done < "${dir}/open/TLD/${base_domain}_TLD.txt"

    sort -u -o "${dir}/open/vhosts/vhosts_ffuf.txt" "${dir}/open/vhosts/vhosts_ffuf.txt" 2>/dev/null || true
    local count
    count=$(wc -l < "${dir}/open/vhosts/vhosts_ffuf.txt" 2>/dev/null || echo 0)
    notification "Virtual host fuzzing complete: ${count} vhosts found" good
    end_func "${dir}/open/vhosts/vhosts_ffuf.txt" "${FUNCNAME[0]}"
}

# Phase 7: Cloud asset enumeration
function open_cloud_enum() {
    start_func "${FUNCNAME[0]}" "Cloud Asset Enumeration"

    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')
    mkdir -p "${dir}/open/cloud"

    if command -v cloud_enum >/dev/null 2>&1 || [[ -f "${tools}/cloud_enum/cloud_enum.py" ]]; then
        notification "Running cloud_enum for cloud asset discovery" info
        local cloud_cmd
        if command -v cloud_enum >/dev/null 2>&1; then
            cloud_cmd="cloud_enum"
        else
            cloud_cmd="python3 ${tools}/cloud_enum/cloud_enum.py"
        fi
        $cloud_cmd -k "$base_domain" -l "${dir}/open/cloud/cloud_enum_results.txt" 2>/dev/null || true
        notification "cloud_enum complete" good
    fi

    # S3Scanner
    if command -v s3scanner >/dev/null 2>&1 && [[ -s "${dir}/open/TLD/${base_domain}_TLD.txt" ]]; then
        notification "Running S3Scanner for bucket enumeration" info
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            s3scanner scan --bucket "${d}" 2>/dev/null >> "${dir}/open/cloud/s3_buckets.txt" || true
        done < "${dir}/open/TLD/${base_domain}_TLD.txt"
    fi

    end_func "${dir}/open/cloud/cloud_enum_results.txt" "${FUNCNAME[0]}"
}

# Phase 8: Consolidate open mode results and prepare for wilde mode
function open_consolidate() {
    start_func "${FUNCNAME[0]}" "Consolidating Open Mode Results"

    local base_domain
    base_domain=$(echo "$domain" | awk -F'.' '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

    # Gather all discovered subdomains from open mode into main subdomains dir
    mkdir -p "${dir}/subdomains"
    cat "${dir}/open/subdomains/"*.txt 2>/dev/null | sort -u >> "${dir}/subdomains/subdomains.txt" || true
    cat "${dir}/open/vhosts/"*.txt 2>/dev/null | sort -u >> "${dir}/subdomains/subdomains.txt" || true
    sort -u -o "${dir}/subdomains/subdomains.txt" "${dir}/subdomains/subdomains.txt" 2>/dev/null || true

    # Save summary
    {
        echo "=== Open Mode Recon Summary for ${domain} ==="
        echo "TLDs found: $(wc -l < "${dir}/open/TLD/${base_domain}_TLD.txt" 2>/dev/null || echo 0)"
        echo "ASNs found: $(wc -l < "${dir}/open/asns/unique_asns.txt" 2>/dev/null || echo 0)"
        echo "CIDRs found: $(wc -l < "${dir}/open/cidrs/unique_cidrs.txt" 2>/dev/null || echo 0)"
        echo "IPs found: $(wc -l < "${dir}/open/ips/unique_ips.txt" 2>/dev/null || echo 0)"
        echo "VHosts found: $(wc -l < "${dir}/open/vhosts/vhosts_ffuf.txt" 2>/dev/null || echo 0)"
        echo "Subdomains from open recon: $(wc -l < "${dir}/subdomains/subdomains.txt" 2>/dev/null || echo 0)"
        echo ""
        echo "=== Files ==="
        echo "TLDs: ${dir}/open/TLD/${base_domain}_TLD.txt"
        echo "IPs:  ${dir}/open/ips/unique_ips.txt"
        echo "CIDRs: ${dir}/open/cidrs/unique_cidrs.txt"
        echo "ASNs: ${dir}/open/asns/unique_asns.txt"
    } > "${dir}/open/summary.txt"

    # Discord notification for new assets
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        local summary
        summary=$(head -20 "${dir}/open/summary.txt" 2>/dev/null)
        discord_notify "**Open Mode Recon Complete** for \`${domain}\`\n\`\`\`${summary}\`\`\`"
    fi

    notification "Open mode consolidation complete. Summary at ${dir}/open/summary.txt" good
    end_func "${dir}/open/summary.txt" "${FUNCNAME[0]}"
}

# Main open mode function
function open_recon_mode() {
    notification "Starting Open Mode Reconnaissance for ${domain}" info
    notification "Phase 1: TLD & WHOIS Discovery" info
    open_tld_collect
    open_whois_enum
    notification "Phase 2: Network Discovery (ASNs & CIDRs)" info
    open_asn_enum
    open_asn_to_cidr
    notification "Phase 3: IP Expansion & Reverse DNS" info
    open_ip_expansion
    notification "Phase 4: Virtual Host Fuzzing" info
    open_vhost_fuzz
    notification "Phase 5: Cloud Asset Enumeration" info
    open_cloud_enum
    notification "Phase 6: Subdomain Enumeration on discovered domains" info
    # Now run wilde mode subdomain enumeration on all found TLDs
    wilde_mode
    notification "Phase 7: Consolidating Open Mode Results" info
    open_consolidate
    notification "Open Mode Reconnaissance Complete for ${domain}" good
}
