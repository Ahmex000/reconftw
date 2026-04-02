#!/bin/bash
# shellcheck disable=SC2154
# reconFTW - Wilde Mode (Comprehensive Subdomain Enumeration) module
[[ -z "${SCRIPTPATH:-}" ]] && { echo "Error: This module must be sourced by reconftw.sh" >&2; exit 1; }

# VirusTotal subdomain enumeration
function sub_virustotal() {
    start_func "${FUNCNAME[0]}" "VirusTotal Subdomain Enumeration"
    [[ "${SUB_VIRUSTOTAL:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }
    [[ -z "${VT_API_KEY:-}" ]] && { notification "VT_API_KEY not set, skipping VirusTotal" warn; end_func "" "${FUNCNAME[0]}"; return; }

    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_API_KEY}&domain=${domain}" 2>/dev/null \
        | jq -r '.domain_siblings[]?, .subdomains[]?' 2>/dev/null \
        | sed 's/^\*\.//' | grep -v '^$' | sort -u \
        > "${dir}/.tmp/subdomains_virustotal.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_virustotal.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_virustotal.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_virustotal.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_virustotal.txt" 2>/dev/null || echo 0)
    notification "VirusTotal found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_virustotal.txt" "${FUNCNAME[0]}"
}

# Subenum aggregator
function sub_subenum() {
    start_func "${FUNCNAME[0]}" "Subenum Aggregated Enumeration"
    [[ "${SUB_SUBENUM:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v subenum >/dev/null 2>&1; then
        notification "subenum not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    subenum -d "${domain}" -u wayback,crt,abuseipdb,Findomain,Subfinder,Amass,Assetfinder \
        -o "${dir}/.tmp/subdomains_subenum.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_subenum.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_subenum.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_subenum.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_subenum.txt" 2>/dev/null || echo 0)
    notification "Subenum found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_subenum.txt" "${FUNCNAME[0]}"
}

# Findomain
function sub_findomain() {
    start_func "${FUNCNAME[0]}" "Findomain Subdomain Enumeration"
    [[ "${SUB_FINDOMAIN:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v findomain >/dev/null 2>&1; then
        notification "findomain not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    findomain -t "${domain}" -u "${dir}/.tmp/subdomains_findomain.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_findomain.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_findomain.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_findomain.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_findomain.txt" 2>/dev/null || echo 0)
    notification "Findomain found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_findomain.txt" "${FUNCNAME[0]}"
}

# Assetfinder
function sub_assetfinder() {
    start_func "${FUNCNAME[0]}" "Assetfinder Subdomain Enumeration"
    [[ "${SUB_ASSETFINDER:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v assetfinder >/dev/null 2>&1; then
        notification "assetfinder not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    assetfinder --subs-only "${domain}" 2>/dev/null \
        | grep -F ".${domain}" \
        | sort -u > "${dir}/.tmp/subdomains_assetfinder.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_assetfinder.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_assetfinder.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_assetfinder.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_assetfinder.txt" 2>/dev/null || echo 0)
    notification "Assetfinder found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_assetfinder.txt" "${FUNCNAME[0]}"
}

# Sublist3r
function sub_sublist3r() {
    start_func "${FUNCNAME[0]}" "Sublist3r Subdomain Enumeration"
    [[ "${SUB_SUBLIST3R:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v sublist3r >/dev/null 2>&1; then
        notification "sublist3r not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    sublist3r -d "${domain}" -o "${dir}/.tmp/subdomains_sublist3r.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_sublist3r.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_sublist3r.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_sublist3r.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_sublist3r.txt" 2>/dev/null || echo 0)
    notification "Sublist3r found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_sublist3r.txt" "${FUNCNAME[0]}"
}

# Shodan CLI subdomain search
function sub_shodan_cli() {
    start_func "${FUNCNAME[0]}" "Shodan CLI Subdomain Enumeration"
    [[ "${SUB_SHODAN:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v shodan >/dev/null 2>&1; then
        notification "shodan CLI not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    shodan search "hostname:${domain}" --fields hostnames --separator ';' 2>/dev/null \
        | tr ';' '\n' | sed 's/\\n//' \
        | grep -iF ".${domain}" \
        | sort -u > "${dir}/.tmp/subdomains_shodan.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_shodan.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_shodan.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_shodan.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_shodan.txt" 2>/dev/null || echo 0)
    notification "Shodan found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_shodan.txt" "${FUNCNAME[0]}"
}

# Chaos subdomain enumeration
function sub_chaos() {
    start_func "${FUNCNAME[0]}" "Chaos Subdomain Enumeration"
    [[ "${SUB_CHAOS:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }
    [[ -z "${CHAOS_API_KEY:-}" ]] && { notification "CHAOS_API_KEY not set, skipping Chaos" warn; end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v chaos >/dev/null 2>&1; then
        notification "chaos not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    chaos -d "${domain}" -key "${CHAOS_API_KEY}" -o "${dir}/.tmp/subdomains_chaos.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_chaos.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_chaos.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_chaos.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_chaos.txt" 2>/dev/null || echo 0)
    notification "Chaos found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_chaos.txt" "${FUNCNAME[0]}"
}

# SecurityTrails API
function sub_securitytrails() {
    start_func "${FUNCNAME[0]}" "SecurityTrails Subdomain Enumeration"
    [[ "${SUB_SECURITYTRAILS:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }
    [[ -z "${SECURITYTRAILS_API_KEY:-}" ]] && { notification "SECURITYTRAILS_API_KEY not set, skipping SecurityTrails" warn; end_func "" "${FUNCNAME[0]}"; return; }

    curl -s -H "APIKEY: ${SECURITYTRAILS_API_KEY}" \
        "https://api.securitytrails.com/v1/domain/${domain}/subdomains" 2>/dev/null \
        | jq -r --arg domain "$domain" '.subdomains[] | . + "." + $domain' 2>/dev/null \
        | sort -u > "${dir}/.tmp/subdomains_securitytrails.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_securitytrails.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_securitytrails.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_securitytrails.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_securitytrails.txt" 2>/dev/null || echo 0)
    notification "SecurityTrails found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_securitytrails.txt" "${FUNCNAME[0]}"
}

# URLScan.io subdomain enumeration
function sub_urlscan() {
    start_func "${FUNCNAME[0]}" "URLScan.io Subdomain Enumeration"
    [[ "${SUB_URLSCAN:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    curl -s "https://urlscan.io/api/v1/search/?q=domain:${domain}" 2>/dev/null \
        | jq -r '.results[].page.domain' 2>/dev/null \
        | grep -F "${domain}" | sort -u \
        > "${dir}/.tmp/subdomains_urlscan.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_urlscan.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_urlscan.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_urlscan.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_urlscan.txt" 2>/dev/null || echo 0)
    notification "URLScan found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_urlscan.txt" "${FUNCNAME[0]}"
}

# GitHub Subdomains
function sub_github_subdomains() {
    start_func "${FUNCNAME[0]}" "GitHub Subdomains Enumeration"
    [[ "${SUB_GITHUB_SUBDOMAINS:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v github-subdomains >/dev/null 2>&1; then
        notification "github-subdomains not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local gh_token
    gh_token=$(head -1 "${GITHUB_TOKENS:-${tools}/.github_tokens}" 2>/dev/null || echo "")
    [[ -z "$gh_token" ]] && { notification "No GitHub token found, skipping github-subdomains" warn; end_func "" "${FUNCNAME[0]}"; return; }

    github-subdomains -d "${domain}" -t "${gh_token}" -o "${dir}/.tmp/subdomains_github.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_github.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_github.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_github.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_github.txt" 2>/dev/null || echo 0)
    notification "GitHub-Subdomains found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_github.txt" "${FUNCNAME[0]}"
}

# GitLab Subdomains
function sub_gitlab_subdomains() {
    start_func "${FUNCNAME[0]}" "GitLab Subdomains Enumeration"
    [[ "${SUB_GITLAB_SUBDOMAINS:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v gitlab-subdomains >/dev/null 2>&1; then
        notification "gitlab-subdomains not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local gl_token
    gl_token=$(head -1 "${GITLAB_TOKENS:-${tools}/.gitlab_tokens}" 2>/dev/null || echo "")
    [[ -z "$gl_token" ]] && { notification "No GitLab token found, skipping gitlab-subdomains" warn; end_func "" "${FUNCNAME[0]}"; return; }

    gitlab-subdomains -d "${domain}" -t "${gl_token}" 2>/dev/null \
        | sort -u > "${dir}/.tmp/subdomains_gitlab.txt" || true

    if [[ -s "${dir}/.tmp/subdomains_gitlab.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_gitlab.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_gitlab.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_gitlab.txt" 2>/dev/null || echo 0)
    notification "GitLab-Subdomains found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_gitlab.txt" "${FUNCNAME[0]}"
}

# ShuffleDNS brute force
function sub_shuffledns() {
    start_func "${FUNCNAME[0]}" "ShuffleDNS Brute Force"
    [[ "${SUB_SHUFFLEDNS:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v shuffledns >/dev/null 2>&1; then
        notification "shuffledns not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local wl="${subs_wordlist:-${WORDLISTS_DIR}/subdomains.txt}"
    local res="${resolvers:-${tools}/resolvers.txt}"

    shuffledns -d "${domain}" -w "${wl}" -r "${res}" \
        -o "${dir}/.tmp/subdomains_shuffledns.txt" 2>/dev/null || true

    if [[ -s "${dir}/.tmp/subdomains_shuffledns.txt" ]]; then
        anew -q "${dir}/subdomains/subdomains.txt" < "${dir}/.tmp/subdomains_shuffledns.txt" 2>/dev/null || \
            cat "${dir}/.tmp/subdomains_shuffledns.txt" >> "${dir}/subdomains/subdomains.txt"
    fi
    local count
    count=$(wc -l < "${dir}/.tmp/subdomains_shuffledns.txt" 2>/dev/null || echo 0)
    notification "ShuffleDNS found ${count} subdomains" good
    end_func "${dir}/.tmp/subdomains_shuffledns.txt" "${FUNCNAME[0]}"
}

# Subdomain fuzzing in tmux
function sub_fuzz_tmux() {
    start_func "${FUNCNAME[0]}" "Subdomain Fuzzing (ffuf)"
    [[ "${SUB_FUZZ:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v ffuf >/dev/null 2>&1; then
        notification "ffuf not installed, skipping subdomain fuzzing" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local wl="${subs_wordlist_big:-${tools}/subdomains_n0kovo_big.txt}"
    if [[ ! -f "$wl" ]]; then
        wl="${subs_wordlist:-${WORDLISTS_DIR}/subdomains.txt}"
    fi

    local tmux_session
    tmux_session=$(tmux display-message -p '#S' 2>/dev/null || echo "")
    local window_name="subfuzz-${domain//\./-}"
    local output_file="${dir}/.tmp/subdomains_ffuf.txt"

    local ffuf_cmd
    ffuf_cmd="ffuf -w '${wl}' -u 'https://FUZZ.${domain}' -v -mc 200,301,302,307,401,403 -of csv -o '${output_file}' -t 100 -rate 100 -silent && echo 'Subdomain fuzzing complete' || true"

    notification "Starting subdomain fuzzing with ffuf" info
    if [[ -n "$tmux_session" ]] && command -v tmux >/dev/null 2>&1; then
        tmux new-window -t "${tmux_session}" -n "${window_name}" 2>/dev/null \
            || tmux new-window -n "${window_name}" 2>/dev/null || true
        tmux send-keys -t "${tmux_session}:${window_name}" "$ffuf_cmd" C-m 2>/dev/null || true
        notification "Subdomain fuzzing started in tmux window '${window_name}'" info
    else
        # Background run
        ffuf -w "${wl}" -u "https://FUZZ.${domain}" -v -mc 200,301,302,307,401,403 \
            -of csv -o "${output_file}" -t 50 -rate 50 -silent 2>/dev/null &
        notification "Subdomain fuzzing started in background (PID: $!)" info
    fi
    end_func "" "${FUNCNAME[0]}"
}

# Subdomain monitor - add target to monitoring queue
function add_to_monitor_queue() {
    local target="$1"
    local queue_file="${SCRIPTPATH}/.monitor_queue"
    local interval="${MONITOR_INTERVAL_MIN:-60}"

    if ! grep -qF "$target" "$queue_file" 2>/dev/null; then
        echo "$target" >> "$queue_file"
        notification "Added ${target} to background monitoring queue (every ${interval}min)" info
    fi
}

# Save subdomains to scanner/ folder in 500-line CSV files
function save_subdomains_to_scanner() {
    local input_file="${dir}/subdomains/subdomains.txt"
    local scanner_dir="${dir}/scanner"
    mkdir -p "$scanner_dir"

    if [[ ! -s "$input_file" ]]; then
        return
    fi

    # Write combined file
    cp "$input_file" "${scanner_dir}/all_subdomains.csv"

    # Write 500-line split files
    split -l 500 -d "$input_file" "${scanner_dir}/subdomains_chunk_"

    # Add target,subdomain format
    while IFS= read -r sub; do
        echo "${domain},${sub}"
    done < "$input_file" > "${scanner_dir}/subdomains_with_target.csv"

    notification "Subdomains saved to ${scanner_dir}/ ($(wc -l < "$input_file") total)" info
}

# IP to port scan and domain extraction
function wilde_ip_portscan() {
    start_func "${FUNCNAME[0]}" "IP Port Scanning (naabu/nmap)"
    [[ "${WILDE_PORTSCAN:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    mkdir -p "${dir}/hosts" "${dir}/subdomains"

    # Resolve subdomains to IPs
    if [[ -s "${dir}/subdomains/subdomains.txt" ]] && command -v dnsx >/dev/null 2>&1; then
        notification "Resolving subdomains to IPs" info
        dnsx -l "${dir}/subdomains/subdomains.txt" -a -resp -silent 2>/dev/null \
            | awk '{print $2}' | tr -d '[]' \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
            | sort -u > "${dir}/hosts/ips_from_subdomains.txt" || true
    fi

    # Port scan with naabu
    if command -v naabu >/dev/null 2>&1 && [[ -s "${dir}/hosts/ips_from_subdomains.txt" ]]; then
        notification "Port scanning IPs with naabu" info
        naabu -l "${dir}/hosts/ips_from_subdomains.txt" \
            -top-ports 1000 -silent -o "${dir}/hosts/open_ports_naabu.txt" 2>/dev/null || true
    fi

    # Reverse DNS on discovered IPs to find related subdomains
    if [[ -s "${dir}/hosts/ips_from_subdomains.txt" ]] && command -v dnsx >/dev/null 2>&1; then
        notification "Reverse DNS on discovered IPs" info
        dnsx -l "${dir}/hosts/ips_from_subdomains.txt" -ptr -resp-only -silent 2>/dev/null \
            | grep -F "${domain}" \
            | sort -u >> "${dir}/subdomains/subdomains.txt" || true
        sort -u -o "${dir}/subdomains/subdomains.txt" "${dir}/subdomains/subdomains.txt" || true
    fi

    end_func "${dir}/hosts/open_ports_naabu.txt" "${FUNCNAME[0]}"
}

# Nuclei scan on live subdomains
function wilde_nuclei_scan() {
    start_func "${FUNCNAME[0]}" "Nuclei Vulnerability Scan"
    [[ "${WILDE_NUCLEI:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if ! command -v nuclei >/dev/null 2>&1; then
        notification "nuclei not installed, skipping" warn
        end_func "" "${FUNCNAME[0]}"
        return
    fi

    local live_subs="${dir}/webs/webs_all.txt"
    if [[ ! -s "$live_subs" ]]; then
        live_subs="${dir}/subdomains/subdomains.txt"
    fi

    mkdir -p "${dir}/nuclei_output"
    local tmux_session
    tmux_session=$(tmux display-message -p '#S' 2>/dev/null || echo "")
    local window_name="nuclei-${domain//\./-}"

    local nuclei_cmd
    nuclei_cmd="nuclei -l '${live_subs}' -severity medium,high,critical -retries 3 -c 50 -rl 150 -silent -o '${dir}/nuclei_output/results.txt' 2>/dev/null"

    if [[ -n "$tmux_session" ]] && command -v tmux >/dev/null 2>&1; then
        tmux new-window -t "${tmux_session}" -n "${window_name}" 2>/dev/null || true
        tmux send-keys -t "${tmux_session}:${window_name}" "$nuclei_cmd" C-m 2>/dev/null || true
        notification "Nuclei scan started in tmux window '${window_name}'" info
    else
        nohup nuclei -l "${live_subs}" -severity medium,high,critical -retries 3 \
            -c 50 -rl 150 -silent -o "${dir}/nuclei_output/results.txt" \
            > "${dir}/nuclei_output/nuclei.log" 2>&1 &
        notification "Nuclei scan started in background (PID: $!)" info
    fi
    end_func "" "${FUNCNAME[0]}"
}

# Subdomain takeover check
function wilde_takeover_check() {
    start_func "${FUNCNAME[0]}" "Subdomain Takeover Check"
    [[ "${SUBTAKEOVER:-true}" != "true" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    local live_subs="${dir}/webs/webs_all.txt"
    [[ ! -s "$live_subs" ]] && { end_func "" "${FUNCNAME[0]}"; return; }

    if command -v nuclei >/dev/null 2>&1; then
        notification "Checking subdomain takeovers with nuclei" info
        nuclei -l "$live_subs" -t "${NUCLEI_TEMPLATES_PATH}/http/takeovers/" \
            -silent -o "${dir}/vulns/takeovers.txt" 2>/dev/null || true
    fi
    end_func "${dir}/vulns/takeovers.txt" "${FUNCNAME[0]}"
}

# Main wilde mode function - runs all subdomain tools in groups of 3
function wilde_mode() {
    notification "Starting Wilde Mode (Comprehensive Subdomain Enumeration) for ${domain}" info
    mkdir -p "${dir}/subdomains" "${dir}/.tmp" "${dir}/webs" "${dir}/hosts" "${dir}/vulns" "${dir}/scanner"
    touch "${dir}/subdomains/subdomains.txt"

    local start_count
    start_count=$(wc -l < "${dir}/subdomains/subdomains.txt" 2>/dev/null || echo 0)

    # GROUP 1 (3 tools simultaneously)
    notification "Subdomain Enum - Group 1: subfinder, crt.sh, VirusTotal" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs sub_passive sub_crt sub_virustotal
    else
        sub_passive; sub_crt; sub_virustotal
    fi

    # GROUP 2 (3 tools simultaneously)
    notification "Subdomain Enum - Group 2: subenum, findomain, assetfinder" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs sub_subenum sub_findomain sub_assetfinder
    else
        sub_subenum; sub_findomain; sub_assetfinder
    fi

    # GROUP 3 (3 tools simultaneously)
    notification "Subdomain Enum - Group 3: sublist3r, shodan-cli, chaos" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs sub_sublist3r sub_shodan_cli sub_chaos
    else
        sub_sublist3r; sub_shodan_cli; sub_chaos
    fi

    # GROUP 4 (3 tools simultaneously)
    notification "Subdomain Enum - Group 4: securitytrails, urlscan, github-subdomains" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs sub_securitytrails sub_urlscan sub_github_subdomains
    else
        sub_securitytrails; sub_urlscan; sub_github_subdomains
    fi

    # GROUP 5 (remaining tools)
    notification "Subdomain Enum - Group 5: gitlab-subdomains, shuffledns, sub_analytics" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs sub_gitlab_subdomains sub_shuffledns sub_analytics
    else
        sub_gitlab_subdomains; sub_shuffledns; sub_analytics
    fi

    # Sequential Group 6: active resolution, DNS records, permutations
    notification "Subdomain Enum - Group 6: active DNS, permutations" info
    sub_active
    sub_dns
    if [[ "${SUBPERMUTE:-true}" == "true" ]]; then sub_permut; fi

    # DNS brute-force: runs in a new tmux window; script WAITS for it to finish
    # before proceeding. This lets you use the terminal freely while it runs.
    if [[ "${SUBBRUTE:-true}" == "true" ]]; then
        local _brute_sentinel
        _brute_sentinel="/tmp/.reconftw_brute_done_${domain//[^a-zA-Z0-9_]/_}"
        rm -f "$_brute_sentinel"

        local _brute_window="brute-${domain//\./-}"
        local _brute_log="${dir}/.log/brute_force.log"

        # Build the brute-force command: original sub_brute logic wrapped with sentinel
        # We call the actual sub_brute function body then touch the sentinel
        local _brute_cmd
        _brute_cmd="cd '${dir}' && bash -c 'source ${SCRIPTPATH}/reconftw.cfg; source ${SCRIPTPATH}/lib/common.sh; source ${SCRIPTPATH}/lib/ui.sh; source ${SCRIPTPATH}/lib/validation.sh; source ${SCRIPTPATH}/modules/utils.sh; source ${SCRIPTPATH}/modules/core.sh; source ${SCRIPTPATH}/modules/subdomains.sh; domain=${domain}; dir=${dir}; resolvers=${resolvers}; resolvers_trusted=${resolvers_trusted}; subs_wordlist=${subs_wordlist}; called_fn_dir=${called_fn_dir}; LOGFILE=${LOGFILE}; sub_brute' 2>&1 | tee '${_brute_log}'; touch '${_brute_sentinel}'"

        if command -v tmux >/dev/null 2>&1; then
            local _tmux_session
            _tmux_session=$(tmux display-message -p '#S' 2>/dev/null || echo "")
            if [[ -n "$_tmux_session" ]]; then
                tmux new-window -t "${_tmux_session}" -n "${_brute_window}" 2>/dev/null \
                    || tmux new-window -n "${_brute_window}" 2>/dev/null || true
                tmux send-keys -t "${_tmux_session}:${_brute_window}" "$_brute_cmd" C-m 2>/dev/null || true
                notification "DNS brute-force started in tmux window '${_brute_window}' — waiting for it to finish..." info
            else
                # No active session — run inline
                sub_brute
                touch "$_brute_sentinel"
            fi
        else
            # No tmux — run inline
            sub_brute
            touch "$_brute_sentinel"
        fi

        # Block here until brute-force window is done (sentinel file appears)
        local _wait_secs=0
        while [[ ! -f "$_brute_sentinel" ]]; do
            sleep 15
            _wait_secs=$((_wait_secs + 15))
            if ((_wait_secs % 120 == 0)); then
                notification "Still waiting for DNS brute-force... (${_wait_secs}s elapsed)" info
            fi
        done
        rm -f "$_brute_sentinel"
        notification "DNS brute-force complete" good
    fi

    # Filter live subdomains — only after ALL enum (including brute) is done
    notification "Checking live subdomains with httpx" info
    if command -v httpx >/dev/null 2>&1 && [[ -s "${dir}/subdomains/subdomains.txt" ]]; then
        httpx -l "${dir}/subdomains/subdomains.txt" -silent -threads "${HTTPX_THREADS:-50}" \
            -o "${dir}/webs/webs_all.txt" 2>/dev/null || true
    fi

    local end_count new_count
    end_count=$(wc -l < "${dir}/subdomains/subdomains.txt" 2>/dev/null || echo 0)
    new_count=$((end_count - start_count))

    # Save to scanner folder
    save_subdomains_to_scanner

    # IP port scanning
    wilde_ip_portscan

    # Nuclei scan (fires in tmux, does NOT block)
    wilde_nuclei_scan

    # Subdomain takeover check
    wilde_takeover_check

    # IIS short name
    if [[ "${IIS_SHORTNAME:-true}" == "true" ]]; then
        iishortname
    fi

    # Subdomain monitoring queue
    add_to_monitor_queue "$domain"

    # Discord notification
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        discord_notify "**Wilde Mode Complete** for \`${domain}\`\nTotal subdomains: ${end_count} (${new_count} new)\nLive: $(wc -l < "${dir}/webs/webs_all.txt" 2>/dev/null || echo 0)"
    fi

    notification "Wilde Mode Complete: ${end_count} subdomains (${new_count} new)" good

    # Proceed to URL collection only after ALL wilde steps (including brute) are done
    notification "Wilde Mode: proceeding to URL collection" info
    url_mode
}

# URL mode - comprehensive URL collection
function url_mode() {
    notification "Starting URL Mode for ${domain}" info
    mkdir -p "${dir}/urls" "${dir}/.tmp" "${dir}/params"

    local live_subs="${dir}/webs/webs_all.txt"
    if [[ ! -s "$live_subs" ]]; then
        # Try to create from subdomains if available
        if [[ -s "${dir}/subdomains/subdomains.txt" ]] && command -v httpx >/dev/null 2>&1; then
            httpx -l "${dir}/subdomains/subdomains.txt" -silent \
                -o "${dir}/webs/webs_all.txt" 2>/dev/null || true
        fi
    fi

    # GROUP 1: Passive URL sources (2 at a time)
    notification "URL Collection - Group 1: gau, waymore" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs _url_gau _url_waymore
    else
        _url_gau; _url_waymore
    fi

    # GROUP 2: Active URL sources (2 at a time)
    notification "URL Collection - Group 2: katana, gospider" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs _url_katana _url_gospider
    else
        _url_katana; _url_gospider
    fi

    # GROUP 3: More URL sources (2 at a time)
    notification "URL Collection - Group 3: paramspider, urlscan-urls" info
    if [[ "${PARALLEL_MODE:-true}" == "true" ]]; then
        parallel_funcs _url_paramspider _url_urlscan
    else
        _url_paramspider; _url_urlscan
    fi

    # Combine and deduplicate all URLs
    notification "Combining and deduplicating URLs" info
    cat "${dir}/urls/"*.txt 2>/dev/null | sort -u > "${dir}/urls/all_urls.txt" || true

    # Filter live URLs and split to 500-line CSV files
    local scanner_dir="${dir}/scanner"
    mkdir -p "$scanner_dir"

    if command -v httpx >/dev/null 2>&1 && [[ -s "${dir}/urls/all_urls.txt" ]]; then
        notification "Filtering live URLs" info
        httpx -l "${dir}/urls/all_urls.txt" -silent -threads "${HTTPX_THREADS:-50}" \
            -o "${dir}/urls/live_urls.txt" 2>/dev/null || true
    else
        cp "${dir}/urls/all_urls.txt" "${dir}/urls/live_urls.txt" 2>/dev/null || true
    fi

    # Split by extension
    if [[ "${URL_EXT:-true}" == "true" ]]; then
        notification "Splitting URLs by extension" info
        _split_urls_by_ext "${dir}/urls/live_urls.txt" "${dir}/urls"
    fi

    # GF pattern matching
    if [[ "${URL_GF:-true}" == "true" ]]; then
        notification "Running GF pattern matching on URLs" info
        url_gf
    fi

    # Save URLs to scanner folder in 500-line chunks
    if [[ -s "${dir}/urls/live_urls.txt" ]]; then
        split -l 500 -d "${dir}/urls/live_urls.txt" "${scanner_dir}/urls_chunk_"
        while IFS= read -r url; do
            echo "${domain},${url}"
        done < "${dir}/urls/live_urls.txt" > "${scanner_dir}/urls_with_target.csv"
    fi

    # JS analysis
    if [[ "${JSCHECKS:-true}" == "true" ]]; then
        notification "Running JS analysis" info
        jschecks
    fi

    local total
    total=$(wc -l < "${dir}/urls/all_urls.txt" 2>/dev/null || echo 0)
    local live
    live=$(wc -l < "${dir}/urls/live_urls.txt" 2>/dev/null || echo 0)

    # Discord notification
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
        discord_notify "**URL Mode Complete** for \`${domain}\`\nTotal URLs: ${total}\nLive URLs: ${live}"
    fi

    notification "URL Mode Complete: ${total} URLs collected, ${live} live" good
}

# Helper URL collection functions
_url_gau() {
    if command -v gau >/dev/null 2>&1; then
        notification "Collecting URLs with gau" info
        echo "$domain" | gau --subs 2>/dev/null \
            | sort -u > "${dir}/urls/urls_gau.txt" || true
    fi
}

_url_waymore() {
    if command -v waymore >/dev/null 2>&1; then
        notification "Collecting URLs with waymore" info
        waymore -i "$domain" -mode U -oU "${dir}/urls/urls_waymore.txt" 2>/dev/null || true
    fi
}

_url_katana() {
    if command -v katana >/dev/null 2>&1 && [[ -s "${dir}/webs/webs_all.txt" ]]; then
        notification "Crawling with katana" info
        katana -list "${dir}/webs/webs_all.txt" -depth 3 -js-crawl -known-files -silent \
            -exclude-extensions woff,css,png,svg,jpg,woff2,jpeg,gif \
            -o "${dir}/urls/urls_katana.txt" 2>/dev/null || true
    fi
}

_url_gospider() {
    if command -v gospider >/dev/null 2>&1 && [[ -s "${dir}/webs/webs_all.txt" ]]; then
        notification "Crawling with gospider" info
        gospider -S "${dir}/webs/webs_all.txt" -c 10 -d 2 -t 50 \
            -o "${dir}/urls/urls_gospider_dir" 2>/dev/null || true
        find "${dir}/urls/urls_gospider_dir" -type f -exec cat {} \; 2>/dev/null \
            | sort -u > "${dir}/urls/urls_gospider.txt" || true
    fi
}

_url_paramspider() {
    if command -v paramspider >/dev/null 2>&1; then
        notification "Collecting params with paramspider" info
        paramspider -d "$domain" -o "${dir}/params/paramspider.txt" 2>/dev/null || true
        [[ -s "${dir}/params/paramspider.txt" ]] && \
            cat "${dir}/params/paramspider.txt" >> "${dir}/urls/urls_paramspider.txt" || true
    fi
}

_url_urlscan() {
    notification "Collecting URLs from URLScan.io" info
    curl -s "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100" 2>/dev/null \
        | jq -r '.results[].page.url' 2>/dev/null \
        | sort -u > "${dir}/urls/urls_urlscan.txt" || true
}

_split_urls_by_ext() {
    local input="$1"
    local out_dir="$2"
    [[ ! -s "$input" ]] && return

    grep -iE '\.(js)(\?|$)' "$input" > "${out_dir}/urls_js.txt" 2>/dev/null || true
    grep -iE '\.(php|asp|aspx|jsp)(\?|$|/)' "$input" > "${out_dir}/urls_dynamic.txt" 2>/dev/null || true
    grep -iE '\.(json|xml|yaml|yml)(\?|$)' "$input" > "${out_dir}/urls_data.txt" 2>/dev/null || true
    grep -iE '\.(pdf|doc|docx|xls|xlsx|txt|csv)(\?|$)' "$input" > "${out_dir}/urls_docs.txt" 2>/dev/null || true
    grep '?' "$input" | grep -v -E '\.(js|css|png|jpg|gif|svg|woff|woff2|ttf)' > "${out_dir}/urls_params.txt" 2>/dev/null || true
}

# Background subdomain monitoring queue processor
function run_monitor_queue() {
    local queue_file="${SCRIPTPATH}/.monitor_queue"
    local interval="${MONITOR_INTERVAL_MIN:-60}"

    [[ ! -f "$queue_file" ]] && return

    notification "Starting background monitor queue processor" info

    while true; do
        while IFS= read -r target; do
            [[ -z "$target" ]] && continue
            notification "Monitor: checking ${target} for new subdomains" info
            local old_dir="${SCRIPTPATH}/Recon/${target}"
            local old_count=0
            [[ -f "${old_dir}/subdomains/subdomains.txt" ]] && \
                old_count=$(wc -l < "${old_dir}/subdomains/subdomains.txt")

            # Run subdomain enum
            domain="$target"
            dir="$old_dir"
            if command -v subfinder >/dev/null 2>&1; then
                subfinder -silent -d "$target" -all 2>/dev/null \
                    | anew -q "${old_dir}/subdomains/subdomains.txt" 2>/dev/null || true
            fi
            curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null \
                | jq -r '.[].name_value' 2>/dev/null \
                | sed 's/^\*\.//' | sort -u \
                | anew -q "${old_dir}/subdomains/subdomains.txt" 2>/dev/null || true

            local new_count
            new_count=$(wc -l < "${old_dir}/subdomains/subdomains.txt" 2>/dev/null || echo 0)
            local diff=$((new_count - old_count))

            if [[ $diff -gt 0 ]]; then
                notification "Monitor: Found ${diff} new subdomains for ${target}!" good
                # Discord notification
                if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
                    discord_notify "**New Subdomains Detected** for \`${target}\`\n+${diff} new subdomains found\nTotal: ${new_count}"
                fi
            fi
        done < "$queue_file"

        notification "Monitor: cycle complete, sleeping ${interval} minutes" info
        sleep $((interval * 60))
    done
}
