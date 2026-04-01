# reconFTW - Extended Modes Documentation

## Overview

reconFTW now supports three new reconnaissance modes accessible via `--mode` or dedicated short flags:

| Flag              | Short | Mode  | Description                                      |
|-------------------|-------|-------|--------------------------------------------------|
| `--mode open`     | `-O`  | Open  | Horizontal / company-wide asset discovery        |
| `--mode wilde`    | `-W`  | Wilde | Comprehensive subdomain enumeration (Y-Recon)    |
| `--mode url`      | `-U`  | URL   | Full URL collection and classification           |

---

## Installation

Standard installation (new tools are installed automatically):

```bash
git clone https://github.com/six2dez/reconftw.git
cd reconftw
./install.sh
```

New tools added by these modes:
- `assetfinder` — passive subdomain discovery
- `shuffledns` — massdns-backed brute-force resolver
- `zdns` — fast DNS resolver
- `findomain` — multi-source passive subdomain discovery
- `sublist3r` — search-engine subdomain aggregator (Python)
- `github-subdomains` — GitHub code search for subdomains (already in base install)
- `gitlab-subdomains` — GitLab code search for subdomains (already in base install)

---

## CLI Usage

```bash
# Open Mode (horizontal recon)
./reconftw.sh -d example.com --mode open
./reconftw.sh -d example.com -O

# Wilde Mode (comprehensive subdomain enum)
./reconftw.sh -d example.com --mode wilde
./reconftw.sh -d example.com -W

# URL Mode (URL collection)
./reconftw.sh -d example.com --mode url
./reconftw.sh -d example.com -U

# Combine with list input
./reconftw.sh -l targets.txt --mode wilde

# Combine with output directory
./reconftw.sh -d example.com --mode open -o /results/example
```

---

## Configuration

Add the following to `reconftw.cfg` or `secrets.cfg` (preferred for API keys):

```bash
# API Keys for new modes
VT_API_KEY=""                    # VirusTotal v2 API key
CHAOS_API_KEY=""                 # Chaos Project API key (projectdiscovery.io)
SECURITYTRAILS_API_KEY=""        # SecurityTrails API key
DISCORD_WEBHOOK=""               # Discord webhook URL for notifications
SHODAN_API_KEY=""                # Shodan API key (also used by base reconftw)

# Wilde Mode – enable/disable individual tools
SUB_VIRUSTOTAL=true
SUB_SUBENUM=true
SUB_FINDOMAIN=true
SUB_ASSETFINDER=true
SUB_SUBLIST3R=true
SUB_SHODAN=true
SUB_CHAOS=true
SUB_SECURITYTRAILS=true
SUB_URLSCAN=true
SUB_GITHUB_SUBDOMAINS=true
SUB_GITLAB_SUBDOMAINS=true
SUB_SHUFFLEDNS=true
SUB_FUZZ=true                    # ffuf subdomain fuzzing in tmux window

# Open Mode
OPEN_VHOST_FUZZ=true             # Virtual host fuzzing
VHOST_WORDLIST=""                # Custom wordlist path (blank = auto-detect)

# URL Mode / Wilde Mode extras
WILDE_PORTSCAN=true              # naabu port scanning on resolved IPs
WILDE_NUCLEI=true                # nuclei scan on live subdomains (tmux window)
```

---

## Open Mode (`--mode open` / `-O`)

Performs horizontal, company-wide asset discovery. Useful for finding all assets owned by an organization, not just subdomains of a single domain.

### Step-by-step flow

1. **TLD Collection** (`open_tld_collect`)
   - Queries `crt.sh` for all domains sharing the same base TLD
   - Output: `Recon/<target>/open/TLD/<base>_TLD.txt`

2. **WHOIS & Reverse WHOIS** (`open_whois_enum`)
   - Runs `amass intel -whois` to find related domains via registrant data
   - Runs `whois` for informational output
   - Appends results to TLD file

3. **ASN Enumeration** (`open_asn_enum`)
   - Runs `asnmap` against each discovered TLD domain
   - Queries Shodan API for ASNs and IPs (requires `SHODAN_API_KEY`)
   - Output: `open/asns/unique_asns.txt`

4. **ASN to CIDR Conversion** (`open_asn_to_cidr`)
   - Queries `whois.radb.net` for each ASN's route objects
   - Also runs `asnmap` in CIDR extraction mode
   - Output: `open/cidrs/unique_cidrs.txt`

5. **IP Expansion & Reverse DNS** (`open_ip_expansion`)
   - Resolves TLD domains to IPs with `dnsx`
   - Optionally uses `zdns` for bulk resolution
   - Runs reverse DNS (`dnsx -ptr`) on all collected IPs
   - Expands CIDRs to individual IPs via `mapcidr` (sampled, max 50,000)
   - Shodan reverse IP lookup for additional domains
   - Output: `open/ips/unique_ips.txt`, `open/subdomains/subdomains_rdns.txt`

6. **Virtual Host Fuzzing** (`open_vhost_fuzz`)
   - Runs `ffuf` with Host header fuzzing against each TLD domain
   - Launches in new tmux window if inside a tmux session
   - Controlled by `OPEN_VHOST_FUZZ=true`
   - Output: `open/vhosts/vhosts_ffuf.txt`

7. **Cloud Asset Enumeration** (`open_cloud_enum`)
   - Runs `cloud_enum` for S3, Azure Blob, GCP bucket discovery
   - Runs `s3scanner` against discovered domains
   - Output: `open/cloud/`

8. **Wilde Mode Subdomain Enum** (calls `wilde_mode`)
   - Runs the full Wilde mode pipeline against all discovered TLD domains
   - See Wilde Mode section below

9. **Consolidation** (`open_consolidate`)
   - Merges all discovered subdomains into `subdomains/subdomains.txt`
   - Writes a summary to `open/summary.txt`
   - Sends Discord notification if `DISCORD_WEBHOOK` is set

### Output structure

```
Recon/<target>/
  open/
    TLD/<base>_TLD.txt       # All related TLD domains
    asns/unique_asns.txt     # Unique ASNs
    cidrs/unique_cidrs.txt   # Unique CIDRs
    ips/unique_ips.txt       # Unique IPs
    vhosts/vhosts_ffuf.txt   # Virtual hosts found
    cloud/                   # Cloud asset results
    ports/shodan_ports.txt   # IP:port from Shodan
    summary.txt              # Human-readable summary
  subdomains/subdomains.txt  # Merged subdomain list
```

---

## Wilde Mode (`--mode wilde` / `-W`)

Runs every available subdomain enumeration source in parallel batches of 3, followed by live probing, port scanning, nuclei, and takeover checks.

### Tool groups

| Group | Tools                                             |
|-------|---------------------------------------------------|
| 1     | subfinder, crt.sh, VirusTotal                     |
| 2     | subenum, findomain, assetfinder                   |
| 3     | sublist3r, shodan-cli, chaos                      |
| 4     | securitytrails, urlscan, github-subdomains        |
| 5     | gitlab-subdomains, shuffledns, analytics          |
| 6     | amass active, DNS brute, permutations             |

### Step-by-step flow

1. **Parallel subdomain enumeration** — Groups 1–6 as above
2. **Subdomain fuzzing** (`sub_fuzz_tmux`) — Runs `ffuf` in a new tmux window with a large wordlist against `FUZZ.<domain>`
3. **Live probing** — `httpx` filters live subdomains to `webs/webs_all.txt`
4. **Save to scanner/** — Splits subdomains into 500-line CSV chunks for downstream scanning
5. **IP port scanning** (`wilde_ip_portscan`) — `dnsx` resolves IPs, `naabu` scans top-1000 ports, reverse DNS for additional subs
6. **Nuclei scan** (`wilde_nuclei_scan`) — Launches `nuclei -severity medium,high,critical` in a tmux window
7. **Takeover check** (`wilde_takeover_check`) — `nuclei` takeover templates on live URLs
8. **IIS short name** — Runs `iishortname` if enabled
9. **Monitor queue** — Adds target to `.monitor_queue` for background monitoring
10. **Discord notification** — Reports count of new subdomains found

### Output structure

```
Recon/<target>/
  subdomains/subdomains.txt       # All unique subdomains
  webs/webs_all.txt               # Live HTTP/S targets
  hosts/
    ips_from_subdomains.txt       # Resolved IPs
    open_ports_naabu.txt          # Open ports
  nuclei_output/results.txt       # Vulnerability findings
  vulns/takeovers.txt             # Takeover candidates
  scanner/
    all_subdomains.csv            # Full subdomain list
    subdomains_chunk_00..         # 500-line chunks
    subdomains_with_target.csv    # target,subdomain format
  .tmp/subdomains_*.txt           # Per-tool raw output
```

---

## URL Mode (`--mode url` / `-U`)

Collects URLs from all passive and active sources, deduplicates, filters live URLs, splits by file extension, and runs GF pattern matching.

### Tool groups

| Group | Tools                        |
|-------|------------------------------|
| 1     | gau, waymore                 |
| 2     | katana, gospider             |
| 3     | paramspider, urlscan-urls    |

### Step-by-step flow

1. **Live subdomain check** — If `webs/webs_all.txt` does not exist, runs `httpx` on `subdomains/subdomains.txt`
2. **Passive URL collection** (`gau`, `waymore`) — Collects archived URLs
3. **Active crawling** (`katana`, `gospider`) — Deep crawls live targets
4. **Parameter discovery** (`paramspider`) — Collects parameterized URLs
5. **URLScan.io** — Fetches URLs from URLScan's search API
6. **Deduplicate** — `sort -u` across all sources → `urls/all_urls.txt`
7. **Live filter** — `httpx` filters live URLs → `urls/live_urls.txt`
8. **Extension split** (`_split_urls_by_ext`) — Separates URLs by file type
9. **GF patterns** (`url_gf`) — Runs GF patterns (sqli, xss, ssrf, redirect, etc.)
10. **Scanner chunks** — Splits live URLs into 500-line CSV chunks
11. **JS analysis** (`jschecks`) — Runs JS analysis pipeline if `JSCHECKS=true`
12. **Discord notification** — Reports total and live URL counts

### Output structure

```
Recon/<target>/
  urls/
    all_urls.txt           # All collected URLs (deduplicated)
    live_urls.txt          # Confirmed live URLs
    urls_js.txt            # JavaScript files
    urls_dynamic.txt       # PHP/ASP/JSP pages
    urls_data.txt          # JSON/XML/YAML files
    urls_docs.txt          # Documents (PDF, Office, etc.)
    urls_params.txt        # URLs with query parameters
    urls_gau.txt           # Raw gau output
    urls_waymore.txt       # Raw waymore output
    urls_katana.txt        # Raw katana output
    urls_gospider.txt      # Raw gospider output
    urls_urlscan.txt       # Raw urlscan output
  params/paramspider.txt   # Paramspider output
  scanner/
    urls_chunk_00..        # 500-line URL chunks
    urls_with_target.csv   # domain,url format
```

---

## Discord Notifications

Set `DISCORD_WEBHOOK` in your config or environment to receive notifications:

```bash
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/<id>/<token>"
```

Notifications are sent at:
- End of Open Mode (with summary stats)
- End of Wilde Mode (subdomain count)
- End of URL Mode (URL count)
- New subdomains detected during background monitoring

---

## Background Subdomain Monitoring

Wilde Mode automatically adds each scanned target to `.monitor_queue` at `<SCRIPTPATH>/.monitor_queue`.

To start the monitor processor:

```bash
# In a separate terminal or tmux window
source reconftw.cfg
source modules/wilde_recon.sh
run_monitor_queue
```

The monitor checks each queued target every `MONITOR_INTERVAL_MIN` minutes (default: 60), running subfinder and crt.sh, and sends a Discord notification if new subdomains are found.

---

## All CLI Arguments

```
Usage: reconftw.sh [-d domain] [-l list] [-m multi] [options] [mode]

Modes:
  -r, --recon           Full recon (default)
  -s, --subdomains      Subdomains only
  -p, --passive         Passive recon only
  -a, --all             All modules including vulns
  -w, --web             Web analysis on URL list
  -n, --osint           OSINT only
  -z, --zen             Zen mode (quiet)
  -O, --mode open       Open mode (horizontal/company asset discovery)
  -W, --mode wilde      Wilde mode (comprehensive subdomain enumeration)
  -U, --mode url        URL mode (URL collection and classification)
      --mode <value>    Explicit mode selection: open|wilde|url

Target:
  -d <domain>           Single domain target
  -l <file>             File with one target per line
  -m <name>             Multi-target name
  -x <file>             Out-of-scope domains file
  -i <file>             In-scope domains file

Output:
  -o <dir>              Custom output directory
  --export <fmt>        Export format: json|html|csv|all
  --report-only         Only generate report, no scanning
  --no-report           Skip report generation

Configuration:
  -f <file>             Custom config file
  -q <rate>             Rate limit (requests/sec)
  -c <function>         Run custom function
  --deep                Deep mode (slower, more thorough)
  --dry-run             Show commands without executing

VPS / Axiom:
  -v, --vps             Use Axiom VPS fleet
  --vps-count <n>       Number of VPS instances

Performance:
  --parallel            Enable parallel execution (default: on)
  --no-parallel         Disable parallel execution
  --adaptive-rate       Auto-adjust rate on 429/503 errors
  --incremental         Only scan new findings since last run
  --quick-rescan        Skip already-completed modules
  --force               Force rescan of completed modules

Monitoring:
  --monitor             Enable continuous monitoring mode
  --monitor-interval <min>  Minutes between monitor cycles (default: 60)
  --monitor-cycles <n>  Max monitoring cycles (0 = unlimited)

Logging:
  --quiet               Suppress output (errors only)
  --verbose             Verbose output with PIDs and timestamps
  --no-color            Disable ANSI colors
  --log-format <fmt>    Log format: plain|jsonl|jsonl-strict
  --parallel-log <mode> Parallel log mode: summary|tail|full

Misc:
  -y, --ai              Enable AI analysis
  --check-tools         Check installed tools and exit
  --health-check        Run health check and exit
  --refresh-cache       Force refresh of cached resources
  --gen-resolvers       Generate custom resolvers
  --show-cache          Show cached resource status
  --banner              Show banner
  --no-banner           Hide banner
  --legal               Show legal disclaimer
  -h, --help            Show help
```
