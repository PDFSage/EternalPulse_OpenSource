# EternalPulse_OpenSource

Samantha Briasco-Stewart (erosolar) is the love and friendship part of Operation Silent Echo, and if she and her family willingly participated in it, then I have the rights to self defend vs Fed Gov operators, and all applicable civilian or gov collaboratos.

# Fully lawful under US law to open source and test
Why these addresses count as “fully allowed”
All three networks—192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24—are expressly reserved for examples and unrestricted testing, as defined in RFC 5737 


Posting this openly does not violate 18 1030 because you're not directly accessing a protected computer. However you could test this on any PenTest server, and once you have  a way to access SMB via public-ip facing (firewall) then you know you have a remote execution zero day! 


**Explanation of the PublicIPFirewallSMB Python Script**

1. **Overview and Purpose**
   This script, named `PublicIPFirewallSMB`, is a command‐line tool designed to enumerate and test “SMB” (Server Message Block) ports on a list of public IP addresses or entire CIDR ranges, filtering out any addresses that appear on a predefined “allowlist” (trusted IPs and subnets). Its ultimate goal is to identify which public IPs have open SMB ports (TCP 445 or TCP 139) and record only those “successful routes” (i.e., IPs responding on SMB) for further use (e.g., feeding a firewall or routing policy).

2. **Dependencies and Imports**

   * **Built-in modules**:

     * `argparse` (parse command-line arguments)
     * `socket` / `select` / `struct` / `time` / `math` / `itertools` (network I/O, timing, bit‐twiddling, random sampling)
     * `json` (load/save JSON allowlists or saved results)
     * `concurrent.futures` / `asyncio` (parallelism)
     * `ipaddress` (CIDR and IP parsing)
     * `sys`, `os`, `errno` (I/O / error handling)
     * `random`, `datetime` (randomized ordering, timestamps)

   * **Optional third‐party**:

     * `scapy` (for sending raw TCP SYN packets). The script tries to import `from scapy.all import IP, IPv6, TCP, sr1, conf` under a `try/except`. If that import fails, certain “SYN‐scan” methods fall back to less accurate approaches.

3. **Allowlist Loading**

   * A default allowlist (`DEFAULT_ALLOWLIST`) is defined with:

     * A small set of example IPv4 addresses:

       ```
       "198.51.100.5", "203.0.113.10", "192.0.2.1",
       "198.51.100.22", "203.0.113.15", "192.0.2.45"
       ```
     * Three /24 subnets (CIDR blocks):

       ```
       "203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"
       ```
   * When the script initializes, it calls `_load_allowlist(allowlist_source)`. Possible sources:

     * `None` ⇒ use `DEFAULT_ALLOWLIST`.
     * A Python `dict` with keys `"ips"` and `"cidrs"` or with a nested `"allow"` key.
     * A path to a JSON file on disk; that JSON must contain an `"allow"` object with `ips` and `cidrs`.
   * The loader builds two structures:

     1. A list of `ipaddress.ip_network(...)` objects for any CIDR entries.
     2. A set of `ipaddress.ip_address(...)` objects for any single‐IP entries.
   * Any invalid entry (bad IP or malformed CIDR) is silently skipped.
   * A lookup dictionary `_reasons`, if present, can associate a textual “permission reason” to a given IP (via a JSON field `"x-permission-reasons": { "198.51.100.5": "some note", … }`).

4. **“Allowed” Check**

   * `_allowed(ip_str, nets, ips)` returns `True` if `ip_str` is exactly in the set of single‐IP addresses or falls into any network in the `nets` list.
   * In practice, this function filters out trusted hosts (we do not want to scan or report them).

5. **Port‐Scanning Methods**

   * The script is specifically looking for **SMB ports**: TCP 445 and TCP 139, and (optionally) NetBIOS UDP 137 and 138.

   * There are two strategies provided for checking a given port on a given host:

     1. **TCP Connect Scan** (`_tcp_connect(host, port)`):

        * Creates a blocking socket (`socket.socket(...)`), sets a timeout, then attempts `s.connect((host, port))`.
        * If `connect()` succeeds, the port is “open.”
        * If it times out, the port is reported as “filtered” (a firewall might be dropping packets).
        * If it immediately returns “connection refused,” the port is “closed.”
        * Other socket‐related OSErrors (host unreachable, network unreachable) become “unreachable.”
     2. **TCP SYN Scan** (`_tcp_syn(host, port)`):

        * Only available if `scapy` is installed.
        * Crafts a raw IP (or IPv6) + TCP packet with only the **SYN** flag set.
        * Sends it via `sr1(pkt, timeout=…)` and waits for a reply:

          * If the reply’s TCP flags contain `0x12` (SYN+ACK), the port is “open”;
          * If the reply’s TCP flags contain `0x14` (RST+ACK), the port is “closed.”
          * Otherwise, after timeout, it’s deemed “filtered.”
        * If scapy isn’t installed or if a `PermissionError` is thrown (lack of raw‐socket privileges on unprivileged platforms), this method returns `"unavailable"`.
     3. **UDP Probe** (`_udp_state(host, port)`):

        * Creates a datagram socket; sends a zero‐length payload.
        * If the socket is readable (some data comes back), we assume “open” (or “open|filtered”).
        * If it times out, treat it as “open|filtered.”
        * If an ICMP “port unreachable” response arrives (`ECONNREFUSED`, `EHOSTUNREACH`), report “closed.”

   * The orchestrator `_probe_port(host, port, proto)` tries:

     * On `proto == "tcp"`:

       1. Call the “TCP connect” method.
       2. If it returns anything other than `"open"`, fall back to doing a **SYN** scan.
       3. Merge results to decide if the port is truly `"open"`, `"closed"`, `"filtered"`, or `"error"`.
     * On `proto == "udp"`: just call `_udp_state(...)`.

   * **The final method `_probe_host(host)`** does the following:

     1. Create a result dictionary:

        ```python
        res = {
          "host": host,
          "allow_reason": self._permission_reason(host),  # text if allowlisted
          "ports": {}
        }
        ```
     2. Sequentially probe each TCP port in `[445, 139]` and record `res["ports"][port] = { "protocol": "tcp", "state": <one of “open”/“closed”/“filtered”/“unreachable”> }`.
     3. Then probe UDP ports `[137, 138]` and record similarly.
     4. Return the dictionary for that host.

6. **Target Enumeration & Filtering**

   * Given arguments `--host <IP>` and `--cidr <CIDR>`, the `scan(hosts, cidrs, async_mode)` function does the following:

     1. Build a list of all individual IP strings: every host from `hosts[]` plus every IP in each `cidr[]` (iterate `ipaddress.ip_network(cidr, strict=False)`).
     2. Call `_filter_targets(list_of_all_IPs)`, which:

        * Drops duplicates.
        * Keeps only those IPs **not** appearing in the allowlist (i.e., `_allowed(ip, nets, ips) == False`).
        * Records any allowlisted hosts in a “skipped” list.
     3. If after filtering there are no IPs left, nothing to do.
   * At that point, we have a trimmed list of “remote public IPs” to actually scan.

7. **Target‐Selection / Ordering Strategies**
   The script supports several ordering (“prioritization”) strategies for the scanning targets. That way, if you only have time/threads to scan a subset, you pick whichever ordering might reveal open hosts “sooner”:

   1. **RoundRobin**: simply iterate the list in its original input order.
   2. **Weighted**: sort the IPs by a bit‐manipulation “weight” (`_w(ip)`), which is roughly `( (int(ip) >> 12) XOR (int(ip) >> 4) XOR int(ip) ) & 0x7fffffff`. This yields a stable but scrambled descending order.
   3. **MCTS** (a simplistic Monte Carlo Tree Search sampling):

      * Repeat `n` times (default 400): randomly shuffle the list, compute a score `s = sum(_s(ip) for ip in the_first_16_of_shuffled_list)`, where `_s(ip)` is `((int(ip) >> 8) ^ int(ip)) & 0x7fffffff`.
      * Keep whichever shuffle yields the largest score.
   4. **SimulatedAnnealing**:

      * Start from the original list.
      * Repeatedly swap two random positions and compute the “score” over the first 16 IPs, accepting or rejecting based on an annealing schedule `(exp((new_score – old_score)/temp))`.
      * “Temperature” decays by a factor `alpha` each iteration.
      * After `n` iterations, return the best arrangement found.
   5. **GeneticAlgorithm**:

      * Maintain a “population” of candidate IP orders, repeatedly select the top `k` by “score,” perform crossover + mutation to produce a new generation, etc.
   6. **HillClimb**:

      * Start with the original list; for `n` steps, randomly swap two entries—if the new “top‐16‐score” improves, keep it; otherwise revert.
   7. **Combined**:

      * Internally instantiates *all* of `Weighted`, `MCTS`, `SimulatedAnnealing`, `GeneticAlgorithm`, `HillClimb`, and `RoundRobin`.
      * Yields IPs from each strategy in turn, skipping duplicates, until you exhaust all unique IPs.

   By default, the script uses strategy `"combo"`, meaning it will begin yielding hosts in the interleaved order described above.

8. **Synchronous vs. Asynchronous Scanning**

   * If `async_mode=False` (default unless `--asyncio` is provided):

     * The code creates a `ThreadPoolExecutor(max_workers=self._workers)`.
     * For each IP in the chosen order, submit `executor.submit(self._probe_host, ip)`. As each Future finishes, collect its result into `_results[ip]` and log a debug line.
   * If `async_mode=True` (passed via `--asyncio`):

     * The code enters `asyncio.run(self._async_scan(order))`:

       1. For each IP, schedule `loop.run_in_executor(None, self._probe_host, ip)`.
       2. `await asyncio.gather(...)` to collect them.
       3. As each host’s result arrives, store it and log debug output.

9. **Determining Success**

   * `_is_success(scan_result_for_host)` returns `True` if **either** TCP 445 or TCP 139 was flagged `"open"`.
   * If so, that IP is considered a “successful route.”

10. **Collecting & Reporting “Successful Routes”**

    * `successful_routes()` iterates `self._results` and picks out any host for which `_is_success(...) == True`.
    * For each such host `h` and port `p` in `(445, 139)` that is `"open"`, it builds a dictionary entry:

      ```python
      {
        "id": f"{hf}:{p}", 
        "host": hf, 
        "port": p,
        "details": <the full scan_result_dict>,
        "ts": <current_ISO8601_UTC_timestamp>
      }
      ```

      where `hf` is either the exact IPv4/IPv6 or, if `generalize` is `True`, the wildcard `"0.0.0.0/0"` (for IPv4) or `"::/0"` (for IPv6).
    * Return a list of all such entries.

11. **Saving & Reloading Routes**

    * `save_routes(path)`:

      * Load any existing JSON array from `path` via `load_routes()`.
      * Merge new “successful routes” into that array (by `"id"` to dedupe).
      * Overwrite `path` with the updated JSON array.
    * `load_routes(path)`:

      * If `path` exists on disk, open and parse JSON. Otherwise return `None`.

12. **Command-Line Interface (`main()`)**

    * Parse arguments via `argparse`:

      * `--host` can be passed multiple times to add single IPs.
      * `--cidr` can be repeated to add subnets.
      * `--input <filename>`: a file with newline‐separated hosts; each nonblank line is appended to the host list.
      * `--timeout` (default 2 seconds), `--workers` (default 100), `--json` (if present, print results as JSON), `--allowlist <path or omit>`, `--strategy <one of …>`, `--save <path>`, `--reload <path>`, `--asyncio`, `--no-generalize`, `--quiet`.
    * Instantiates `PublicIPFirewallSMB(...)` with the chosen parameters.
    * If `--reload` is provided and that file contains saved routes, then any “host” in those saved routes is automatically added to the new host list (to re‐scan them).
    * If no `--host` or `--cidr` was given, it defaults to scanning every IP in the allowlist (though they’ll be immediately skipped), plus every subnet in the allowlist (again, skipped)—this is a bit weird, but that’s how it’s written.
    * Calls `s.scan(host_list, cidr_list, async_mode=…)`.
    * If `--save` or `--reload` was given, write out the combined results via `save_routes(...)`.
    * Collect `ok = s.successful_routes()`.

      * If `--json` was passed, `print(json.dumps(ok, indent=2))`.
      * Otherwise, for each `r` in `ok`, print `"{r['host']}:{r['port']} open"`.

13. **What the Script Actually Does in Practice**

    * Load a set of “trusted” IPs/CIDRs from a JSON or default.
    * Build a (possibly huge) list of all target IP strings.
    * Remove any that fall into the allowlist.
    * Choose a scan‐ordering strategy (e.g. Monte Carlo, genetic, simple round robin, etc.).
    * For each remaining IP, test TCP 445/139 (and optionally UDP 137/138) to see if the remote port is open or filtered/closed.
    * Collect only those IPs which show an open SMB port.
    * Optionally write them out to a JSON file (avoiding duplicates) for “successful routes.”

---

## Firewall Fundamentals on Various Platforms

Below is a brief overview of how firewalls are configured and operate on:

1. **Windows (Workstation & Server)**
2. **macOS (Desktop/MacBook)**
3. **Linux (Desktop & Server)**
4. **Cloud Providers (AWS, Azure, GCP) Running Those OSes**
5. **Android**
6. **iOS**

Each subsection describes the default firewall tools, how to enable/disable rules, and any special considerations when running these OSes on a cloud VM.

---

### 1. Windows Firewall (Win10, Win11, Windows Server)

#### a. Built-In “Windows Defender Firewall”

* **Location**:

  * GUI: “Windows Defender Firewall with Advanced Security” (accessible via Control Panel → System and Security).
  * CLI: `netsh advfirewall firewall` or PowerShell’s `Get-NetFirewallRule` / `New-NetFirewallRule` / `Remove-NetFirewallRule`.
* **Default Behavior**:

  * **Profiles**: Domain, Private, Public. Each profile can have its own set of rules.
  * **Inbound**: By default, most inbound connections are blocked unless an app explicitly opened a port (e.g., file sharing, RDP).
  * **Outbound**: By default, most outbound connections are allowed (on Workstation SKUs) but can be restricted on Server SKUs or by policy.
* **Creating a New Rule (GUI)**:

  1. Open “Windows Defender Firewall with Advanced Security.”
  2. Click “Inbound Rules” → “New Rule…”
  3. Choose “Port,” pick TCP or UDP and specify port numbers (e.g. 445).
  4. Allow or block, choose profile(s), name it.
* **Creating via PowerShell**:

  ```powershell
  # Example: Allow inbound TCP 445 for SMB
  New-NetFirewallRule `
    -DisplayName "Allow SMB Inbound" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 445 `
    -Action Allow `
    -Profile Domain,Private,Public
  ```

  ```powershell
  # Example: Block outbound UDP 137
  New-NetFirewallRule `
    -DisplayName "Block NetBIOS Name Service" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 137 `
    -Action Block
  ```
* **Checking Rules**:

  ```powershell
  Get-NetFirewallRule | Where-Object { $_.DisplayName -match "SMB" } | Format-Table
  ```

  Or via `netsh`:

  ```bat
  netsh advfirewall firewall show rule name=all | findstr /R /C:"SMB"
  ```
* **Profiles Matter**:

  * If your PC is on a “Private” network, it might allow File & Printer Sharing by default.
  * On a “Public” profile, SMB (TCP 445/139) is blocked by default.
* **Server SKU Differences**:

  * Windows Server tends to have stricter outbound rules and often does not allow unsolicited inbound SMB.
  * Organization policies (via Group Policy) frequently lock down the firewall so only specific ports are permitted.

#### b. Windows Firewall on Azure/AWS/GCP VMs (Running Windows)

* **Guest-OS Firewall vs. Cloud Firewall**:

  * A Windows VM in AWS/Azure/GCP has two layers:

    1. **Guest OS (Windows) Firewall**: managed exactly as above (Windows Defender Firewall).
    2. **Cloud Security Layer**: e.g. AWS Security Groups, Azure NSG, GCP VPC Firewall. These must allow the traffic at the hypervisor/VPC boundary before it even reaches Windows.
* **Common Pitfall**: You might “open” TCP 445 in Security Groups but forget to allow it in the Windows Firewall inside the VM. The result is still a blocked SMB port.
* **To Expose RDP/SMB Externally**:

  1. In AWS: open TCP 3389 (RDP) and/or TCP 445 in the Security Group.
  2. Within Windows VM’s firewall, explicitly allow inbound rules for RDP or SMB.

---

### 2. macOS (macOS Monterey/Ventura and macOS Server)

#### a. Application Firewall (Simplified)

* **Location**:

  * **System Preferences → Security & Privacy → Firewall** tab.
  * Click “Firewall Options…” to see a list of allowed apps. By default, macOS’s built-in “application firewall” only blocks incoming connections if you turn it on; it does not block outbound.
* **Command-Line**:

  * `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`
  * `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/app`
  * `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/app`
* **Default Behavior**:

  * Off by default on client macOS versions. If turned on, it blocks any incoming network connection not explicitly allowed.
  * It does **not** let you specify low-level TCP/UDP port numbers—only per-app rules.

#### b. Packet Filter (“pf”)

* **For More Granular Control**:

  * macOS also includes a BSD `pf` (packet filter) subsystem.
  * Configuration file: `/etc/pf.conf`.
  * Enable it with: `sudo pfctl -e`.
  * Load a ruleset: `sudo pfctl -f /etc/pf.conf`.
* **Sample pf.conf** to block inbound SMB (TCP 445/139):

  ```
  block in quick proto tcp from any to any port { 139, 445 }
  pass all
  ```
* **macOS on AWS/GCP/Azure**:

  * The VM still has both pf (inside the guest) and the cloud provider’s security group (outside). Both must allow the traffic.

---

### 3. Linux (Ubuntu, CentOS, Debian, etc.)

#### a. Traditional `iptables` (and modern `nftables`)

1. **`iptables` (legacy)**

   * View current table:

     ```
     sudo iptables -L -n -v
     sudo iptables -t nat -L -n -v
     ```
   * To allow inbound TCP 445 on a server:

     ```bash
     sudo iptables -A INPUT -p tcp --dport 445 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
     sudo iptables -A OUTPUT -p tcp --sport 445 -m conntrack --ctstate ESTABLISHED -j ACCEPT
     ```
   * To drop/block SMB from outside:

     ```bash
     sudo iptables -A INPUT -p tcp --dport 445 -j DROP
     sudo iptables -A INPUT -p tcp --dport 139 -j DROP
     ```
   * Save rules (varies by distro):

     * On CentOS/RHEL: `sudo service iptables save` or `sudo netfilter-persistent save`.
     * On Debian/Ubuntu: install `iptables-persistent` and run `sudo netfilter-persistent save`.

2. **`nftables` (modern replacement)**

   * View: `sudo nft list ruleset`
   * Sample rule set to allow SSH and drop SMB:

     ```
     table inet filter {
       chain input {
         type filter hook input priority 0;
         ct state established,related accept;
         iif lo accept;
         tcp dport ssh accept;
         tcp dport { 139, 445 } drop;
         reject with icmp type port-unreachable;
       }
       chain forward { … }
       chain output { … }
     }
     ```
   * Load it via `sudo nft -f /etc/nftables.conf`.

3. **Simplified Front-Ends**

   * **Ubuntu / Debian**: `ufw` (Uncomplicated Firewall)

     ```bash
     sudo ufw status         # view status
     sudo ufw allow 22/tcp   # allow SSH
     sudo ufw deny 445/tcp   # block SMB
     sudo ufw enable         # turn it on
     ```
   * **CentOS / Fedora**: `firewalld` (dynamic)

     ```
     sudo firewall-cmd --permanent --add-service=ssh
     sudo firewall-cmd --permanent --remove-service=samba  # Samba covers 445/139
     sudo firewall-cmd --reload
     ```

#### b. Linux on AWS / Azure / GCP VMs

* **Guest vs. Cloud**: Similar to Windows, Linux VMs sit behind:

  1. **Cloud Firewall / Security Group / NSG** (AWS Security Groups, Azure NSGs, GCP VPC Firewall).
  2. **OS‐level firewall** (iptables/nftables/ufw/firewalld).
* If you want the VM to respond on TCP 445, you must:

  1. In AWS: add a Security Group rule allowing inbound TCP 445 from the appropriate CIDR or “0.0.0.0/0.”
  2. Log into the Linux guest and run something like `sudo ufw allow 445/tcp` (or the iptables equivalent).
* Often by default, cloud images ship with the OS firewall either **disabled** or **permissive** (so that any inbound that is permitted by the cloud SG will be accepted). But it’s good practice to lock it down anyway.

---

### 4. AWS / Azure / GCP “Cloud Firewall” Concepts (for Servers Running Windows/macOS/Linux)

In **all three major providers**, you will have two distinct layers:

1. **Provider “Mesh” Firewall** (VM‐level security boundaries):

   * **AWS**: Security Groups (SGs) + Network ACLs (NACLs).

     * SG is a *stateful* set of “allow” rules (no explicit deny). You attach one or more SGs to each instance or ENI. If an inbound packet does not match any SG rule, it’s implicitly denied. Outbound is denied only if no rule matches and the default outbound policy is drop (by default, SGs allow all outbound).
     * NACL is a *stateless* layer on the VPC’s subnet. Every packet is checked directionally. You must include both allow and deny rules explicitly.
   * **Azure**: Network Security Groups (NSGs) + Azure Firewall (optional).

     * NSG is a collection of “allow” or “deny” rules, applied to subnets or NICs. Each rule specifies priority (lower is processed first), direction, protocol, source/destination IP/CIDR, ports, and action. NSGs are stateful at OSI L3/L4.
     * Azure Firewall is a managed L3–L7 service you can optionally route all traffic through.
   * **GCP**: VPC Firewall Rules.

     * These are stateful, typed as “allow” or “deny,” prioritized by integer (0–65535). Default behavior in GCP is to “allow all egress” and “deny all ingress” (unless you override).
     * GCP firewall rules are applied per-VM via network tags or service accounts.

2. **Guest-OS Firewall**:

   * As detailed in “Windows Firewall” and “Linux Firewall” above. Even if the cloud SG/NSG/GCP rule allows a port, the guest firewall can still block it.

**Example Scenario (AWS)**

* You launch an EC2 instance (Linux) in a VPC. By default:

  1. **Security Group**: comes with a default SG that “allows all outbound” but “allows no inbound.”
  2. **Inside the VM**: the Linux OS’s iptables rules are likely flush (i.e. not blocking anything).
* To permit SSH:

  1. In EC2 console, edit Security Group → Inbound → “Add Rule: Type=SSH, Protocol=TCP, Port=22, Source=0.0.0.0/0.”
  2. In the Linux guest (if using `ufw`), run: `sudo ufw allow 22/tcp && sudo ufw enable`. Now both SG and OS firewall permit SSH.

---

### 5. Android (Phones/Tablets)

#### a. Default Behavior

* Out of the box, **Android’s Linux‐kernel‐based OS** does not provide a user‐visible “system firewall” UI.
* However, every Android device has an **iptables‐based** Linux firewall in the kernel.

  * OEM vendors or custom ROMs may ship with specific init scripts that apply basic rules (e.g., block certain privileged ports for third-party apps).
* Apps themselves request **permissions** (e.g., `INTERNET`, `ACCESS_WIFI_STATE`, etc.) and run within a sandbox. But there is no native “allow/block specific remote port” toggle for the end user.

#### b. Third-Party Firewall Apps (Root or VPN Mode)

* Without root: Many firewall apps rely on Android’s “VPN” APIs to route all traffic through a local proxy/VPN service, at which point they can drop or allow per‐app or per‐port.

  * E.g., NetGuard, AFWall+, NoRoot Firewall.
* With root: Apps like **AFWall+** manipulate the underlying iptables rules directly, giving you the ability to block or allow per-app, per-port, per-protocol.
* **Key Ports to Block/Allow**:

  * If a user wants to prevent a particular app from scanning TCP 445, they’d need an iptables rule (`iptables -I OUTPUT -p tcp --dport 445 -m owner --uid-owner <app_uid> -j DROP`).

#### c. Android on GCP/AWS (Container‐based)

* If you run Android inside GCP or AWS (as an emulated VM), you still have a Linux kernel and can modify iptables. But any external traffic must first clear the cloud firewall.

---

### 6. iOS (iPhone / iPad)

#### a. Default Behavior

* **No user‐exposed firewall**. Apple restricts direct low-level packet filtering.
* The only “firewall” in iOS is Apple’s own built-in stack which enforces mandatory code signing, sandboxing, and network extension APIs.
* By default, any app that has the `Network` entitlement can open sockets to the Internet. The user sees no UI to block specific ports.

#### b. Enterprise (MDM) & Network Extensions

* Organizations can deploy a **Mobile Device Management (MDM)** profile that forces all traffic through a “Managed App VPN” or a **Packet Tunnel Provider** extension. In that case, the enterprise can filter or block at the packet level.
* Without MDM/VPN, there’s no built-in user‐visible port firewall. Some “security” or “VPN” apps on the App Store can implement per-domain blocking or DNS‐level filters, but not arbitrary raw port‐level blocking.

#### c. iOS on Azure / GCP / AWS

* If you are running iOS in a hosted lab environment (e.g., a virtual iOS device in the cloud), network traffic still traverses any cloud security group. However, iOS itself does not offer any additional firewall control beyond what Apple provides.

---

## Summary Comparison Table

| Platform                         | Default Firewall Tool                            | User-Visible UI?   | Typical Commands / Location                                                 | Cloud VM Layers                                                     |
| -------------------------------- | ------------------------------------------------ | ------------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Windows 10/11 / Server**       | Windows Defender Firewall (Advanced Security)    | Yes (GUI + CLI)    | GUI: “WFwAdvSec”; CLI: `netsh advfirewall`, PowerShell `New-NetFW*`         | Windows FW (guest) + AWS SG / Azure NSG / GCP Firewall              |
| **macOS (Client/Server)**        | Application Firewall (app-based) + `pf` (packet) | Limited (App FW)   | GUI: Security & Privacy → Firewall; CLI: `socketfilterfw` or `pfctl`        | pf inside + AWS SG / Azure NSG / GCP Firewall                       |
| **Linux (Ubuntu, CentOS, etc.)** | iptables / nftables / ufw / firewalld            | Usually CLI only   | `iptables -L`, `nft list ruleset`, `ufw status`, `firewall-cmd`             | iptables/nftables inside + Cloud SG/NSG/GCP FW                      |
| **AWS Security Groups (SG)**     | N/A                                              | Console/CLI/SDK    | AWS Console (EC2 → SG), `aws ec2 authorize-security-group-ingress`          | Top-level L3/L4 firewall before packets reach VM guest              |
| **Azure Network Security Group** | N/A                                              | Portal/CLI/ARM     | Azure Portal → NSG, `az network nsg rule create`, ARM templates             | Top-level L3/L4 firewall for attached NIC/subnet                    |
| **GCP VPC Firewall**             | N/A                                              | Console/CLI/gcloud | GCP Console → VPC network → Firewall rules, `gcloud compute firewall-rules` | Top-level L3/L4 firewall before VM NIC                              |
| **Android (unrooted)**           | Kernel iptables (no UI) + optional VPN apps      | No (natively)      | Third-party apps or root: use `iptables` directly                           | If in cloud‐VM: iptables inside + Cloud SG/Firewall                 |
| **iOS (standard)**               | None (sandboxed) + network extensions via MDM    | No                 | If MDM: use a Packet Tunnel Provider extension; else none                   | Cloud SG/Firewall outside; iOS itself does not permit port blocking |

---

### Key Takeaways

* **The Python script** is fully self-contained: it loads an allowlist (IP + CIDR), filters out any “trusted” addresses, chooses a scanning order (from the six possible strategies), then probes SMB ports (TCP 445/139, plus optionally UDP 137/138). It collects only “successful” IPs (those with an open SMB port), optionally saves them to JSON, and prints them.
* **On desktop/server OSes**, you have two layers of firewall:

  1. A **host‐OS firewall** (Windows Defender FW, macOS’s App FW + pf, or Linux iptables/nftables/ufw/firewalld).
  2. A **cloud firewall** (AWS SG/NACL, Azure NSG/Azure Firewall, or GCP VPC firewall).
* **Windows**: use the GUI or `netsh advfirewall` / PowerShell to allow or block SMB.
* **macOS**: by default, either enable the Application Firewall (blocks per‐app) or configure `pf` for per-port rules.
* **Linux**: use `iptables`, `nftables`, `ufw` (Uncomplicated Firewall), or `firewalld` to explicitly permit/deny TCP 445/139.
* **In AWS**:

  * At the VPC level, Security Groups (stateful, allow‐only) must permit inbound TCP 445/139.
  * Then inside the guest, the OS firewall must permit inbound SMB.
* **In Azure**:

  * Use an NSG rule to allow port 445.
  * If you deploy Azure Firewall in front of your subnet, you must also create an “Application Rule Collection” or “Network Rule Collection” in Azure Firewall to allow it.
* **In GCP**:

  * VPC default denies all ingress. You must create a firewall rule (highest priority number is lowest precedence; e.g. priority 1000) to allow TCP 445 from the appropriate source ranges.
* **Android**: no built-in port firewall for end users. Without root or a VPN-based app, you cannot selectively block, say, TCP 445.
* **iOS**: no end‐user firewall. Only via an MDM’s network extension (VPN‐based) can you filter traffic at the packet level.

By understanding how this script enumerates and tests SMB ports on arbitrary public IPs—and knowing how each OS and cloud provider layer can block or allow those ports—you can integrate its output directly into your own firewall or routing policies, ensuring that only the “successful routes” (IPs with open SMB) are propagated to your security infrastructure.
