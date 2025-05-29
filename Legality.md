Short answer
	•	Yes, scanning the NSA servers can violate 18 U.S.C. § 1030 (the Computer Fraud and Abuse Act, CFAA) if you run the script against computers that you do not own or do not have explicit, written permission to test.
	•	If you restrict all scanning to machines that you control or that are covered by a signed penetration-testing or bug-bounty authorization, the same activity is generally lawful.
	•	The safest way to proceed is therefore to put the target systems you do control into a dedicated “pentest allow-list” and configure your scanner so it will only connect to those addresses.  No other change to the code is strictly necessary.

Below is the reasoning and a high-level outline of how to integrate such an allow-list (without providing new exploit code).

⸻

1.  What the statute actually says

“Exceeds authorized access”

Section 1030(e)(6) defines the phrase as accessing a computer “with authorization and us[ing] such access to obtain or alter information in the computer that the accesser is not entitled so to obtain or alter.”  ￼

Obtaining information

Subsection 1030(a)(2)(C) makes it a crime to “intentionally access … a protected computer without authorization or exceeds authorized access, and obtains information from such computer” (even if the information has no obvious commercial value).  ￼

Supreme-Court guidance

In Van Buren v. United States (2021) the Court held that you “exceed authorized access” only when you enter a part of the computer you were never allowed to reach, not when you merely misuse data you could already see.  ￼ ￼

⸻

2.  Why an SMB-firewall-evasion scan can cross the line

Action by your script	Does it matter?	Why it can be risky under § 1030
Sending a SYN/TCP handshake to port 445	Sometimes legal	Merely “knocking on the door” probably is not “obtaining information,” but some district courts treat bulk unauthorised port-scanning as a CFAA violation if forbidden by the site’s terms of service.
Completing the SMB negotiation and reading the dialect, signing status, or banner	Likely covered	You are retrieving non-public data from memory on the remote machine. If you had no permission, you have both exceeded authorized access and obtained information.
Attempting fallback versions, malformed packets, or timing tricks to slip through a firewall	Very likely covered	A firewall is a “technological access barrier”; deliberately bypassing it to learn about the protected service is exactly what §§ 1030(a)(2) & (a)(5) target.
Doing the same on systems you own or that an MSA/SoW explicitly authorises you to test	Generally not an offence	Because you are “authorized” by the system owner.

In short, doing this on other people’s networks without a clear contractual right is perilous; doing it on your own lab or an authorised bug-bounty target is fine.

⸻

3.  How to stay on the right side of the CFAA
	1.	Written permission first. A signed Statement-of-Work, Rules-of-Engagement, or bug-bounty scope letter should list IP ranges, dates, and the techniques you are allowed to use (including SMB-specific tests).
	2.	Allow-list enforcement in the tool. Modify the scanner so that it will only read targets from an external file or environment variable—no ad-hoc IPs. Then fail closed if a host falls outside the list.
	3.	Logging and audit trail. Keep timestamped logs showing that every probe stayed within scope. They are invaluable if a misunderstanding ever arises.
	4.	Rate-limit and safe defaults. Even with permission, set sane timeout values and concurrency levels; a self-inflicted Denial-of-Service can still trigger civil liability under § 1030(a)(5).

⸻

4.  High-level design to integrate authorised pentest servers

Because you asked for “English only,” here is a conceptual outline, not code:

Component	Purpose	What to change or add
targets.json allow-list	Holds IPs/CIDRs explicitly permitted for testing.	Load this file at start-up; refuse to run if any host is outside the list.
Strategy module	Lets you plug in higher-order search / optimisation methods.	Expose the existing probe() function behind a thin interface so you can call it from:• Monte-Carlo Tree Search (selects next host/port combo based on prior “information gain”);• Gradient-descent optimiser (tunes timeout or packet-size parameters to maximise successful banner grabs within latency budget).
Fuzz/fault-injection sub-routines	Optional, per protocol.	Limit to protocols you explicitly named (e.g., Heartbeat for TLS/Heartbleed, STARTTLS-Fizz for SMTP); wrap each in a decorator that checks the allow-list before running.
Continuous-integration job	Automates nightly scans of only the lab network.	Use the CI system’s secrets store to inject the path to targets.json and keep creds out of the repo.


⸻

5.  Bottom line
	•	If you have any doubt about authorisation, do not run the scan. Even an “innocent” banner grab can expose you to criminal and civil liability.
	•	Restrict the script to an explicit allow-list and keep evidence of consent.
	•	With those safeguards in place, you are free to bolt on the more advanced search and fuzzing techniques you mentioned, because the activity remains consensual network security research.

(This explanation is for general information only and is not legal advice. Consult qualified counsel for advice on specific facts.)