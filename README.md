# EternalPulse_OpenSource
Why these addresses count as “fully allowed”
All three networks—192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24—are expressly reserved for examples and unrestricted testing, as defined in RFC 5737 
IETF Datatracker
Wikipedia
RFC Hashnode
.
Testing those hosts is also widely accepted within safe-harbor and bug-bounty policies, including HackerOne and Bugcrowd program scopes 
HackerOne Help Center
HackerOne Help Center
Bugcrowd Docs
Bugcrowd Docs
, and is reflected in common documentation from vendors such as Oracle 
Oracle Docs
 and community practice discussions 
Reddit
Bugcrowd
.

Running the script prints the purified JSON that contains only the documentation-range IPs and CIDRs—i.e., those you can safely “fully allow.”

Posting this openly does not violate 18 1030 because you're not directly accessing a protected computer. However you could test this on any PenTest server, and once you have  a way to access SMB via public-ip facing (firewall) then you know you have a remote execution zero day! 

![0630BB35-0FFB-4620-9A29-DF73536E2A11](https://github.com/user-attachments/assets/c293c82a-57fc-4a59-8e48-4d2e9b3cfc30)

![3C5F1AF5-9025-4A6B-92EF-5B2BBFE79384](https://github.com/user-attachments/assets/39dcec1f-c2bb-4703-8709-e5eb76c57e26)

I should also consider the potential integration of firewall commands, like iptables, if that’s relevant.

in english not code, carefully analyze how this script attempts to find public ip firewall access for smb, then save to disk any successful finds, and think about how this save may be useful across all ip addresses as many as possible that exist; then implement in full: 

fully implement these additional capabilities as much as possible for public ip firewall access through smb, keeping in mind that any saved succesful access should be able to be generalized across any public ip and work as much of the time as possible: 