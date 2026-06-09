# Security Policy

## Authorized Use Only

mcpray is designed exclusively for **authorized security testing**. Use of this tool against 
systems you do not own or have **explicit written permission** to test is illegal and unethical.

The authors accept no liability for misuse. By using mcpray, you agree that you are solely 
responsible for ensuring your use complies with all applicable laws and regulations.

## Scope

mcpray is intended for:
- Penetration testing engagements with written authorization
- CTF (Capture The Flag) competitions
- Security research on systems you own
- Testing your own MCP server deployments

mcpray MUST NOT be used for:
- Unauthorized access to any system
- Disruption of services (DoS/DDoS)
- Exfiltration of data from systems without authorization
- Any illegal activity

## Capabilities Disclosure

mcpray includes modules that can:
- Execute SQL injection attacks against MCP resource templates
- Generate reverse shell payloads (cmdinj module — requires --unsafe-mode)
- Read sensitive files (/etc/shadow, SSH keys) via command injection (cmdinj — requires --unsafe-mode)  
- Probe cloud metadata services (AWS IMDSv1/v2, GCP, Azure) (ssrf module)
- Intercept and proxy MCP traffic (mitm module)

These capabilities are included for legitimate authorized security testing only.

## Reporting Vulnerabilities in mcpray

If you discover a security vulnerability in mcpray itself, please report it by opening a 
GitHub issue with the label "security". For sensitive disclosures, email [maintainer contact].

Do NOT open public issues for unpatched vulnerabilities — use private disclosure first.

## Bug Bounty

mcpray does not offer a bug bounty program.
