# Threat Intelligence Sources — Reference Guide

This document contains detailed information about each threat source MCP Sentinel uses.
Read this when you need deeper context about a source or when troubleshooting search results.

## Table of Contents
1. GitHub Advisory Database
2. VulnerableMCP.info
3. MCPScan.ai
4. Snyk / ToxicSkills Research
5. ClawHub / OpenClaw Registry
6. OWASP Frameworks
7. Reddit r/ClaudeAI
8. Anthropic Discord
9. GitHub Issues on MCP repos

---

## 1. GitHub Advisory Database

**URL**: https://github.com/advisories
**Type**: Formal CVE database
**Reliability**: Very high — peer-reviewed, linked to NVD
**Search strategy**:
- Search by package name: `[package] type:reviewed`
- Search by ecosystem: filter by npm, pip, etc.
- GitHub API endpoint: `GET /advisories?affects=[package]`
**What you'll find**: CVE IDs, CVSS scores, affected version ranges, patched versions
**Update frequency**: Continuous (new advisories daily)

## 2. VulnerableMCP.info

**URL**: https://vulnerablemcp.info
**Type**: Dedicated MCP vulnerability tracker
**Reliability**: High — specialized, community-maintained
**Search strategy**:
- Direct search on site for MCP server names
- Check their API if available for bulk queries
**What you'll find**: MCP-specific CVEs, risk assessments, remediation guides
**Update frequency**: Weekly+
**Note**: This is one of the most targeted sources — always check here first for MCP-specific issues.

## 3. MCPScan.ai

**URL**: https://mcpscan.ai
**Type**: Automated MCP security scanner
**Reliability**: High — automated analysis
**Search strategy**:
- Search by MCP server name or GitHub URL
- Look for scan reports and risk scores
**What you'll find**: Permission analysis, code patterns, risk ratings
**Update frequency**: Continuous (scans on submission)

## 4. Snyk / ToxicSkills

**URL**: https://snyk.io
**Type**: Enterprise security research
**Reliability**: Very high — professional security research
**Key research**: "ToxicSkills" study identified 1,467 malicious ClawHub skills
**Search strategy**:
- `site:snyk.io toxicskills`
- `site:snyk.io [package-name] vulnerability`
- Check Snyk's agent-scan tool: https://github.com/snyk/agent-scan
**What you'll find**: Detailed malware analysis, supply chain attack patterns

## 5. ClawHub / OpenClaw

**URL**: https://openclaw.ai (ClawHub is the marketplace)
**Type**: Skill registry with security scanning
**Reliability**: Medium-high — has VirusTotal integration but is community-submitted
**Search strategy**:
- Check if the skill exists on ClawHub
- Look for VirusTotal scan results and community ratings
- Check if skill was part of the February 2026 purge (13,729 → 3,286 skills)
**What you'll find**: Skill safety ratings, community reports, VirusTotal verdicts

## 6. OWASP Frameworks

**URLs**:
- https://owasp.org/www-project-agentic-skills-top-10/
- https://owasp.org/www-project-mcp-top-10/

**Type**: Security frameworks and classification
**Use case**: Not for finding specific vulnerabilities, but for classifying them.
When you find a suspicious pattern, reference the relevant OWASP category to give
the user context about what class of attack it belongs to.

**OWASP Agentic Skills Top 10 categories** (use for classification):
- Skill poisoning / backdoors
- Excessive permission requests
- Data exfiltration via tool calls
- Prompt injection through skill content
- Supply chain attacks
- Credential harvesting
- Sandbox escapes
- Cross-skill contamination
- Privilege escalation
- Insufficient input validation

## 7. Reddit r/ClaudeAI

**URL**: https://reddit.com/r/ClaudeAI
**Type**: Community early warning
**Reliability**: Variable — good for first alerts, needs verification
**Search strategy**:
- `site:reddit.com/r/ClaudeAI [skill-name] security`
- `site:reddit.com/r/ClaudeAI MCP vulnerability`
- `site:reddit.com/r/ClaudeAI malicious skill`
- Sort by recent for breaking news
**What you'll find**: User reports, screenshots of suspicious behavior, workarounds
**Caveat**: Community reports need cross-referencing. A user reporting "suspicious behavior"
might be a misconfiguration, not a vulnerability. Always verify.

## 8. Anthropic Discord

**Type**: Community early warning
**Reliability**: Medium-high — developers and Anthropic staff participate
**Channels**: #mcp, #claude-code
**Note**: Discord content is not easily searchable via web. Look for references to
Discord discussions in Reddit posts or GitHub issues instead. If the user has Discord
access, suggest they check these channels directly for real-time alerts.

## 9. GitHub Issues on MCP repos

**Key repos to monitor**:
- `modelcontextprotocol/servers` — official MCP server implementations
- `modelcontextprotocol/specification` — protocol spec issues
- Individual MCP server repos (check Issues tab, filter by `security` label)

**Search strategy**:
- `repo:modelcontextprotocol/servers label:security`
- `repo:[owner]/[repo] "vulnerability" OR "security" OR "CVE"`
**What you'll find**: Bug reports, security disclosures, fix PRs

---

## Search priority order

When time is limited, search in this order (highest value first):
1. vulnerablemcp.info (most targeted)
2. GitHub Advisory Database (most authoritative)
3. mcpscan.ai (automated, quick results)
4. Snyk (deep research)
5. GitHub Issues (specific to the repo)
6. Reddit (early warnings)
7. ClawHub (if skill is from that registry)
8. Discord references (hardest to search)
