# Write-ups — index

Polished, reproducible-by-a-stranger narrative write-ups, one per solved challenge,
organized by theme/category. These are separate from `challenges/*.md`, which are the
raw working investigation logs (every dead end, every session) that a write-up gets
distilled from once a challenge is solved.

Every file here follows the section structure and frontmatter of
[`report_template.md`](../report_template.md) (the assignment's required report shape):
Executive Summary → Investigation & Technical Analysis (Technical Incident Overview,
Scope & Methodology, Attack Chain & Detailed Findings, Root Cause Analysis, Indicators of
Compromise) → Impact Analysis → Remediation & Recommendations → Appendices. Fill in the
`author:` frontmatter field (currently `TODO` everywhere) before these get turned into
the actual PDF deliverables.

- [DACL](dacl/index.md)
- [Misconfig](misconfig/index.md)
- [Kerberos](kerberos/index.md)

See also: [Remediation Roadmap](remediation-roadmap.md) — a consolidated,
prioritized view of fixes across all solved challenges, for root causes
that repeat across multiple independently-scored findings.

**Note:** the three theme folders above are not yet up to date with the
full set of solved challenges — see `write-ups/<slug>/` (e.g.
`write-ups/dangerous_services/`) for the current casual+technical
write-up pairs covering all 11 solved challenges. This index still needs
reconciling against that newer structure.
