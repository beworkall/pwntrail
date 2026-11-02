# Penetration Test Report: {{ name }}

**Client:** {{ client }}  
**Engagement window:** {{ first_activity|dt("%d %b %Y") or "n/a" }} → {{ last_activity|dt("%d %b %Y") or "n/a" }}  
**Tester:** {{ tester or "n/a" }}{% if company %}  
**Prepared by:** {{ company }}{% endif %}  
**Generated:** {{ generated|dt("%d %b %Y %H:%M") }} with PwnTrail v{{ version }}  
**Overall risk:** {{ sev_label[overall] }}

> CONFIDENTIAL. This document contains security-sensitive information about {{ client }}.

---

## 1. Executive summary

{% for p in summary %}
{{ p }}

{% endfor %}
| Critical | High | Medium | Low | Info |
|:-:|:-:|:-:|:-:|:-:|
| {{ sev_counts.critical }} | {{ sev_counts.high }} | {{ sev_counts.medium }} | {{ sev_counts.low }} | {{ sev_counts.info }} |

{% if findings %}
| Ref | Finding | Target | Severity |
|---|---|---|---|
{% for f in findings %}
| {{ f.ref }} | {{ f.title|replace("|", "\\|") }} | `{{ f.target }}` | **{{ sev_label[f.severity] }}** |
{% endfor %}
{% endif %}

## 2. Scope & approach

**In scope:** {% for e in scope_in %}`{{ e }}`{% if not loop.last %}, {% endif %}{% else %}not recorded{% endfor %}  
{% if scope_ex %}**Excluded:** {% for e in scope_ex %}`{{ e }}`{% if not loop.last %}, {% endif %}{% endfor %}  
{% endif %}
**Hosts assessed ({{ hosts|length }}):** {% for h in hosts %}`{{ h }}`{% if not loop.last %}, {% endif %}{% else %}n/a{% endfor %}

**Tools used:** {% for tool, n in tools %}`{{ tool }}` ×{{ n }}{% if not loop.last %}, {% endif %}{% else %}none recorded{% endfor %}

Every command was recorded with its output, working directory, exit code and timestamp by PwnTrail, and each
piece of evidence was hashed into a tamper-evident chain of custody (Appendix C).{% if redacted %} Credentials,
tokens and keys were automatically redacted.{% endif %}

{% if scope_incidents %}
**Scope control:** the scope guard intercepted {{ scope_incidents|length }} out-of-scope command(s).

| Time | Action | Detail |
|---|---|---|
{% for e in scope_incidents %}
| {{ e.ts|dt("%d %b %H:%M:%S") }} | {{ "Blocked" if e.kind == "scope_block" else "Allowed" }} | `{{ e.text|replace("|", "\\|") }}` |
{% endfor %}
{% endif %}

{% if findings %}
## 3. Findings

{% for f in findings %}
### {{ f.ref }} · {{ f.title }}

| Severity | Target | {{ "CVSS" if f.cvss else "Reference" }} | Source |
|---|---|---|---|
| **{{ sev_label[f.severity] }}** | `{{ f.target or "n/a" }}` | {{ f.cvss or (f.cves|join(", ")) or "n/a" }} | {{ f.source }} |

{% if f.description %}
**Description**

{{ f.description }}

{% endif %}
{% if f.matched_at %}
**Affected**

{% for m in f.matched_at[:15] %}
- `{{ m }}`
{% endfor %}

{% endif %}
{% if f.commands or f.extracted or f.shots %}
**Evidence**

{% for c in f.commands %}
Command #{{ c.id }} · {{ c.started|dt("%d %b %Y %H:%M:%S") }}{% if c.exit_code is not none %} · exit {{ c.exit_code }}{% endif %}

```console
$ {{ c.command }}
{{ c.output }}
```

{% endfor %}
{% if f.extracted %}
```text
{{ f.extracted|join("\n") }}
```

{% endif %}
{% for s in f.shots %}
- Screenshot #{{ s.id }}{% if s.note %}: {{ s.note }}{% endif %} (sha256 `{{ s.sha256[:16] }}…`)
{% endfor %}

{% endif %}
**Remediation**

{{ f.remediation or "Validate the issue and apply the vendor's recommended fix." }}

{% if f.refs %}
**References**

{% for r in f.refs[:8] %}
- <{{ r }}>
{% endfor %}

{% endif %}
---

{% endfor %}
{% endif %}
{% if services or endpoints %}
## 4. Attack surface

{% if services %}
| Host | Port | Service | Product / version |
|---|---|---|---|
{% for s in services %}
| `{{ s.host }}`{% if s.hostname %} ({{ s.hostname }}){% endif %} | {{ s.port }}/{{ s.proto }} | {{ s.service }} | {{ s.product }} {{ s.version }} |
{% endfor %}

{% endif %}
{% if endpoints %}
| URL | Status | Size |
|---|---|---|
{% for e in endpoints[:200] %}
| `{{ e.url }}` | {{ e.status }} | {{ e.length or "" }} |
{% endfor %}

{% endif %}
{% endif %}
## Appendix A · Activity log

| # | Time | Command | Exit |
|---|---|---|---|
{% for c in commands %}
| {{ c.id }} | {{ c.started|dt("%d %b %H:%M:%S") }} | `{{ c.command|replace("|", "\\|")|replace("`", "'") }}` | {{ c.exit_code if c.exit_code is not none else "" }} |
{% endfor %}

{% if notes %}
## Appendix B · Tester notes

{% for n in notes %}
- **{{ n.ts|dt("%d %b %H:%M:%S") }}**{% if n.target %} `{{ n.target }}`{% endif %}: {{ n.text }}
{% endfor %}

{% endif %}
## Appendix C · Evidence integrity

Integrity check at report time: **{{ "PASSED" if integrity_ok else "FAILED" }}** ({{ custody_count }} custody entries).
{% if not integrity_ok %}

{% for p in integrity_problems %}
- {{ p }}
{% endfor %}
{% endif %}

Chain head (SHA-256): `{{ chain_head }}`

{% if evidence_files %}
| Type | File | SHA-256 |
|---|---|---|
{% for e in evidence_files %}
| {{ e.kind }} | `{{ e.path }}` | `{{ e.sha256 }}` |
{% endfor %}
{% endif %}
