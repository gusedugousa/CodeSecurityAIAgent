"""Prompt-building utilities.

Plain functions that build and format a `langchain_core.prompts.PromptTemplate`
and return the resulting string. These are NOT chains and hold no state -
callers pass the formatted string straight to a model client (e.g. litellm).
"""

from __future__ import annotations

from langchain_core.prompts import PromptTemplate

_REDACTION_NOTE = (
    "All inputs have already been redacted upstream by app.core.security.redact_secrets; "
    "never ask for, guess, or reproduce raw secret values."
)


def build_sast_analysis_prompt(code_snippet: str, tool_findings_summary: str) -> str:
    template = PromptTemplate(
        input_variables=["code_snippet", "tool_findings_summary", "redaction_note"],
        template=(
            "You are a security analyst triaging static analysis (SAST) findings.\n"
            "{redaction_note}\n\n"
            "Code snippet under review:\n"
            "```\n{code_snippet}\n```\n\n"
            "Raw SAST tool findings for this snippet:\n"
            "{tool_findings_summary}\n\n"
            "Review this batch of findings. For each finding, assess whether it is a true "
            "positive, note the likely severity and confidence, and briefly explain the "
            "vulnerable pattern in the code. Respond with a JSON object summarizing your "
            "triage of each finding."
        ),
    )
    return template.format(
        code_snippet=code_snippet,
        tool_findings_summary=tool_findings_summary,
        redaction_note=_REDACTION_NOTE,
    )


def build_secrets_triage_prompt(finding_summary: str) -> str:
    template = PromptTemplate(
        input_variables=["finding_summary", "redaction_note"],
        template=(
            "You are a security analyst triaging a detected secret finding.\n"
            "{redaction_note}\n\n"
            "Detected secret finding (redacted):\n"
            "{finding_summary}\n\n"
            "Based only on the surrounding context, variable naming, file path, and pattern "
            "type provided, assess whether this looks like a true-positive live credential "
            "versus a placeholder, example, or test fixture value. Respond with only a JSON object "
            'of the form {{"is_placeholder": <true|false>, "confidence": "<high|medium|low>", '
            '"rationale": "<one short sentence>"}}.'
        ),
    )
    return template.format(finding_summary=finding_summary, redaction_note=_REDACTION_NOTE)


def build_dependency_risk_prompt(package_name: str, vulnerability_summary: str) -> str:
    template = PromptTemplate(
        input_variables=["package_name", "vulnerability_summary", "redaction_note"],
        template=(
            "You are a security analyst assessing dependency vulnerability risk.\n"
            "{redaction_note}\n\n"
            "Package: {package_name}\n"
            "Known vulnerability information:\n"
            "{vulnerability_summary}\n\n"
            "Summarize the real-world exploitability and business risk of this vulnerability "
            "for a typical production deployment. Consider attack surface, whether exploitation "
            "requires local or network access, and likely business impact if exploited. Respond "
            "with a JSON object containing an exploitability rating, a business_impact "
            "narrative, and a recommended priority."
        ),
    )
    return template.format(
        package_name=package_name,
        vulnerability_summary=vulnerability_summary,
        redaction_note=_REDACTION_NOTE,
    )


def build_remediation_prompt(
    finding_title: str,
    finding_description: str,
    code_snippet: str,
    cwe: str | None,
) -> str:
    template = PromptTemplate(
        input_variables=[
            "finding_title",
            "finding_description",
            "code_snippet",
            "cwe",
            "redaction_note",
        ],
        template=(
            "You are a security engineer proposing a remediation for a code finding.\n"
            "{redaction_note}\n\n"
            "Finding: {finding_title}\n"
            "Description: {finding_description}\n"
            "CWE: {cwe}\n"
            "Vulnerable code snippet:\n"
            "```\n{code_snippet}\n```\n\n"
            "Propose a concrete remediation. Respond with a JSON object containing a short "
            "summary of the fix, a unified diff patch (patch_diff) if you can produce one from "
            "the snippet alone, and an explanation of why the fix resolves the vulnerability."
        ),
    )
    return template.format(
        finding_title=finding_title,
        finding_description=finding_description,
        code_snippet=code_snippet,
        cwe=cwe or "unknown",
        redaction_note=_REDACTION_NOTE,
    )


def build_report_summary_prompt(severity_counts_json: str, top_findings_summary: str) -> str:
    template = PromptTemplate(
        input_variables=["severity_counts_json", "top_findings_summary", "redaction_note"],
        template=(
            "You are a security analyst writing an executive summary for a code security report.\n"
            "{redaction_note}\n\n"
            "Severity counts:\n"
            "{severity_counts_json}\n\n"
            "Top findings:\n"
            "{top_findings_summary}\n\n"
            "Write a concise executive summary paragraph (plain prose, no JSON) for a "
            "non-technical stakeholder audience, describing the overall risk posture and the "
            "most important issues to address first."
        ),
    )
    return template.format(
        severity_counts_json=severity_counts_json,
        top_findings_summary=top_findings_summary,
        redaction_note=_REDACTION_NOTE,
    )
