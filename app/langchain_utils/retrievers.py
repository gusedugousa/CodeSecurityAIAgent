"""Retriever abstractions for a future RAG layer over CWE/OWASP/CVE knowledge.

These are simple, synchronous, in-process placeholders. The real vector-backed
implementation is future work in app/persistence/vector_store.py (built by
another agent) - StaticKnowledgeRetriever below is a real, working, non-vector
stand-in usable today by remediation/report agents.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

_KNOWLEDGE_BASE: list[dict[str, str]] = [
    {
        "source": "CWE-79",
        "content": (
            "CWE-79: Improper Neutralization of Input During Web Page Generation "
            "(Cross-site Scripting). Untrusted input is rendered in a web page without "
            "proper escaping, allowing attacker-controlled script execution in victims' browsers."
        ),
    },
    {
        "source": "CWE-89",
        "content": (
            "CWE-89: Improper Neutralization of Special Elements used in an SQL Command "
            "(SQL Injection). Untrusted input is concatenated into a SQL query, allowing "
            "attackers to alter query logic or exfiltrate/modify database contents."
        ),
    },
    {
        "source": "CWE-798",
        "content": (
            "CWE-798: Use of Hard-coded Credentials. Credentials embedded directly in source "
            "code or config allow anyone with code access to authenticate as that identity, "
            "and rotation typically requires a code change."
        ),
    },
    {
        "source": "CWE-327",
        "content": (
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm. Weak algorithms "
            "(e.g. MD5, SHA1, DES, RC4) or insufficient key sizes can be broken with feasible "
            "attacker resources, undermining confidentiality or integrity guarantees."
        ),
    },
    {
        "source": "OWASP-A01",
        "content": (
            "OWASP Top 10 A01:2021 Broken Access Control. Restrictions on what authenticated "
            "users are allowed to do are not properly enforced, enabling privilege escalation, "
            "unauthorized data access, or data tampering."
        ),
    },
    {
        "source": "OWASP-A03",
        "content": (
            "OWASP Top 10 A03:2021 Injection. Untrusted data sent to an interpreter (SQL, "
            "OS command, LDAP, etc.) as part of a command or query can alter its execution, "
            "covering SQL injection, command injection, and similar flaws."
        ),
    },
    {
        "source": "CWE-502",
        "content": (
            "CWE-502: Deserialization of Untrusted Data. Deserializing attacker-controlled "
            "data without validation can lead to remote code execution, denial of service, "
            "or object injection attacks depending on the deserialization library used."
        ),
    },
    {
        "source": "OWASP-A02",
        "content": (
            "OWASP Top 10 A02:2021 Cryptographic Failures. Sensitive data is exposed due to "
            "missing or weak encryption in transit or at rest, often the root cause behind "
            "data breaches involving credentials, financial data, or PII."
        ),
    },
]


class SimpleRetriever(ABC):
    @abstractmethod
    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        raise NotImplementedError


class StaticKnowledgeRetriever(SimpleRetriever):
    def __init__(self, knowledge_base: list[dict[str, str]] | None = None) -> None:
        self._knowledge_base = knowledge_base if knowledge_base is not None else _KNOWLEDGE_BASE

    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        query_keywords = [kw for kw in query.lower().split() if kw]
        scored: list[dict] = []
        for entry in self._knowledge_base:
            content_lower = entry["content"].lower()
            source_lower = entry["source"].lower()
            score = sum(
                1
                for kw in query_keywords
                if kw in content_lower or kw in source_lower
            )
            if score > 0:
                scored.append({"content": entry["content"], "source": entry["source"], "score": float(score)})

        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]


class NullRetriever(SimpleRetriever):
    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        return []
