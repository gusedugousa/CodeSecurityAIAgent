# Security Analysis Report — b3587413-d137-4da1-abb8-f8ff5133b5e5

_Generated at 2026-07-02T15:52:33.313610+00:00_

## Executive Summary

{"summary": "mock report", "sections": []}

**Warnings:**

- sast: tool 'semgrep' not installed/available
- secrets: tool 'gitleaks' not installed/available
- secrets: tool 'trufflehog' not installed/available
- dependency: tool 'pip_audit' not installed/available
- dependency: tool 'osv_scanner' not installed/available
- dependency: tool 'trivy' not installed/available
- dependency: tool 'checkov' not installed/available

## Repository Metadata

| Field | Value |
|---|---|
| repo_url | N/A |
| branch | main |
| commit_sha | N/A |
| file_count | 5 |
| primary_languages | Python, Terraform |

## Severity Summary

| Severity | Count |
|---|---|
| critical | 0 |
| high | 3 |
| medium | 4 |
| low | 4 |
| info | 0 |
| total | 11 |

## Findings Table

| ID | Title | Severity | Category | File | Line |
|---|---|---|---|---|---|
| ec113e9d-668f-44e1-a0a0-a6a6fabc597a | subprocess_popen_with_shell_equals_true | high | sast | tests/fixtures/sample_vulnerable_repo/app.py | 27 |
| 340d7958-053d-42f4-99f2-9f837be16e86 | flask_debug_true | high | sast | tests/fixtures/sample_vulnerable_repo/app.py | 42 |
| 91dd1da6-bc00-4eb9-81ad-e192be062bb9 | hashlib | high | sast | tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py | 7 |
| 1cbce214-22f0-4e89-b84a-4bce617cb343 | hardcoded_sql_expressions | medium | sast | tests/fixtures/sample_vulnerable_repo/app.py | 19 |
| f7586a53-e4f2-434b-a494-90b118d7bd5b | blacklist | medium | sast | tests/fixtures/sample_vulnerable_repo/app.py | 34 |
| c9d84fb9-9c72-4b6d-b5ec-ecccb0aefebd | hardcoded_bind_all_interfaces | medium | sast | tests/fixtures/sample_vulnerable_repo/app.py | 42 |
| aad06592-1d13-4b91-9a42-454ed17f897b | blacklist | medium | sast | tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py | 11 |
| d24c8d17-13f0-4d64-b59b-9ea22679cb27 | blacklist | low | sast | tests/fixtures/sample_vulnerable_repo/app.py | 4 |
| f78e4911-931b-4468-ac4b-aba8c32295c1 | hardcoded_password_string | low | sast | tests/fixtures/sample_vulnerable_repo/app.py | 11 |
| 5d3ad956-92dc-49ce-8411-8e6ff819238c | blacklist | low | sast | tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py | 3 |
| d65df353-6d88-476a-b451-e08cebcb76e8 | hardcoded_password_string | low | sast | tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py | 14 |

## Detailed Findings

### [HIGH] subprocess_popen_with_shell_equals_true (ec113e9d-668f-44e1-a0a0-a6a6fabc597a)

subprocess call with shell=True identified, security issue.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:27-27

```
26     host = request.args.get("host")
27     output = subprocess.check_output("ping -c 1 " + host, shell=True)
28     return output

```

**CWE:** CWE-78

**Evidence:**

- Detected by bandit static analysis
  ```
  26     host = request.args.get("host")
27     output = subprocess.check_output("ping -c 1 " + host, shell=True)
28     return output

  ```

**Business Impact:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Attack Scenario:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Remediation Suggestion:**

mock remediation

mock remediation suggestion, no real model called

---

### [HIGH] flask_debug_true (340d7958-053d-42f4-99f2-9f837be16e86)

A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:42-42

```
41 if __name__ == "__main__":
42     app.run(debug=True, host="0.0.0.0")

```

**CWE:** CWE-94

**Evidence:**

- Detected by bandit static analysis
  ```
  41 if __name__ == "__main__":
42     app.run(debug=True, host="0.0.0.0")

  ```

**Business Impact:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Attack Scenario:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Remediation Suggestion:**

mock remediation

mock remediation suggestion, no real model called

---

### [HIGH] hashlib (91dd1da6-bc00-4eb9-81ad-e192be062bb9)

Use of weak MD5 hash for security. Consider usedforsecurity=False

**Location:** tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py:7-7

```
6 def hash_password(password: str) -> str:
7     return hashlib.md5(password.encode()).hexdigest()
8 

```

**CWE:** CWE-327

**Evidence:**

- Detected by bandit static analysis
  ```
  6 def hash_password(password: str) -> str:
7     return hashlib.md5(password.encode()).hexdigest()
8 

  ```

**Business Impact:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Attack Scenario:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Remediation Suggestion:**

mock remediation

mock remediation suggestion, no real model called

---

### [MEDIUM] hardcoded_sql_expressions (1cbce214-22f0-4e89-b84a-4bce617cb343)

Possible SQL injection vector through string-based query construction.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:19-19

```
18     cursor = conn.cursor()
19     query = "SELECT * FROM users WHERE id = " + user_id
20     cursor.execute(query)

```

**CWE:** CWE-89

**Evidence:**

- Detected by bandit static analysis
  ```
  18     cursor = conn.cursor()
19     query = "SELECT * FROM users WHERE id = " + user_id
20     cursor.execute(query)

  ```

**Business Impact:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Attack Scenario:**

{"summary": "mock analysis", "findings_reviewed": 0}

---

### [MEDIUM] blacklist (f7586a53-e4f2-434b-a494-90b118d7bd5b)

Use of possibly insecure function - consider using safer ast.literal_eval.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:34-34

```
33     expr = request.args.get("expr")
34     return str(eval(expr))
35 

```

**CWE:** CWE-78

**Evidence:**

- Detected by bandit static analysis
  ```
  33     expr = request.args.get("expr")
34     return str(eval(expr))
35 

  ```

**Business Impact:**

{"summary": "mock analysis", "findings_reviewed": 0}

**Attack Scenario:**

{"summary": "mock analysis", "findings_reviewed": 0}

---

### [MEDIUM] hardcoded_bind_all_interfaces (c9d84fb9-9c72-4b6d-b5ec-ecccb0aefebd)

Possible binding to all interfaces.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:42-42

```
41 if __name__ == "__main__":
42     app.run(debug=True, host="0.0.0.0")

```

**CWE:** CWE-605

**Evidence:**

- Detected by bandit static analysis
  ```
  41 if __name__ == "__main__":
42     app.run(debug=True, host="0.0.0.0")

  ```

---

### [MEDIUM] blacklist (aad06592-1d13-4b91-9a42-454ed17f897b)

Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.

**Location:** tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py:11-11

```
10 def deserialize(data: bytes):
11     return pickle.loads(data)
12 

```

**CWE:** CWE-502

**Evidence:**

- Detected by bandit static analysis
  ```
  10 def deserialize(data: bytes):
11     return pickle.loads(data)
12 

  ```

---

### [LOW] blacklist (d24c8d17-13f0-4d64-b59b-9ea22679cb27)

Consider possible security implications associated with the subprocess module.

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:4-4

```
3 import sqlite3
4 import subprocess
5 

```

**CWE:** CWE-78

**Evidence:**

- Detected by bandit static analysis
  ```
  3 import sqlite3
4 import subprocess
5 

  ```

---

### [LOW] hardcoded_password_string (f78e4911-931b-4468-ac4b-aba8c32295c1)

Possible hardcoded password: 'SuperSecretPassword123!'

**Location:** tests/fixtures/sample_vulnerable_repo/app.py:11-11

```
10 AWS_ACCESS_KEY = "[REDACTED]"
11 DB_PASSWORD = "SuperSecretPassword123!"
12 

```

**CWE:** CWE-259

**Evidence:**

- Detected by bandit static analysis
  ```
  10 AWS_ACCESS_KEY = "[REDACTED]"
11 DB_PASSWORD = "SuperSecretPassword123!"
12 

  ```

---

### [LOW] blacklist (5d3ad956-92dc-49ce-8411-8e6ff819238c)

Consider possible security implications associated with pickle module.

**Location:** tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py:3-3

```
2 import hashlib
3 import pickle
4 

```

**CWE:** CWE-502

**Evidence:**

- Detected by bandit static analysis
  ```
  2 import hashlib
3 import pickle
4 

  ```

---

### [LOW] hardcoded_password_string (d65df353-6d88-476a-b451-e08cebcb76e8)

Possible hardcoded password: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12'

**Location:** tests/fixtures/sample_vulnerable_repo/utils/crypto_helper.py:14-14

```
13 
14 API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

```

**CWE:** CWE-259

**Evidence:**

- Detected by bandit static analysis
  ```
  13 
14 API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

  ```

---

## Tool Coverage

| Tool | Category | Available | Findings Count |
|---|---|---|---|
| semgrep | sast | False | 0 |
| bandit | sast | True | 11 |
| gitleaks | secrets | False | 0 |
| trufflehog | secrets | False | 0 |
| pip_audit | dependency | False | 0 |
| osv_scanner | dependency | False | 0 |
| trivy | dependency | False | 0 |
| checkov | iac | False | 0 |

## Tools Unavailable

- semgrep
- gitleaks
- trufflehog
- pip_audit
- osv_scanner
- trivy
- checkov
