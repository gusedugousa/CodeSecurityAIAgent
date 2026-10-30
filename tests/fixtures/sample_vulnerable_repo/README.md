# Sample Vulnerable Repo

Deliberately insecure fixture used by `make analyze-sample` and integration tests to exercise
the SAST, Secrets, and Dependency agents end-to-end.

Known issues seeded in this fixture (non-exhaustive):

- `app.py`: SQL injection, shell injection, `eval()` on user input, unsafe YAML load, hardcoded
  AWS key, hardcoded DB password, Flask debug mode.
- `utils/crypto_helper.py`: MD5 password hashing, unsafe `pickle.loads`, hardcoded token.
- `requirements.txt`: pinned to old vulnerable versions of `flask`, `pyyaml`, `requests`.
- `infra/main.tf`: public S3 bucket, wide-open security group, unencrypted/public RDS instance
  with a hardcoded password.

Do not deploy or execute any code in this directory. It exists solely as a scanner target.
