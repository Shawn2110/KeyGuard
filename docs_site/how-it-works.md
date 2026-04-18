# How it works

Short version: two-layer envelope encryption. A stable 32-byte Data
Encryption Key (DEK) encrypts the vault body with AES-256-GCM. The DEK
itself is wrapped (again AES-256-GCM) under one or more Key Encryption
Keys (KEKs), each derived via HKDF-per-input + Argon2id.

For the full walkthrough — threat model, crypto parameters, module
boundaries, and a directory tour — see
[`docs/project-&-code-explanation.md`](https://github.com/Shawn2110/KeyGuard/blob/main/docs/project-%26-code-explanation.md)
in the repo.

For the formal threat model (what adversaries are considered, what they
can and cannot achieve), see
[`docs/THREAT_MODEL.md`](https://github.com/Shawn2110/KeyGuard/blob/main/docs/THREAT_MODEL.md).
