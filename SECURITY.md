# Security

This repository is the environment-handling service for Brainsless, published so it can be read and
verified. We welcome scrutiny of it.

## Reporting a vulnerability

Email **security@brainsless.com** with enough detail to reproduce. We acknowledge within one business
day and will keep you updated through remediation. Please give us a reasonable window to fix an issue
before disclosing it publicly. Do not test against production tenants or data that is not yours.

## Scope

In scope: the Worker in `worker/`, the CLIs in `cli/` and `python/`, the log mask in `runner/`, and
the wire format they share. A finding that lets any party other than the customer's own sandbox read
a sealed value is the class we care about most.

Out of scope: reports generated solely by automated scanners with no demonstrated impact, and issues
in dependencies without a working path to exploit here.

## Keys and encryption

A sealed environment is protected twice at rest. The vault seals the values to its own key, which the
control plane does not hold, so the control plane stores ciphertext it cannot open. That blob is then
stored under a per-tenant key wrapped by a non-exportable **Google Cloud KMS** key (one KMS key per
environment), so the at-rest store is itself under a hardware-backed root. Neither layer alone reveals
a value. In transit, values are sealed on the customer's machine (AES-256-GCM with an RSA-OAEP-wrapped
data key) before anything leaves it; the vault is the only place a value is briefly in plaintext, in
isolate memory, and it is never persisted, logged, or returned.

## Verifying the running service

The copy running in production is verifiably the copy in this repository. See
[VERIFY.md](VERIFY.md) to reproduce the deployed build's fingerprint and compare it to what the live
service reports.

## Broader posture

Our full security program (compliance, sub-processors, and our SOC 2 work) lives in the Trust Center
at **https://trust.brainsless.com**, where documentation and a security questionnaire are available on
request.
