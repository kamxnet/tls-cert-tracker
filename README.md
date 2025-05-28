# TLS Certificate Expiry Tracker

## Overview

This Python-based tool helps GCP users track the expiration status of TLS certificates used with HTTPS Load Balancers. It identifies both self-managed and Google-managed certificates, extracts metadata, and reports their expiration status to proactively prevent service outages.

## Features

* Scans all Target HTTPS Proxies in a GCP project
* Retrieves linked SSL certificates (both managed and self-managed)
* Parses expiration date from PEM certificate body
* Flags expiring or unparseable certificates
* Outputs a categorized summary report

## How It Works

1. The script authenticates using Application Default Credentials (ADC).
2. It queries all HTTPS Target Proxies in the provided project.
3. For each proxy, it collects linked SSL certificates.
4. Self-managed certificates are parsed using `cryptography` to extract expiry dates.
5. Google-managed certificates are noted but skipped from expiry parsing.
6. A summary report is printed to stdout.

### Expiry Status Categories

The tool evaluates the expiration status of each **self-managed TLS certificate** and assigns it to one of the following categories:

* **OK** — More than 30 days remaining
* **WARNING** — Expiring within 30 days
* **EXPIRING\_SOON** — Less than 10 days remaining
* **ERROR** — Unable to parse the certificate or missing certificate body

> **Note:** Google-managed certificates are automatically renewed by GCP and marked as `Managed: True` with `Expiry: None`.

## Prerequisites

* GCP project with HTTPS Load Balancers
* Python 3.6+
* IAM permissions to read Target HTTPS Proxies and SSL Certificates
* Installed dependencies:

```Cloud Shell
pip install google-auth google-auth-httplib2 google-api-python-client cryptography pytz
```

## Usage

```Cloud Shell
gcloud auth application-default login
* Click on OATH2 link > go to the gcloud CLI link in your browser, and complete the sign-in prompts by coping the authorization code

python3 tls_cert_tracker.py --project <PROJECT_ID>
```

## Example Output

```
Proxy: my-https-lb — Certificates: 1
   Cert: custom-cert-01 | Managed: False

TLS Certificate Expiry Report:
OK | Proxy: my-https-lb | Cert: custom-cert-01 | Managed: False | Expiry: 2025-07-11T02:41:11+00:00
```

## Security Notes

* This script uses only read-only API calls.
* No secrets or credentials are logged.
* ADC credentials can be revoked anytime.

## License

MIT License

## Owner

Kamal Bawa [ksbnetworks@gmail.com](mailto:ksbnetworks@gmail.com.com)
