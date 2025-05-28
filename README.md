# TLS Certificate Expiry Tracker

## Overview

This Python-based tool helps GCP users track the expiration status of TLS certificates used with HTTPS Load Balancers. It identifies both self-managed and Google-managed certificates, extracts metadata, and reports their expiration status to proactively prevent service outages.

## Features

- Scans all Target HTTPS Proxies in a GCP project
- Retrieves linked SSL certificates (both managed and self-managed)
- Parses expiration dates from PEM certificate bodies
- Flags expiring or unparseable certificates
- Outputs a categorized summary report

## How It Works

1. The script authenticates using Application Default Credentials (ADC).
2. It queries all HTTPS Target Proxies in the provided project.
3. For each proxy, it collects linked SSL certificates.
4. Self-managed certificates are parsed using the `cryptography` library to extract expiry dates.
5. Google-managed certificates are identified and skipped from expiry parsing (they renew automatically).
6. A categorized summary report is printed to stdout.

### Expiry Status Categories

The tool evaluates the expiration status of each **self-managed TLS certificate** and assigns it to one of the following categories:

- **OK** — More than 30 days remaining
- **WARNING** — Expiring within 30 days
- **EXPIRING_SOON** — Less than 10 days remaining
- **ERROR** — Unable to parse the certificate or missing certificate body

> **Note:** Google-managed certificates are automatically renewed by GCP and are shown with `Managed: True` and `Expiry: None`.

## Prerequisites

- GCP project with configured HTTPS Load Balancers
- Python 3.6 or higher
- IAM permissions to read Target HTTPS Proxies and SSL Certificates
- Installed dependencies:

```bash
pip install google-auth google-auth-httplib2 google-api-python-client cryptography pytz
```

## Usage

```bash
gcloud auth application-default login
```

Follow the link provided in the CLI output, complete the sign-in flow in your browser, and paste the generated verification code back into the terminal.

Then run:

```bash
python3 tls_cert_tracker.py --project <PROJECT_ID>
```

## Example Output

```
TLS Certificate Expiry Report:
🟢 OK | Proxy: apigee-lb-k5gobsc6uxu8 | Cert: apigee-ssl-cert-cwwcsnstbuz2 | Managed: True | Expiry: None
🔴 Expiring Soon | Proxy: apigee-lb-k5gobsc6uxu8 | Cert: expire7-cert | Managed: False | Expiry: 2025-06-04T08:18:30+00:00
🟡 Warning | Proxy: apigee-lb-k5gobsc6uxu8 | Cert: expire15-cert | Managed: False | Expiry: 2025-06-12T08:18:37+00:00
🟢 OK | Proxy: kam-https-lb-target-proxy | Cert: kam-test-cert | Managed: False | Expiry: 2025-07-11T02:41:11+00:00
```

## Project Structure

```
/ (root)
├── tls_cert_tracker.py    # Main Python script for TLS certificate tracking
├── README.md              # Documentation for the project
├── LICENSE                # Open source license (MIT)
├── sample_output.txt      # Example output file from Cloud Shell
```

## License

MIT License

## Owner

Kamal Bawa — [ksbnetworks@gmail.com](mailto:ksbnetworks@gmail.com)
