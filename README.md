# TLS Certificate Expiry Tracker

## Overview

This Python-based tool helps GCP users track the expiration status of TLS certificates used with Classic / Application [Global/Regional & External/Internal], and SSL Proxy Load Balancers. It identifies both self-managed and Google-managed certificates, extracts metadata, and reports their expiration status to proactively prevent service outages.

## Key Benefits

Centralized visibility into TLS certificates attached to supported GCP Load Balancer proxy resources
Differentiates Google-managed and self-managed certificates
Parses expiry dates for self-managed PEM certificates
Categorizes certificate risk using clear status labels
Supports multiple proxy-based Load Balancer types
Produces a structured summary and table output for easier review
Useful for troubleshooting, audits, operational reviews, and proactive risk detection

## How It Works

Authenticates to Google Cloud using Application Default Credentials.
Builds a Compute Engine API client.
Lists global forwarding rules and regional forwarding rules.
Builds a forwarding rule index to map proxy resources to Load Balancer metadata.
Scans global Target HTTPS Proxies.
Scans regional Target HTTPS Proxies.
Scans global Target SSL Proxies.
Retrieves attached SSL certificate resources.
Identifies certificate type: Google-managed or self-managed.
Parses self-managed PEM certificates using the Python
cryptography
library.
Calculates days remaining until expiry.
Prints a summary and detailed table sorted by urgency.

### Expiry Status Categories

The tool evaluates the expiration status of each **self-managed TLS certificate** and assigns it to one of the following categories:

- **OK** — More than 30 days remaining
- **WARNING** — Expiring within 30 days
- **EXPIRING_SOON** — Less than 10 days remaining
- **ERROR** — Unable to parse the certificate or missing certificate body

> **Note:** Google-managed certificates are automatically renewed by GCP and are shown with `Managed: True` and `Expiry: None`.

## Prerequisites

- GCP project with configured Load Balancers
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
TLS Certificate Expiry Report
====================================================================================================

Summary
----------------------------------------------------------------------------------------------------
Total certificates scanned : 8
Expired                    : 3
Expiring soon (<=10 days)  : 2
Warning (<=30 days)        : 1
Errors                     : 0
OK                         : 2

Detailed Results
----------------------------------------------------------------------------------------------------
+---------------+------+------------------------------------+-------------+-----------------------------+------------------------------+---------+------------+
| Status        | Days | LB Type                            | Region      | Proxy                       | Certificate                  | Managed | Expiry     |
+---------------+------+------------------------------------+-------------+-----------------------------+------------------------------+---------+------------+
| EXPIRED       | -347 | External Application Load Balancer | global      | apigee-lb-k5gobsc6uxu8      | expire7-cert                 | False   | 2025-06-04 |
| EXPIRED       | -339 | External Application Load Balancer | global      | apigee-lb-k5gobsc6uxu8      | expire15-cert                | False   | 2025-06-12 |
| EXPIRED       | -310 | External Application Load Balancer | global      | kam-https-lb-target-proxy   | kam-test-cert                | False   | 2025-07-11 |
| EXPIRING_SOON | 6    | External Application Load Balancer | global      | tls-demo-global-app-proxy   | tls-demo-global-cert-7       | False   | 2026-05-23 |
| EXPIRING_SOON | 6    | SSL Proxy Load Balancer            | global      | tls-demo-ssl-proxy          | tls-demo-global-cert-7       | False   | 2026-05-23 |
| WARNING       | 14   | Classic Application Load Balancer  | global      | tls-demo-classic-app-proxy  | tls-demo-global-cert-15      | False   | 2026-05-31 |
| OK            | 59   | Regional External Application L... | us-central1 | tls-demo-regional-app-proxy | tls-demo-regional-cert-60    | False   | 2026-07-15 |
| OK            | N/A  | External Application Load Balancer | global      | apigee-lb-k5gobsc6uxu8      | apigee-ssl-cert-cwwcsnstbuz2 | True    | N/A        |
+---------------+------+------------------------------------+-------------+-----------------------------+------------------------------+---------+------------+

Status Meaning
----------------------------------------------------------------------------------------------------
EXPIRED       : Self-managed certificate is already expired.
EXPIRING_SOON : Self-managed certificate expires within 10 days.
WARNING       : Self-managed certificate expires within 30 days.
ERROR         : Certificate expiry could not be parsed or is unsupported.
OK            : Google-managed cert, or self-managed cert has more than 30 days left.
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
