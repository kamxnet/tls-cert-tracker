# TLS Certificate Expiry Tracker

## Overview

This Python-based tool helps GCP users track the expiration status of TLS certificates used with Classic / Application [Global/Regional & External/Internal], and SSL Proxy Load Balancers. It identifies both self-managed and Google-managed certificates, extracts metadata, and reports their expiration status to proactively prevent service outages.

It also includes a **one-command automated email alert setup** (`setup_alerts.sh`) using serverless **Cloud Run Jobs**, **Cloud Scheduler**, and **Cloud Monitoring Log-Based Alerts**.

## Key Benefits

- Centralized visibility into TLS certificates attached to supported GCP Load Balancer proxy resources.
- Differentiates Google-managed and self-managed certificates.
- Parses expiry dates for self-managed PEM certificates.
- Categorizes certificate risk using clear status labels.
- Supports multiple proxy-based Load Balancer types.
- Produces a structured summary and table output for easier review.
- **Automated Email Alerts:** One-command setup to run daily in GCP and email you when certificates are expiring soon or expired.
- Useful for troubleshooting, audits, operational reviews, and proactive risk detection.

## How It Works

1. Authenticates to Google Cloud using Application Default Credentials.
2. Builds a Compute Engine API client.
3. Lists global forwarding rules and regional forwarding rules.
4. Builds a forwarding rule index to map proxy resources to Load Balancer metadata.
5. Scans global Target HTTPS Proxies.
6. Scans regional Target HTTPS Proxies.
7. Scans global Target SSL Proxies.
8. Retrieves attached SSL certificate resources.
9. Identifies certificate type: Google-managed or self-managed.
10. Parses self-managed PEM certificates using the Python `cryptography` library.
11. Calculates days remaining until expiry.
12. Prints a summary and detailed table sorted by urgency (and optionally emits structured JSON alert logs for Cloud Monitoring email notifications).

### Expiry Status Categories

The tool evaluates the expiration status of each **self-managed TLS certificate** and assigns it to one of the following categories:

- **EXPIRED** — Certificate has already expired (`days_left < 0`)
- **EXPIRING_SOON** — 10 days or fewer remaining (`0 <= days_left <= 10`)
- **WARNING** — 30 days or fewer remaining (`11 <= days_left <= 30`)
- **ERROR** — Unable to parse the certificate or missing certificate body
- **OK** — More than 30 days remaining

> **Note:** Google-managed certificates are automatically renewed by GCP and are shown with `Managed: True` and `Expiry: N/A`.

## Prerequisites

- GCP project with configured Load Balancers
- Python 3.6 or higher
- IAM permissions to read Target HTTPS Proxies and SSL Certificates (`roles/compute.viewer`)
- Installed dependencies:

```bash
pip install -r requirements.txt
```

## Usage (On-Demand CLI Scan)

Authenticate with Application Default Credentials:

```bash
gcloud auth application-default login
```

Follow the link provided in the CLI output, complete the sign-in flow in your browser, and paste the generated verification code back into the terminal.

Then run:

```bash
python3 tls_cert_tracker.py --project <PROJECT_ID>
```

### Optional CLI Flags

| Flag | Description |
| :--- | :--- |
| `--project <PROJECT_ID>` | **(Required)** GCP project ID to scan. |
| `--regions <r1,r2>` | Optional comma-separated region list. If omitted, all regions are scanned. |
| `--global-only` | Scan only global Target HTTPS Proxies. |
| `--regional-only` | Scan only regional Target HTTPS Proxies. |
| `--classic-only` | Show only Classic Application Load Balancer records. |
| `--ssl-proxy-only` | Scan and show only SSL Proxy Load Balancer records. |
| `--skip-ssl-proxy` | Skip scanning Target SSL Proxies during the default full scan. |
| `--emit-log-alerts` | Emit structured JSON alert logs to stdout for Cloud Logging / Cloud Monitoring email alerts. |
| `--alert-on <STATUSES>` | Comma-separated statuses that trigger an alert when `--emit-log-alerts` is set (default: `EXPIRED,EXPIRING_SOON,WARNING`). |

---

## Automated Daily Email Alerts (1-Command Setup)

You can set up automatic daily scans and receive **native GCP email alerts** whenever any certificate is `EXPIRED`, `EXPIRING_SOON` (<=10 days), or in `WARNING` (<=30 days)—without managing any servers or external email tools.

### Quick Setup in Google Cloud Shell

Clone this repository in Google Cloud Shell and run `setup_alerts.sh`:

```bash
chmod +x setup_alerts.sh
./setup_alerts.sh --project <PROJECT_ID> --email <YOUR_EMAIL_ADDRESS>
```

### What `setup_alerts.sh` Does Automatically

1. **Enables Required APIs:** Compute Engine, Cloud Run, Cloud Build, Cloud Scheduler, Cloud Logging, and Cloud Monitoring.
2. **Creates a Least-Privilege Service Account:** Grants `roles/compute.viewer`, `roles/logging.logWriter`, and `roles/run.invoker`.
3. **Deploys a Serverless Cloud Run Job (`tls-cert-tracker-job`):** Packages `tls_cert_tracker.py` and runs it with `--emit-log-alerts` (runs for a few seconds per day within the GCP Free Tier).
4. **Schedules Daily Execution (`tls-cert-tracker-daily`):** Configures Cloud Scheduler to run the job every day at `09:00 UTC` (customizable via `--schedule`).
5. **Configures Email Notification & Cloud Monitoring Alert Policy:** Creates an email notification channel for `--email` and a Log-Based Alert Policy (`TLS Certificate Expiry Alert`) that emails you a consolidated summary of affected certificates, proxies, and days left.
6. **Runs an Immediate Test Scan:** Executes the Cloud Run Job right away so you can verify everything works.

### Customizing the Alert Setup

```bash
# Alert only on EXPIRED and EXPIRING_SOON (<=10 days), running daily at 8:00 AM UTC in us-east1:
./setup_alerts.sh \
  --project <PROJECT_ID> \
  --email <YOUR_EMAIL_ADDRESS> \
  --region us-east1 \
  --schedule "0 8 * * *" \
  --alert-on "EXPIRED,EXPIRING_SOON"
```

---

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
├── tls_cert_tracker.py    # Main Python script for TLS certificate tracking & structured alert logging
├── setup_alerts.sh        # One-command automated email alert setup (Cloud Run Job + Scheduler + Monitoring)
├── Dockerfile             # Container image definition for serverless Cloud Run Job execution
├── requirements.txt       # Python package dependencies
├── README.md              # Documentation for the project
├── LICENSE                # Open source license (MIT)
├── sample_output.txt      # Example output file from Cloud Shell
```

## License

MIT License

## Owner

Kamal Bawa — [ksbnetworks@gmail.com](mailto:ksbnetworks@gmail.com)
