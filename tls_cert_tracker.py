# TLS Certificate Expiry Tracker Script

"""
This Python script scans all Target HTTPS Proxies in a specified Google Cloud Platform (GCP) project to identify associated TLS (SSL) certificates,
parse their expiration dates, and categorize their status based on how close they are to expiration.

It supports both Google-managed and self-managed certificates:
- Google-managed certs are auto-renewed and safe by default.
- Self-managed certs are parsed using the 'cryptography' library to extract and evaluate their expiration dates.

The script helps proactively detect expired or about-to-expire certificates, which can prevent outages in HTTPS services.
It is designed for internal visibility and can be used in operational monitoring or compliance reviews.

Author: Kamal Bawa (kamxnet)
License: MIT
"""

import argparse  # For parsing command-line arguments
import google.auth  # For obtaining application default credentials
from google.auth.transport.requests import Request  # For refreshing credentials
from googleapiclient.discovery import build  # To access GCP compute APIs
from datetime import datetime  # To handle and compare expiration dates
from cryptography import x509  # For parsing PEM-formatted SSL certificates
from cryptography.hazmat.backends import default_backend  # Required backend for x509 parser
import pytz  # To standardize timezone as UTC

def get_credentials():
    """
    Ensures that we use properly scoped and refreshed credentials.
    Required for accessing GCP APIs securely.
    Returns:
        credentials: Refreshed and scoped ADC credentials.
    """
    try:
        # Get ADC credentials and refresh them
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(Request())
        return credentials
    except Exception as e:
        print("❌ Failed to load or refresh default credentials.")
        raise e

def fetch_target_https_proxies(project):
    """
    Fetches all HTTPS Load Balancers and associated SSL certificates in the given GCP project.
    Extracts and parses certificate expiry info where applicable.

    Args:
        project (str): GCP project ID
    Returns:
        list: Dictionary of proxy, certificate name, type, and expiry info
    """
    credentials = get_credentials()
    compute = build('compute', 'v1', credentials=credentials)

    print(f"\n🔍 Scanning HTTPS Load Balancers in project: {project}")
    proxies = compute.targetHttpsProxies().list(project=project).execute()
    ssl_infos = []  # Stores results

    if 'items' not in proxies:
        print("⚠️ No target HTTPS proxies found.")
        return []

    for proxy in proxies['items']:
        proxy_name = proxy['name']
        certs = proxy.get('sslCertificates', [])  # List of certificate URLs
        print(f"\n🔗 Proxy: {proxy_name} — Certificates: {len(certs)}")

        for cert_url in certs:
            cert_name = cert_url.split('/')[-1]  # Extract cert name from URL
            cert = compute.sslCertificates().get(project=project, sslCertificate=cert_name).execute()
            cert_data = cert.get('certificate')  # PEM-encoded cert body
            cert_type = cert.get('type')  # MANAGED or SELF_MANAGED
            is_managed = cert_type == 'MANAGED'
            expiry_date = None

            print(f"   🔒 Cert: {cert_name} | Managed: {is_managed}")

            if not is_managed and cert_data:
                try:
                    # Decode PEM cert and extract expiration date
                    decoded_cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                    expiry_date = decoded_cert.not_valid_after.astimezone(pytz.utc)
                except Exception as e:
                    # Save error as expiry date string if parsing fails
                    expiry_date = f"❌ Error parsing cert: {str(e)}"

            # Append certificate metadata to result list
            ssl_infos.append({
                'proxy_name': proxy_name,
                'cert_name': cert_name,
                'is_managed': is_managed,
                'expiry_date': expiry_date.isoformat() if isinstance(expiry_date, datetime) else expiry_date
            })

    return ssl_infos

if __name__ == "__main__":
    # CLI argument parsing setup
    parser = argparse.ArgumentParser(description="Track TLS certificate expiry for GCP Load Balancers.")
    parser.add_argument("--project", required=True, help="GCP project ID")
    args = parser.parse_args()

    # Run the certificate scan
    cert_info = fetch_target_https_proxies(args.project)

    # Print summary of certificate statuses
    print("\n📋 TLS Certificate Expiry Report:\n")
    for item in cert_info:
        status = "🟢 OK"  # Default status

        # Error case: certificate not parsable
        if isinstance(item['expiry_date'], str) and "Error" in item['expiry_date']:
            status = "❌ Error"

        # Only check expiry date for self-managed certs
        elif not item['is_managed']:
            try:
                dt = datetime.fromisoformat(item['expiry_date'].replace("Z", "+00:00"))
                days_left = (dt - datetime.now(pytz.utc)).days

                # Categorize based on how close to expiry
                if days_left <= 10:
                    status = "🔴 Expiring Soon"
                elif days_left <= 30:
                    status = "🟡 Warning"
            except:
                status = "⚠️ Parse Error"  # Unexpected format or date parsing failure

        # Output one line per certificate with status
        print(f"{status} | Proxy: {item['proxy_name']} | Cert: {item['cert_name']} | Managed: {item['is_managed']} | Expiry: {item['expiry_date']}")
