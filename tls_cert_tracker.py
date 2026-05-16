import argparse
from datetime import datetime

import google.auth
import pytz
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def get_credentials():
    """Load and refresh Application Default Credentials."""
    try:
        credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
        credentials.refresh(Request())
        return credentials
    except Exception as error:
        print("ERROR: Failed to load or refresh Application Default Credentials.")
        raise error


def build_compute_service():
    """Build and return the Compute Engine API client."""
    credentials = get_credentials()
    return build("compute", "v1", credentials=credentials)


def extract_resource_name(resource_url):
    """Extract the final resource name from a Google Cloud selfLink."""
    if not resource_url:
        return None
    return resource_url.split("/")[-1]


def extract_region_from_url(resource_url):
    """Extract the region from a regional selfLink."""
    if not resource_url or "/regions/" not in resource_url:
        return None

    parts = resource_url.split("/")
    try:
        region_index = parts.index("regions") + 1
        return parts[region_index]
    except (ValueError, IndexError):
        return None


def list_regions(compute, project):
    """Return all Compute Engine regions available to the project."""
    response = compute.regions().list(project=project).execute()
    return [region["name"] for region in response.get("items", [])]


def build_forwarding_rule_index(compute, project):
    """
    Build a lookup table from target proxy selfLink to forwarding rule metadata.

    This helps classify proxies into specific LB types using loadBalancingScheme.
    """
    index = {}

    try:
        global_rules = compute.globalForwardingRules().list(project=project).execute()
        for rule in global_rules.get("items", []):
            target = rule.get("target")
            if target:
                index[target] = {
                    "forwarding_rule_name": rule.get("name"),
                    "scope": "global",
                    "region": None,
                    "load_balancing_scheme": rule.get("loadBalancingScheme"),
                    "ip_address": rule.get("IPAddress"),
                    "port_range": rule.get("portRange"),
                    "ports": rule.get("ports"),
                }
    except Exception as error:
        print(f"WARNING: Could not list global forwarding rules: {error}")

    try:
        regional_rules = compute.forwardingRules().aggregatedList(project=project).execute()

        for scoped_list in regional_rules.get("items", {}).values():
            for rule in scoped_list.get("forwardingRules", []):
                target = rule.get("target")
                rule_region = extract_region_from_url(rule.get("region"))

                # Avoid overwriting global forwarding-rule metadata.
                if not target or not rule_region:
                    continue

                index[target] = {
                    "forwarding_rule_name": rule.get("name"),
                    "scope": "regional",
                    "region": rule_region,
                    "load_balancing_scheme": rule.get("loadBalancingScheme"),
                    "ip_address": rule.get("IPAddress"),
                    "port_range": rule.get("portRange"),
                    "ports": rule.get("ports"),
                }

    except Exception as error:
        print(f"WARNING: Could not list regional forwarding rules: {error}")

    return index


def classify_https_load_balancer(proxy_scope, forwarding_rule_info):
    """Classify HTTPS proxy-based load balancers using forwarding rule metadata."""
    if not forwarding_rule_info:
        if proxy_scope == "global":
            return "Global HTTPS proxy based load balancer"
        return "Regional HTTPS proxy based load balancer"

    scheme = forwarding_rule_info.get("load_balancing_scheme")
    scope = forwarding_rule_info.get("scope")

    if scheme == "EXTERNAL_MANAGED" and scope == "global":
        return "External Application Load Balancer"
    if scheme == "EXTERNAL_MANAGED" and scope == "regional":
        return "Regional External Application Load Balancer"
    if scheme == "INTERNAL_MANAGED":
        return "Internal Application Load Balancer"
    if scheme == "EXTERNAL" and scope == "global":
        return "Classic Application Load Balancer"
    if scheme == "EXTERNAL":
        return "External proxy-based load balancer"

    return f"Unknown HTTPS proxy based load balancer ({scheme})"


def classify_ssl_proxy_load_balancer(forwarding_rule_info):
    """Classify Target SSL Proxy resources."""
    if not forwarding_rule_info:
        return "SSL Proxy Load Balancer"

    scheme = forwarding_rule_info.get("load_balancing_scheme")
    if scheme in ("EXTERNAL", "EXTERNAL_MANAGED"):
        return "SSL Proxy Load Balancer"

    return f"SSL Proxy Load Balancer ({scheme})"


def fetch_ssl_certificate(compute, project, cert_url, fallback_region=None):
    """Retrieve a global or regional SSL certificate resource."""
    cert_name = extract_resource_name(cert_url)
    region = extract_region_from_url(cert_url) or fallback_region

    if "/regions/" in cert_url:
        return compute.regionSslCertificates().get(
            project=project,
            region=region,
            sslCertificate=cert_name,
        ).execute()

    return compute.sslCertificates().get(
        project=project,
        sslCertificate=cert_name,
    ).execute()


def parse_self_managed_cert_expiry(cert_resource):
    """Parse expiry date from a self-managed PEM certificate."""
    cert_data = cert_resource.get("certificate")
    if not cert_data:
        return None

    try:
        decoded_cert = x509.load_pem_x509_certificate(
            cert_data.encode("utf-8"),
            default_backend(),
        )

        if hasattr(decoded_cert, "not_valid_after_utc"):
            return decoded_cert.not_valid_after_utc

        return pytz.utc.localize(decoded_cert.not_valid_after)

    except Exception as error:
        return f"Error parsing certificate: {error}"


def build_certificate_record(
    compute,
    project,
    proxy,
    proxy_scope,
    proxy_region,
    cert_url,
    forwarding_rule_index,
    proxy_kind,
):
    """Create one normalized output record for one certificate attached to one proxy."""
    proxy_name = proxy.get("name")
    proxy_self_link = proxy.get("selfLink")
    forwarding_rule_info = forwarding_rule_index.get(proxy_self_link, {})

    if proxy_kind == "ssl":
        lb_type = classify_ssl_proxy_load_balancer(forwarding_rule_info)
    else:
        lb_type = classify_https_load_balancer(proxy_scope, forwarding_rule_info)

    cert_name = extract_resource_name(cert_url)
    cert_resource = fetch_ssl_certificate(
        compute=compute,
        project=project,
        cert_url=cert_url,
        fallback_region=proxy_region,
    )

    cert_type = cert_resource.get("type")
    is_managed = cert_type == "MANAGED"

    expiry_date = None
    if not is_managed:
        expiry_date = parse_self_managed_cert_expiry(cert_resource)

    return {
        "lb_type": lb_type,
        "proxy_kind": proxy_kind,
        "proxy_scope": proxy_scope,
        "proxy_region": proxy_region,
        "forwarding_rule_name": forwarding_rule_info.get("forwarding_rule_name"),
        "load_balancing_scheme": forwarding_rule_info.get("load_balancing_scheme"),
        "ip_address": forwarding_rule_info.get("ip_address"),
        "proxy_name": proxy_name,
        "cert_name": cert_name,
        "is_managed": is_managed,
        "cert_type": cert_type,
        "expiry_date": expiry_date.isoformat() if isinstance(expiry_date, datetime) else expiry_date,
    }


def scan_global_target_https_proxies(compute, project, forwarding_rule_index):
    """Scan global Target HTTPS Proxies."""
    records = []

    print(f"\nScanning global Target HTTPS Proxies in project: {project}")
    response = compute.targetHttpsProxies().list(project=project).execute()

    for proxy in response.get("items", []):
        proxy_name = proxy.get("name")
        cert_urls = proxy.get("sslCertificates", [])
        certificate_map = proxy.get("certificateMap")

        print(f"  Proxy: {proxy_name} | Certificates: {len(cert_urls)}")

        if certificate_map and not cert_urls:
            records.append({
                "lb_type": "Certificate map based HTTPS proxy",
                "proxy_kind": "https",
                "proxy_scope": "global",
                "proxy_region": None,
                "forwarding_rule_name": None,
                "load_balancing_scheme": None,
                "ip_address": None,
                "proxy_name": proxy_name,
                "cert_name": extract_resource_name(certificate_map),
                "is_managed": None,
                "cert_type": "CERTIFICATE_MAP",
                "expiry_date": "Certificate map parsing not implemented",
            })
            continue

        for cert_url in cert_urls:
            records.append(
                build_certificate_record(
                    compute=compute,
                    project=project,
                    proxy=proxy,
                    proxy_scope="global",
                    proxy_region=None,
                    cert_url=cert_url,
                    forwarding_rule_index=forwarding_rule_index,
                    proxy_kind="https",
                )
            )

    return records


def scan_regional_target_https_proxies(compute, project, regions, forwarding_rule_index):
    """
    Scan regional Target HTTPS Proxies.

    Empty regions are not printed one by one, which keeps output clean.
    """
    records = []
    scanned_regions = 0
    regions_with_proxies = 0

    print(f"\nScanning regional Target HTTPS Proxies across {len(regions)} region(s)...")

    for region in regions:
        scanned_regions += 1

        try:
            response = compute.regionTargetHttpsProxies().list(
                project=project,
                region=region,
            ).execute()
        except Exception as error:
            print(f"  WARNING: Could not scan region {region}: {error}")
            continue

        proxies = response.get("items", [])
        if not proxies:
            continue

        regions_with_proxies += 1
        print(f"  Found {len(proxies)} regional HTTPS proxy resource(s) in {region}")

        for proxy in proxies:
            proxy_name = proxy.get("name")
            cert_urls = proxy.get("sslCertificates", [])
            certificate_map = proxy.get("certificateMap")

            print(f"    Proxy: {proxy_name} | Certificates: {len(cert_urls)}")

            if certificate_map and not cert_urls:
                records.append({
                    "lb_type": "Certificate map based regional HTTPS proxy",
                    "proxy_kind": "https",
                    "proxy_scope": "regional",
                    "proxy_region": region,
                    "forwarding_rule_name": None,
                    "load_balancing_scheme": None,
                    "ip_address": None,
                    "proxy_name": proxy_name,
                    "cert_name": extract_resource_name(certificate_map),
                    "is_managed": None,
                    "cert_type": "CERTIFICATE_MAP",
                    "expiry_date": "Certificate map parsing not implemented",
                })
                continue

            for cert_url in cert_urls:
                records.append(
                    build_certificate_record(
                        compute=compute,
                        project=project,
                        proxy=proxy,
                        proxy_scope="regional",
                        proxy_region=region,
                        cert_url=cert_url,
                        forwarding_rule_index=forwarding_rule_index,
                        proxy_kind="https",
                    )
                )

    print(
        f"Regional scan complete: scanned {scanned_regions} region(s), "
        f"found proxies in {regions_with_proxies} region(s)."
    )

    return records


def scan_global_target_ssl_proxies(compute, project, forwarding_rule_index):
    """Scan global Target SSL Proxies."""
    records = []

    print(f"\nScanning global Target SSL Proxies in project: {project}")

    try:
        response = compute.targetSslProxies().list(project=project).execute()
    except Exception as error:
        print(f"  WARNING: Could not list Target SSL Proxies: {error}")
        return records

    for proxy in response.get("items", []):
        proxy_name = proxy.get("name")
        cert_urls = proxy.get("sslCertificates", [])
        certificate_map = proxy.get("certificateMap")

        print(f"  Proxy: {proxy_name} | Certificates: {len(cert_urls)}")

        if certificate_map and not cert_urls:
            records.append({
                "lb_type": "Certificate map based SSL proxy",
                "proxy_kind": "ssl",
                "proxy_scope": "global",
                "proxy_region": None,
                "forwarding_rule_name": None,
                "load_balancing_scheme": None,
                "ip_address": None,
                "proxy_name": proxy_name,
                "cert_name": extract_resource_name(certificate_map),
                "is_managed": None,
                "cert_type": "CERTIFICATE_MAP",
                "expiry_date": "Certificate map parsing not implemented",
            })
            continue

        for cert_url in cert_urls:
            records.append(
                build_certificate_record(
                    compute=compute,
                    project=project,
                    proxy=proxy,
                    proxy_scope="global",
                    proxy_region=None,
                    cert_url=cert_url,
                    forwarding_rule_index=forwarding_rule_index,
                    proxy_kind="ssl",
                )
            )

    return records


def calculate_status(expiry_date, is_managed):
    """Convert expiry information into operational status."""
    if is_managed:
        return "OK", None

    if not expiry_date:
        return "ERROR", None

    if isinstance(expiry_date, str) and "Error" in expiry_date:
        return "ERROR", None

    try:
        expiry_datetime = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
        days_left = (expiry_datetime - datetime.now(pytz.utc)).days

        if days_left < 0:
            return "EXPIRED", days_left
        if days_left <= 10:
            return "EXPIRING_SOON", days_left
        if days_left <= 30:
            return "WARNING", days_left
        return "OK", days_left

    except Exception:
        return "ERROR", None


def get_status_rank(status):
    """Sort urgent results first."""
    rank = {
        "EXPIRED": 1,
        "EXPIRING_SOON": 2,
        "WARNING": 3,
        "ERROR": 4,
        "OK": 5,
    }
    return rank.get(status, 99)


def shorten(value, max_length):
    """Shorten long strings so the table fits better in Cloud Shell."""
    if value is None:
        return "N/A"

    value = str(value)
    if len(value) <= max_length:
        return value

    return value[: max_length - 3] + "..."


def format_expiry(expiry_date):
    """Convert full ISO timestamp into YYYY-MM-DD for table readability."""
    if not expiry_date:
        return "N/A"

    if isinstance(expiry_date, str) and "T" in expiry_date:
        return expiry_date.split("T")[0]

    return str(expiry_date)


def print_table(headers, rows):
    """Print a simple ASCII table without third-party dependencies."""
    widths = []

    for column_index, header in enumerate(headers):
        max_cell_width = len(header)
        for row in rows:
            max_cell_width = max(max_cell_width, len(str(row[column_index])))
        widths.append(max_cell_width)

    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def print_row(row):
        line = "| " + " | ".join(
            str(cell).ljust(widths[index])
            for index, cell in enumerate(row)
        ) + " |"
        print(line)

    print(separator)
    print_row(headers)
    print(separator)

    for row in rows:
        print_row(row)

    print(separator)


def filter_records(records, classic_only=False, ssl_proxy_only=False):
    """Filter records for focused demos."""
    if classic_only:
        return [
            record for record in records
            if record.get("lb_type") == "Classic Application Load Balancer"
        ]

    if ssl_proxy_only:
        return [
            record for record in records
            if record.get("proxy_kind") == "ssl"
        ]

    return records


def print_report(records):
    """Print final report with summary and detailed table."""
    print("\nTLS Certificate Expiry Report")
    print("=" * 100)

    if not records:
        print("No supported proxy certificates found.")
        return

    enriched_records = []
    summary = {
        "EXPIRED": 0,
        "EXPIRING_SOON": 0,
        "WARNING": 0,
        "ERROR": 0,
        "OK": 0,
    }

    for record in records:
        status, days_left = calculate_status(
            expiry_date=record.get("expiry_date"),
            is_managed=record.get("is_managed"),
        )

        summary[status] = summary.get(status, 0) + 1

        enriched_records.append({
            **record,
            "status": status,
            "days_left": days_left if days_left is not None else "N/A",
            "region": record.get("proxy_region") or "global",
            "expiry_display": format_expiry(record.get("expiry_date")),
        })

    enriched_records.sort(
        key=lambda item: (
            get_status_rank(item["status"]),
            99999 if item["days_left"] == "N/A" else item["days_left"],
            item.get("lb_type") or "",
            item.get("proxy_name") or "",
        )
    )

    print("\nSummary")
    print("-" * 100)
    print(f"Total certificates scanned : {len(enriched_records)}")
    print(f"Expired                    : {summary.get('EXPIRED', 0)}")
    print(f"Expiring soon (<=10 days)  : {summary.get('EXPIRING_SOON', 0)}")
    print(f"Warning (<=30 days)        : {summary.get('WARNING', 0)}")
    print(f"Errors                     : {summary.get('ERROR', 0)}")
    print(f"OK                         : {summary.get('OK', 0)}")

    print("\nDetailed Results")
    print("-" * 100)

    headers = [
        "Status",
        "Days",
        "LB Type",
        "Region",
        "Proxy",
        "Certificate",
        "Managed",
        "Expiry",
    ]

    rows = []
    for record in enriched_records:
        rows.append([
            record["status"],
            record["days_left"],
            shorten(record.get("lb_type"), 34),
            shorten(record.get("region"), 18),
            shorten(record.get("proxy_name"), 28),
            shorten(record.get("cert_name"), 28),
            record.get("is_managed"),
            record.get("expiry_display"),
        ])

    print_table(headers, rows)

    print("\nStatus Meaning")
    print("-" * 100)
    print("EXPIRED       : Self-managed certificate is already expired.")
    print("EXPIRING_SOON : Self-managed certificate expires within 10 days.")
    print("WARNING       : Self-managed certificate expires within 30 days.")
    print("ERROR         : Certificate expiry could not be parsed or is unsupported.")
    print("OK            : Google-managed cert, or self-managed cert has more than 30 days left.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Track TLS certificate expiry for GCP proxy-based Load Balancers."
    )

    parser.add_argument("--project", required=True, help="GCP project ID to scan.")
    parser.add_argument(
        "--regions",
        default="",
        help="Optional comma-separated region list. If omitted, all regions are scanned.",
    )
    parser.add_argument(
        "--global-only",
        action="store_true",
        help="Scan only global Target HTTPS Proxies.",
    )
    parser.add_argument(
        "--regional-only",
        action="store_true",
        help="Scan only regional Target HTTPS Proxies.",
    )
    parser.add_argument(
        "--classic-only",
        action="store_true",
        help="Show only Classic Application Load Balancer records.",
    )
    parser.add_argument(
        "--ssl-proxy-only",
        action="store_true",
        help="Scan and show only SSL Proxy Load Balancer records.",
    )
    parser.add_argument(
        "--skip-ssl-proxy",
        action="store_true",
        help="Skip scanning Target SSL Proxies during the default full scan.",
    )

    args = parser.parse_args()

    selected_modes = [args.global_only, args.regional_only, args.ssl_proxy_only]
    if sum(bool(mode) for mode in selected_modes) > 1:
        raise ValueError("Use only one of --global-only, --regional-only, or --ssl-proxy-only.")

    if args.classic_only and (args.regional_only or args.ssl_proxy_only):
        raise ValueError("--classic-only can only be used with global HTTPS proxy scanning.")

    compute = build_compute_service()
    forwarding_rule_index = build_forwarding_rule_index(compute, args.project)
    all_records = []

    if args.ssl_proxy_only:
        all_records.extend(scan_global_target_ssl_proxies(
            compute=compute,
            project=args.project,
            forwarding_rule_index=forwarding_rule_index,
        ))

    elif args.regional_only:
        if args.regions:
            regions = [region.strip() for region in args.regions.split(",") if region.strip()]
        else:
            regions = list_regions(compute, args.project)

        all_records.extend(scan_regional_target_https_proxies(
            compute=compute,
            project=args.project,
            regions=regions,
            forwarding_rule_index=forwarding_rule_index,
        ))

    elif args.global_only or args.classic_only:
        all_records.extend(scan_global_target_https_proxies(
            compute=compute,
            project=args.project,
            forwarding_rule_index=forwarding_rule_index,
        ))

    else:
        all_records.extend(scan_global_target_https_proxies(
            compute=compute,
            project=args.project,
            forwarding_rule_index=forwarding_rule_index,
        ))

        if args.regions:
            regions = [region.strip() for region in args.regions.split(",") if region.strip()]
        else:
            regions = list_regions(compute, args.project)

        all_records.extend(scan_regional_target_https_proxies(
            compute=compute,
            project=args.project,
            regions=regions,
            forwarding_rule_index=forwarding_rule_index,
        ))

        if not args.skip_ssl_proxy:
            all_records.extend(scan_global_target_ssl_proxies(
                compute=compute,
                project=args.project,
                forwarding_rule_index=forwarding_rule_index,
            ))

    all_records = filter_records(
        records=all_records,
        classic_only=args.classic_only,
        ssl_proxy_only=args.ssl_proxy_only,
    )

    print_report(all_records)


if __name__ == "__main__":
    main()
