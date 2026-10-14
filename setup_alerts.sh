#!/usr/bin/env bash
# ==============================================================================
# One-Command Automated Email Alert Setup for TLS Certificate Expiry Tracker
#
# Deploys tls_cert_tracker.py as a serverless Cloud Run Job, schedules it daily
# with Cloud Scheduler, and configures a native GCP Cloud Monitoring Email Alert
# Policy triggered whenever expiring or expired certificates are detected.
#
# Usage:
#   ./setup_alerts.sh --project <PROJECT_ID> --email <EMAIL_ADDRESS> [options]
# ==============================================================================

set -euo pipefail

PROJECT_ID=""
EMAIL_ADDRESS=""
REGION="us-central1"
SCHEDULE="0 9 * * *"
ALERT_ON="EXPIRED,EXPIRING_SOON,WARNING"
JOB_NAME="tls-cert-tracker-job"
SCHEDULER_NAME="tls-cert-tracker-daily"
SA_NAME="tls-cert-tracker-sa"

usage() {
  cat <<EOF
Usage:
  ./setup_alerts.sh --project <PROJECT_ID> --email <EMAIL_ADDRESS> [options]

Required Flags:
  --project <PROJECT_ID>       GCP Project ID to scan and deploy into.
  --email <EMAIL_ADDRESS>      Email address to receive certificate expiry alerts.

Optional Flags:
  --region <REGION>            Cloud Run & Cloud Scheduler region (default: us-central1).
  --schedule "<CRON>"          Cron schedule in UTC (default: "0 9 * * *" = 9:00 AM UTC daily).
  --alert-on "<STATUSES>"      Comma-separated statuses to trigger alerts
                               (default: "EXPIRED,EXPIRING_SOON,WARNING").
  -h, --help                   Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project)
      PROJECT_ID="${2:-}"
      shift 2
      ;;
    --email)
      EMAIL_ADDRESS="${2:-}"
      shift 2
      ;;
    --region)
      REGION="${2:-}"
      shift 2
      ;;
    --schedule)
      SCHEDULE="${2:-}"
      shift 2
      ;;
    --alert-on)
      ALERT_ON="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${PROJECT_ID}" || -z "${EMAIL_ADDRESS}" ]]; then
  echo "ERROR: Both --project and --email are required." >&2
  echo ""
  usage
  exit 1
fi

SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "======================================================================"
echo " Setting up Automated TLS Certificate Expiry Email Alerts"
echo "======================================================================"
echo " Project ID : ${PROJECT_ID}"
echo " Alert Email: ${EMAIL_ADDRESS}"
echo " Region     : ${REGION}"
echo " Schedule   : ${SCHEDULE} (UTC)"
echo " Alert On   : ${ALERT_ON}"
echo "======================================================================"

echo ""
echo "[1/6] Enabling required Google Cloud APIs..."
gcloud services enable \
  compute.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  cloudscheduler.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  --project="${PROJECT_ID}" \
  --quiet

echo ""
echo "[2/6] Configuring least-privilege Service Account (${SA_EMAIL})..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="TLS Certificate Expiry Tracker Service Account" \
    --project="${PROJECT_ID}" \
    --quiet
fi

for ROLE in "roles/compute.viewer" "roles/logging.logWriter" "roles/run.invoker"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${ROLE}" \
    --condition=None \
    --quiet >/dev/null
done

echo ""
echo "[3/6] Building and deploying Cloud Run Job (${JOB_NAME})..."
gcloud run jobs deploy "${JOB_NAME}" \
  --source=. \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --service-account="${SA_EMAIL}" \
  --max-retries=1 \
  --task-timeout=10m \
  --args="^:^--project=${PROJECT_ID}:--emit-log-alerts:--alert-on=${ALERT_ON}" \
  --quiet

echo ""
echo "[4/6] Configuring daily Cloud Scheduler trigger (${SCHEDULER_NAME})..."
RUN_JOB_URI="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${PROJECT_ID}/jobs/${JOB_NAME}:run"

if gcloud scheduler jobs describe "${SCHEDULER_NAME}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud scheduler jobs update http "${SCHEDULER_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --schedule="${SCHEDULE}" \
    --time-zone="Etc/UTC" \
    --uri="${RUN_JOB_URI}" \
    --http-method=POST \
    --oauth-service-account-email="${SA_EMAIL}" \
    --quiet
else
  gcloud scheduler jobs create http "${SCHEDULER_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --schedule="${SCHEDULE}" \
    --time-zone="Etc/UTC" \
    --uri="${RUN_JOB_URI}" \
    --http-method=POST \
    --oauth-service-account-email="${SA_EMAIL}" \
    --quiet
fi

echo ""
echo "[5/6] Configuring Cloud Monitoring Email Notification Channel & Alert Policy..."
EXISTING_CHANNEL=$(gcloud beta monitoring channels list \
  --project="${PROJECT_ID}" \
  --filter="type=\"email\" AND labels.email_address=\"${EMAIL_ADDRESS}\"" \
  --format="value(name)" \
  --limit=1)

if [[ -n "${EXISTING_CHANNEL}" ]]; then
  CHANNEL_NAME="${EXISTING_CHANNEL}"
  echo "  Reusing existing email notification channel: ${CHANNEL_NAME}"
else
  CHANNEL_NAME=$(gcloud beta monitoring channels create \
    --project="${PROJECT_ID}" \
    --display-name="TLS Cert Expiry Alerts (${EMAIL_ADDRESS})" \
    --description="Email notifications for GCP Load Balancer TLS certificate expiry" \
    --type=email \
    --channel-labels="email_address=${EMAIL_ADDRESS}" \
    --format="value(name)")
  echo "  Created email notification channel: ${CHANNEL_NAME}"
fi

POLICY_DISPLAY_NAME="TLS Certificate Expiry Alert (${PROJECT_ID})"
EXISTING_POLICY=$(gcloud alpha monitoring policies list \
  --project="${PROJECT_ID}" \
  --filter="displayName=\"${POLICY_DISPLAY_NAME}\"" \
  --format="value(name)" \
  --limit=1)

POLICY_FILE=$(mktemp /tmp/tls_cert_alert_policy.XXXXXX.json)
trap 'rm -f "${POLICY_FILE}"' EXIT

cat > "${POLICY_FILE}" <<EOF
{
  "displayName": "${POLICY_DISPLAY_NAME}",
  "combiner": "OR",
  "enabled": true,
  "notificationChannels": [
    "${CHANNEL_NAME}"
  ],
  "documentation": {
    "mimeType": "text/markdown",
    "content": "### TLS Certificate Expiry Alert for Project \`\${log.extracted_label.project}\`\n\n**Summary:** \${log.extracted_label.message}\n\n#### Affected Certificates\n\`\`\`text\n\${log.extracted_label.certificate_details}\n\`\`\`\n\n#### Next Steps\n1. Review the expiring or expired self-managed TLS certificates listed above.\n2. Upload a renewed certificate and attach it to the affected Target HTTPS / SSL Proxy, or migrate to a Google-managed certificate.\n3. Run \`python3 tls_cert_tracker.py --project ${PROJECT_ID}\` in Cloud Shell to verify."
  },
  "conditions": [
    {
      "displayName": "Expiring or Expired Load Balancer TLS Certificates Detected",
      "conditionMatchedLog": {
        "filter": "resource.type=\"cloud_run_job\" AND resource.labels.job_name=\"${JOB_NAME}\" AND jsonPayload.event=\"TLS_CERT_EXPIRY_ALERT\"",
        "labelExtractors": {
          "project": "EXTRACT(jsonPayload.project)",
          "alert_count": "EXTRACT(jsonPayload.alert_count)",
          "message": "EXTRACT(jsonPayload.message)",
          "certificate_details": "EXTRACT(jsonPayload.certificate_details)"
        }
      }
    }
  ],
  "alertStrategy": {
    "notificationRateLimit": {
      "period": "300s"
    },
    "autoClose": "86400s"
  }
}
EOF

if [[ -n "${EXISTING_POLICY}" ]]; then
  gcloud alpha monitoring policies update "${EXISTING_POLICY}" \
    --project="${PROJECT_ID}" \
    --policy-from-file="${POLICY_FILE}" \
    --quiet >/dev/null
  echo "  Updated Cloud Monitoring alert policy: ${EXISTING_POLICY}"
else
  CREATED_POLICY=$(gcloud alpha monitoring policies create \
    --project="${PROJECT_ID}" \
    --policy-from-file="${POLICY_FILE}" \
    --format="value(name)")
  echo "  Created Cloud Monitoring alert policy: ${CREATED_POLICY}"
fi

echo ""
echo "[6/6] Running initial scan now to verify setup..."
gcloud run jobs execute "${JOB_NAME}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}" \
  --wait

echo ""
echo "======================================================================"
echo " Setup Complete!"
echo " - Daily scan scheduled via Cloud Scheduler (${SCHEDULER_NAME})"
echo " - Email alerts configured for: ${EMAIL_ADDRESS}"
echo " - If expiring/expired certificates were found in step [6/6], an"
echo "   email alert will arrive in your inbox shortly."
echo "======================================================================"
