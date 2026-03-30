# MuleSoft Log Intelligence Dashboard

A real-time log analysis dashboard for MuleSoft APIs with Razorpay payment tracking, built for logs stored in Amazon S3.

## Features

- **Live S3 reading** — streams log files directly from your S3 bucket with 5-min caching
- **MuleSoft log parser** — handles multi-line entries, extracts API name, endpoint, flow, event ID
- **Razorpay insight** — parses embedded JSON payloads: order status, payment capture, error codes, UPI method, loan numbers
- **Overview dashboard** — 6 summary cards, 6 charts (timeline, endpoints, payment status, errors, flows, UPI methods)
- **Log Explorer** — paginated table with filters: level, endpoint, date, full-text search by loan#/customer/paymentId
- **Payments tab** — revenue tracking, order-to-capture funnel, daily breakdown
- **Alerts** — configurable threshold rules (error count, error rate, failed payments) with Slack/Teams webhook notifications checked every 5 minutes

## Log Format Supported

```
INFO  2026-01-24 01:34:36,818 [[MuleRuntime].uber.37830: [s-razorpay-loanacc-api].post:\\create:...] [processor: implemtation_flowSub_Flow/processors/1; event: 1-d7e96100-...] ...: before razorpay log {...}
```

## S3 File Naming Convention

```
{S3_PREFIX}mule-app-{api-name}_log.YYYY-MM-DD
```
Example: `10.1.7.84/mule-app-s-razorpay-loanacc-api_log.2026-01-24`

## Setup

### Railway Deployment

1. Push this folder to a GitHub repo
2. Railway → New Project → Deploy from GitHub
3. Set these environment variables:

| Variable | Description | Example |
|---|---|---|
| `S3_BUCKET` | S3 bucket name | `pe-mule-prod-log` |
| `S3_PREFIX` | Key prefix for your logs | `10.1.7.84/` |
| `AWS_REGION` | AWS region | `ap-south-1` |
| `AWS_ACCESS_KEY_ID` | IAM access key | (from Railway secrets) |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key | (from Railway secrets) |
| `CACHE_TTL` | Cache TTL in seconds | `300` |
| `ALERT_CHECK_INTERVAL` | Alert check frequency (s) | `300` |

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::pe-mule-prod-log",
      "arn:aws:s3:::pe-mule-prod-log/*"
    ]
  }]
}
```

Create a **dedicated IAM user** with only this policy — never use root credentials.

### Local Development

```bash
pip install -r requirements.txt

export S3_BUCKET=pe-mule-prod-log
export S3_PREFIX=10.1.7.84/
export AWS_REGION=ap-south-1
export AWS_ACCESS_KEY_ID=YOUR_KEY
export AWS_SECRET_ACCESS_KEY=YOUR_SECRET
export FLASK_ENV=development

python app.py
# Open http://localhost:5000
```

## Alert Webhooks

Supports Slack Incoming Webhooks, Microsoft Teams connectors, or any HTTP endpoint expecting:

```json
{ "text": "🔴 MuleSoft Alert: High Error Rate\nMetric `error_rate` = `15.3` (> 10)\nDate: 2026-01-24 | API: s-razorpay-loanacc-api" }
```

## API Endpoints

| Route | Description |
|---|---|
| `GET /api/health` | Health check |
| `GET /api/apis` | List all API names from S3 |
| `GET /api/dates?api=NAME` | List available log dates |
| `GET /api/stats?api=&date_from=&date_to=` | Aggregated stats |
| `GET /api/logs?api=&date=&level=&endpoint=&search=&page=` | Filtered log entries |
| `POST /api/cache/clear` | Clear in-memory cache |
| `GET /api/alerts` | List alert rules |
| `POST /api/alerts` | Create alert rule |
| `PUT /api/alerts/:id` | Update alert |
| `DELETE /api/alerts/:id` | Delete alert |
| `POST /api/alerts/test-webhook` | Send test webhook |
