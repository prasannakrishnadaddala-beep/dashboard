import re, json, os, threading, time
from flask import Flask, jsonify, request, Response
from datetime import datetime, timedelta
from collections import defaultdict, Counter

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

app = Flask(__name__, template_folder='templates')
app.config['JSON_SORT_KEYS'] = False

# ─── Config ───────────────────────────────────────────────────────────────────

S3_BUCKET      = os.environ.get('S3_BUCKET', 'pe-mule-prod-log')
S3_PREFIX      = os.environ.get('S3_PREFIX', '10.1.7.84/')
AWS_REGION     = os.environ.get('AWS_REGION', 'ap-south-1')
CACHE_TTL      = int(os.environ.get('CACHE_TTL', '300'))
ALERT_FILE     = os.environ.get('ALERT_FILE', 'alerts.json')
CHECK_INTERVAL = int(os.environ.get('ALERT_CHECK_INTERVAL', '300'))
TODAY          = datetime.now().strftime('%Y-%m-%d')

# ─── In-memory cache ──────────────────────────────────────────────────────────

_cache = {}
_cache_lock = threading.Lock()

def cache_get(key):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and (time.time() - entry['ts']) < CACHE_TTL:
            return entry['val']
    return None

def cache_set(key, val):
    with _cache_lock:
        _cache[key] = {'val': val, 'ts': time.time()}

def cache_clear():
    with _cache_lock:
        _cache.clear()

# ─── S3 helpers ───────────────────────────────────────────────────────────────

def get_s3():
    if not HAS_BOTO:
        raise RuntimeError("boto3 not installed")
    key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if not key_id or not secret:
        raise RuntimeError(
            "AWS credentials not set. Add AWS_ACCESS_KEY_ID and "
            "AWS_SECRET_ACCESS_KEY to Railway environment variables."
        )
    return boto3.client(
        's3',
        region_name=AWS_REGION,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
    )


# ---------------------------------------------------------------------------
# FILE NAMING PATTERNS FOUND IN pe-mule-prod-log/10.1.7.84/
#
# Pattern A — dated rotated mule-app log:
#   mule-app-{api}.log.YYYY-MM-DD
#   e.g.  mule-app-s-aws-sfdc-bulk-job.log.2026-03-19
#
# Pattern B — current (undated) mule-app log:
#   mule-app-{api}.log
#   e.g.  mule-app-s-aws-sfdc-bulk-job.log
#
# Pattern C — split / rotated parts (numbered suffix):
#   {api}-{N}.log   or   {api}-{N}.log.YYYY-MM-DD
#   e.g.  common-authentication-app-1.log
#         google-secops-common-api-3.log
#
# Pattern D — plain api log (no prefix, no date):
#   {api}.log
#   e.g.  common-authentication-app.log
#         google-secops-common-api.log
#         csv-s3-salesforce-sync-api.log
#
# We derive the api name by stripping:
#   - leading "mule-app-" prefix (if present)
#   - trailing "-N" numeric split suffix
#   - ".log" and any ".YYYY-MM-DD" date part
# ---------------------------------------------------------------------------

# Matches  {basename}.log.YYYY-MM-DD
_RE_DATED   = re.compile(r'^(.+?)\.log\.(\d{4}-\d{2}-\d{2})$')
# Matches  {basename}.log  (no date)
_RE_UNDATED = re.compile(r'^(.+?)\.log(\.\d+)?$')
# Strips the leading "mule-app-" prefix
_RE_PREFIX  = re.compile(r'^mule-app-', re.IGNORECASE)
# Strips a trailing numeric split suffix like "-1", "-10"
_RE_SPLIT   = re.compile(r'-\d+$')

# File names to skip entirely (system logs, not API logs)
_SKIP_NAMES = {'mule_agent', 'mule_ee', 'hello-sample', 'mule_agent_log'}


def _parse_filename(filename):
    """
    Return (api_name, date_str) from a log filename, or None if unrecognised.
    date_str is YYYY-MM-DD when available, else today's date.
    """
    m = _RE_DATED.match(filename)
    if m:
        basename, date = m.group(1), m.group(2)
        api = _RE_PREFIX.sub('', basename)
        api = _RE_SPLIT.sub('', api)
        if api.lower() in _SKIP_NAMES:
            return None
        return api, date

    m = _RE_UNDATED.match(filename)
    if m:
        basename = m.group(1)
        api = _RE_PREFIX.sub('', basename)
        api = _RE_SPLIT.sub('', api)
        if api.lower() in _SKIP_NAMES:
            return None
        # Undated file — use S3 LastModified date (filled by caller) or today
        return api, None   # caller injects date

    return None


def list_s3_files():
    """List all API log files from S3. Returns list of dicts."""
    cached = cache_get('s3:filelist')
    if cached is not None:
        return cached

    try:
        s3 = get_s3()
    except RuntimeError as e:
        app.logger.error(str(e))
        raise

    paginator = s3.get_paginator('list_objects_v2')
    files = []
    skipped = []

    try:
        for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX):
            for obj in page.get('Contents', []):
                key      = obj['Key']
                filename = key.split('/')[-1]
                size     = obj['Size']
                lm       = obj['LastModified']

                if size == 0:
                    continue  # skip empty files

                result = _parse_filename(filename)
                if result is None:
                    skipped.append(filename)
                    continue

                api, date = result
                if date is None:
                    # Use the LastModified date from S3 metadata
                    date = lm.strftime('%Y-%m-%d')

                files.append({
                    'key':           key,
                    'api':           api,
                    'date':          date,
                    'filename':      filename,
                    'size':          size,
                    'last_modified': lm.isoformat(),
                })

    except (ClientError, NoCredentialsError) as e:
        app.logger.error(f"S3 error: {e}")
        raise

    files.sort(key=lambda x: (x['date'], x['api']), reverse=True)
    cache_set('s3:filelist', files)

    app.logger.info(
        f"S3 scan: {len(files)} matched, {len(skipped)} skipped "
        f"under s3://{S3_BUCKET}/{S3_PREFIX}"
    )
    return files


def load_s3_file(key):
    """Fetch and cache a single S3 object as text."""
    ck = f's3:file:{key}'
    cached = cache_get(ck)
    if cached is not None:
        return cached
    try:
        s3  = get_s3()
        obj = s3.get_object(Bucket=S3_BUCKET, Key=key)
        content = obj['Body'].read().decode('utf-8', errors='replace')
        cache_set(ck, content)
        return content
    except Exception as e:
        app.logger.error(f"S3 read error [{key}]: {e}")
        return None

# ─── Log parser ───────────────────────────────────────────────────────────────

LOG_HEADER_RE = re.compile(
    r'^(INFO|ERROR|WARN|DEBUG)\s+'
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+'
    r'\[.*?\[([^\]]+)\]\.(get|post|put|delete):\\+([^:]+):'
    r'.*?\]\s+'
    r'\[processor:\s*([^;/\]]+).*?;\s*event:\s*([^\]]+)\]\s+'
    r'.*?:\s+(.*)',
    re.IGNORECASE | re.DOTALL
)


def parse_log_content(content, api_hint=''):
    """Parse MuleSoft multi-line log content into entry dicts."""
    lines   = content.splitlines()
    blocks  = []
    current = []

    for line in lines:
        if re.match(r'^(INFO|ERROR|WARN|DEBUG)\s+\d{4}', line):
            if current:
                blocks.append('\n'.join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append('\n'.join(current))

    entries = []
    for block in blocks:
        m = LOG_HEADER_RE.match(block)
        if not m:
            continue

        level, ts, api, method, endpoint, flow, event_id, message = m.groups()
        endpoint = '/' + endpoint.replace('\\', '/')

        entry = {
            'level':     level.upper(),
            'timestamp': ts,
            'date':      ts[:10],
            'hour':      ts[11:13],
            'api':       api or api_hint,
            'method':    method.upper(),
            'endpoint':  endpoint,
            'flow':      flow.strip(),
            'event_id':  event_id.strip(),
            'message':   message[:500],
            'is_error':  level.upper() in ('ERROR', 'WARN'),
            'rz_status':   None,
            'error_code':  None,
            'error_desc':  None,
            'amount_inr':  None,
            'payment_id':  None,
            'order_id':    None,
            'upi_method':  None,
            'loan_number': None,
            'customer':    None,
        }

        # Extract embedded Razorpay / JSON payload
        json_m = re.search(r'\{[\s\S]*\}', message)
        if json_m:
            try:
                rz = json.loads(json_m.group())
                entry['rz_status']  = rz.get('status')
                ec = rz.get('error_code')
                entry['error_code'] = ec if ec and str(ec).lower() not in ('null', 'none', '') else None
                entry['error_desc'] = rz.get('error_description')
                amt = rz.get('amount')
                entry['amount_inr'] = round(amt / 100, 2) if amt else None
                entry['payment_id'] = rz.get('id') or rz.get('receipt', '')
                entry['order_id']   = rz.get('order_id') or rz.get('receipt', '')
                entry['upi_method'] = rz.get('method')
                notes = rz.get('notes') or {}
                if isinstance(notes, dict):
                    entry['loan_number'] = notes.get('loanNumber')
                    entry['customer']    = notes.get('customerName')
                if entry['error_code']:
                    entry['is_error'] = True
            except Exception:
                pass

        entries.append(entry)

    return entries


def load_entries_for_files(file_list):
    all_entries = []
    for f in file_list:
        content = load_s3_file(f['key'])
        if content:
            all_entries.extend(parse_log_content(content, api_hint=f.get('api', '')))
    return all_entries

# ─── Aggregation ──────────────────────────────────────────────────────────────

def aggregate(entries):
    total = len(entries)
    if total == 0:
        return empty_stats()

    errors   = sum(1 for e in entries if e['is_error'])
    warnings = sum(1 for e in entries if e['level'] == 'WARN')

    hourly  = defaultdict(int)
    for e in entries:
        hourly[f"{e['date']} {e['hour']}:00"] += 1

    daily     = Counter(e['date']    for e in entries)
    endpoints = Counter(f"{e['method']} {e['endpoint']}" for e in entries)
    flows     = Counter(e['flow']    for e in entries)

    created  = sum(1 for e in entries if e.get('rz_status') == 'created')
    captured = sum(1 for e in entries if e.get('rz_status') == 'captured')
    failed   = sum(1 for e in entries if e.get('error_code'))
    revenue  = sum(
        e.get('amount_inr') or 0
        for e in entries if e.get('rz_status') == 'captured'
    )

    methods  = Counter(e.get('upi_method') for e in entries if e.get('upi_method'))
    statuses = Counter(e.get('rz_status')  for e in entries if e.get('rz_status'))

    err_by_ep   = Counter(f"{e['method']} {e['endpoint']}" for e in entries if e['is_error'])
    err_by_flow = Counter(e['flow'] for e in entries if e['is_error'])

    recent_errors = [e for e in entries if e['is_error']][-50:]
    sorted_hours  = sorted(hourly.keys())

    return {
        'total':             total,
        'errors':            errors,
        'warnings':          warnings,
        'error_rate':        round(errors / total * 100, 2) if total else 0,
        'payments_created':  created,
        'payments_captured': captured,
        'payments_failed':   failed,
        'revenue_inr':       round(revenue, 2),
        'hourly_labels':     sorted_hours,
        'hourly_values':     [hourly[h] for h in sorted_hours],
        'daily':             dict(sorted(daily.items())),
        'endpoints':         dict(endpoints.most_common()),
        'flows':             dict(flows.most_common()),
        'payment_methods':   dict(methods.most_common()),
        'payment_statuses':  dict(statuses.most_common()),
        'err_by_endpoint':   dict(err_by_ep.most_common(10)),
        'err_by_flow':       dict(err_by_flow.most_common()),
        'recent_errors':     recent_errors,
        'apis':              sorted(set(e['api'] for e in entries)),
    }


def empty_stats():
    return {
        'total': 0, 'errors': 0, 'warnings': 0, 'error_rate': 0,
        'payments_created': 0, 'payments_captured': 0, 'payments_failed': 0,
        'revenue_inr': 0, 'hourly_labels': [], 'hourly_values': [],
        'daily': {}, 'endpoints': {}, 'flows': {}, 'payment_methods': {},
        'payment_statuses': {}, 'err_by_endpoint': {}, 'err_by_flow': {},
        'recent_errors': [], 'apis': [],
    }

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    html_path = os.path.join(app.template_folder, 'index.html')
    with open(html_path) as f:
        return f.read()


@app.route('/favicon.ico')
def favicon():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
           b'<rect width="16" height="16" rx="3" fill="#FF6B35"/>'
           b'<text x="3" y="13" font-size="12" font-family="sans-serif" fill="white">M</text>'
           b'</svg>')
    return Response(svg, mimetype='image/svg+xml')


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'ts': datetime.now().isoformat()})


# ── Debug endpoint: open this first after deploying ──────────────────────────
@app.route('/api/debug')
def debug():
    info = {
        'boto3_installed': HAS_BOTO,
        'S3_BUCKET':       S3_BUCKET,
        'S3_PREFIX':       S3_PREFIX,
        'AWS_REGION':      AWS_REGION,
        'has_access_key':  bool(os.environ.get('AWS_ACCESS_KEY_ID')),
        'has_secret_key':  bool(os.environ.get('AWS_SECRET_ACCESS_KEY')),
    }
    try:
        files = list_s3_files()
        info['s3_ok']       = True
        info['total_files'] = len(files)
        if files:
            dates = sorted(set(f['date'] for f in files))
            info['earliest_date']  = dates[0]
            info['latest_date']    = dates[-1]
            info['available_apis'] = sorted(set(f['api'] for f in files))
            info['sample_files']   = [
                {'key': f['key'], 'api': f['api'], 'date': f['date']}
                for f in files[:8]
            ]
        else:
            info['warning'] = (
                "S3 connected but NO files matched. "
                "Check S3_PREFIX is correct and files exist under that path."
            )
    except Exception as e:
        info['s3_ok'] = False
        info['error'] = str(e)
    return jsonify(info)


@app.route('/api/apis')
def list_apis():
    try:
        files = list_s3_files()
        apis  = sorted(set(f['api'] for f in files))
        return jsonify({'apis': apis, 'total_files': len(files)})
    except Exception as e:
        return jsonify({'error': str(e), 'apis': [], 'total_files': 0}), 500


@app.route('/api/dates')
def list_dates():
    api = request.args.get('api', '')
    try:
        files = list_s3_files()
        dates = sorted(
            set(f['date'] for f in files if not api or f['api'] == api),
            reverse=True
        )
        return jsonify({'dates': dates})
    except Exception as e:
        return jsonify({'error': str(e), 'dates': []}), 500


@app.route('/api/stats')
def get_stats():
    api      = request.args.get('api', '')
    # Default: last 30 days — covers recent logs comfortably
    date_from = request.args.get(
        'date_from',
        (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    )
    date_to  = request.args.get('date_to', TODAY)
    show_all = request.args.get('all', 'false').lower() == 'true'

    ck = f'stats:{api}:{date_from}:{date_to}:{show_all}'
    cached = cache_get(ck)
    if cached:
        return jsonify(cached)

    try:
        files = list_s3_files()
    except Exception as e:
        return jsonify({'error': str(e), **empty_stats(), 'files_loaded': 0}), 500

    if show_all:
        matched = [f for f in files if not api or f['api'] == api]
    else:
        matched = [
            f for f in files
            if (not api or f['api'] == api)
            and date_from <= f['date'] <= date_to
        ]

    entries = load_entries_for_files(matched)
    result  = aggregate(entries)
    result['files_loaded'] = len(matched)
    result['date_from']    = date_from
    result['date_to']      = date_to

    if files:
        all_dates = sorted(set(f['date'] for f in files))
        result['available_from'] = all_dates[0]
        result['available_to']   = all_dates[-1]

    cache_set(ck, result)
    return jsonify(result)


@app.route('/api/logs')
def get_logs():
    api      = request.args.get('api', '')
    date     = request.args.get('date', '')
    level    = request.args.get('level', '').upper()
    endpoint = request.args.get('endpoint', '')
    search   = request.args.get('search', '')
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(200, int(request.args.get('per_page', 50)))

    try:
        files = list_s3_files()
    except Exception as e:
        return jsonify({'error': str(e), 'logs': [], 'total': 0}), 500

    if date:
        matched = [f for f in files if (not api or f['api'] == api) and f['date'] == date][:10]
    else:
        cutoff  = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        matched = [f for f in files if (not api or f['api'] == api) and f['date'] >= cutoff][:10]

    entries = load_entries_for_files(matched)

    if level:
        entries = [e for e in entries if e['level'] == level]
    if endpoint:
        entries = [e for e in entries if endpoint.lower() in e['endpoint'].lower()]
    if search:
        sl = search.lower()
        entries = [
            e for e in entries
            if sl in e['message'].lower()
            or sl in (e.get('loan_number') or '').lower()
            or sl in (e.get('customer') or '').lower()
            or sl in (e.get('payment_id') or '').lower()
        ]

    total     = len(entries)
    paginated = entries[(page - 1) * per_page: page * per_page]

    return jsonify({
        'logs':     paginated,
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    (total + per_page - 1) // per_page,
    })


@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    cache_clear()
    return jsonify({'success': True, 'message': 'Cache cleared'})

# ─── Alert CRUD ───────────────────────────────────────────────────────────────

def load_alerts():
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE) as f:
            return json.load(f)
    return []


def save_alerts(alerts):
    with open(ALERT_FILE, 'w') as f:
        json.dump(alerts, f, indent=2)


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify({'alerts': load_alerts()})


@app.route('/api/alerts', methods=['POST'])
def create_alert():
    data    = request.json or {}
    missing = [k for k in ('name', 'metric', 'threshold', 'operator') if not data.get(k)]
    if missing:
        return jsonify({'error': f'Missing: {missing}'}), 400
    alerts = load_alerts()
    data.update({'id': str(int(time.time() * 1000)),
                 'created_at': datetime.now().isoformat(),
                 'enabled': data.get('enabled', True),
                 'last_fired': None})
    alerts.append(data)
    save_alerts(alerts)
    return jsonify({'success': True, 'alert': data})


@app.route('/api/alerts/<alert_id>', methods=['PUT'])
def update_alert(alert_id):
    data   = request.json or {}
    alerts = load_alerts()
    for a in alerts:
        if a.get('id') == alert_id:
            a.update({k: v for k, v in data.items() if k not in ('id', 'created_at')})
            break
    save_alerts(alerts)
    return jsonify({'success': True})


@app.route('/api/alerts/<alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    save_alerts([a for a in load_alerts() if a.get('id') != alert_id])
    return jsonify({'success': True})


@app.route('/api/alerts/test-webhook', methods=['POST'])
def test_webhook():
    url = (request.json or {}).get('webhook_url', '')
    if not url:
        return jsonify({'success': False, 'error': 'No webhook URL'}), 400
    if not HAS_REQUESTS:
        return jsonify({'success': False, 'error': 'requests not installed'}), 500
    try:
        r = req_lib.post(url, json={'text': '✅ MuleSoft Dashboard: webhook working!'}, timeout=5)
        return jsonify({'success': True, 'status_code': r.status_code})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ─── Alert background checker ─────────────────────────────────────────────────

METRIC_KEYS = {
    'errors': 'errors', 'error_rate': 'error_rate',
    'payments_failed': 'payments_failed',
    'total_requests': 'total', 'warnings': 'warnings',
}


def _fire_alert(alert, value, today):
    url = alert.get('webhook_url', '').strip()
    if not url or not HAS_REQUESTS:
        return
    emojis = {'errors': '🔴', 'error_rate': '📈', 'payments_failed': '💳',
               'total_requests': '📊', 'warnings': '⚠️'}
    try:
        req_lib.post(url, json={'text': (
            f"{emojis.get(alert['metric'], '🚨')} *MuleSoft Alert: {alert['name']}*\n"
            f"Metric `{alert['metric']}` = `{value}` "
            f"(threshold: {alert['operator']} {alert['threshold']})\n"
            f"Date: {today} | API: {alert.get('api', 'ALL')}"
        )}, timeout=5)
    except Exception as e:
        app.logger.warning(f"Alert webhook failed: {e}")


def alert_checker():
    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            alerts = load_alerts()
            if not alerts:
                continue
            today = datetime.now().strftime('%Y-%m-%d')
            try:
                files = list_s3_files()
            except Exception:
                continue
            for alert in alerts:
                if not alert.get('enabled', True):
                    continue
                api     = alert.get('api', '')
                matched = [f for f in files if f['date'] == today and (not api or f['api'] == api)]
                if not matched:
                    continue
                stats     = aggregate(load_entries_for_files(matched))
                mk        = METRIC_KEYS.get(alert['metric'], alert['metric'])
                value     = stats.get(mk, 0)
                threshold = float(alert.get('threshold', 0))
                op        = alert.get('operator', '>')
                triggered = (
                    (op == '>'  and value > threshold) or
                    (op == '>=' and value >= threshold) or
                    (op == '<'  and value < threshold) or
                    (op == '<=' and value <= threshold)
                )
                if triggered:
                    _fire_alert(alert, value, today)
                    saved = load_alerts()
                    for a in saved:
                        if a.get('id') == alert.get('id'):
                            a['last_fired'] = datetime.now().isoformat()
                    save_alerts(saved)
        except Exception as e:
            app.logger.error(f"Alert checker error: {e}")


threading.Thread(target=alert_checker, daemon=True).start()

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
