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

S3_BUCKET             = os.environ.get('S3_BUCKET', 'pe-mule-prod-log')
S3_PREFIX             = os.environ.get('S3_PREFIX', '10.1.7.84/')
AWS_REGION            = os.environ.get('AWS_REGION', 'ap-south-1')
CACHE_TTL             = int(os.environ.get('CACHE_TTL', '300'))
CACHE_TTL_RECENT      = int(os.environ.get('CACHE_TTL_RECENT', '60'))   # shorter TTL for hours_back queries
ALERT_FILE            = os.environ.get('ALERT_FILE', 'alerts.json')
CHECK_INTERVAL        = int(os.environ.get('ALERT_CHECK_INTERVAL', '300'))
MAX_FILES_PER_REQUEST = int(os.environ.get('MAX_FILES_PER_REQUEST', '5'))
MAX_LINES_PER_FILE    = int(os.environ.get('MAX_LINES_PER_FILE', '50000'))
MAX_BYTES_PER_FILE    = int(os.environ.get('MAX_BYTES_PER_FILE', str(4 * 1024 * 1024)))
MAX_BYTES_TAIL        = int(os.environ.get('MAX_BYTES_TAIL', str(8 * 1024 * 1024)))  # read more for tail

_cache = {}
_cache_lock = threading.Lock()

def cache_get(key, ttl=None):
    with _cache_lock:
        entry = _cache.get(key)
        if entry and (time.time() - entry['ts']) < (ttl or CACHE_TTL):
            return entry['val']
    return None

def cache_set(key, val):
    with _cache_lock:
        _cache[key] = {'val': val, 'ts': time.time()}

def cache_clear():
    with _cache_lock:
        _cache.clear()

def get_s3():
    if not HAS_BOTO:
        raise RuntimeError("boto3 not installed")
    key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if not key_id or not secret:
        raise RuntimeError("AWS credentials not set in Railway environment variables.")
    return boto3.client('s3', region_name=AWS_REGION,
                        aws_access_key_id=key_id, aws_secret_access_key=secret)

_RE_DATED   = re.compile(r'^(.+?)\.log\.(\d{4}-\d{2}-\d{2})$')
_RE_UNDATED = re.compile(r'^(.+?)\.log(\.\d+)?$')
_RE_PREFIX  = re.compile(r'^mule-app-', re.IGNORECASE)
_RE_SPLIT   = re.compile(r'-\d+$')
_SKIP_NAMES = {'mule_agent', 'mule_ee', 'hello-sample', 'mule_agent_log', 'mule'}

def _parse_filename(filename):
    m = _RE_DATED.match(filename)
    if m:
        api = _RE_SPLIT.sub('', _RE_PREFIX.sub('', m.group(1)))
        return None if api.lower() in _SKIP_NAMES else (api, m.group(2))
    m = _RE_UNDATED.match(filename)
    if m:
        api = _RE_SPLIT.sub('', _RE_PREFIX.sub('', m.group(1)))
        return None if api.lower() in _SKIP_NAMES else (api, None)
    return None

def _parse_ts(ts_str):
    """Parse a log timestamp string like '2026-01-24 01:34:36' into a datetime."""
    try:
        return datetime.strptime(ts_str.strip(), '%Y-%m-%d %H:%M:%S')
    except Exception:
        return datetime.min

def list_s3_files():
    cached = cache_get('s3:filelist')
    if cached is not None:
        return cached
    s3 = get_s3()
    paginator = s3.get_paginator('list_objects_v2')
    files, skipped = [], 0
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX):
        for obj in page.get('Contents', []):
            if obj['Size'] == 0:
                continue
            key = obj['Key']
            filename = key.split('/')[-1]
            result = _parse_filename(filename)
            if result is None:
                skipped += 1
                continue
            api, date = result
            if date is None:
                date = obj['LastModified'].strftime('%Y-%m-%d')
            files.append({
                'key':           key,
                'api':           api,
                'date':          date,
                'filename':      filename,
                'size':          obj['Size'],
                'last_modified': obj['LastModified'].isoformat(),
            })
    files.sort(key=lambda x: (x['date'], x['api']), reverse=True)
    cache_set('s3:filelist', files)
    app.logger.info(f"S3: {len(files)} files matched, {skipped} skipped under s3://{S3_BUCKET}/{S3_PREFIX}")
    return files

def stream_s3_file_lines(key):
    """Read the first MAX_BYTES_PER_FILE bytes of an S3 file (historical data)."""
    try:
        s3 = get_s3()
        obj = s3.get_object(Bucket=S3_BUCKET, Key=key,
                            Range=f'bytes=0-{MAX_BYTES_PER_FILE - 1}')
        body = obj['Body']
        line_count = 0
        buf = b''
        for chunk in body.iter_chunks(chunk_size=65536):
            buf += chunk
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                yield line.decode('utf-8', errors='replace')
                line_count += 1
                if line_count >= MAX_LINES_PER_FILE:
                    return
        if buf:
            yield buf.decode('utf-8', errors='replace')
    except Exception as e:
        app.logger.error(f"S3 stream error [{key}]: {e}")

def stream_s3_file_lines_tail(key):
    """
    Read the LAST MAX_BYTES_TAIL bytes of an S3 file — ideal for 'last N hours' queries
    since the most recent log entries are at the end of the file.
    """
    try:
        s3 = get_s3()
        # bytes=-N means "last N bytes" in S3 Range requests
        obj = s3.get_object(Bucket=S3_BUCKET, Key=key,
                            Range=f'bytes=-{MAX_BYTES_TAIL}')
        buf = b''
        for chunk in obj['Body'].iter_chunks(chunk_size=65536):
            buf += chunk
        raw = buf.decode('utf-8', errors='replace')
        lines = raw.split('\n')
        # First line may be partial (we cut into the file) — skip it
        if lines:
            lines = lines[1:]
        return lines
    except Exception as e:
        app.logger.error(f"S3 tail error [{key}]: {e}")
        return []

LOG_HEADER_RE = re.compile(
    r'^(INFO|ERROR|WARN|DEBUG)\s+'
    r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+'
    r'\[.*?\[([^\]]+)\]\.(get|post|put|delete):\\+([^:]+):'
    r'.*?\]\s+'
    r'\[processor:\s*([^;/\]]+).*?;\s*event:\s*([^\]]+)\]\s+'
    r'.*?:\s+(.*)',
    re.IGNORECASE | re.DOTALL
)
LOG_START_RE = re.compile(r'^(INFO|ERROR|WARN|DEBUG)\s+\d{4}')

def parse_streamed_lines(line_iter, api_hint=''):
    entries, current = [], []

    def _flush(block_lines):
        block = '\n'.join(block_lines)
        m = LOG_HEADER_RE.match(block)
        if not m:
            return
        level, ts, api, method, endpoint, flow, event_id, message = m.groups()
        endpoint = '/' + endpoint.replace('\\', '/')
        entry = {
            'level':      level.upper(),
            'timestamp':  ts,
            'date':       ts[:10],
            'hour':       ts[11:13],
            'minute':     ts[11:16],   # HH:MM for per-minute timeline
            'api':        api or api_hint,
            'method':     method.upper(),
            'endpoint':   endpoint,
            'flow':       flow.strip(),
            'event_id':   event_id.strip(),
            'message':    message[:5000],  # was 400 — increased to show full context
            'is_error':   level.upper() in ('ERROR', 'WARN'),
            # Razorpay fields (kept for alert compatibility)
            'rz_status':  None, 'error_code': None, 'error_desc': None,
            'amount_inr': None, 'payment_id': None, 'order_id':   None,
            'upi_method': None, 'loan_number': None, 'customer':   None,
        }
        json_m = re.search(r'\{[\s\S]*?\}', message)
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

    for line in line_iter:
        if LOG_START_RE.match(line):
            if current:
                _flush(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        _flush(current)
    return entries

def load_entries_for_files(file_list, tail=False):
    all_entries = []
    for f in file_list:
        if tail:
            lines = stream_s3_file_lines_tail(f['key'])
            entries = parse_streamed_lines(iter(lines), api_hint=f.get('api', ''))
        else:
            entries = parse_streamed_lines(stream_s3_file_lines(f['key']), api_hint=f.get('api', ''))
        all_entries.extend(entries)
        app.logger.info(f"  {f['filename']}: {len(entries)} entries ({f['size'] // 1024}KB)"
                        f"{' [tail]' if tail else ''}")
    return all_entries

def aggregate(entries, per_minute_mode=False):
    total = len(entries)
    if total == 0:
        return empty_stats()

    errors   = sum(1 for e in entries if e['is_error'])
    warnings = sum(1 for e in entries if e['level'] == 'WARN')

    # Level breakdown
    level_counts = Counter(e['level'] for e in entries)

    # Timelines
    hourly = defaultdict(int)
    per_minute = defaultdict(int)
    for e in entries:
        hourly[f"{e['date']} {e['hour']}:00"] += 1
        if per_minute_mode:
            per_minute[f"{e['date']} {e['minute']}"] += 1

    daily     = Counter(e['date']    for e in entries)
    endpoints = Counter(f"{e['method']} {e['endpoint']}" for e in entries)
    flows     = Counter(e['flow']    for e in entries)
    apis      = Counter(e['api']     for e in entries)

    # Per-level endpoint breakdown
    err_by_ep   = Counter(f"{e['method']} {e['endpoint']}" for e in entries if e['is_error'])
    err_by_flow = Counter(e['flow'] for e in entries if e['is_error'])
    err_by_api  = Counter(e['api']  for e in entries if e['is_error'])

    # Error rate over time (hourly)
    hourly_errors = defaultdict(int)
    for e in entries:
        if e['is_error']:
            hourly_errors[f"{e['date']} {e['hour']}:00"] += 1

    # Razorpay (kept for alert checker compatibility)
    created  = sum(1 for e in entries if e.get('rz_status') == 'created')
    captured = sum(1 for e in entries if e.get('rz_status') == 'captured')
    failed   = sum(1 for e in entries if e.get('error_code'))
    revenue  = sum(e.get('amount_inr') or 0 for e in entries if e.get('rz_status') == 'captured')
    methods  = Counter(e.get('upi_method') for e in entries if e.get('upi_method'))
    statuses = Counter(e.get('rz_status')  for e in entries if e.get('rz_status'))

    sorted_hours = sorted(hourly.keys())
    sorted_minutes = sorted(per_minute.keys()) if per_minute_mode else []

    return {
        # Summary
        'total':        total,
        'errors':       errors,
        'warnings':     warnings,
        'error_rate':   round(errors / total * 100, 2) if total else 0,
        'success_rate': round((total - errors) / total * 100, 2) if total else 100,
        'apis_active':  len(set(e['api'] for e in entries)),
        'avg_per_hour': round(total / max(len(hourly), 1), 1),
        # Breakdowns
        'level_counts':    dict(level_counts),
        'hourly_labels':   sorted_hours,
        'hourly_values':   [hourly[h] for h in sorted_hours],
        'hourly_errors':   [hourly_errors.get(h, 0) for h in sorted_hours],
        'per_minute_labels': sorted_minutes,
        'per_minute_values': [per_minute[m] for m in sorted_minutes],
        'daily':           dict(sorted(daily.items())),
        'endpoints':       dict(endpoints.most_common()),
        'flows':           dict(flows.most_common()),
        'apis':            dict(apis.most_common()),
        'err_by_endpoint': dict(err_by_ep.most_common(10)),
        'err_by_flow':     dict(err_by_flow.most_common(10)),
        'err_by_api':      dict(err_by_api.most_common(10)),
        'recent_errors':   [e for e in entries if e['is_error']][-100:],
        # Razorpay (for alert compatibility)
        'payments_created':  created,
        'payments_captured': captured,
        'payments_failed':   failed,
        'revenue_inr':       round(revenue, 2),
        'payment_methods':   dict(methods.most_common()),
        'payment_statuses':  dict(statuses.most_common()),
    }

def empty_stats():
    return {
        'total': 0, 'errors': 0, 'warnings': 0, 'error_rate': 0,
        'success_rate': 100, 'apis_active': 0, 'avg_per_hour': 0,
        'level_counts': {}, 'hourly_labels': [], 'hourly_values': [],
        'hourly_errors': [], 'per_minute_labels': [], 'per_minute_values': [],
        'daily': {}, 'endpoints': {}, 'flows': {}, 'apis': {},
        'err_by_endpoint': {}, 'err_by_flow': {}, 'err_by_api': {},
        'recent_errors': [],
        'payments_created': 0, 'payments_captured': 0, 'payments_failed': 0,
        'revenue_inr': 0, 'payment_methods': {}, 'payment_statuses': {},
    }

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    with open(os.path.join(app.template_folder, 'index.html')) as f:
        return f.read()

@app.route('/favicon.ico')
def favicon():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
           b'<rect width="16" height="16" rx="3" fill="#4D9EFF"/>'
           b'<text x="3" y="13" font-size="12" font-family="sans-serif" fill="white">M</text></svg>')
    return Response(svg, mimetype='image/svg+xml')

@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok', 'ts': datetime.now().isoformat(),
        'max_files_per_request': MAX_FILES_PER_REQUEST,
        'max_bytes_per_file_mb': MAX_BYTES_PER_FILE // (1024 * 1024),
        'max_bytes_tail_mb':     MAX_BYTES_TAIL // (1024 * 1024),
    })

@app.route('/api/debug')
def debug():
    info = {
        'boto3_installed': HAS_BOTO, 'S3_BUCKET': S3_BUCKET, 'S3_PREFIX': S3_PREFIX,
        'AWS_REGION': AWS_REGION, 'has_access_key': bool(os.environ.get('AWS_ACCESS_KEY_ID')),
        'has_secret_key': bool(os.environ.get('AWS_SECRET_ACCESS_KEY')),
        'max_files_per_request': MAX_FILES_PER_REQUEST,
        'max_bytes_per_file_mb': MAX_BYTES_PER_FILE // (1024 * 1024),
        'max_bytes_tail_mb':     MAX_BYTES_TAIL // (1024 * 1024),
    }
    try:
        files = list_s3_files()
        info['s3_ok'] = True
        info['total_files'] = len(files)
        if files:
            dates = sorted(set(f['date'] for f in files))
            info['earliest_date']  = dates[0]
            info['latest_date']    = dates[-1]
            info['available_apis'] = sorted(set(f['api'] for f in files))
            info['sample_files']   = [
                {'key': f['key'], 'api': f['api'], 'date': f['date'], 'size_kb': f['size'] // 1024}
                for f in files[:10]
            ]
        else:
            info['warning'] = f"0 files matched under s3://{S3_BUCKET}/{S3_PREFIX}"
    except Exception as e:
        info['s3_ok'] = False
        info['error'] = str(e)
    return jsonify(info)

@app.route('/api/apis')
def list_apis():
    try:
        files = list_s3_files()
        return jsonify({'apis': sorted(set(f['api'] for f in files)), 'total_files': len(files)})
    except Exception as e:
        return jsonify({'error': str(e), 'apis': [], 'total_files': 0}), 500

@app.route('/api/dates')
def list_dates():
    api = request.args.get('api', '')
    try:
        files = list_s3_files()
        dates = sorted(set(f['date'] for f in files if not api or f['api'] == api), reverse=True)
        return jsonify({'dates': dates})
    except Exception as e:
        return jsonify({'error': str(e), 'dates': []}), 500

@app.route('/api/stats')
def get_stats():
    api        = request.args.get('api', '')
    hours_back = request.args.get('hours_back', type=int)      # NEW: timestamp-based query
    date_from  = request.args.get('date_from', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to    = request.args.get('date_to',  datetime.now().strftime('%Y-%m-%d'))
    show_all   = request.args.get('all', 'false').lower() == 'true'

    ck = f'stats:{api}:{hours_back or ""}:{date_from}:{date_to}:{show_all}'
    ttl = CACHE_TTL_RECENT if hours_back else CACHE_TTL
    cached = cache_get(ck, ttl=ttl)
    if cached:
        return jsonify(cached)

    try:
        files = list_s3_files()
    except Exception as e:
        return jsonify({'error': str(e), **empty_stats(), 'files_loaded': 0}), 500

    if hours_back:
        # ── Timestamp-based: read tail of today's (and maybe yesterday's) files ──
        cutoff_dt = datetime.now() - timedelta(hours=hours_back)
        today     = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        candidates = [
            f for f in files
            if (not api or f['api'] == api) and f['date'] in (today, yesterday)
        ]
        matched = candidates[:MAX_FILES_PER_REQUEST]
        entries = load_entries_for_files(matched, tail=True)
        # Filter by actual log timestamp (not just file date)
        entries = [e for e in entries if _parse_ts(e['timestamp']) >= cutoff_dt]
        per_minute_mode = hours_back <= 12
    elif show_all:
        candidates = [f for f in files if not api or f['api'] == api]
        matched = candidates[:MAX_FILES_PER_REQUEST]
        entries = load_entries_for_files(matched, tail=False)
        per_minute_mode = False
    else:
        candidates = [f for f in files if (not api or f['api'] == api) and date_from <= f['date'] <= date_to]
        matched = candidates[:MAX_FILES_PER_REQUEST]
        entries = load_entries_for_files(matched, tail=False)
        per_minute_mode = False

    result = aggregate(entries, per_minute_mode=per_minute_mode)
    result.update({
        'files_loaded':    len(matched),
        'files_available': len(candidates),
        'files_capped':    len(candidates) > MAX_FILES_PER_REQUEST,
        'date_from':       date_from,
        'date_to':         date_to,
        'hours_back':      hours_back,
        'cutoff_ts':       (datetime.now() - timedelta(hours=hours_back)).isoformat() if hours_back else None,
    })
    if files:
        all_dates = sorted(set(f['date'] for f in files))
        result['available_from'] = all_dates[0]
        result['available_to']   = all_dates[-1]
    cache_set(ck, result)
    return jsonify(result)

@app.route('/api/logs')
def get_logs():
    api        = request.args.get('api', '')
    date       = request.args.get('date', '')
    hours_back = request.args.get('hours_back', type=int)      # NEW
    level      = request.args.get('level', '').upper()
    endpoint   = request.args.get('endpoint', '')
    search     = request.args.get('search', '')
    page       = max(1, int(request.args.get('page', 1)))
    per_page   = min(200, int(request.args.get('per_page', 50)))
    sort_col   = request.args.get('sort', 'timestamp')
    sort_dir   = request.args.get('dir', 'desc')

    try:
        files = list_s3_files()
    except Exception as e:
        return jsonify({'error': str(e), 'logs': [], 'total': 0}), 500

    if hours_back:
        # Timestamp-based: load tail of today + yesterday
        cutoff_dt = datetime.now() - timedelta(hours=hours_back)
        today     = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        candidates = [
            f for f in files
            if (not api or f['api'] == api) and f['date'] in (today, yesterday)
        ]
        matched = candidates[:MAX_FILES_PER_REQUEST]
        entries = load_entries_for_files(matched, tail=True)
        entries = [e for e in entries if _parse_ts(e['timestamp']) >= cutoff_dt]
    elif date:
        candidates = [f for f in files if (not api or f['api'] == api) and f['date'] == date]
        matched    = candidates[:MAX_FILES_PER_REQUEST]
        entries    = load_entries_for_files(matched, tail=False)
    else:
        cutoff = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        candidates = [f for f in files if (not api or f['api'] == api) and f['date'] >= cutoff]
        matched    = candidates[:MAX_FILES_PER_REQUEST]
        entries    = load_entries_for_files(matched, tail=False)

    # Filters
    if level:    entries = [e for e in entries if e['level'] == level]
    if endpoint: entries = [e for e in entries if endpoint.lower() in e['endpoint'].lower()]
    if search:
        sl = search.lower()
        entries = [e for e in entries if
                   sl in e['message'].lower()
                   or sl in (e.get('loan_number') or '').lower()
                   or sl in (e.get('customer')    or '').lower()
                   or sl in (e.get('payment_id')  or '').lower()
                   or sl in (e.get('event_id')    or '').lower()
                   or sl in e['endpoint'].lower()
                   or sl in e['api'].lower()]

    # Sort
    reverse = (sort_dir == 'desc')
    sortable_cols = {
        'timestamp': lambda e: e['timestamp'],
        'level':     lambda e: e['level'],
        'api':       lambda e: e['api'],
        'endpoint':  lambda e: e['endpoint'],
        'method':    lambda e: e['method'],
    }
    if sort_col in sortable_cols:
        entries.sort(key=sortable_cols[sort_col], reverse=reverse)

    total = len(entries)
    return jsonify({
        'logs':     entries[(page - 1) * per_page: page * per_page],
        'total':    total,
        'page':     page,
        'per_page': per_page,
        'pages':    (total + per_page - 1) // per_page,
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    cache_clear()
    return jsonify({'success': True, 'message': 'Cache cleared'})

# ── Alert management ───────────────────────────────────────────────────────────

def load_alerts():
    return json.load(open(ALERT_FILE)) if os.path.exists(ALERT_FILE) else []

def save_alerts(alerts):
    json.dump(alerts, open(ALERT_FILE, 'w'), indent=2)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify({'alerts': load_alerts()})

@app.route('/api/alerts', methods=['POST'])
def create_alert():
    data = request.json or {}
    missing = [k for k in ('name', 'metric', 'threshold', 'operator') if not data.get(k)]
    if missing:
        return jsonify({'error': f'Missing: {missing}'}), 400
    alerts = load_alerts()
    data.update({'id': str(int(time.time() * 1000)), 'created_at': datetime.now().isoformat(),
                 'enabled': data.get('enabled', True), 'last_fired': None})
    alerts.append(data)
    save_alerts(alerts)
    return jsonify({'success': True, 'alert': data})

@app.route('/api/alerts/<alert_id>', methods=['PUT'])
def update_alert(alert_id):
    data = request.json or {}
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

# ── Alert background checker ───────────────────────────────────────────────────

METRIC_KEYS = {
    'errors':          'errors',
    'error_rate':      'error_rate',
    'payments_failed': 'payments_failed',
    'total_requests':  'total',
    'warnings':        'warnings',
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
            f"Metric `{alert['metric']}` = `{value}` (threshold: {alert['operator']} {alert['threshold']})\n"
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
                matched = [f for f in files if f['date'] == today and (not api or f['api'] == api)][:MAX_FILES_PER_REQUEST]
                if not matched:
                    continue
                stats = aggregate(load_entries_for_files(matched))
                mk    = METRIC_KEYS.get(alert['metric'], alert['metric'])
                value = stats.get(mk, 0)
                threshold = float(alert.get('threshold', 0))
                op = alert.get('operator', '>')
                triggered = (
                    (op == '>'  and value > threshold) or
                    (op == '>=' and value >= threshold) or
                    (op == '<'  and value < threshold)  or
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
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_ENV') == 'development')
