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

S3_BUCKET          = os.environ.get('S3_BUCKET', 'pe-mule-prod-log')
# Support both S3_PREFIXES (comma-separated, e.g. "10.1.7.84/,10.1.8.118/")
# and legacy S3_PREFIX (single value). S3_PREFIXES takes priority.
_raw_prefixes      = os.environ.get('S3_PREFIXES') or os.environ.get('S3_PREFIX', '10.1.7.84/')
S3_PREFIXES_LIST   = [p.strip() for p in _raw_prefixes.split(',') if p.strip()]
S3_PREFIX          = S3_PREFIXES_LIST[0]   # kept for backward-compat display in /api/debug
AWS_REGION         = os.environ.get('AWS_REGION', 'ap-south-1')
SYNC_INTERVAL      = int(os.environ.get('SYNC_INTERVAL', '1800'))       # 30 min — matches S3 cadence
STORE_DAYS         = int(os.environ.get('STORE_DAYS', '14'))             # keep last 14 days in RAM
ALERT_FILE         = os.environ.get('ALERT_FILE', 'alerts.json')
CHECK_INTERVAL     = int(os.environ.get('ALERT_CHECK_INTERVAL', '300'))
MAX_LINES_PER_FILE = int(os.environ.get('MAX_LINES_PER_FILE', '100000'))
MAX_BYTES_PER_FILE = int(os.environ.get('MAX_BYTES_PER_FILE', str(10 * 1024 * 1024)))  # 10 MB

# ─── Background store ─────────────────────────────────────────────────────────
# All Flask routes read from here. Zero S3 calls during request handling.
_bg_lock  = threading.Lock()
_bg_store = {
    'entries':     [],   # all parsed log entry dicts, sorted by timestamp
    'file_list':   [],   # S3 file metadata from last listing
    'last_sync':   None, # ISO string of last successful sync
    'next_sync':   None, # ISO string of next scheduled sync
    'syncing':     False,
    'sync_error':  None,
    'stats_cache': {},   # aggregation cache, invalidated on each sync
}

# Per-file parse cache: (s3_key, last_modified_iso) → list[entry]
# Historical files that haven't changed are NEVER re-fetched from S3.
_file_entry_cache = {}
_fec_lock = threading.Lock()

# ─── S3 helpers ───────────────────────────────────────────────────────────────
def get_s3():
    if not HAS_BOTO:
        raise RuntimeError("boto3 not installed — add boto3 to requirements.txt")
    key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if not key_id or not secret:
        raise RuntimeError("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set in environment")
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

def _list_s3_files_raw():
    """List all matching S3 files across ALL prefixes within STORE_DAYS window."""
    s3 = get_s3()
    paginator = s3.get_paginator('list_objects_v2')
    files, skipped = [], 0
    seen_keys = set()  # deduplicate in case prefixes overlap
    cutoff = (datetime.now() - timedelta(days=STORE_DAYS)).strftime('%Y-%m-%d')
    today  = datetime.now().strftime('%Y-%m-%d')

    app.logger.info(f"S3 listing {len(S3_PREFIXES_LIST)} prefix(es): {S3_PREFIXES_LIST}")

    for prefix in S3_PREFIXES_LIST:
        prefix_files = 0
        for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
            for obj in page.get('Contents', []):
                if obj['Size'] == 0:
                    continue
                key = obj['Key']
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                filename = key.split('/')[-1]
                result = _parse_filename(filename)
                if result is None:
                    skipped += 1
                    continue
                api, date = result
                if date is None:
                    date = obj['LastModified'].strftime('%Y-%m-%d')
                if date < cutoff:
                    continue  # outside retention window
                files.append({
                    'key': key, 'api': api, 'date': date,
                    'filename': filename, 'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'is_today': (date == today),
                    'prefix': prefix,  # track which server this came from
                })
                prefix_files += 1
        app.logger.info(f"  prefix '{prefix}': {prefix_files} files matched")

    files.sort(key=lambda x: (x['date'], x['api']), reverse=True)
    app.logger.info(f"S3 list total: {len(files)} files matched, {skipped} skipped")
    return files

def _stream_lines(key):
    """Stream lines from S3 object with a byte cap."""
    try:
        s3 = get_s3()
        obj = s3.get_object(Bucket=S3_BUCKET, Key=key,
                            Range=f'bytes=0-{MAX_BYTES_PER_FILE - 1}')
        buf, count = b'', 0
        for chunk in obj['Body'].iter_chunks(chunk_size=65536):
            buf += chunk
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                yield line.decode('utf-8', errors='replace')
                count += 1
                if count >= MAX_LINES_PER_FILE:
                    return
        if buf:
            yield buf.decode('utf-8', errors='replace')
    except Exception as e:
        app.logger.error(f"S3 stream [{key}]: {e}")

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
            'level': level.upper(), 'timestamp': ts, 'date': ts[:10],
            'hour': ts[11:13], 'api': api or api_hint, 'method': method.upper(),
            'endpoint': endpoint, 'flow': flow.strip(), 'event_id': event_id.strip(),
            'message': message[:400], 'is_error': level.upper() in ('ERROR', 'WARN'),
            'rz_status': None, 'error_code': None, 'error_desc': None,
            'amount_inr': None, 'payment_id': None, 'order_id': None,
            'upi_method': None, 'loan_number': None, 'customer': None,
        }
        json_m = re.search(r'\{[\s\S]*?\}', message)
        if json_m:
            try:
                rz = json.loads(json_m.group())
                entry['rz_status']  = rz.get('status')
                ec = rz.get('error_code')
                entry['error_code'] = ec if ec and str(ec).lower() not in ('null','none','') else None
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

# ─── Background sync engine ───────────────────────────────────────────────────
def _do_sync():
    """
    Core sync logic. Only called from the background thread (or force-sync endpoint).

    Strategy:
      1. List all S3 files — cheap, metadata only
      2. For each file:
         • today's file  → always re-fetch (it's still growing)
         • other files   → use _file_entry_cache keyed by (s3_key, last_modified)
                           so unchanged historical files are never re-fetched
      3. Merge all entries into _bg_store, invalidate stats_cache
    """
    with _bg_lock:
        if _bg_store['syncing']:
            return  # already running
        _bg_store['syncing']    = True
        _bg_store['sync_error'] = None

    app.logger.info("▶ Background sync started")
    try:
        files = _list_s3_files_raw()
        all_entries = []
        fetched_count = 0

        for f in files:
            cache_key = (f['key'], f['last_modified'])
            is_today  = f['is_today']

            with _fec_lock:
                cached = None if is_today else _file_entry_cache.get(cache_key)

            if cached is not None:
                all_entries.extend(cached)
                continue

            # Fetch + parse from S3
            entries = parse_streamed_lines(_stream_lines(f['key']), api_hint=f.get('api', ''))
            fetched_count += 1
            app.logger.info(f"  {f['filename']}: {len(entries)} entries ({f['size']//1024} KB)")

            # Cache historical files (today's file is volatile — don't cache)
            if not is_today:
                with _fec_lock:
                    _file_entry_cache[cache_key] = entries

            all_entries.extend(entries)

        # Sort by timestamp ascending so slice/filter stays deterministic
        all_entries.sort(key=lambda e: e['timestamp'])

        with _bg_lock:
            _bg_store['entries']     = all_entries
            _bg_store['file_list']   = files
            _bg_store['last_sync']   = datetime.now().isoformat()
            _bg_store['next_sync']   = (datetime.now() + timedelta(seconds=SYNC_INTERVAL)).isoformat()
            _bg_store['syncing']     = False
            _bg_store['stats_cache'] = {}   # force re-aggregation on next request

        app.logger.info(
            f"✓ Sync done: {len(all_entries)} entries | "
            f"{len(files)} files total | {fetched_count} fetched from S3"
        )

    except Exception as e:
        app.logger.error(f"✗ Sync error: {e}")
        with _bg_lock:
            _bg_store['syncing']    = False
            _bg_store['sync_error'] = str(e)


def _sync_loop():
    """Runs forever as a daemon thread. Initial sync fires 5s after startup."""
    time.sleep(5)  # let Flask finish binding before first S3 hit
    _do_sync()
    while True:
        time.sleep(SYNC_INTERVAL)
        _do_sync()

threading.Thread(target=_sync_loop, daemon=True).start()

# ─── Aggregation ─────────────────────────────────────────────────────────────
def aggregate(entries):
    total = len(entries)
    if total == 0:
        return empty_stats()
    errors      = sum(1 for e in entries if e['is_error'])
    warnings    = sum(1 for e in entries if e['level'] == 'WARN')
    hourly      = defaultdict(int)
    for e in entries:
        hourly[f"{e['date']} {e['hour']}:00"] += 1
    daily       = Counter(e['date']    for e in entries)
    endpoints   = Counter(f"{e['method']} {e['endpoint']}" for e in entries)
    flows       = Counter(e['flow']    for e in entries)
    created     = sum(1 for e in entries if e.get('rz_status') == 'created')
    captured    = sum(1 for e in entries if e.get('rz_status') == 'captured')
    failed      = sum(1 for e in entries if e.get('error_code'))
    revenue     = sum(e.get('amount_inr') or 0 for e in entries if e.get('rz_status') == 'captured')
    methods     = Counter(e.get('upi_method') for e in entries if e.get('upi_method'))
    statuses    = Counter(e.get('rz_status')  for e in entries if e.get('rz_status'))
    err_by_ep   = Counter(f"{e['method']} {e['endpoint']}" for e in entries if e['is_error'])
    err_by_flow = Counter(e['flow'] for e in entries if e['is_error'])
    sorted_hours = sorted(hourly.keys())
    return {
        'total': total, 'errors': errors, 'warnings': warnings,
        'error_rate': round(errors / total * 100, 2) if total else 0,
        'payments_created': created, 'payments_captured': captured,
        'payments_failed':  failed,  'revenue_inr': round(revenue, 2),
        'hourly_labels':  sorted_hours,
        'hourly_values':  [hourly[h] for h in sorted_hours],
        'daily':          dict(sorted(daily.items())),
        'endpoints':      dict(endpoints.most_common()),
        'flows':          dict(flows.most_common()),
        'payment_methods':  dict(methods.most_common()),
        'payment_statuses': dict(statuses.most_common()),
        'err_by_endpoint':  dict(err_by_ep.most_common(10)),
        'err_by_flow':      dict(err_by_flow.most_common()),
        'recent_errors':    [e for e in entries if e['is_error']][-50:],
        'apis':             sorted(set(e['api'] for e in entries)),
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

# ─── Routes ──────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    with open(os.path.join(app.template_folder, 'index.html')) as f:
        return f.read()

@app.route('/favicon.ico')
def favicon():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
           b'<rect width="16" height="16" rx="3" fill="#FF6B35"/>'
           b'<text x="3" y="13" font-size="12" font-family="sans-serif" fill="white">M</text></svg>')
    return Response(svg, mimetype='image/svg+xml')

@app.route('/api/health')
def health():
    with _bg_lock:
        return jsonify({
            'status': 'ok', 'ts': datetime.now().isoformat(),
            'syncing': _bg_store['syncing'],
            'last_sync': _bg_store['last_sync'],
            'entry_count': len(_bg_store['entries']),
        })

@app.route('/api/sync/status')
def sync_status():
    """Lightweight endpoint polled by the frontend every 30s."""
    with _bg_lock:
        return jsonify({
            'syncing':          _bg_store['syncing'],
            'last_sync':        _bg_store['last_sync'],
            'next_sync':        _bg_store['next_sync'],
            'sync_error':       _bg_store['sync_error'],
            'entry_count':      len(_bg_store['entries']),
            'file_count':       len(_bg_store['file_list']),
            'sync_interval_secs': SYNC_INTERVAL,
        })

@app.route('/api/sync/force', methods=['POST'])
def force_sync():
    """Trigger an immediate out-of-cycle sync."""
    with _bg_lock:
        if _bg_store['syncing']:
            return jsonify({'success': False, 'message': 'Sync already in progress'})
    threading.Thread(target=_do_sync, daemon=True).start()
    return jsonify({'success': True, 'message': 'Sync triggered'})

@app.route('/api/debug')
def debug():
    with _bg_lock:
        store = {k: v for k, v in _bg_store.items() if k not in ('entries', 'stats_cache')}
        store['entry_count'] = len(_bg_store['entries'])
    info = {
        'boto3_installed': HAS_BOTO,
        'S3_BUCKET': S3_BUCKET, 'S3_PREFIXES': S3_PREFIXES_LIST,
        'S3_PREFIX_legacy_env': os.environ.get('S3_PREFIX'),
        'S3_PREFIXES_env': os.environ.get('S3_PREFIXES'),
        'AWS_REGION': AWS_REGION,
        'has_access_key': bool(os.environ.get('AWS_ACCESS_KEY_ID')),
        'has_secret_key': bool(os.environ.get('AWS_SECRET_ACCESS_KEY')),
        'sync_interval_secs': SYNC_INTERVAL, 'store_days': STORE_DAYS,
        **store,
    }
    files = _bg_store.get('file_list', [])
    if files:
        dates = sorted(set(f['date'] for f in files))
        info['earliest_date']  = dates[0]
        info['latest_date']    = dates[-1]
        info['available_apis'] = sorted(set(f['api'] for f in files))
        info['sample_files']   = [
            {'key': f['key'], 'api': f['api'], 'date': f['date'], 'size_kb': f['size']//1024}
            for f in files[:10]
        ]
    return jsonify(info)

@app.route('/api/apis')
def list_apis():
    with _bg_lock:
        files = _bg_store['file_list']
    return jsonify({
        'apis': sorted(set(f['api'] for f in files)),
        'total_files': len(files),
    })

@app.route('/api/dates')
def list_dates():
    api = request.args.get('api', '')
    with _bg_lock:
        files = _bg_store['file_list']
    dates = sorted(set(f['date'] for f in files if not api or f['api'] == api), reverse=True)
    return jsonify({'dates': dates})

@app.route('/api/stats')
def get_stats():
    api       = request.args.get('api', '')
    date_from = request.args.get('date_from', (datetime.now()-timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to   = request.args.get('date_to',   datetime.now().strftime('%Y-%m-%d'))

    ck = f'stats:{api}:{date_from}:{date_to}'
    with _bg_lock:
        cached = _bg_store['stats_cache'].get(ck)
        if cached:
            return jsonify(cached)
        all_entries = list(_bg_store['entries'])   # snapshot — don't hold lock during aggregation
        files       = _bg_store['file_list']
        last_sync   = _bg_store['last_sync']

    # All filtering + aggregation in RAM — zero S3 calls
    entries = [e for e in all_entries
               if date_from <= e['date'] <= date_to
               and (not api or e['api'] == api)]

    result = aggregate(entries)
    result.update({
        'files_loaded': len([f for f in files
                              if (not api or f['api'] == api)
                              and date_from <= f['date'] <= date_to]),
        'date_from': date_from, 'date_to': date_to,
        'last_sync': last_sync,
    })
    if files:
        all_dates = sorted(set(f['date'] for f in files))
        result['available_from'] = all_dates[0]
        result['available_to']   = all_dates[-1]

    with _bg_lock:
        _bg_store['stats_cache'][ck] = result
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

    with _bg_lock:
        all_entries = list(_bg_store['entries'])   # snapshot

    entries = all_entries
    if api:
        entries = [e for e in entries if e['api'] == api]
    if date:
        entries = [e for e in entries if e['date'] == date]
    else:
        cutoff  = (datetime.now()-timedelta(days=7)).strftime('%Y-%m-%d')
        entries = [e for e in entries if e['date'] >= cutoff]
    if level:
        entries = [e for e in entries if e['level'] == level]
    if endpoint:
        entries = [e for e in entries if endpoint.lower() in e['endpoint'].lower()]
    if search:
        sl = search.lower()
        entries = [e for e in entries if
                   sl in e['message'].lower()
                   or sl in (e.get('loan_number') or '').lower()
                   or sl in (e.get('customer') or '').lower()
                   or sl in (e.get('payment_id') or '').lower()]

    total = len(entries)
    return jsonify({
        'logs':     entries[(page-1)*per_page : page*per_page],
        'total':    total, 'page': page, 'per_page': per_page,
        'pages':    (total + per_page - 1) // per_page,
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    with _bg_lock:
        _bg_store['stats_cache'] = {}
    return jsonify({'success': True, 'message': 'Stats cache cleared'})

# ─── Alert CRUD ───────────────────────────────────────────────────────────────
def load_alerts():
    return json.load(open(ALERT_FILE)) if os.path.exists(ALERT_FILE) else []

def save_alerts(alerts):
    json.dump(alerts, open(ALERT_FILE, 'w'), indent=2)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify({'alerts': load_alerts()})

@app.route('/api/alerts', methods=['POST'])
def create_alert():
    data    = request.json or {}
    missing = [k for k in ('name', 'metric', 'threshold', 'operator') if not data.get(k)]
    if missing:
        return jsonify({'error': f'Missing: {missing}'}), 400
    alerts  = load_alerts()
    data.update({'id': str(int(time.time()*1000)), 'created_at': datetime.now().isoformat(),
                 'enabled': data.get('enabled', True), 'last_fired': None})
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
    if not url:           return jsonify({'success': False, 'error': 'No webhook URL'}), 400
    if not HAS_REQUESTS:  return jsonify({'success': False, 'error': 'requests not installed'}), 500
    try:
        r = req_lib.post(url, json={'text': '✅ MuleSoft Dashboard: webhook working!'}, timeout=5)
        return jsonify({'success': True, 'status_code': r.status_code})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ─── Alert checker (reads from _bg_store — zero S3) ───────────────────────────
METRIC_KEYS = {'errors': 'errors', 'error_rate': 'error_rate',
               'payments_failed': 'payments_failed', 'total_requests': 'total',
               'warnings': 'warnings'}

def _fire_alert(alert, value, today):
    url = alert.get('webhook_url', '').strip()
    if not url or not HAS_REQUESTS: return
    emojis = {'errors': '🔴', 'error_rate': '📈', 'payments_failed': '💳',
               'total_requests': '📊', 'warnings': '⚠️'}
    try:
        req_lib.post(url, json={'text': (
            f"{emojis.get(alert['metric'],'🚨')} *MuleSoft Alert: {alert['name']}*\n"
            f"Metric `{alert['metric']}` = `{value}` "
            f"(threshold: {alert['operator']} {alert['threshold']})\n"
            f"Date: {today} | API: {alert.get('api','ALL')}"
        )}, timeout=5)
    except Exception as e:
        app.logger.warning(f"Alert webhook failed: {e}")

def alert_checker():
    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            alerts = load_alerts()
            if not alerts: continue
            today = datetime.now().strftime('%Y-%m-%d')
            # Read today's entries from RAM — no S3
            with _bg_lock:
                today_entries = [e for e in _bg_store['entries'] if e['date'] == today]
            if not today_entries: continue
            global_stats = aggregate(today_entries)

            for alert in alerts:
                if not alert.get('enabled', True): continue
                api = alert.get('api', '')
                stats = aggregate([e for e in today_entries if not api or e['api'] == api]) if api else global_stats
                mk    = METRIC_KEYS.get(alert['metric'], alert['metric'])
                value = stats.get(mk, 0)
                thr   = float(alert.get('threshold', 0))
                op    = alert.get('operator', '>')
                hit   = ((op=='>'  and value > thr) or (op=='>=' and value >= thr) or
                         (op=='<'  and value < thr) or (op=='<=' and value <= thr))
                if hit:
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
