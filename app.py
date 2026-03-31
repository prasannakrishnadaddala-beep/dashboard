import re, json, os, threading, time, sqlite3, hashlib, gc
from flask import Flask, jsonify, request, Response
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import boto3
    from botocore.config import Config as BotoConfig
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
S3_BUCKET          = os.environ.get('S3_BUCKET', 'pe-mule-prod-log')
_raw_prefixes      = os.environ.get('S3_PREFIXES') or os.environ.get('S3_PREFIX', '10.1.7.84/')
S3_PREFIXES_LIST   = [p.strip() for p in _raw_prefixes.split(',') if p.strip()]
S3_PREFIX          = S3_PREFIXES_LIST[0]
AWS_REGION         = os.environ.get('AWS_REGION', 'ap-south-1')
SYNC_INTERVAL      = int(os.environ.get('SYNC_INTERVAL', '1800'))
STORE_DAYS         = int(os.environ.get('STORE_DAYS', '7'))           # 7 days (was 14)
ALERT_FILE         = os.environ.get('ALERT_FILE', 'alerts.json')
CHECK_INTERVAL     = int(os.environ.get('ALERT_CHECK_INTERVAL', '300'))
MAX_LINES_PER_FILE  = int(os.environ.get('MAX_LINES_PER_FILE',  '10000'))  # 10k lines per file
MAX_BYTES_PER_FILE  = int(os.environ.get('MAX_BYTES_PER_FILE',  str(1 * 1024 * 1024)))  # 1MB per file
PARALLEL_WORKERS    = int(os.environ.get('PARALLEL_WORKERS',    '2'))    # 2 threads — OOM fix
MAX_TODAY_ENTRIES   = int(os.environ.get('MAX_TODAY_ENTRIES',   '20000'))# raw today entries kept in RAM
# HIST: never stored as raw entries — aggregated to stats dicts only
HIST_DAYS_RAW       = int(os.environ.get('HIST_DAYS_RAW',       '1'))    # days of raw entries (today only)
DISK_CACHE_PATH    = os.environ.get('DISK_CACHE_PATH', '/tmp/mulesoft_cache.db')

# ─── SQLite Disk Cache ─────────────────────────────────────────────────────────
# Stores pre-aggregated STATS (not raw entries) for historical files.
# A stats dict is ~2KB JSON vs. ~500KB pickled entries — 250x smaller.
# Key = hash(s3_key + last_modified) → JSON stats string
class DiskCache:
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        self._init_db()

    def _conn(self):
        if not getattr(self._local, 'conn', None):
            c = sqlite3.connect(self.path, check_same_thread=False)
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('PRAGMA synchronous=NORMAL')
            c.execute('PRAGMA cache_size=-2000')   # 2MB page cache
            self._local.conn = c
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self.path)
        # New schema: stats_json instead of entries blob
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_stats (
                cache_key TEXT PRIMARY KEY,
                stats_json TEXT NOT NULL,
                created    TEXT NOT NULL
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_created ON file_stats(created)')
        # Drop old raw-entries table if it exists (migration)
        conn.execute('DROP TABLE IF EXISTS file_cache')
        conn.commit()
        conn.close()

    def get_stats(self, s3_key: str, last_modified: str):
        """Return pre-aggregated stats dict, or None on miss."""
        ck = self._key(s3_key, last_modified)
        try:
            row = self._conn().execute(
                'SELECT stats_json FROM file_stats WHERE cache_key=?', (ck,)
            ).fetchone()
            return json.loads(row[0]) if row else None
        except Exception:
            return None

    def set_stats(self, s3_key: str, last_modified: str, stats: dict):
        """Store pre-aggregated stats dict (never raw entries)."""
        ck = self._key(s3_key, last_modified)
        try:
            self._conn().execute(
                'INSERT OR REPLACE INTO file_stats(cache_key,stats_json,created) VALUES(?,?,?)',
                (ck, json.dumps(stats, default=str), datetime.now().isoformat())
            )
            self._conn().commit()
        except Exception as e:
            app.logger.warning(f"DiskCache.set_stats failed: {e}")

    def evict_old(self, keep_days=30):
        cutoff = (datetime.now() - timedelta(days=keep_days)).isoformat()
        try:
            self._conn().execute('DELETE FROM file_stats WHERE created<?', (cutoff,))
            self._conn().commit()
        except Exception:
            pass

    def stats(self):
        try:
            row = self._conn().execute(
                'SELECT COUNT(*), SUM(LENGTH(stats_json)) FROM file_stats'
            ).fetchone()
            return {'rows': row[0] or 0, 'size_mb': round((row[1] or 0) / 1024 / 1024, 1)}
        except Exception:
            return {'rows': 0, 'size_mb': 0}

    def wipe(self):
        try:
            self._conn().execute('DELETE FROM file_stats')
            self._conn().commit()
        except Exception:
            pass

    @staticmethod
    def _key(s3_key, last_modified):
        return hashlib.md5(f"{s3_key}|{last_modified}".encode()).hexdigest()

_disk_cache = DiskCache(DISK_CACHE_PATH)

# ─── Background store ─────────────────────────────────────────────────────────
# today_entries: raw log dicts for today only (Log Explorer + alerts)
# hist_stats:    pre-aggregated stats per (api, date) — no raw entries
_bg_lock  = threading.Lock()
_bg_store = {
    'today_entries': [],   # raw entries for today — capped at MAX_TODAY_ENTRIES
    'hist_stats':    {},   # key: "api|date" → aggregated stats dict (no raw entries)
    'file_list':     [],
    'last_sync':     None,
    'next_sync':     None,
    'syncing':       False,
    'sync_error':    None,
    'stats_cache':   {},
}

# ─── Sync progress ────────────────────────────────────────────────────────────
_sync_progress = {
    'phase': 'idle', 'phase_label': '',
    'prefixes': [], 'current_file': '',
    'total_files': 0, 'files_done': 0,
    'disk_hits': 0, 'mem_hits': 0, 's3_fetches': 0,
    'entries_parsed': 0, 'elapsed_secs': 0,
    'started_at': None, 'finished_at': None,
    'log': [], 'cache_stats': {},
}
_sp_lock = threading.Lock()

def _sp(update: dict, msg: str = None):
    with _sp_lock:
        _sync_progress.update(update)
        if _sync_progress['started_at']:
            _sync_progress['elapsed_secs'] = round(
                (datetime.now() - datetime.fromisoformat(_sync_progress['started_at'])).total_seconds(), 1)
        if msg:
            _sync_progress['log'].append({'ts': datetime.now().strftime('%H:%M:%S'), 'msg': msg})
            if len(_sync_progress['log']) > 60:
                _sync_progress['log'] = _sync_progress['log'][-60:]

# ─── S3 — thread-local clients (boto3 is NOT thread-safe) ────────────────────
_s3_local = threading.local()

def _get_s3_client():
    if not HAS_BOTO:
        raise RuntimeError("boto3 not installed")
    if not getattr(_s3_local, 'client', None):
        key_id = os.environ.get('AWS_ACCESS_KEY_ID')
        secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
        if not key_id or not secret:
            raise RuntimeError("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not set")
        _s3_local.client = boto3.client(
            's3', region_name=AWS_REGION,
            aws_access_key_id=key_id, aws_secret_access_key=secret,
            config=BotoConfig(
                max_pool_connections=PARALLEL_WORKERS + 4,
                retries={'max_attempts': 3, 'mode': 'adaptive'},
                connect_timeout=10, read_timeout=60,
            )
        )
    return _s3_local.client

# ─── Filename parser ──────────────────────────────────────────────────────────
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

# ─── S3 listing ───────────────────────────────────────────────────────────────
def _list_s3_files_raw():
    s3 = _get_s3_client()
    paginator = s3.get_paginator('list_objects_v2')
    files, skipped, seen_keys = [], 0, set()
    cutoff = (datetime.now() - timedelta(days=STORE_DAYS)).strftime('%Y-%m-%d')
    today  = datetime.now().strftime('%Y-%m-%d')

    app.logger.info(f"S3 listing {len(S3_PREFIXES_LIST)} prefix(es): {S3_PREFIXES_LIST}")
    for prefix in S3_PREFIXES_LIST:
        pcount = 0
        for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
            for obj in page.get('Contents', []):
                if obj['Size'] == 0: continue
                key = obj['Key']
                if key in seen_keys: continue
                seen_keys.add(key)
                filename = key.split('/')[-1]
                result = _parse_filename(filename)
                if result is None: skipped += 1; continue
                api, date = result
                if date is None:
                    date = obj['LastModified'].strftime('%Y-%m-%d')
                if date < cutoff: continue
                files.append({
                    'key': key, 'api': api, 'date': date,
                    'filename': filename, 'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat(),
                    'etag': obj.get('ETag', '').strip('"'),
                    'is_today': (date == today),
                    'prefix': prefix,
                })
                pcount += 1
        app.logger.info(f"  prefix '{prefix}': {pcount} files matched")

    # Today's files first → partial results appear faster
    today_f = [f for f in files if f['is_today']]
    hist_f  = sorted([f for f in files if not f['is_today']],
                     key=lambda x: x['date'], reverse=True)
    files   = today_f + hist_f
    app.logger.info(f"S3 list: {len(files)} matched ({len(today_f)} today), {skipped} skipped")
    return files

# ─── S3 line streaming ────────────────────────────────────────────────────────
def _stream_lines(key):
    try:
        s3  = _get_s3_client()
        obj = s3.get_object(Bucket=S3_BUCKET, Key=key,
                            Range=f'bytes=0-{MAX_BYTES_PER_FILE - 1}')
        raw = obj['Body'].read()
        for line in raw.split(b'\n')[:MAX_LINES_PER_FILE]:
            yield line.decode('utf-8', errors='replace')
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
        if not m: return
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
            if current: _flush(current)
            current = [line]
        elif current:
            current.append(line)
    if current: _flush(current)
    return entries

# ─── Per-file workers ────────────────────────────────────────────────────────
def _fetch_today(f: dict):
    """Fetch today's file → return raw entries (kept in RAM, capped)."""
    entries = parse_streamed_lines(_stream_lines(f['key']), api_hint=f.get('api', ''))
    return f, entries, 's3'

def _fetch_hist(f: dict):
    """Fetch historical file → return aggregated stats dict only (never raw entries).
    Cache hit: load stats from SQLite (tiny JSON).
    Cache miss: download from S3, parse, aggregate immediately, store stats, discard raw."""
    key      = f['key']
    last_mod = f['last_modified']

    # Try SQLite stats cache first
    cached_stats = _disk_cache.get_stats(key, last_mod)
    if cached_stats is not None:
        return f, cached_stats, 'disk'

    # Cold miss: download → parse → aggregate → store stats → discard raw
    entries = parse_streamed_lines(_stream_lines(key), api_hint=f.get('api', ''))
    stats   = aggregate_to_dict(entries)   # pure dicts/counters, no entry objects
    del entries                            # immediately free raw entries
    gc.collect()
    _disk_cache.set_stats(key, last_mod, stats)
    return f, stats, 's3'

# ─── Main sync ────────────────────────────────────────────────────────────────
def _do_sync():
    with _bg_lock:
        if _bg_store['syncing']:
            return
        _bg_store['syncing']    = True
        _bg_store['sync_error'] = None

    now_iso = datetime.now().isoformat()
    _sp({'phase': 'listing', 'phase_label': 'Listing S3 files…',
         'started_at': now_iso, 'finished_at': None, 'total_files': 0,
         'files_done': 0, 'disk_hits': 0, 'mem_hits': 0, 's3_fetches': 0,
         'entries_parsed': 0, 'current_file': '', 'prefixes': [], 'log': [],
         'cache_stats': _disk_cache.stats()},
        msg='▶ Sync started')
    app.logger.info("▶ Background sync started")

    try:
        files = _list_s3_files_raw()

        prefix_map = {}
        for f in files:
            p = f.get('prefix', S3_PREFIXES_LIST[0])
            if p not in prefix_map:
                prefix_map[p] = {'prefix': p, 'files_found': 0,
                                 'files_s3': 0, 'files_cached': 0, 'bytes_read': 0}
            prefix_map[p]['files_found'] += 1

        today_files = [f for f in files if f['is_today']]
        hist_files  = [f for f in files if not f['is_today']]

        _sp({'phase': 'parsing',
             'phase_label': f'Fetching {len(today_files)} today + {len(hist_files)} hist files…',
             'total_files': len(files),
             'prefixes': list(prefix_map.values())},
            msg=f'Found {len(files)} files ({len(today_files)} today, {len(hist_files)} historical)')

        files_done = 0
        disk_hits  = 0
        s3_fetches = 0

        # ── Phase A: Today's files → raw entries (few files, small RAM) ────────
        _sp({}, msg=f'Phase A: {len(today_files)} today files → raw entries')
        with _bg_lock:
            _bg_store['today_entries'] = []
            _bg_store['stats_cache']   = {}

        new_today = []
        with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
            futures = {pool.submit(_fetch_today, f): f for f in today_files}
            for future in as_completed(futures):
                try:
                    f, entries, source = future.result()
                    files_done += 1; s3_fetches += 1
                    new_today.extend(entries)
                    _sp({'current_file': f['filename'], 'files_done': files_done,
                         's3_fetches': s3_fetches,
                         'phase_label': f'TODAY [{files_done}/{len(files)}] {f["filename"]}'})
                except Exception as e:
                    app.logger.error(f"Today worker error: {e}")

        # Cap today entries and publish
        new_today.sort(key=lambda e: e['timestamp'])
        if len(new_today) > MAX_TODAY_ENTRIES:
            new_today = new_today[-MAX_TODAY_ENTRIES:]
        with _bg_lock:
            _bg_store['today_entries'] = new_today
            _bg_store['stats_cache']   = {}
        n_today = len(new_today)
        _sp({'entries_parsed': n_today},
            msg=f'✓ Phase A: {n_today} today entries live — starting historical sync…')
        del new_today
        gc.collect()

        # ── Phase B: Historical files → stats only (never raw entries in RAM) ──
        _sp({}, msg=f'Phase B: {len(hist_files)} historical files → stats aggregation only')
        new_hist = {}  # key: "api|date" → stats dict

        # Process 1 file at a time to keep memory near zero
        for i, f in enumerate(hist_files):
            try:
                f_out, stats, source = _fetch_hist(f)
                files_done += 1
                key_ad = f"{f['api']}|{f['date']}"
                if key_ad in new_hist:
                    new_hist[key_ad] = merge_stats(new_hist[key_ad], stats)
                else:
                    new_hist[key_ad] = stats
                if source == 'disk':
                    disk_hits += 1
                    pfx = f.get('prefix', S3_PREFIXES_LIST[0])
                    with _sp_lock:
                        for pr in _sync_progress['prefixes']:
                            if pr['prefix'] == pfx:
                                pr['files_cached'] += 1
                else:
                    s3_fetches += 1
                    pfx = f.get('prefix', S3_PREFIXES_LIST[0])
                    with _sp_lock:
                        for pr in _sync_progress['prefixes']:
                            if pr['prefix'] == pfx:
                                pr['files_s3']   += 1
                                pr['bytes_read'] += f['size']
                if i % 10 == 0:
                    _sp({'current_file': f['filename'], 'files_done': files_done,
                         'disk_hits': disk_hits, 's3_fetches': s3_fetches,
                         'phase_label': f'HIST [{files_done}/{len(files)}] {f["filename"]} ({source.upper()})'})
            except Exception as e:
                app.logger.error(f"Hist worker error [{f['key']}]: {e}")

        with _bg_lock:
            _bg_store['hist_stats']  = new_hist
            _bg_store['file_list']   = files
            _bg_store['stats_cache'] = {}

        del new_hist
        gc.collect()

        now = datetime.now()
        with _bg_lock:
            _bg_store['last_sync'] = now.isoformat()
            _bg_store['next_sync'] = (now + timedelta(seconds=SYNC_INTERVAL)).isoformat()
            _bg_store['syncing']   = False
            final_today = len(_bg_store['today_entries'])
            final_hist  = len(_bg_store['hist_stats'])

        _disk_cache.evict_old(keep_days=STORE_DAYS + 2)
        cs = _disk_cache.stats()
        elapsed = _sync_progress['elapsed_secs']
        _sp({'phase': 'done', 'phase_label': 'Sync complete',
             'files_done': len(files), 'entries_parsed': final_today,
             'current_file': '', 'finished_at': datetime.now().isoformat(),
             'cache_stats': cs},
            msg=(f'✓ Done in {elapsed}s — {final_today} today entries | '
                 f'{final_hist} hist buckets | {s3_fetches} S3 | {disk_hits} cache | '
                 f'SQLite: {cs["rows"]} rows {cs["size_mb"]}MB'))
        app.logger.info(f"✓ Sync done in {elapsed}s | today:{final_today} hist:{final_hist} "
                        f"S3:{s3_fetches} cache:{disk_hits}")

    except Exception as e:
        app.logger.error(f"✗ Sync error: {e}")
        with _bg_lock:
            _bg_store['syncing']    = False
            _bg_store['sync_error'] = str(e)
        _sp({'phase': 'error', 'phase_label': f'Error: {e}',
             'finished_at': datetime.now().isoformat()},
            msg=f'✗ Error: {e}')

def _sync_loop():
    time.sleep(5)
    _do_sync()
    while True:
        time.sleep(SYNC_INTERVAL)
        _do_sync()

threading.Thread(target=_sync_loop, daemon=True).start()

# ─── Aggregation ─────────────────────────────────────────────────────────────
def aggregate_to_dict(entries):
    """Aggregate raw entries into a compact stats dict. No entry objects retained."""
    total = len(entries)
    if total == 0: return empty_stats()
    errors   = sum(1 for e in entries if e['is_error'])
    warnings = sum(1 for e in entries if e['level'] == 'WARN')
    hourly   = defaultdict(int)
    for e in entries:
        hourly[f"{e['date']} {e['hour']}:00"] += 1
    daily    = Counter(e['date'] for e in entries)
    eps      = Counter(f"{e['method']} {e['endpoint']}" for e in entries)
    flows    = Counter(e['flow'] for e in entries)
    created  = sum(1 for e in entries if e.get('rz_status') == 'created')
    captured = sum(1 for e in entries if e.get('rz_status') == 'captured')
    failed   = sum(1 for e in entries if e.get('error_code'))
    revenue  = sum(e.get('amount_inr') or 0 for e in entries if e.get('rz_status') == 'captured')
    methods  = Counter(e.get('upi_method') for e in entries if e.get('upi_method'))
    statuses = Counter(e.get('rz_status')  for e in entries if e.get('rz_status'))
    err_ep   = Counter(f"{e['method']} {e['endpoint']}" for e in entries if e['is_error'])
    err_fl   = Counter(e['flow'] for e in entries if e['is_error'])
    # Keep only the 50 most recent errors (compact list of small dicts)
    recent_errors = [
        {'level': e['level'], 'timestamp': e['timestamp'], 'api': e['api'],
         'method': e['method'], 'endpoint': e['endpoint'], 'flow': e.get('flow',''),
         'error_code': e.get('error_code'), 'message': (e.get('message') or '')[:300],
         'rz_status': e.get('rz_status'), 'amount_inr': e.get('amount_inr'),
         'payment_id': e.get('payment_id'), 'order_id': e.get('order_id'),
         'upi_method': e.get('upi_method'), 'loan_number': e.get('loan_number'),
         'customer': e.get('customer'), 'event_id': e.get('event_id',''),
         'error_desc': e.get('error_desc'), 'date': e['date']}
        for e in entries if e['is_error']][-50:]
    sorted_hours = sorted(hourly.keys())
    return {
        'total': total, 'errors': errors, 'warnings': warnings,
        'error_rate': round(errors / total * 100, 2) if total else 0,
        'payments_created': created, 'payments_captured': captured,
        'payments_failed': failed, 'revenue_inr': round(revenue, 2),
        'hourly': dict(hourly),
        'hourly_labels': sorted_hours, 'hourly_values': [hourly[h] for h in sorted_hours],
        'daily': dict(daily),
        'endpoints': dict(eps.most_common()),
        'flows': dict(flows.most_common()),
        'payment_methods': dict(methods.most_common()),
        'payment_statuses': dict(statuses.most_common()),
        'err_by_endpoint': dict(err_ep.most_common(10)),
        'err_by_flow': dict(err_fl.most_common()),
        'recent_errors': recent_errors,
        'apis': sorted(set(e['api'] for e in entries)),
    }

def merge_stats(a: dict, b: dict) -> dict:
    """Merge two aggregated stats dicts into one (for multi-file same api/date)."""
    if not a: return b
    if not b: return a
    hourly = defaultdict(int, a.get('hourly', {}))
    for k, v in b.get('hourly', {}).items():
        hourly[k] += v
    daily = defaultdict(int, a.get('daily', {}))
    for k, v in b.get('daily', {}).items():
        daily[k] += v
    def _merge_counter(da, db):
        r = dict(da or {})
        for k, v in (db or {}).items():
            r[k] = r.get(k, 0) + v
        return dict(sorted(r.items(), key=lambda x: -x[1]))
    sorted_hours = sorted(hourly.keys())
    recent = sorted(
        (a.get('recent_errors') or []) + (b.get('recent_errors') or []),
        key=lambda e: e['timestamp'])[-50:]
    apis = sorted(set((a.get('apis') or []) + (b.get('apis') or [])))
    total = a.get('total', 0) + b.get('total', 0)
    errors = a.get('errors', 0) + b.get('errors', 0)
    return {
        'total': total,
        'errors': errors,
        'warnings': a.get('warnings', 0) + b.get('warnings', 0),
        'error_rate': round(errors / total * 100, 2) if total else 0,
        'payments_created': a.get('payments_created', 0) + b.get('payments_created', 0),
        'payments_captured': a.get('payments_captured', 0) + b.get('payments_captured', 0),
        'payments_failed': a.get('payments_failed', 0) + b.get('payments_failed', 0),
        'revenue_inr': round((a.get('revenue_inr', 0) or 0) + (b.get('revenue_inr', 0) or 0), 2),
        'hourly': dict(hourly),
        'hourly_labels': sorted_hours, 'hourly_values': [hourly[h] for h in sorted_hours],
        'daily': dict(daily),
        'endpoints': _merge_counter(a.get('endpoints'), b.get('endpoints')),
        'flows': _merge_counter(a.get('flows'), b.get('flows')),
        'payment_methods': _merge_counter(a.get('payment_methods'), b.get('payment_methods')),
        'payment_statuses': _merge_counter(a.get('payment_statuses'), b.get('payment_statuses')),
        'err_by_endpoint': _merge_counter(a.get('err_by_endpoint'), b.get('err_by_endpoint')),
        'err_by_flow': _merge_counter(a.get('err_by_flow'), b.get('err_by_flow')),
        'recent_errors': recent,
        'apis': apis,
    }

def aggregate(entries):
    """Legacy: aggregate raw entries list. Used for today's entries only."""
    return aggregate_to_dict(entries)


    total = len(entries)
    if total == 0: return empty_stats()
    errors      = sum(1 for e in entries if e['is_error'])
    warnings    = sum(1 for e in entries if e['level'] == 'WARN')
    hourly      = defaultdict(int)
    for e in entries:
        hourly[f"{e['date']} {e['hour']}:00"] += 1
    daily       = Counter(e['date'] for e in entries)
    endpoints   = Counter(f"{e['method']} {e['endpoint']}" for e in entries)
    flows       = Counter(e['flow']   for e in entries)
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
        'payments_failed': failed, 'revenue_inr': round(revenue, 2),
        'hourly_labels': sorted_hours,
        'hourly_values': [hourly[h] for h in sorted_hours],
        'daily': dict(sorted(daily.items())),
        'endpoints': dict(endpoints.most_common()),
        'flows': dict(flows.most_common()),
        'payment_methods': dict(methods.most_common()),
        'payment_statuses': dict(statuses.most_common()),
        'err_by_endpoint': dict(err_by_ep.most_common(10)),
        'err_by_flow': dict(err_by_flow.most_common()),
        'recent_errors': [e for e in entries if e['is_error']][-50:],
        'apis': sorted(set(e['api'] for e in entries)),
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
            'entry_count': len(_bg_store['today_entries']),
            'hist_buckets': len(_bg_store['hist_stats']),
        })

@app.route('/api/sync/status')
def sync_status():
    with _bg_lock:
        return jsonify({
            'syncing': _bg_store['syncing'],
            'last_sync': _bg_store['last_sync'],
            'next_sync': _bg_store['next_sync'],
            'sync_error': _bg_store['sync_error'],
            'entry_count': len(_bg_store['today_entries']),
            'hist_buckets': len(_bg_store['hist_stats']),
            'file_count': len(_bg_store['file_list']),
            'sync_interval_secs': SYNC_INTERVAL,
        })

@app.route('/api/sync/progress')
def sync_progress_route():
    with _sp_lock:
        progress = dict(_sync_progress)
        progress['prefixes'] = list(progress.get('prefixes', []))
    with _bg_lock:
        progress['syncing']      = _bg_store['syncing']
        progress['sync_error']   = _bg_store['sync_error']
        progress['last_sync']    = _bg_store['last_sync']
        progress['next_sync']    = _bg_store['next_sync']
        progress['entry_count']  = len(_bg_store['today_entries'])
        progress['hist_buckets'] = len(_bg_store['hist_stats'])
        progress['file_count']   = len(_bg_store['file_list'])
    return jsonify(progress)

@app.route('/api/sync/force', methods=['POST'])
def force_sync():
    with _bg_lock:
        if _bg_store['syncing']:
            return jsonify({'success': False, 'message': 'Sync already in progress'})
    threading.Thread(target=_do_sync, daemon=True).start()
    return jsonify({'success': True, 'message': 'Sync triggered'})

@app.route('/api/debug')
def debug():
    with _bg_lock:
        store = {k: v for k, v in _bg_store.items()
                 if k not in ('today_entries', 'hist_stats', 'stats_cache')}
        store['today_entry_count'] = len(_bg_store['today_entries'])
        store['hist_bucket_count'] = len(_bg_store['hist_stats'])
    files = _bg_store.get('file_list', [])
    info = {
        'boto3_installed': HAS_BOTO,
        'S3_BUCKET': S3_BUCKET,
        'S3_PREFIXES': S3_PREFIXES_LIST,
        'S3_PREFIXES_env': os.environ.get('S3_PREFIXES'),
        'S3_PREFIX_legacy': os.environ.get('S3_PREFIX'),
        'AWS_REGION': AWS_REGION,
        'has_access_key': bool(os.environ.get('AWS_ACCESS_KEY_ID')),
        'has_secret_key': bool(os.environ.get('AWS_SECRET_ACCESS_KEY')),
        'sync_interval_secs': SYNC_INTERVAL,
        'store_days': STORE_DAYS,
        'parallel_workers': PARALLEL_WORKERS,
        'disk_cache_path': DISK_CACHE_PATH,
        'disk_cache_stats': _disk_cache.stats(),
        **store,
    }
    if files:
        dates = sorted(set(f['date'] for f in files))
        info['earliest_date']  = dates[0]
        info['latest_date']    = dates[-1]
        info['available_apis'] = sorted(set(f['api'] for f in files))
        info['sample_files']   = [
            {'key': f['key'], 'api': f['api'], 'date': f['date'],
             'size_kb': f['size'] // 1024, 'prefix': f.get('prefix', '')}
            for f in files[:10]
        ]
    return jsonify(info)

@app.route('/api/apis')
def list_apis():
    with _bg_lock:
        files = _bg_store['file_list']
    return jsonify({'apis': sorted(set(f['api'] for f in files)), 'total_files': len(files)})

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
    date_from = request.args.get('date_from', (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'))
    date_to   = request.args.get('date_to',   datetime.now().strftime('%Y-%m-%d'))
    ck = f'stats:{api}:{date_from}:{date_to}'

    with _bg_lock:
        cached = _bg_store['stats_cache'].get(ck)
        if cached: return jsonify(cached)
        today_entries = list(_bg_store['today_entries'])
        hist_stats    = dict(_bg_store['hist_stats'])
        files         = _bg_store['file_list']
        last_sync     = _bg_store['last_sync']

    today = datetime.now().strftime('%Y-%m-%d')

    # Today's raw entries → aggregate (only those in date range)
    today_filtered = [e for e in today_entries
                      if date_from <= e['date'] <= date_to
                      and (not api or e['api'] == api)]
    result = aggregate_to_dict(today_filtered)
    del today_filtered

    # Historical stats → merge each matching bucket
    for key_ad, s in hist_stats.items():
        parts = key_ad.split('|', 1)
        if len(parts) != 2: continue
        bucket_api, bucket_date = parts
        if bucket_date == today: continue          # skip today — already in today_entries
        if not (date_from <= bucket_date <= date_to): continue
        if api and bucket_api != api: continue
        result = merge_stats(result, s)

    result.update({
        'files_loaded': len([f for f in files
                             if (not api or f['api'] == api)
                             and date_from <= f['date'] <= date_to]),
        'date_from': date_from, 'date_to': date_to, 'last_sync': last_sync,
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
        entries = list(_bg_store['today_entries'])

    # Log Explorer only serves today's raw entries.
    # Historical log search is not supported to avoid OOM.
    today = datetime.now().strftime('%Y-%m-%d')
    if date and date != today:
        return jsonify({
            'logs': [], 'total': 0, 'page': 1, 'per_page': per_page, 'pages': 0,
            'note': f'Raw log entries are only kept for today ({today}). '
                    'Use the Overview tab to explore historical data via charts.'
        })

    if api:      entries = [e for e in entries if e['api'] == api]
    if level:    entries = [e for e in entries if e['level'] == level]
    if endpoint: entries = [e for e in entries if endpoint.lower() in e['endpoint'].lower()]
    if search:
        sl = search.lower()
        entries = [e for e in entries if
                   sl in e['message'].lower()
                   or sl in (e.get('loan_number') or '').lower()
                   or sl in (e.get('customer') or '').lower()
                   or sl in (e.get('payment_id') or '').lower()]
    total = len(entries)
    return jsonify({
        'logs': entries[(page - 1) * per_page: page * per_page],
        'total': total, 'page': page, 'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_stats_cache():
    with _bg_lock:
        _bg_store['stats_cache'] = {}
    return jsonify({'success': True, 'message': 'Stats cache cleared'})

@app.route('/api/cache/disk/clear', methods=['POST'])
def clear_disk_cache():
    """Wipe SQLite stats cache — next sync re-downloads and re-aggregates all historical files."""
    _disk_cache.wipe()
    with _bg_lock:
        _bg_store['hist_stats']  = {}
        _bg_store['stats_cache'] = {}
    return jsonify({'success': True, 'message': 'Disk cache wiped — next sync fetches everything fresh'})

# ─── Alerts ───────────────────────────────────────────────────────────────────
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
    alerts = load_alerts()
    data.update({'id': str(int(time.time() * 1000)), 'created_at': datetime.now().isoformat(),
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
            if not alerts: continue
            today = datetime.now().strftime('%Y-%m-%d')
            with _bg_lock:
                today_entries = list(_bg_store['today_entries'])
            if not today_entries: continue
            global_stats = aggregate(today_entries)
            for alert in alerts:
                if not alert.get('enabled', True): continue
                api   = alert.get('api', '')
                stats = aggregate([e for e in today_entries if not api or e['api'] == api]) if api else global_stats
                mk    = METRIC_KEYS.get(alert['metric'], alert['metric'])
                value = stats.get(mk, 0)
                thr   = float(alert.get('threshold', 0))
                op    = alert.get('operator', '>')
                hit   = ((op == '>' and value > thr) or (op == '>=' and value >= thr) or
                         (op == '<' and value < thr) or (op == '<=' and value <= thr))
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
