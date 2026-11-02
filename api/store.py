"""SQLite state shared by the unprivileged HTTP API and local VPN controller."""
import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, quote


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, tags TEXT NOT NULL,
                    credential TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL,
                    upload INTEGER NOT NULL DEFAULT 0, download INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT OR IGNORE INTO meta VALUES ('revision', '0');
                INSERT OR IGNORE INTO meta VALUES ('applied', '-1');
                CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT, expires INTEGER);
                CREATE TABLE IF NOT EXISTS oauth (state TEXT PRIMARY KEY, verifier TEXT, expires INTEGER);
                CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER, generation TEXT);
                CREATE TABLE IF NOT EXISTS revoked_credentials (credential TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS daily (day TEXT, user_id TEXT, upload INTEGER DEFAULT 0,
                    download INTEGER DEFAULT 0, PRIMARY KEY(day,user_id));
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, time INTEGER, action TEXT, user_id TEXT);
            ''')
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def meta(self):
        with self.connect() as db:
            return dict(db.execute('SELECT key,value FROM meta').fetchall())

    @staticmethod
    def set_meta(db, key, value):
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, str(value)))

    def users(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM users ORDER BY created DESC, name')]

    def mutate(self, action, user_id=None, payload=None):
        payload = payload or {}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if action in ('create', 'edit'):
                name = payload.get('name', '')
                tags = payload.get('tags', [])
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                    raise ValueError('Enter a name between 1 and 80 characters.')
                if not isinstance(tags, list) or len(tags) > 10 or any(not isinstance(t, str) or not 1 <= len(t.strip()) <= 30 for t in tags):
                    raise ValueError('Use up to 10 tags, each 1–30 characters.')
                tags = json.dumps(list(dict.fromkeys(t.strip() for t in tags)))
            if action == 'create':
                user_id = str(uuid.uuid4())
                db.execute('INSERT INTO users (id,name,tags,credential,token,created) VALUES (?,?,?,?,?,?)',
                           (user_id, name.strip(), tags, str(uuid.uuid4()), secrets.token_urlsafe(32), int(time.time())))
            else:
                row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
                if not row:
                    raise LookupError('User not found.')
                if action == 'edit':
                    db.execute('UPDATE users SET name=?, tags=? WHERE id=?', (name.strip(), tags, user_id))
                elif action == 'toggle':
                    db.execute('UPDATE users SET enabled=1-enabled WHERE id=?', (user_id,))
                elif action == 'rotate':
                    # An imported UUID may still be untagged until the first sync.
                    db.execute('INSERT OR IGNORE INTO revoked_credentials VALUES (?)', (row['credential'],))
                    db.execute('UPDATE users SET token=?,credential=? WHERE id=?',
                               (secrets.token_urlsafe(32), str(uuid.uuid4()), user_id))
                elif action == 'delete':
                    # Remove the bearer link and usage in the same transaction.
                    # Keep its UUID revoked even if an imported client has not synced yet.
                    db.execute('INSERT OR IGNORE INTO revoked_credentials VALUES (?)', (row['credential'],))
                    db.execute('DELETE FROM daily WHERE user_id=?', (user_id,))
                    counters = ['user>>>'+user_id+'@vpn-admin.local>>>traffic>>>'+direction
                                for direction in ('uplink', 'downlink')]
                    db.executemany('DELETE FROM counters WHERE name=?', [(name,) for name in counters])
                    db.execute('DELETE FROM users WHERE id=?', (user_id,))
                else:
                    raise ValueError('Unknown action.')
            # Editing labels does not interrupt VPN connections.
            if action != 'edit':
                db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'")
            db.execute('INSERT INTO audit(time,action,user_id) VALUES (?,?,?)', (int(time.time()), action, user_id))
        return user_id

    def snapshot(self):
        with self.connect() as db:
            db.execute('BEGIN')
            revision = db.execute("SELECT value FROM meta WHERE key='revision'").fetchone()[0]
            users = [dict(r) for r in db.execute('SELECT * FROM users')]
            revoked = {r['credential'] for r in db.execute('SELECT credential FROM revoked_credentials')}
            return revision, users, revoked

    def record_stats(self, stats, generation):
        now = int(time.time())
        day = time.strftime('%Y-%m-%d', time.gmtime(now))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for stat in stats:
                parts = stat.get('name', '').split('>>>')
                if len(parts) != 4 or parts[0] != 'user' or parts[2] != 'traffic' or parts[3] not in ('uplink', 'downlink'):
                    continue
                if not parts[1].endswith('@vpn-admin.local'):
                    continue
                user_id = parts[1].split('@')[0]
                if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
                    continue
                value = int(stat['value'])
                if value < 0:
                    continue
                old = db.execute('SELECT value,generation FROM counters WHERE name=?', (stat['name'],)).fetchone()
                delta = value if not old or old['generation'] != generation or value < old['value'] else value-old['value']
                column = 'upload' if parts[3] == 'uplink' else 'download'
                db.execute('UPDATE users SET '+column+'='+column+'+? WHERE id=?', (delta, user_id))
                db.execute('INSERT OR IGNORE INTO daily(day,user_id) VALUES (?,?)', (day,user_id))
                db.execute('UPDATE daily SET '+column+'='+column+'+? WHERE day=? AND user_id=?', (delta,day,user_id))
                db.execute('INSERT OR REPLACE INTO counters VALUES (?,?,?)', (stat['name'],value,generation))
            self.set_meta(db, 'stats_at', now)


def connection_uri(user, host, port, ws_path):
    # Preserve the ALPN setting from the existing working Shadowrocket profiles.
    query = urlencode({'encryption':'none', 'security':'tls', 'type':'ws', 'host':host, 'sni':host, 'path':ws_path, 'alpn':'http/1.1'})
    return 'vless://{}@{}:{}?{}#{}'.format(user['credential'], host, port, query, quote(user['name'], safe=''))
