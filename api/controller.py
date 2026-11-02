"""Local-only Docker controller. Never expose this process as an HTTP service."""
import argparse
import copy
import fcntl
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from .store import Store


def failure_message(error):
    """Keep credentials out of logs while retaining actionable failure details."""
    if isinstance(error, OSError):
        filename = Path(error.filename).name if error.filename else 'local operation'
        return '{}: {} (errno {}).'.format(type(error).__name__, filename, error.errno)
    if isinstance(error, (ValueError, RuntimeError)):
        return str(error)
    return 'Controller failed: {}.'.format(type(error).__name__)


def credential_key(value):
    # Xray accepts UUIDs irrespective of textual case; imports canonicalize them.
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return value


def render_config(original, users, revoked_credentials=()):
    config = copy.deepcopy(original)
    inbound = [i for i in config.get('inbounds',[]) if i.get('protocol')=='vless']
    if len(inbound) != 1:
        raise ValueError('Exactly one VLESS inbound is required. Select an adapter before managing a different topology.')
    inbound = inbound[0]
    if inbound.get('streamSettings',{}).get('network') != 'ws':
        raise ValueError('This adapter supports the existing VLESS WebSocket server only.')
    managed_ids = {credential_key(u['credential']) for u in users} | {credential_key(c) for c in revoked_credentials}
    clients = inbound.setdefault('settings',{}).get('clients',[])
    # Preserve unmanaged clients, but remove managed, imported, and explicitly revoked IDs.
    clients = [c for c in clients if not c.get('email','').endswith('@vpn-admin.local') and credential_key(c.get('id')) not in managed_ids]
    clients += [{'id':u['credential'],'email':u['id']+'@vpn-admin.local','level':100} for u in users if u['enabled']]
    inbound['settings']['clients'] = clients
    config.setdefault('stats',{})
    config.setdefault('policy',{}).setdefault('levels',{}).setdefault('100',{}).update({'statsUserUplink':True,'statsUserDownlink':True})
    existing_api = config.get('api')
    if existing_api and existing_api.get('tag') != 'vpn-admin-api':
        raise ValueError('An existing Xray API needs manual review; refusing to replace it.')
    config['api'] = {'tag':'vpn-admin-api','services':['StatsService']}
    config['inbounds'] = [i for i in config['inbounds'] if i.get('tag') != 'vpn-admin-api-in']
    config['inbounds'].append({'tag':'vpn-admin-api-in','listen':'127.0.0.1','port':10085,
                               'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}})
    routing = config.setdefault('routing',{})
    rules = [r for r in routing.get('rules',[]) if r.get('outboundTag') != 'vpn-admin-api']
    routing['rules'] = [{'type':'field','inboundTag':['vpn-admin-api-in'],'outboundTag':'vpn-admin-api'}]+rules
    return config


class Controller:
    def __init__(self, store, config, container='shadowrocket_vless'):
        self.store,self.path,self.container = store,Path(config).resolve(),container
        self.docker = shutil.which('docker')
        if not self.docker:
            raise RuntimeError('Docker CLI is not on PATH.')

    def command(self, *args, input_data=None):
        operation = 'docker '+args[0]
        if args[0] == 'exec':
            # Only fixed executable/subcommand names; never include config or credentials.
            offset = 3 if args[1] == '-i' else 2
            operation += ' '+ ' '.join(args[offset:offset+2])
        try:
            return subprocess.run([self.docker,*args],input=input_data,check=True,capture_output=True,text=True,timeout=45).stdout
        except subprocess.TimeoutExpired:
            raise RuntimeError(operation+' timed out after 45 seconds.') from None
        except subprocess.CalledProcessError as error:
            diagnostic = (error.stderr or '').lower()
            reason = 'Command failed; inspect the VPN container locally for details.'
            for marker, explanation in (
                ('permission denied', 'Permission denied accessing Docker or a mounted file.'),
                ('client version', 'Docker client/server API version mismatch.'),
                ('no such container', 'Configured Xray container does not exist.'),
                ('is not running', 'Xray container is not running.'),
                ('executable file not found', 'Required executable is missing in the Xray container.'),
                ('read-only file system', 'The target filesystem is read-only.'),
                ('cannot connect to the docker daemon', 'Docker daemon is unreachable.'),
                ('connection refused', 'The requested service is not listening.'),
            ):
                if marker in diagnostic:
                    reason = explanation
                    break
            raise RuntimeError('{} exited {}. {}'.format(operation,error.returncode,reason)) from None

    def collect(self):
        generation = self.command('inspect','--format','{{.State.StartedAt}}',self.container).strip()
        raw = self.command('exec',self.container,'xray','api','statsquery','--server=127.0.0.1:10085')
        data = json.loads(raw)
        self.store.record_stats(data.get('stat',[]),generation)

    def import_existing(self):
        config = json.loads(self.path.read_text())
        inbound = [i for i in config.get('inbounds',[]) if i.get('protocol')=='vless']
        if len(inbound)!=1:
            raise ValueError('Expected exactly one VLESS inbound.')
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for index, client in enumerate(inbound[0].get('settings',{}).get('clients',[]),1):
                credential = str(uuid.UUID(client['id']))
                if (client.get('email','').endswith('@vpn-admin.local')
                        or db.execute('SELECT 1 FROM users WHERE credential=?',(credential,)).fetchone()
                        or db.execute('SELECT 1 FROM revoked_credentials WHERE credential=?',(credential,)).fetchone()):
                    continue
                uid = str(uuid.uuid4())
                db.execute('INSERT INTO users(id,name,tags,credential,token,created) VALUES(?,?,?,?,?,?)',
                           (uid,'Existing client '+str(index),'["Imported"]',credential,secrets.token_urlsafe(32),int(time.time())))
                db.execute('INSERT INTO audit(time,action,user_id) VALUES(?,?,?)',(int(time.time()),'import',uid))
                db.execute("UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'")

    def tick(self):
        meta = self.store.meta()
        stats_error = None
        try:
            self.collect()
        except Exception as error:
            stats_error = 'Traffic collection failed. '+failure_message(error)
        revision,users,revoked = self.store.snapshot()
        original = self.path.read_bytes()
        config_hash = hashlib.sha256(original).hexdigest()
        if revision != meta['applied'] or meta.get('config_hash') != config_hash:
            if meta.get('config_hash') and meta['config_hash'] != config_hash:
                raise RuntimeError('Xray config changed outside this app. Review it before clearing config_hash in the database.')
            new = (json.dumps(render_config(json.loads(original),users,revoked),indent=2)+'\n').encode()
            # Minimal Xray images have no shell or rm. Validate over stdin so no
            # temporary credentials or cleanup commands are needed in the container.
            self.command('exec','-i',self.container,'xray','run','-test',
                         '-format','json','-config','stdin:',input_data=new.decode())
            backup = self.path.with_name(self.path.name+'.vpn-admin-backup-'+str(time.time_ns()))
            backup.write_bytes(original)
            backup.chmod(0o600)
            try:
                # Keep the inode: the existing container bind-mounts a single file.
                with self.path.open('wb') as output:
                    output.write(new)
                    output.flush()
                    os.fsync(output.fileno())
                self.command('restart',self.container)
                # Docker restart returns before the stats listener necessarily accepts requests.
                for attempt in range(10):
                    try:
                        self.collect()
                        break
                    except Exception:
                        if attempt==9:
                            raise
                        time.sleep(1)
            except Exception:
                self.path.write_bytes(original)
                self.command('restart',self.container)
                raise RuntimeError('Apply failed; restored the previous config. Check the VPN container.')
            with self.store.connect() as db:
                self.store.set_meta(db,'applied',revision)
                self.store.set_meta(db,'config_hash',hashlib.sha256(new).hexdigest())
            stats_error = None
        with self.store.connect() as db:
            self.store.set_meta(db,'controller_at',int(time.time()))
            self.store.set_meta(db,'error',stats_error or '')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',help='Enable config writes and Xray restarts.')
    parser.add_argument('--import-existing',action='store_true',help='Keep existing UUIDs and add their owners to the dashboard.')
    parser.add_argument('--once',action='store_true')
    args = parser.parse_args()
    if not args.apply:
        parser.error('--apply is required. Applying VPN changes briefly restarts Xray.')
    os.umask(0o077)
    store = Store(os.environ.get('DATABASE_PATH','data/vpn.sqlite3'))
    lock = open(store.path+'.controller.lock','w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    controller = Controller(store,os.environ['XRAY_CONFIG'],os.environ.get('XRAY_CONTAINER','shadowrocket_vless'))
    if args.import_existing:
        controller.import_existing()
    while True:
        try:
            controller.tick()
        except Exception as error:
            # Do not persist subprocess output: Xray diagnostics can contain credentials.
            message = failure_message(error)
            with store.connect() as db:
                store.set_meta(db,'error',message)
            print(message,flush=True)
            if args.once:
                raise SystemExit(1)
        if args.once:
            break
        time.sleep(15)


if __name__=='__main__':
    main()
