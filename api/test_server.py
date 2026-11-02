"""HTTP deletion regressions with isolated state; never use the production database."""
import base64
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from api.controller import Controller, render_config
from api.server import App, handler_for
from api.store import Store, digest


class SubscriptionDeletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {
            'DATABASE_PATH': str(Path(self.temp.name) / 'test.sqlite3'),
            'PUBLIC_URL': 'http://127.0.0.1',
            'ADMIN_EMAIL': 'admin@example.test',
            'VPN_HOST': 'vpn.example.test',
            'VPN_WS_PATH': '/connect-test',
        }):
            self.app = App()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(self.app))
        self.app.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        with self.app.store.connect() as db:
            db.execute('INSERT INTO sessions VALUES (?,?,?)',
                       (digest('test-admin-session'), self.app.admin, int(time.time()) + 60))
        self.uid = self.app.store.mutate('create', payload={'name': 'Delete me', 'tags': []})
        self.other = self.app.store.mutate('create', payload={'name': 'Keep me', 'tags': []})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, signed_in=True, origin=None):
        headers = {'Origin': self.app.origin if origin is None else origin}
        if signed_in:
            headers['Cookie'] = 'session=test-admin-session'
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body='{}' if method == 'POST' else None, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def delete(self, user_id, **kwargs):
        return self.request('POST', '/api/users/' + user_id + '/delete', **kwargs)

    def test_delete_revokes_link_and_client_and_preserves_other_users(self):
        users = {u['id']: u for u in self.app.store.users()}
        deleted = users[self.uid]
        for uid in users:
            self.app.store.record_stats([
                {'name': 'user>>>' + uid + '@vpn-admin.local>>>traffic>>>' + direction, 'value': 123}
                for direction in ('uplink', 'downlink')
            ], 'test-generation')
        original = {'inbounds': [{'protocol': 'vless', 'streamSettings': {'network': 'ws'},
                                  'settings': {'clients': [{'id': 'unmanaged-client'}]}}]}
        applied = render_config(original, self.app.store.users())
        revision = self.app.store.meta()['revision']
        with self.app.store.connect() as db:
            self.app.store.set_meta(db, 'applied', revision)
        status, body = self.request('GET', '/sub/' + deleted['token'], signed_in=False)
        self.assertEqual(status, 200)
        self.assertIn(deleted['credential'].encode(), base64.b64decode(body))

        self.assertEqual(self.delete(self.uid)[0], 200)
        self.assertEqual(self.request('GET', '/sub/' + deleted['token'], signed_in=False)[0], 404)
        status, body = self.request('GET', '/api/dashboard')
        self.assertEqual(status, 200)
        dashboard = json.loads(body)
        self.assertEqual([u['id'] for u in dashboard['users']], [self.other])
        self.assertEqual(dashboard['audit'][0]['action'], 'delete')
        self.assertEqual(dashboard['audit'][0]['user_id'], self.uid)
        self.assertEqual(int(dashboard['meta']['revision']), int(revision) + 1)
        self.assertEqual(dashboard['meta']['applied'], revision)
        self.assertEqual(dashboard['users'][0]['download'], 123)
        with self.app.store.connect() as db:
            self.assertEqual([r['user_id'] for r in db.execute('SELECT user_id FROM daily')], [self.other])
            counters = [r['name'] for r in db.execute('SELECT name FROM counters')]
            self.assertEqual(len(counters), 2)
            self.assertTrue(all(self.other in name for name in counters))
        updated = render_config(applied, self.app.store.users())
        credentials = {c['id'] for c in updated['inbounds'][0]['settings']['clients']}
        self.assertEqual(credentials, {'unmanaged-client', users[self.other]['credential']})
        # In-flight stats after deletion cannot recreate usage for the removed user.
        self.app.store.record_stats([{'name': 'user>>>' + self.uid + '@vpn-admin.local>>>traffic>>>downlink',
                                      'value': 999}], 'test-generation')
        with self.app.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM daily WHERE user_id=?', (self.uid,)).fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM counters').fetchone()[0], 2)

    def assert_imported_deletion_stays_revoked(self, rotate_first=False, uppercase=False):
        credential = 'e07e477e-8896-4dbc-8982-73c6c789cbd9'
        retained = '88be4758-17e6-4eac-bec1-40989130c046'
        original = {'inbounds': [{'protocol': 'vless', 'streamSettings': {'network': 'ws'},
                                  'settings': {'clients': [{'id': credential.upper() if uppercase else credential}, {'id': retained}]}}]}
        path = Path(self.temp.name) / 'xray.json'
        path.write_text(json.dumps(original))
        controller = Controller.__new__(Controller)
        controller.store, controller.path = self.app.store, path
        controller.import_existing()
        imported = next(u for u in self.app.store.users() if u['credential'] == credential)
        if rotate_first:
            self.assertEqual(self.request('POST', '/api/users/' + imported['id'] + '/rotate')[0], 200)
        self.assertEqual(self.delete(imported['id'])[0], 200)
        # Simulate a process restart and another import before the next controller apply.
        reopened = Store(self.app.store.path)
        controller.store = reopened
        controller.import_existing()
        revision, users, revoked = reopened.snapshot()
        self.assertIn(credential, revoked)
        self.assertNotIn(credential, {u['credential'] for u in users})
        controller.container = 'isolated-test-vpn'
        with patch.object(controller, 'collect'), patch.object(controller, 'command', return_value=''):
            controller.tick()
        rendered = json.loads(path.read_text())
        credentials = {c['id'] for c in rendered['inbounds'][0]['settings']['clients']}
        self.assertNotIn(credential, credentials)
        self.assertIn(retained, credentials)
        self.assertIn(self.other, {u['id'] for u in users})
        self.assertEqual(reopened.meta()['applied'], revision)

    def test_imported_user_deleted_before_first_sync_stays_revoked(self):
        self.assert_imported_deletion_stays_revoked()

    def test_imported_user_rotated_then_deleted_before_sync_stays_revoked(self):
        self.assert_imported_deletion_stays_revoked(rotate_first=True)

    def test_imported_uppercase_uuid_deleted_before_sync_stays_revoked(self):
        self.assert_imported_deletion_stays_revoked(uppercase=True)

    def test_delete_requires_session_and_same_origin(self):
        revision = self.app.store.meta()['revision']
        self.assertEqual(self.delete(self.uid, signed_in=False)[0], 401)
        self.assertEqual(self.delete(self.uid, origin='https://untrusted.example')[0], 403)
        self.assertEqual(self.app.store.meta()['revision'], revision)
        self.assertEqual(len(self.app.store.users()), 2)

    def test_deleting_missing_or_already_deleted_user_does_not_queue_changes(self):
        revision = self.app.store.meta()['revision']
        self.assertEqual(self.delete('missing-user')[0], 404)
        self.assertEqual(self.app.store.meta()['revision'], revision)
        self.assertEqual(self.delete(self.uid)[0], 200)
        revision = self.app.store.meta()['revision']
        self.assertEqual(self.delete(self.uid)[0], 404)
        self.assertEqual(self.app.store.meta()['revision'], revision)
        with self.app.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM audit WHERE action='delete'").fetchone()[0], 1)

    def test_disabled_subscription_can_be_deleted(self):
        self.app.store.mutate('toggle', self.uid)
        self.assertEqual(self.delete(self.uid)[0], 200)
        self.assertEqual([u['id'] for u in self.app.store.users()], [self.other])


if __name__ == '__main__':
    unittest.main()
