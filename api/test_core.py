import json
import tempfile
import unittest
import subprocess
from unittest.mock import patch
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from api.store import Store, connection_uri
from api.controller import Controller, failure_message, render_config


class CoreTests(unittest.TestCase):
    def test_docker_error_identifies_operation_without_leaking_stderr(self):
        controller = Controller.__new__(Controller)
        controller.docker = '/usr/bin/docker'
        error = subprocess.CalledProcessError(1, ['docker'], stderr='permission denied secret-user-credential')
        with patch('api.controller.subprocess.run', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                controller.command('cp', '/tmp/private-config.json', 'vpn:/tmp/config.json')
        message = str(caught.exception)
        self.assertIn('docker cp exited 1', message)
        self.assertIn('Permission denied', message)
        self.assertNotIn('secret-user-credential', message)
        self.assertNotIn('private-config', message)

    def test_filesystem_error_identifies_file_and_errno(self):
        message = failure_message(PermissionError(13, 'Permission denied', '/private/xray.json'))
        self.assertIn('xray.json', message)
        self.assertIn('errno 13', message)
        self.assertNotIn('/private/', message)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name)/'test.sqlite3')
        self.uid = self.store.mutate('create',payload={'name':'Alex','tags':['Family']})

    def tearDown(self):
        self.temp.cleanup()

    def controller_fixture(self):
        path = Path(self.temp.name)/'xray.json'
        path.write_text(json.dumps({'inbounds':[{'protocol':'vless',
            'streamSettings':{'network':'ws'},'settings':{'clients':[{'id':'external'}]}}]}))
        controller = Controller.__new__(Controller)
        controller.store, controller.path, controller.container = self.store, path, 'vpn'
        controller.docker = '/usr/bin/docker'
        return controller

    def test_apply_on_minimal_xray_image_without_copy_or_rm(self):
        controller = self.controller_fixture()
        original = controller.path.read_bytes()
        def run(command, **kwargs):
            if command[1:3] == ['exec', '-i']:
                self.assertEqual(command[3:], ['vpn','xray','run','-test','-format','json','-config','stdin:'])
                candidate = json.loads(kwargs['input'])
                self.assertEqual(len(candidate['inbounds'][0]['settings']['clients']), 2)
            elif command[1:] != ['restart', 'vpn']:
                self.fail('Unexpected command: '+repr(command))
            return subprocess.CompletedProcess(command, 0, stdout='')
        with patch('api.controller.subprocess.run', side_effect=run) as calls, patch.object(controller, 'collect'):
            controller.tick()
        self.assertEqual(calls.call_count, 2)
        self.assertEqual(self.store.meta()['applied'], self.store.meta()['revision'])
        self.assertEqual(self.store.meta()['error'], '')
        backups = list(controller.path.parent.glob('xray.json.vpn-admin-backup-*'))
        self.assertEqual(backups[0].read_bytes(), original)

    def test_invalid_candidate_does_not_modify_config_or_restart(self):
        controller = self.controller_fixture()
        original = controller.path.read_bytes()
        error = subprocess.CalledProcessError(23, ['docker'], stderr='invalid config private-credential')
        with patch('api.controller.subprocess.run', side_effect=error) as calls, patch.object(controller, 'collect'):
            with self.assertRaisesRegex(RuntimeError, 'docker exec xray run exited 23'):
                controller.tick()
        self.assertEqual(calls.call_count, 1)
        self.assertEqual(controller.path.read_bytes(), original)
        self.assertNotEqual(self.store.meta()['applied'], self.store.meta()['revision'])

    def test_rotation_changes_link_and_uuid(self):
        old = self.store.users()[0]
        self.store.mutate('rotate',self.uid)
        new = self.store.users()[0]
        self.assertNotEqual(old['token'],new['token'])
        self.assertNotEqual(old['credential'],new['credential'])
        self.assertEqual(old['id'],new['id'])

    def test_rename_does_not_queue_restart(self):
        revision = self.store.meta()['revision']
        self.store.mutate('edit',self.uid,{'name':'Alex New','tags':['Friends']})
        self.assertEqual(self.store.meta()['revision'],revision)

    def test_counter_persistence_and_restart(self):
        name = 'user>>>'+self.uid+'@vpn-admin.local>>>traffic>>>downlink'
        for value in (100,100,140):
            self.store.record_stats([{'name':name,'value':value}],'first')
        self.store.record_stats([{'name':name,'value':170}],'second')
        self.assertEqual(self.store.users()[0]['download'],310)
        self.assertEqual(Store(self.store.path).users()[0]['download'],310)

    def test_preserve_unmanaged_remove_revoked(self):
        original = {'inbounds':[{'protocol':'vless','streamSettings':{'network':'ws'},'settings':{'clients':[{'id':'external'}]}}]}
        active = render_config(original,self.store.users())
        self.assertEqual(len(active['inbounds'][0]['settings']['clients']),2)
        self.store.mutate('toggle',self.uid)
        disabled = render_config(active,self.store.users())
        self.assertEqual(disabled['inbounds'][0]['settings']['clients'],[{'id':'external'}])
        self.assertEqual(disabled['inbounds'][1]['listen'],'127.0.0.1')
        self.assertEqual(len(original['inbounds']),1)

    def test_rotation_removes_old_credential(self):
        original = {'inbounds':[{'protocol':'vless','streamSettings':{'network':'ws'},'settings':{'clients':[]}}]}
        old = self.store.users()[0]['credential']
        active = render_config(original,self.store.users())
        self.store.mutate('rotate',self.uid)
        updated = render_config(active,self.store.users())
        self.assertNotIn(old,json.dumps(updated))

    def test_validation_and_uri_encoding(self):
        with self.assertRaises(ValueError):
            self.store.mutate('create',payload={'name':'','tags':[]})
        user=self.store.users()[0]
        user['name']='Alex & family'
        uri=connection_uri(user,'vpn.example.com',443,'/connect path')
        self.assertIn('security=tls',uri)
        self.assertIn('path=%2Fconnect+path',uri)
        self.assertEqual(parse_qs(urlsplit(uri).query)['alpn'], ['http/1.1'])
        self.assertTrue(uri.endswith('#Alex%20%26%20family'))


if __name__=='__main__':
    unittest.main()
