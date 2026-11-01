import json
import tempfile
import unittest
from pathlib import Path
from api.store import Store, connection_uri
from api.controller import render_config


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name)/'test.sqlite3')
        self.uid = self.store.mutate('create',payload={'name':'Alex','tags':['Family']})

    def tearDown(self):
        self.temp.cleanup()

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
        self.assertTrue(uri.endswith('#Alex%20%26%20family'))


if __name__=='__main__':
    unittest.main()
