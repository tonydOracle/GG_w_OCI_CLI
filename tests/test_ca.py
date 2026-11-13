import base64
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from fixtures import configuration
from ggsetup.common import SetupError
from ggsetup.discovery import fetch_ca

class CaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name).resolve()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.root/'key.pem'),'-out',str(cls.root/'ca.pem'),'-days','1','-subj','/CN=Generic Fixture'],check=True,capture_output=True)
        cls.pem=(cls.root/'ca.pem').read_text()
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def responses(self,c,raw=None):
        return [{'status':'ok','data':{'id':c['target']['db_system_id'],'compartment-id':c['oci']['compartment_id']}},
                {'status':'ok','data':{'primary-db-endpoint':{'fqdn':c['target']['host'],'port':5432},'ca-certificate':self.pem if raw is None else raw}}]
    def test_pem_and_base64_certificates(self):
        for raw in (self.pem,base64.b64encode(self.pem.encode()).decode()):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();c=configuration()
                with patch('ggsetup.discovery.oci_get',side_effect=self.responses(c,raw)):
                    report=fetch_ca(c,root/'environment.json')
                self.assertEqual(report['certificate_count'],1)
                self.assertEqual((root/'destination-ca.pem').read_text(),self.pem)
    def test_identity_or_endpoint_mismatch_never_saves(self):
        for variant in ('identity','endpoint'):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();c=configuration();responses=self.responses(c)
                if variant=='identity':responses[0]['data']['id']='wrong'
                else:responses[1]['data']['primary-db-endpoint']['fqdn']='wrong.test'
                with patch('ggsetup.discovery.oci_get',side_effect=responses),self.assertRaises(SetupError):fetch_ca(c,root/'environment.json')
                self.assertFalse((root/'destination-ca.pem').exists())
    def test_refuses_overwrite_and_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();c=configuration();out=root/'destination-ca.pem';out.write_text('old')
            with patch('ggsetup.discovery.oci_get',side_effect=self.responses(c)),self.assertRaises(FileExistsError):fetch_ca(c,root/'environment.json')
            self.assertEqual(out.read_text(),'old');out.unlink()
            with patch('ggsetup.discovery.oci_get',side_effect=self.responses(c,self.pem+'\nPRIVATE KEY')),self.assertRaises(SetupError):fetch_ca(c,root/'environment.json')
            self.assertFalse(out.exists())
    def test_invalid_certificate_never_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();c=configuration()
            with patch('ggsetup.discovery.oci_get',side_effect=self.responses(c,'garbage')),self.assertRaises(SetupError):fetch_ca(c,root/'environment.json')
            self.assertFalse((root/'destination-ca.pem').exists())
