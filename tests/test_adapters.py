from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from fixtures import configuration
from ggsetup.adapters import OCI,GG,SQL,NoRedirect
from ggsetup.common import SetupError

class AdapterTests(unittest.TestCase):
    def test_mutation_cli_uses_private_json_file_no_retry_and_explicit_profile(self):
        c=configuration()
        def fake(argv,**kwargs):
            self.assertIn('--no-retry',argv);self.assertIn('--profile',argv);self.assertNotIn('--force',argv)
            p=Path(argv[argv.index('--from-json')+1].removeprefix('file://'))
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertIn('passwordSecretId',p.read_text())
            self.assertNotIn('actual-password',' '.join(argv))
            return subprocess.CompletedProcess(argv,0,'{"data":{"id":"resource"}}','')
        with patch('ggsetup.adapters.shutil.which',return_value='/fake/oci'),patch('ggsetup.adapters.subprocess.run',side_effect=fake):
            result=OCI(c).call('deployment','create',payload={'passwordSecretId':'ocid1.vaultsecret.oc1..fixture'})
        self.assertEqual(result['data']['id'],'resource')
    def test_unknown_cli_response_does_not_retry(self):
        with patch('ggsetup.adapters.shutil.which',return_value='/fake/oci'),patch('ggsetup.adapters.subprocess.run',side_effect=subprocess.TimeoutExpired('oci',1)) as run:
            with self.assertRaises(SetupError):OCI(configuration()).call('deployment','create',payload={})
            self.assertEqual(run.call_count,1)
    def test_forbidden_oci_route(self):
        with self.assertRaises(SetupError):OCI(configuration()).call('deployment','delete')
    def test_http_credentials_never_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.test'))
        for url in ('http://source.test','https://user:password@source.test','https://source.test/path','https://source.test?x=1'):
            with self.assertRaises(SetupError):GG(url,'user','password')
    def test_sql_execution_password_not_in_argv_and_errors_redacted(self):
        c=configuration();sql=SQL(c,'/private/environment.json')
        with patch('ggsetup.adapters.discovery.hidden',return_value='admin-secret'),patch('ggsetup.adapters.discovery.client.find_client',return_value='/fake/psql'),patch('ggsetup.adapters.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','failed actual-new-password')) as run:
            with self.assertRaises(SetupError) as error:sql.execute('target',"CREATE ROLE x PASSWORD E'actual-new-password';")
            self.assertNotIn('actual-new-password',str(error.exception));self.assertNotIn('admin-secret',str(run.call_args[0][0]))
            self.assertIn('default_transaction_read_only=off',run.call_args.kwargs['env']['PGOPTIONS'])
    def test_checkpoint_comments_execute_as_apply_owner(self):
        c=configuration();sql=SQL(c,'/private/environment.json')
        with patch('ggsetup.adapters.discovery.hidden',return_value='apply-secret'),patch('ggsetup.adapters.discovery.client.find_client',return_value='/fake/psql'),patch('ggsetup.adapters.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,'[{"database_name":"OrdersDb","username":"ggapply"}]',''),subprocess.CompletedProcess([],0,'[{"ssl":true}]',''),subprocess.CompletedProcess([],0,'','')]) as run:
            sql.execute('target','COMMENT ON TABLE ggschema.cp IS \'marker\';',username='ggapply')
            self.assertEqual(run.call_args.kwargs['env']['PGUSER'],'ggapply')
            self.assertEqual(sql.c['target']['inspection_user'],c['target']['inspection_user'])

if __name__=='__main__':unittest.main()
