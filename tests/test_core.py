from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from ggsetup import config,planner,discovery
from ggsetup.common import SetupError,read_json,write_json,private_directory,digest
from ggsetup.state import Journal
from ggsetup.__main__ import main
from fixtures import configuration,inspection,col,key,table

class ConfigTests(unittest.TestCase):
    def test_valid_different_databases(self):
        for c in (configuration(),configuration('warehouse','InventoryDb','WH')):self.assertIs(config.validate(c),c)
    def test_rejects_secret_or_unknown_properties(self):
        for path in ((),('source',),('target',),('oci',),('goldengate',),('scope',)):
            c=configuration();obj=c
            for k in path:obj=obj[k]
            obj['password']='not-allowed'
            with self.subTest(path=path),self.assertRaises(SetupError):config.validate(c)
    def test_bool_port_and_invalid_auth(self):
        for side,k,v in [('source','port',True),('target','port',0),('oci','auth','other'),('source','trust_server_certificate','true')]:
            c=configuration();c[side][k]=v
            with self.subTest(k=k),self.assertRaises(SetupError):config.validate(c)
    def test_state_fingerprint_distinct_for_database_and_prefix(self):
        c=configuration();d=deepcopy(c);d['source']['database']='Other'
        self.assertNotEqual(config.fingerprint(c),config.fingerprint(d))
        d=deepcopy(c);d['goldengate']['prefix']='NEW';self.assertNotEqual(config.fingerprint(c),config.fingerprint(d))
    def test_process_names_max_eight(self):
        c=configuration(prefix='TEST');n=config.names(c)
        for key_ in ('initial_extract','initial_replicat','cdc_extract','cdc_replicat'):self.assertLessEqual(len(n[key_]),8)
        self.assertNotEqual(n['initial_trail'],n['cdc_trail'])
    def test_rejects_duplicate_aliases_and_scope(self):
        c=configuration();c['goldengate']['network_alias']=c['goldengate']['source_alias']
        with self.assertRaises(SetupError):config.validate(c)
        c=configuration();c['scope']['exclude_tables']=[['sales','Orders'],['sales','Orders']]
        with self.assertRaises(SetupError):config.validate(c)
    def test_explicit_scope_rules(self):
        c=configuration();c['scope'].update(mode='selected',include_tables=[])
        with self.assertRaises(SetupError):config.validate(c)
        c['scope']['include_tables']=[['sales','Orders']];config.validate(c)
    def test_target_ip_and_identifier_byte_limits(self):
        c=configuration();c['target']['host']='192.0.2.30'
        with self.assertRaises(SetupError):config.validate(c)
        with self.assertRaises(SetupError):config.identifier('é'*32,'name')
    def test_duplicate_json_properties_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.json';p.write_text('{"a":1,"a":2}')
            with self.assertRaises(SetupError):read_json(p)

class MappingTests(unittest.TestCase):
    def test_supported_scalar_mappings(self):
        expected={'int':'integer','bigint':'bigint','tinyint':'smallint','money':'numeric(19,4)','uniqueidentifier':'uuid','bit':'boolean','varbinary':'bytea','datetime':'timestamp(6) without time zone'}
        for typ,wanted in expected.items():
            with self.subTest(typ=typ):self.assertEqual(planner.target_type(col('V',typ)),wanted)
    def test_char_and_max_types(self):
        for typ,width,wanted in [('nvarchar',80,'character varying(40)'),('nchar',8,'character(4)'),('varchar',-1,'text'),('nvarchar',-1,'text'),('char',3,'character(3)')]:
            with self.subTest(typ=typ):self.assertEqual(planner.target_type(col('V',typ,max_length=width)),wanted)
    def test_timestamp_precision_gate(self):
        for typ in ('datetime2','time'):
            planner.target_type(col('V',typ,scale=6))
            with self.assertRaises(SetupError):planner.target_type(col('V',typ,scale=7))
    def test_computed_and_special_features_are_not_silently_dropped(self):
        for flag in ('is_computed','is_user_defined','is_assembly_type','is_filestream','is_sparse','is_column_set','is_hidden'):
            with self.subTest(flag=flag),self.assertRaises(SetupError):planner.target_type(col('V',**{flag:True}))
    def test_encryption_and_generated_always(self):
        for fields in ({'encryption_type':1},{'generated_always_type':1}):
            with self.assertRaises(SetupError):planner.target_type(col('V',**fields))
    def test_unknown_and_ambiguous_types(self):
        for typ in ('datetimeoffset','xml','hierarchyid','geography','rowversion','sql_variant','sysname','ntext'):
            with self.subTest(typ=typ),self.assertRaises(SetupError):planner.target_type(col('V',typ))
    def test_bad_width_and_numeric(self):
        for fields in ({'data_type':'nvarchar','max_length':3},{'data_type':'char','max_length':-1},{'data_type':'decimal','precision':39},{'data_type':'decimal','precision':5,'scale':6}):
            with self.subTest(fields=fields),self.assertRaises(SetupError):planner.target_type(col('V',**fields))
    def test_missing_flags_and_fake_boolean_rejected(self):
        c=col('V');del c['is_sparse']
        with self.assertRaises(SetupError):planner.target_type(c)
        c=col('V',is_computed='false')
        with self.assertRaises(SetupError):planner.target_type(c)

class PlanningTests(unittest.TestCase):
    def setUp(self):self.c=configuration();self.r=inspection(self.c)
    def build(self):return planner.build(self.c,self.r)
    def test_plan_uses_configured_database(self):
        p=self.build();self.assertEqual(p['status'],'schema_plan_ready');self.assertEqual(p['planned_column_count'],3)
        self.assertFalse(p['replication_ready']);self.assertFalse(p['remote_changes_performed'])
        a=planner.artifacts(self.c,p);self.assertIn("decode('"+"OrdersDb".encode().hex(),a['target-schema.review.sql'])
        self.assertIn('"sales"."Orders"',a['target-schema.review.sql'])
        self.assertNotIn('SNAPSHOT',a['capture-tables.review.prm'])
    def test_second_schema_and_table_count(self):
        c=configuration('warehouse','WarehouseDb','WH');r=inspection(c)
        r['source']['queries']['tables']['rows'].append(table('inventory','Items'))
        x=col('ItemID');x.update(schema_name='inventory',table_name='Items');r['source']['queries']['columns']['rows'].append(x)
        k=key('ItemID');k.update(schema_name='inventory',table_name='Items');r['source']['queries']['keys']['rows'].append(k)
        p=planner.build(c,r);self.assertEqual(p['status'],'schema_plan_ready');self.assertEqual(p['planned_table_count'],2)
        self.assertIn("decode('"+"WarehouseDb".encode().hex(),planner.artifacts(c,p)['target-schema.review.sql'])
    def test_database_identity_config_binding(self):
        self.r['source']['queries']['identity']['rows'][0]['database_name']='Different'
        self.assertEqual(self.build()['status'],'blocked')
        self.r['configuration_sha256']='wrong'
        with self.assertRaises(SetupError):self.build()
    def test_partial_and_truncated_metadata_block(self):
        for status in ('error','truncated','unavailable'):
            self.r['source']['queries']['columns']['status']=status
            with self.subTest(status=status):self.assertEqual(self.build()['status'],'blocked')
    def test_missing_primary_key(self):
        self.r['source']['queries']['keys']['rows']=[]
        self.assertTrue(any(x['code']=='PRIMARY_KEY' for x in self.build()['blockers']))
    def test_filtered_disabled_and_invalid_pk(self):
        for field,value in [('has_filter',True),('is_disabled',True),('key_ordinal',0)]:
            self.r=inspection(self.c);self.r['source']['queries']['keys']['rows'][0][field]=value
            with self.subTest(field=field):self.assertEqual(self.build()['status'],'blocked')
    def test_nullable_unique_index_uses_pg15_semantics(self):
        self.r['source']['queries']['keys']['rows'].append(key('Description',index='UniqueDescription',primary=False))
        p=self.build();self.assertEqual(p['status'],'schema_plan_ready')
        self.assertIn('NULLS NOT DISTINCT',planner.artifacts(self.c,p)['target-schema.review.sql'])
    def test_duplicate_columns_and_keys(self):
        self.r['source']['queries']['columns']['rows'].append(col('OrderID'))
        self.assertEqual(self.build()['status'],'blocked')
    def test_unsupported_table_features(self):
        for flag in ('is_memory_optimized','is_filetable','is_external','has_row_security'):
            self.r=inspection(self.c);self.r['source']['queries']['tables']['rows'][0][flag]=True
            with self.subTest(flag=flag):self.assertEqual(self.build()['status'],'blocked')
    def test_target_existing_object_tls_or_standby_block(self):
        self.r['target']['queries']['tables']['rows']=[{'schema_name':'sales','table_name':'Orders','relkind':'r'}]
        self.assertEqual(self.build()['status'],'blocked')
        self.r=inspection(self.c);self.r['target']['queries']['tls']['rows'][0]['ssl']=False
        self.assertEqual(self.build()['status'],'blocked')
        self.r=inspection(self.c);self.r['target']['queries']['identity']['rows'][0]['is_standby']=True
        self.assertEqual(self.build()['status'],'blocked')
    def test_missing_scope_not_silently_skipped(self):
        self.c['scope'].update(mode='selected',include_tables=[['not','found']]);self.r=inspection(self.c)
        self.assertEqual(self.build()['status'],'blocked')
    def test_exclusions_are_explicit(self):
        self.c['scope']['exclude_tables']=[['sales','Orders']];self.r=inspection(self.c)
        self.assertTrue(any(x['code']=='EMPTY_SCOPE' for x in self.build()['blockers']))
    def test_computed_blocks_entire_artifact_emission(self):
        self.r['source']['queries']['columns']['rows'][1]['is_computed']=True
        p=self.build();self.assertEqual(p['status'],'blocked')
        with self.assertRaises(SetupError):planner.artifacts(self.c,p)
    def test_visibility_and_oci_mismatch(self):
        self.r['source']['queries']['visibility']['rows'][0]['view_definition']=0
        self.assertEqual(self.build()['status'],'blocked')
        self.r=inspection(self.c);self.r['oci']['connection']['data']['primary-db-endpoint']['fqdn']='other.test'
        self.assertEqual(self.build()['status'],'blocked')
    def test_quoted_parameter_injection_is_rejected(self):
        self.r['source']['queries']['columns']['rows'][1]['column_name']='x"; TABLE other;'
        p=self.build();self.assertEqual(p['status'],'blocked')
    def test_sql_identifier_and_literal_escaping(self):
        self.assertEqual(planner.quote('a"b'),'"a""b"')
        self.assertEqual(planner.literal("a'b"),"'a''b'")
    def test_database_guard_uses_hex_for_dollar_and_quote_safety(self):
        self.c['target']['database']="X$ggsetup_guard$'\\Y"
        self.r=inspection(self.c)
        p=self.build();self.assertEqual(p['status'],'schema_plan_ready')
        sql=planner.artifacts(self.c,p)['target-schema.review.sql']
        self.assertNotIn(self.c['target']['database'],sql)
        self.assertIn(self.c['target']['database'].encode().hex(),sql)
    def test_artifact_emission_requires_same_configuration(self):
        p=self.build();self.c['target']['database']='Other'
        with self.assertRaises(SetupError):planner.artifacts(self.c,p)
    def test_non_contiguous_column_ids_are_valid(self):
        self.assertEqual(self.build()['status'],'schema_plan_ready') # ordinals 1,2,4

class StateTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.c=configuration()
    def tearDown(self):self.tmp.cleanup()
    def test_environment_binding(self):
        d=self.root/'state'
        with Journal(d,self.c) as j:j.event('test',{'ok':True})
        with Journal(d,self.c) as j:self.assertEqual(len(j.data['events']),1)
        c=configuration('other','OtherDb','OT')
        with self.assertRaises(SetupError):
            with Journal(d,c):pass
    def test_exclusive_lock(self):
        with Journal(self.root/'state',self.c):
            with self.assertRaises(RuntimeError):
                with Journal(self.root/'state',self.c):pass
    def test_pending_intent_survives_and_cannot_be_replayed(self):
        d=self.root/'state'
        with Journal(d,self.c) as j:token=j.intent('create',{'resource':'one'})
        with Journal(d,self.c) as j:
            self.assertEqual(j.data['intents']['create']['status'],'pending')
            with self.assertRaises(SetupError):j.intent('create',{'resource':'one'})
            with self.assertRaises(SetupError):j.acknowledge('create','wrong',{'id':'one'})
            j.acknowledge('create',token,{'id':'one'})
            with self.assertRaises(SetupError):j.acknowledge('create',token,{'id':'one'})
    def test_private_permissions_no_overwrite(self):
        p=self.root/'private'/'x.json';write_json(p,{'ok':True})
        self.assertEqual(p.stat().st_mode&0o777,0o600);self.assertEqual(p.parent.stat().st_mode&0o777,0o700)
        with self.assertRaises(FileExistsError):write_json(p,{'changed':True})
        self.assertEqual(read_json(p),{'ok':True})
    def test_symlink_refused(self):
        (self.root/'actual').mkdir(mode=0o700);(self.root/'link').symlink_to(self.root/'actual',target_is_directory=True)
        with self.assertRaises(SetupError):private_directory(self.root/'link')
    def test_separate_environment_directories(self):
        with Journal(self.root/'a',self.c) as j:a=j.data['run_id']
        with Journal(self.root/'b',configuration('other','OtherDb','OT')) as j:self.assertNotEqual(a,j.data['run_id'])

class ClientTests(unittest.TestCase):
    def test_passwords_not_in_arguments_and_override_cleanup(self):
        for side in ('source','target'):
            e=discovery.endpoint(configuration(),side,'/private/environment.json')
            with patch.dict(os.environ,{'PGSERVICE':'bad','SQLCMDINI':'bad'}):
                argv,env,sql=discovery.client.command(e,'client','pw-secret','SELECT 1 AS x',10,30)
            self.assertNotIn('pw-secret',' '.join(argv)+sql);self.assertNotIn('PGSERVICE',env);self.assertNotIn('SQLCMDINI',env)
            if side=='source':self.assertIn('-N',argv);self.assertNotIn('-C',argv);self.assertNotIn('-h',argv)
            else:self.assertEqual(env['PGSSLMODE'],'verify-full');self.assertIn('default_transaction_read_only=on',env['PGOPTIONS'])
    def test_unicode_line_separators_survive_sqlcmd_output(self):
        e=discovery.endpoint(configuration(),'source','/private/environment.json')
        with patch('ggsetup.discovery.subprocess.run',return_value=subprocess.CompletedProcess([],0,'[{"name":"a\u2028b"}]\n','')):
            result=discovery.query(e,'sqlcmd','pw','SELECT 1 AS x')
        self.assertEqual(result['rows'][0]['name'],'a\u2028b')
    def test_truncation_error_and_timeout(self):
        e=discovery.endpoint(configuration(),'source','/private/environment.json')
        with patch('ggsetup.discovery.subprocess.run',return_value=subprocess.CompletedProcess([],0,'[{},{},{}]','')):
            self.assertEqual(discovery.query(e,'sqlcmd','pw','SELECT 1 AS x',2)['status'],'truncated')
        with patch('ggsetup.discovery.subprocess.run',side_effect=subprocess.TimeoutExpired('client',1)):
            self.assertEqual(discovery.query(e,'sqlcmd','pw','SELECT 1 AS x')['status'],'error')
        with patch('ggsetup.discovery.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','password=pw')):
            self.assertNotIn('pw',str(discovery.query(e,'sqlcmd','pw','SELECT 1 AS x')))
    def test_only_fixed_select_queries_exist(self):
        for sql in list(discovery.SOURCE_QUERIES.values())+list(discovery.TARGET_QUERIES.values()):self.assertTrue(sql.lstrip().startswith('SELECT '))
    def test_oci_only_allows_two_get_routes(self):
        with self.assertRaises(SetupError):discovery.oci_get(configuration(),['goldengate','deployment','create'])
    def test_target_collection_continues_after_missing_source_client(self):
        with patch('ggsetup.discovery.client.find_client',return_value=None),patch('ggsetup.discovery.hidden') as hidden:
            r=discovery.inspect_sql(configuration(),'/private/environment.json',progress=lambda x:None)
            self.assertEqual(r['source']['status'],'unavailable');self.assertEqual(r['target']['status'],'unavailable');hidden.assert_not_called()
    def test_oci_auth_region_and_config_explicit(self):
        c=configuration()
        with patch('ggsetup.discovery.shutil.which',return_value='/fake/oci'),patch('ggsetup.discovery.subprocess.run',return_value=subprocess.CompletedProcess([],0,'{"data":{"id":"fixture"}}','')) as run:
            self.assertEqual(discovery.oci_get(c,['psql','db-system','get','--db-system-id','fixture'])['status'],'ok')
            argv=run.call_args[0][0]
            for flag in ('--profile','--auth','--region','--config-file','--cli-rc-file'):self.assertIn(flag,argv)

class CliTests(unittest.TestCase):
    def test_complete_offline_init_validate_plan_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();cfg=root/'environment.json';c=configuration();write_json(cfg,c)
            report=root/'inspection.json';write_json(report,inspection(c))
            self.assertEqual(main(['validate','--config',str(cfg)]),0)
            output=root/'plan'
            self.assertEqual(main(['plan','--config',str(cfg),'--inspection',str(report),'--output',str(output)]),0)
            self.assertTrue((output/'target-schema.review.sql').exists())
            self.assertEqual(main(['status','--config',str(cfg)]),0)
            self.assertEqual(main(['plan','--config',str(cfg),'--inspection',str(report),'--output',str(output)]),2)
    def test_blocked_plan_writes_diagnosis_but_no_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();cfg=root/'environment.json';c=configuration();write_json(cfg,c)
            r=inspection(c);r['source']['queries']['columns']['rows'][0]['is_computed']=True
            report=root/'inspection.json';write_json(report,r)
            output=root/'plan'
            self.assertEqual(main(['plan','--config',str(cfg),'--inspection',str(report),'--output',str(output)]),2)
            self.assertTrue((output/'plan.json').exists());self.assertFalse((output/'target-schema.review.sql').exists())
    def test_inspection_refuses_placeholder_before_connection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();cfg=root/'environment.json';write_json(cfg,config.example())
            with patch('ggsetup.discovery.inspect') as inspect:
                self.assertEqual(main(['inspect','--config',str(cfg)]),2);inspect.assert_not_called()

if __name__=='__main__':unittest.main()
