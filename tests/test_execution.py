from copy import deepcopy
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from fixtures import configuration,inspection
from ggsetup import planner,execution_plan,verification
from ggsetup.common import SetupError,digest,now
from ggsetup.executor import Executor
from ggsetup.state import Journal


def execution_inputs():
    c=configuration();c['goldengate']['subnet_id']='ocid1.subnet.oc1..fixture'
    s=execution_plan.example()
    s.update(source_version='oggmssql:fixture',target_version='oggpostgresql:fixture',nsg_ids=['ocid1.networksecuritygroup.oc1..fixture'])
    for k in ('source_admin_secret_id','target_admin_secret_id','capture_secret_id','apply_secret_id'):s[k]='ocid1.vaultsecret.oc1..fixture_'+k
    p=planner.build(c,inspection(c));return c,p,s,execution_plan.build(c,p,s)

class FakeSQL:
    def __init__(self,c,p):self.c=c;self.p=p;self.executed=[];self.source_created=False;self.apply_created=False;self.loaded=False;self.checkpoints=set();self.corrupt=False
    def query(self,side,query,limit=10000):
        from ggsetup import discovery
        if ' AS account_exists' in query:return [{'account_exists':False if side=='target' else 0}]
        if side=='source':
            for name,sql in discovery.SOURCE_QUERIES.items():
                if query==sql:
                    if name in ('identity','visibility','tables','columns','keys'):return deepcopy(inspection(self.c)['source']['queries'][name]['rows'])
                    if name=='database':return [{'is_cdc_enabled':True,'snapshot_isolation_state':1}]
                    if name=='services':return [{'servicename':'SQL Server Agent','status_desc':'Running'}]
                    if name=='lob_limit':return [{'running':-1}]
            if 'IS_ROLEMEMBER' in query:return [{'db_owner':1,'sysadmin':0,'has_schema':1,'agent_reader':1}]
            if 'min_lsn' in query:return [{'schema_name':t['schema'],'table_name':t['table'],'min_lsn':'0x00000001000000010001','max_lsn':'0x00000099000000990099'} for t in self.p['tables']]
            if 'cc.column_name FROM cdc.change_tables' in query:return [{'schema_name':t['schema'],'table_name':t['table'],'capture_instance':'fixture_'+t['table'],'column_name':x['name']} for t in self.p['tables'] for x in t['columns']]
            if 'SELECT job_type' in query:return [{'job_type':'capture'}]
            if 'SELECT j.enabled' in query:return [{'enabled':True,'is_running':1}]
            if 'sys.dm_cdc_errors' in query:return []
        else:
            for name,sql in __import__('ggsetup.discovery',fromlist=['TARGET_QUERIES']).TARGET_QUERIES.items():
                if query==sql:return deepcopy(inspection(self.c)['target']['queries'][name]['rows'])
            if 'has_table_privilege' in query:return [{'can_apply':True}]
            if 'has_schema_privilege' in query:return [{'usable':True,'creatable':True}]
            if 'pg_catalog.pg_attribute' in query:return [{'schema_name':t['schema'],'table_name':t['table'],'column_name':x['name'],'ordinal':i+1,'data_type':x['target_type'],'not_null':not x['nullable'],'relkind':'r','relrowsecurity':False} for t in self.p['tables'] for i,x in enumerate(t['columns'])]
            if 'FROM pg_catalog.pg_roles' in query:return [{'rolcanlogin':True,'rolsuper':False,'rolcreatedb':False,'rolcreaterole':False,'rolreplication':False}]
            if 'to_regclass' in query:return [{'exists':False}]
        if 'COUNT_BIG' in query or 'SELECT count(*)' in query:return [{'n':1 if side=='source' or self.loaded else 0}]
        if 'comparison_page' in query or 'AS cmp' in query:
            offset=int(re.search(r'OFFSET (\d+)',query).group(1))
            if offset>0:return []
            return [{'c0':'1','c1':'Changed' if side=='target' and self.corrupt else 'Unicode \u2028 exact  ','c2':'1.2345' if side=='source' else '1.234500'}]
        raise AssertionError('Unexpected SQL query '+query)
    def as_user(self,side,username):return self
    def execute(self,side,sql,username=None):self.executed.append((side,sql));return {'statement_completed':True}

class FakeOCI:
    def __init__(self):self.data={};self.calls=[];self.n=0;self.fail_next=False
    def call(self,resource,operation,args=(),payload=None):
        self.calls.append((resource,operation,deepcopy(payload),list(args)))
        if self.fail_next:self.fail_next=False;raise SetupError('simulated unknown outcome')
        if operation in ('create','create-microsoft-sqlserver-connection','create-postgresql-connection','create-goldengate-connection'):
            self.n+=1;id_='ocid1.'+resource.replace('-','')+'.oc1..fixture'+str(self.n)
            d={re.sub(r'([A-Z])',lambda m:'-'+m[1].lower(),k):deepcopy(v) for k,v in payload.items()}
            d.update(id=id_,**{'lifecycle-state':'ACTIVE'})
            if resource=='deployment':d['deployment-url']='https://'+('source' if payload['deploymentType']=='DATABASE_MICROSOFT_SQLSERVER' else 'target')+'.example.test';d['ogg-data']={'admin-username':payload['adminUsername'],'ogg-version':payload['oggVersion'],'password-secret-id':payload['passwordSecretId']}
            if resource=='connection-assignment':d['alias-name']=self.data[payload['connectionId']]['display-name']
            self.data[id_]=d;return {'data':deepcopy(d)}
        if operation=='test':return {'data':{'result-type':'SUCCEEDED'}}
        if operation in ('stop','start'):
            self.data[args[1]]['lifecycle-state']='INACTIVE' if operation=='stop' else 'ACTIVE';return {'accepted':True}
        raise AssertionError((resource,operation))
    def list(self,resource,extra=()):return [deepcopy(d) for d in self.data.values() if d['id'].startswith('ocid1.'+resource.replace('-','')+'.')]
    def get(self,resource,id_):return deepcopy(self.data[id_])
    def wait(self,resource,id_,desired=('ACTIVE',),timeout=1800):
        d=self.get(resource,id_)
        if d['lifecycle-state'] not in desired:raise AssertionError((d,desired))
        return d

class FakeGG:
    def __init__(self,c,p,sql):self.c=c;self.p=p;self.sql=sql;self.docs={};self.calls=[];self.globals=['GGSCHEMA ggadmin'];self.clock=0;self.executions={}
    def get(self,path,optional=False):
        if path=='/services/v2/config/files/GLOBALS':return {'lines':self.globals[:]}
        if path in ('/services/v2/extracts','/services/v2/replicats','/services/v2/sources','/services/v2/tasks'):return {'items':[{'name':k.rsplit('/',1)[1]} for k in self.docs if k.startswith(path+'/')]}
        if path.endswith('/info/history'):
            base=path[:-len('/info/history')]
            if '/tasks/' in base:return {'history':[{'status':'stopped','exitCode':0,'finished':now(),'killedManually':False}]}
            return {'history':deepcopy(self.executions.get(base,{}).get('history',[]))}
        if '/info/reports/' in path:
            base=path.split('/info/reports/')[0];doc=self.docs[base];ex=self.executions[base]
            lines=['Process id: '+str(ex['processId']),'Description: '+doc['description'],*doc['config'],"OGG-05381 database '"+self.c['source']['database']+"' at LSN 0x0000004b:000046a8:0004"]
            lines+=['OGG-02911 Processing table "'+t['schema']+'"."'+t['table']+'".' for t in self.p['tables']]
            return {'lines':lines}
        if path.endswith('/info/checkpoints'):return {'current':{'input':[],'output':[]}}
        if path.endswith('/info/status') or path.endswith('/info'):
            suffix='/info/status' if path.endswith('/info/status') else '/info';base=path[:-len(suffix)]
            d=self.docs[base];ex=self.executions.get(base,{})
            return {'status':d['status'],'processId':ex.get('processId'),'lastStarted':ex.get('lastStarted'),'lag':0,'sinceLagReported':0}
        if path in self.docs:return deepcopy(self.docs[path])
        if optional:return None
        raise AssertionError('Unexpected GG read '+path)
    def call(self,method,path,payload=None,optional=False):
        self.calls.append((method,path,deepcopy(payload)))
        if method=='GET':return self.get(path,optional)
        if path.endswith('/trandata/table'):
            if payload['operation']=='info':return {'tables':[{'tableName':payload['tableName'],'enabled':True}]}
            return {'completed':True}
        if path.endswith('/tables/checkpoint'):self.sql.checkpoints.add(payload['name']);return {'completed':True}
        if path=='/services/v2/config/files/GLOBALS':self.globals=payload['lines'][:];return {'updated':True}
        if method=='POST':
            if path in self.docs:raise AssertionError('Duplicate process creation')
            self.docs[path]=deepcopy(payload);return {'created':True}
        if method=='PATCH':
            d=self.docs[path];d['status']=payload['status']
            if payload['status']=='running':
                if path in self.executions:raise AssertionError('Repeated START')
                self.clock+=1;date=now();ex={'lastStarted':date,'processId':100+self.clock,'history':[]};self.executions[path]=ex
                if d.get('source')=='tables':
                    d['status']='stopped';ex['history']=[{'status':'stopped','exitCode':0,'started':date,'finished':date,'processId':ex['processId']}]
                if '/replicats/' in path and path.endswith('LOAD'):self.sql.loaded=True
            return {'updated':True}
        raise AssertionError((method,path))
    def schema(self,name):
        return {'properties':{'response':{'properties':{'begin':{'oneOf':[{'type':'object','required':['at'],'properties':{'at':{'oneOf':[{'description':'Position at transaction begin LSN','required':['lsn'],'additionalProperties':False,'properties':{'lsn':{'type':'string','pattern':r'^0x[0-9a-f]{8}:[0-9a-f]{8}:[0-9a-f]{4}$'}}}]}}}]}}}}}
    def wait(self,path,key='status',desired=('running',),timeout=900):
        d=self.get(path)
        if d.get(key) not in desired:raise AssertionError((path,d,desired))
        return d

class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.c,self.p,self.s,self.plan=execution_inputs()
        self.sql=FakeSQL(self.c,self.p);self.oci=FakeOCI();self.admins={}
    def tearDown(self):self.tmp.cleanup()
    def runner(self,j):
        def factory(url,user,password,cafile):
            side='source' if 'source' in url else 'target'
            if side not in self.admins:self.admins[side]=FakeGG(self.c,self.p,self.sql)
            return self.admins[side]
        return Executor(self.c,self.root/'environment.json',self.plan,j,self.oci,self.sql,factory)
    def test_complete_supported_pipeline_without_remote_access(self):
        # Public CA parser is independently tested; inject valid fixture behavior here.
        with Journal(self.root/'state',self.c) as j,patch('ggsetup.discovery.hidden',return_value="Aa1_fixture'password"),patch('ggsetup.executor.Path.read_bytes',return_value=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'),patch('ssl.SSLContext.load_verify_locations'):
            ex=self.runner(j)
            for stage in execution_plan.STAGES:
                result=ex.execute(stage,self.plan['execution_sha256'],True)
                self.assertEqual(result['status'],'stage_completed',stage)
            self.assertEqual(ex.health()['status'],'execution_health_healthy')
            self.assertTrue(j.data['proofs']['initial_verification']['matched'])
            self.assertEqual(j.data['proofs']['snapshot']['lsn'],'0x0000004b:000046a8:0004')
            self.assertNotIn("Aa1_fixture'password",json.dumps(j.data))
            starts=sum(m=='PATCH' and p.get('status')=='running' for gg in self.admins.values() for m,_,p in gg.calls)
            ex.execute('start-cdc',self.plan['execution_sha256'],True)
            self.assertEqual(starts,sum(m=='PATCH' and p.get('status')=='running' for gg in self.admins.values() for m,_,p in gg.calls))
    def test_target_input_trails_are_not_mistaken_for_replay(self):
        with Journal(self.root/'state',self.c) as j,patch('ggsetup.discovery.hidden',return_value='Aa1_fixture_password'),patch('ggsetup.executor.Path.read_bytes',return_value=b'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n'),patch('ssl.SSLContext.load_verify_locations'):
            ex=self.runner(j)
            for stage in execution_plan.STAGES:
                if stage=='load-initial':
                    target=ex.gg('target');original=target.get
                    def received(path,optional=False):
                        if '/trails/' in path and any('/sources/' in k and v.get('status')=='running' for k,v in ex.gg('source').docs.items()):return {'items':[{'name':'0'}]}
                        return original(path,optional)
                    target.get=received
                ex.execute(stage,self.plan['execution_sha256'],True)
            self.assertTrue(j.data['proofs']['initial_verification']['matched'])
    def test_password_confirmation_failure_leaves_no_mutation_intent(self):
        with Journal(self.root/'state',self.c) as j,patch('ggsetup.discovery.hidden',side_effect=['first','different']):
            ex=self.runner(j)
            with self.assertRaises(SetupError):ex.execute('accounts',self.plan['execution_sha256'],True)
            self.assertEqual(j.data['intents'],{});self.assertEqual(self.sql.executed,[])
    def test_manifest_cannot_inject_target_type_sql(self):
        self.p['tables'][0]['columns'][0]['target_type']='integer); DROP DATABASE anything; --'
        with self.assertRaises(SetupError):execution_plan.build(self.c,self.p,self.s)
    def test_schema_positioning_rejects_missing_or_wrong_semantics(self):
        with self.assertRaises(SetupError):execution_plan.verify_lsn_schema({},'0x0000004b:000046a8:0004')
        gg=FakeGG(self.c,self.p,self.sql);doc=gg.schema('extract')
        self.assertEqual(execution_plan.verify_lsn_schema(doc,'0x0000004b:000046a8:0004')['lsn'],'0x0000004b:000046a8:0004')
        doc['properties']['response']['properties']['begin']['oneOf'][0]['properties']['at']['oneOf'][0]['description']='Position at commit SCN'
        with self.assertRaises(SetupError):execution_plan.verify_lsn_schema(doc,'0x0000004b:000046a8:0004')
    def test_invalid_unicode_and_nul_are_not_logged_or_normalized(self):
        for v in ('bad\0text','bad\ud800'):
            with self.assertRaises(SetupError) as error:verification.canonical({'source_type':'nvarchar'},v)
            self.assertNotIn(v,str(error.exception))
    def test_existing_cdc_consumer_is_rejected_before_account_writes(self):
        from ggsetup import discovery
        original=self.sql.query
        def existing(side,query,limit=10000):
            result=original(side,query,limit)
            if side=='source' and query==discovery.SOURCE_QUERIES['tables']:result[0]['is_tracked_by_cdc']=True
            return result
        with Journal(self.root/'state',self.c) as j,patch.object(self.sql,'query',side_effect=existing):
            ex=self.runner(j)
            with self.assertRaises(SetupError):ex.execute('accounts',self.plan['execution_sha256'],True)
            self.assertEqual(j.data['intents'],{});self.assertEqual(self.sql.executed,[])
    def test_settings_can_change_only_before_any_mutation_intent(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind()
            settings=deepcopy(self.s);settings['ocpu_count']=2;new=execution_plan.build(self.c,self.p,settings)
            candidate=Executor(self.c,self.root/'environment.json',new,j,self.oci,self.sql);candidate.bind()
            self.assertEqual(j.data['execution_sha256'],new['execution_sha256'])
            j.intent('unknown',{'x':1})
            with self.assertRaises(SetupError):self.runner(j)
    def test_approval_pause_and_stage_order_before_mutations(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j)
            for stage,sha,paused in [('accounts','wrong',True),('accounts',self.plan['execution_sha256'],False),('provision',self.plan['execution_sha256'],True)]:
                with self.assertRaises(SetupError):ex.execute(stage,sha,paused)
            self.assertEqual(self.oci.calls,[]);self.assertEqual(self.sql.executed,[])
    def test_unknown_operation_never_replays(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind();called=[]
            def fail():called.append(1);raise SetupError('Lost response')
            with self.assertRaises(SetupError):ex.once('request',{'x':1},fail)
            with self.assertRaises(SetupError):ex.once('request',{'x':1},fail)
            self.assertEqual(called,[1]);self.assertEqual(j.data['intents']['request']['status'],'pending')
    def test_payload_drift_rejected(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind();ex.once('request',{'x':1},lambda:{'id':'one'})
            with self.assertRaises(SetupError):ex.once('request',{'x':2},lambda:{'id':'two'})
    def test_resource_reconciliation_requires_exact_owned_readback(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind()
            payload={'displayName':'Fixture','compartmentId':self.c['oci']['compartment_id'],'technologyType':'MICROSOFT_SQLSERVER','host':'source.example.test','passwordSecretId':self.s['capture_secret_id'],'freeformTags':{'ggsetup_environment':self.c['environment'],'ggsetup_plan':self.plan['execution_sha256']}}
            j.data.setdefault('resource_requests',{})['connection:source']={'resource':'connection','payload':payload}
            j.intent('create:connection:source',payload)
            d=self.oci.call('connection','create-microsoft-sqlserver-connection',payload=payload)['data']
            saved=self.oci.data[d['id']]['freeform-tags'];self.oci.data[d['id']]['freeform-tags']={}
            with self.assertRaises(SetupError):ex.reconcile_resource('connection:source',d['id'])
            self.oci.data[d['id']]['freeform-tags']=saved
            result=ex.reconcile_resource('connection:source',d['id'])
            self.assertEqual(result['status'],'resource_reconciled_no_remote_mutation')
    def test_pin_rejects_changed_process(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind()
            j.intent('initial:start:extract',{});item=j.data['intents']['initial:start:extract'];j.acknowledge('initial:start:extract',item['token'],{'ok':True})
            with patch.object(ex,'process_info',return_value={'lastStarted':now(),'processId':123}):ex.pin('initial','extract')
            with patch.object(ex,'process_info',return_value={'lastStarted':now(),'processId':124}),self.assertRaises(SetupError):ex.pin('initial','extract')
    def test_retention_gap_prevents_first_cdc_start(self):
        with Journal(self.root/'state',self.c) as j:
            ex=self.runner(j);ex.bind();j.data['proofs']['snapshot']={'lsn':'0x0000004b:000046a8:0004'}
            with patch.object(self.sql,'query',return_value=[{'schema_name':'sales','table_name':'Orders','min_lsn':'0x99999999999999999999','max_lsn':'0xffffffffffffffffffff'}]),self.assertRaises(SetupError):ex.retention()
    def test_corrupt_target_fails_whole_value_comparison(self):
        self.sql.loaded=True;self.sql.corrupt=True
        with self.assertRaises(SetupError):verification.compare(self.sql,self.p['tables'],{'sales.Orders':1})
    def test_edited_execution_plan_cannot_run(self):
        self.plan['target_sql']='DROP DATABASE anything'
        with Journal(self.root/'state',self.c) as j,self.assertRaises(SetupError):self.runner(j)
    def test_unsupported_float_blocks_execution_before_changes(self):
        self.p['tables'][0]['columns'][1]['source_type']='float'
        with self.assertRaises(SetupError):execution_plan.build(self.c,self.p,self.s)
    def test_definitions_use_wss_correct_trails_and_no_rejected_parameters(self):
        for kind in ('initial','cdc'):
            d=execution_plan.definitions(self.c,self.p,'https://target.example.test',kind,'marker','0x0000004b:000046a8:0004')
            self.assertTrue(d['path']['document']['target']['uri'].startswith('wss://'))
            text=json.dumps(d)
            for bad in ('targetInitiated','NOBATCHSQL','MANAGEDCCLEANUP','_SKIPNULLVALIDATION','HANDLECOLLISIONS'):self.assertNotIn(bad,text)
    def test_sql_account_values_are_quoted_and_source_gets_no_sysadmin(self):
        sql=execution_plan.source_account_sql(self.c,"Aa1'quote")
        self.assertIn("N'Aa1''quote'",sql);self.assertNotIn('ADD MEMBER [sysadmin]',sql);self.assertIn('SQLAgentReaderRole',sql)
    def test_decimal_canonical_does_not_round_38_digits(self):
        c={'source_type':'decimal'}
        self.assertEqual(verification.canonical(c,'12345678901234567890123456789012.123456'),'12345678901234567890123456789012.123456')
    def test_timestamp_padding_and_seventh_digit_gate(self):
        c={'source_type':'datetime'}
        self.assertEqual(verification.canonical(c,'2026-11-12T12:00:00.003'),'2026-11-12T12:00:00.003000')
        with self.assertRaises(SetupError):verification.canonical(c,'2026-11-12T12:00:00.0030001')
    def test_unicode_whitespace_and_null_are_distinct(self):
        c={'source_type':'nvarchar'}
        self.assertEqual(verification.canonical(c,'a\u2028  '),'a\u2028  ')
        self.assertNotEqual(verification.canonical(c,None),verification.canonical(c,''))
    def test_plan_requires_supported_schema_and_complete_secret_settings(self):
        self.s['capture_secret_id']='password-not-a-secret-id'
        with self.assertRaises(SetupError):execution_plan.build(self.c,self.p,self.s)

if __name__=='__main__':unittest.main()
