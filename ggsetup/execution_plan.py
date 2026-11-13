"""Reviewed execution settings and deterministic pipeline definitions."""
import base64
from pathlib import Path
import re
from .common import require,digest
from .config import shape,text,ocid,names,fingerprint
from .planner import artifacts,quote,qname,gg_identifier

STAGES=('accounts','target-schema','provision','connections','capture-schema','logging','prepare-initial','extract-initial','prepare-cdc','load-initial','verify-initial','start-cdc')

def example():
    return {'schema_version':1,'license_model':'LICENSE_INCLUDED','environment_type':'DEVELOPMENT_OR_TESTING','ocpu_count':1,
       'source_version':'REPLACE_WITH_REGIONAL_SQLSERVER_BUILD','target_version':'REPLACE_WITH_REGIONAL_POSTGRESQL_BUILD',
       'source_admin_user':'sa','target_admin_user':'admin','console_user':'oggadmin','accounts_mode':'create',
       'nsg_ids':['ocid1.networksecuritygroup.oc1..REPLACE_ME'],
       'source_admin_secret_id':'ocid1.vaultsecret.oc1..REPLACE_ME','target_admin_secret_id':'ocid1.vaultsecret.oc1..REPLACE_ME',
       'capture_secret_id':'ocid1.vaultsecret.oc1..REPLACE_ME','apply_secret_id':'ocid1.vaultsecret.oc1..REPLACE_ME',
       'cleanup_days':3,'configure_unlimited_lob':False,'deployment_ca_file':''}

def validate(s,c):
    shape(s,example().keys(),'execution settings')
    require(re.fullmatch(r'[a-z_][a-z0-9_]*',c['goldengate']['schema']) is not None,'Execution GGSCHEMA must use lowercase ASCII identifier syntax.')
    require(c['goldengate']['schema'] not in ('public','dbo','cdc','sys','information_schema','pg_catalog'),'Use a dedicated GoldenGate management schema.')
    require(s['schema_version']==1,'Unsupported execution settings version.')
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{2,29}',s['console_user']) is not None,'Console username must use 3–30 ASCII letters/digits/underscores.')
    require(s['license_model'] in ('LICENSE_INCLUDED','BRING_YOUR_OWN_LICENSE'),'Choose a license model explicitly.')
    require(type(s['ocpu_count']) is int and 1<=s['ocpu_count']<=8,'ocpu_count must be 1–8.')
    require(s['environment_type'] in ('DEVELOPMENT_OR_TESTING','PRODUCTION'),'Choose the deployment environment type explicitly.')
    require(s['accounts_mode'] in ('create','existing'),'accounts_mode must be create/existing.')
    for k in ('source_version','target_version','source_admin_user','target_admin_user','console_user'):text(s[k],k)
    require(s['source_version'].startswith('oggmssql:') and s['target_version'].startswith('oggpostgresql:'),'Choose the correct regional GoldenGate technology builds.')
    for k in ('source_admin_secret_id','target_admin_secret_id','capture_secret_id','apply_secret_id'):ocid(s[k],'vaultsecret',k)
    require(isinstance(s['nsg_ids'],list) and bool(s['nsg_ids']) and len(set(s['nsg_ids']))==len(s['nsg_ids']),'Provide distinct existing NSG OCIDs.')
    for v in s['nsg_ids']:ocid(v,'networksecuritygroup','nsg_ids')
    ocid(c['goldengate']['subnet_id'],'subnet','goldengate.subnet_id')
    require(type(s['configure_unlimited_lob']) is bool,'configure_unlimited_lob must be boolean.')
    require(type(s['cleanup_days']) is int and 1<=s['cleanup_days']<=30,'cleanup_days must be 1–30.')
    text(s['deployment_ca_file'],'deployment_ca_file',4096,empty=True)
    require('REPLACE_' not in str(s) and 'REPLACE_' not in c['goldengate']['subnet_id'],'Replace execution template values.')
    return s

def validate_manifest(p):
    require(isinstance(p,dict) and isinstance(p.get('tables'),list) and bool(p['tables']),'Schema manifest must contain tables.')
    seen=set()
    fixed={'int':'integer','smallint':'smallint','tinyint':'smallint','bigint':'bigint','bit':'boolean','money':'numeric(19,4)','smallmoney':'numeric(10,4)','uniqueidentifier':'uuid','binary':'bytea','varbinary':'bytea','date':'date','datetime':'timestamp(6) without time zone','smalldatetime':'timestamp(6) without time zone'}
    for t in p['tables']:
        require(isinstance(t,dict) and all(k in t for k in ('schema','table','columns','primary_key','unique_indexes')),'Invalid table manifest.')
        gg_identifier(t['schema']);gg_identifier(t['table']);identity=(t['schema'],t['table']);require(identity not in seen,'Duplicate manifest table.');seen.add(identity)
        require(isinstance(t['columns'],list) and bool(t['columns']),'Empty manifest columns.');columns={}
        for col in t['columns']:
            gg_identifier(col['name']);require(col['name'] not in columns,'Duplicate manifest column.');columns[col['name']]=col
            require(type(col.get('nullable')) is bool and type(col.get('identity')) is bool,'Invalid column flags.')
            source=col.get('source_type');target=col.get('target_type');require(isinstance(source,str) and isinstance(target,str),'Invalid type mapping.')
            if source in fixed:require(target==fixed[source],'Unsafe or inconsistent fixed type mapping.')
            elif source in ('decimal','numeric'):
                match=re.fullmatch(r'numeric\((\d+),(\d+)\)',target);require(match is not None and 0<=int(match[2])<=int(match[1])<=38 and int(match[1])>=1,'Invalid numeric mapping.')
            elif source in ('varchar','nvarchar','char','nchar'):
                pattern=r'character varying\(([1-9][0-9]*)\)' if source in ('varchar','nvarchar') else r'character\(([1-9][0-9]*)\)'
                match=re.fullmatch(pattern,target);require((source in ('varchar','nvarchar') and target=='text') or (match is not None and int(match[1])<=8000),'Invalid character mapping.')
            elif source in ('datetime2','time'):
                require(re.fullmatch(r'timestamp\([0-6]\) without time zone' if source=='datetime2' else r'time\([0-6]\) without time zone',target) is not None,'Invalid temporal mapping.')
            else:require(False,'Execution verification adapter does not yet support '+source+'.')
        require(isinstance(t['primary_key'],list) and bool(t['primary_key']) and len(t['primary_key'])==len(set(t['primary_key'])) and all(k in columns and not columns[k]['nullable'] for k in t['primary_key']),'Invalid primary key manifest.')
        require(isinstance(t['unique_indexes'],list),'Invalid unique indexes.')
        for idx in t['unique_indexes']:
            require(isinstance(idx.get('source_name'),str) and idx['source_name'] and isinstance(idx.get('columns'),list) and bool(idx['columns']) and all(k in columns for k in idx['columns']),'Invalid unique index manifest.')

def build(c,p,s):
    validate(s,c);validate_manifest(p)
    require(p.get('schema_version')==1 and p.get('report_type')=='ggsetup_schema_plan','Use a generated ggsetup schema plan.')
    require(p.get('status')=='schema_plan_ready' and p.get('configuration_sha256')==fingerprint(c) and not p.get('blockers'),'Execution requires a supported schema plan for this configuration.')
    # The comparison engine must support every planned column before any changes.
    exact={'int','bigint','smallint','tinyint','bit','decimal','numeric','money','smallmoney','char','nchar','varchar','nvarchar','binary','varbinary','uniqueidentifier','date','datetime','smalldatetime','datetime2','time'}
    for t in p['tables']:
        for col in t['columns']:require(col['source_type'] in exact,'Execution verification adapter does not yet support '+col['source_type']+'; no changes permitted.')
    result={'schema_version':1,'report_type':'ggsetup_execution_plan','configuration_sha256':fingerprint(c),
      'schema_plan':p,'settings':s,'names':names(c),'stages':list(STAGES),
      'prerequisites':['Existing private subnet and NSGs with DB/console/WSS routing','IAM/Vault access for provided four secrets',
        'Target SQL database exists; source/target administrator logins available','Source trusted TLS or explicit configured test bypass',
        'Application writes and schema changes paused from preparation through full verification/CDC startup',
        'Isolated source SQL database: no existing CDC consumers or concurrent installers',
        'Selected SQL Server edition/GG builds/managed PostgreSQL service support reviewed'],
      'policy':{'no_automatic_rollback':True,'no_unknown_outcome_retries':True,'no_position_resets':True,'no_data_collision_overrides':True},
      'source_cleanup_changes':{'drop_source_database_native_cleanup_job':True,'goldengate_max_retention_days':s['cleanup_days'],'schedule_minutes':10},
      'source_empty_deployment_restart':True,
      'source_account_changes':{'login':c['source']['capture_user'],'schema':c['goldengate']['schema'],'roles':['source db_owner','msdb SQLAgentReaderRole'],'sysadmin':False,'enable_database_CDC':True,'enable_snapshot_isolation':True},
      'billable_changes':{'deployments':2,'ocpus_each':s['ocpu_count'],'license_model':s['license_model'],'environment_type':s['environment_type'],'autoscaling':False},
      'target_sql':artifacts(c,p)['target-schema.review.sql'],
      'source_sql_preview':source_account_sql(c,'PASSWORD_PROMPTED_IN_MEMORY')+source_settings_sql(c),
      'instance_lob_setting':-1 if s['configure_unlimited_lob'] else 'unchanged'}
    initial_preview=definitions(c,p,'https://TARGET_DEPLOYMENT.example.invalid','initial','ggsetup:EXECUTION_PLAN_SHA256')
    cdc_preview=definitions(c,p,'https://TARGET_DEPLOYMENT.example.invalid','cdc','ggsetup:EXECUTION_PLAN_SHA256','0x00000000:00000000:0001')
    cdc_preview['extract']['document']['begin']={'at':{'lsn':'FROM_VERIFIED_FRESH_SNAPSHOT'}}
    result['pipeline_previews']={'initial':initial_preview,'cdc':cdc_preview,'note':'Preview placeholders are never executed; target origin comes from OCI deployment readback and LSN from verified initial report.'}
    result['execution_sha256']=digest(result)
    return result

def validate_plan(c,plan):
    require(isinstance(plan,dict) and 'schema_plan' in plan and 'settings' in plan,'Expected a compiled execution plan.')
    expected=build(c,plan['schema_plan'],plan['settings'])
    require(expected==plan,'Execution plan was changed or no longer matches its compiler/configuration.')
    return plan

def sqlid(v):return '['+v.replace(']',']]')+']'
def sqlstr(v):return "N'"+v.replace("'","''")+"'"
def target_guard(c):return "DO $g$ BEGIN IF current_database() <> convert_from(decode('"+c['target']['database'].encode().hex()+"','hex'),'UTF8') THEN RAISE EXCEPTION 'Wrong database'; END IF; END $g$;\n"

def source_account_sql(c,password):
    db=sqlid(c['source']['database']);user=sqlid(c['source']['capture_user']);schema=sqlid(c['goldengate']['schema'])
    uname=sqlstr(c['source']['capture_user']);sname=sqlstr(c['goldengate']['schema'])
    return f"""SET NOCOUNT ON; SET XACT_ABORT ON;
USE [master];
IF SUSER_ID({uname}) IS NOT NULL THROW 51000,'Capture login already exists; no adoption or password reset performed',1;
USE {db};
IF USER_ID({uname}) IS NOT NULL OR SCHEMA_ID({sname}) IS NOT NULL THROW 51000,'Capture user/schema already exists',1;
USE [msdb]; IF USER_ID({uname}) IS NOT NULL THROW 51000,'msdb capture user already exists',1;
BEGIN TRANSACTION;
USE [master]; CREATE LOGIN {user} WITH PASSWORD={sqlstr(password)}, CHECK_POLICY=ON, CHECK_EXPIRATION=OFF;
USE {db}; CREATE USER {user} FOR LOGIN {user};
EXEC({sqlstr('CREATE SCHEMA '+schema+' AUTHORIZATION '+user)});
ALTER ROLE [db_owner] ADD MEMBER {user};
USE [msdb]; CREATE USER {user} FOR LOGIN {user}; ALTER ROLE [SQLAgentReaderRole] ADD MEMBER {user};
COMMIT TRANSACTION;
GO
"""

def source_settings_sql(c):
    db=sqlid(c['source']['database'])
    return f"""SET NOCOUNT ON; USE {db};
IF DB_NAME()<>{sqlstr(c['source']['database'])} THROW 51000,'Wrong source database',1;
IF (SELECT is_cdc_enabled FROM sys.databases WHERE database_id=DB_ID())=0 EXEC sys.sp_cdc_enable_db;
ALTER DATABASE {db} SET ALLOW_SNAPSHOT_ISOLATION ON;
GO
"""

def target_account_sql(c):
    # Password is supplied to psql through a separate :variable literal in memory
    # by the caller; source SQL values never become shell text.
    user=quote(c['target']['apply_user']);schema=quote(c['goldengate']['schema'])
    return 'BEGIN;\n'+target_guard(c)+"DO $g$ BEGIN IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=convert_from(decode('"+c['target']['apply_user'].encode().hex()+"','hex'),'UTF8')) THEN RAISE EXCEPTION 'Apply role already exists'; END IF; END $g$;\n"+'CREATE ROLE '+user+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'new_apply_password';\n"+'CREATE SCHEMA '+schema+' AUTHORIZATION '+user+';\nCOMMIT;\n'

def grants(c,p):
    user=quote(c['target']['apply_user']);lines=['BEGIN;',target_guard(c)]
    for schema in sorted({t['schema'] for t in p['tables']}):lines.append('GRANT USAGE ON SCHEMA '+quote(schema)+' TO '+user+';')
    for t in p['tables']:lines.append('GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON TABLE '+qname(t['schema'],t['table'])+' TO '+user+';')
    lines+=['COMMIT;'];return '\n'.join(lines)+'\n'

def definitions(c,p,target_url,kind,marker,lsn=None):
    n=names(c);initial=kind=='initial';key='initial' if initial else 'cdc';trail=n[key+'_trail']
    extract=n['initial_extract' if initial else 'cdc_extract'];rep=n['initial_replicat' if initial else 'cdc_replicat'];path=n[key+'_path']
    sa=c['goldengate']['source_alias'];ta=c['goldengate']['target_alias'];na=c['goldengate']['network_alias']
    conf=['EXTRACT '+extract,'USERIDALIAS '+sa+' DOMAIN OracleGoldenGate']
    if initial:conf+=['INITIALLOADOPTIONS USESNAPSHOT','EXTFILE ./dirdat/'+trail+', MEGABYTES 100']
    else:
        require(isinstance(lsn,str) and re.fullmatch(r'0x[0-9a-fA-F]{8}:[0-9a-fA-F]{8}:[0-9a-fA-F]{4}',lsn) and int(lsn[2:].replace(':',''),16)>0,'A verified nonzero snapshot LSN is required.')
        conf+=['EXTTRAIL ./dirdat/'+trail]
    rconf=['REPLICAT '+rep,'USERIDALIAS '+ta+' DOMAIN OracleGoldenGate','GROUPTRANSOPS 1','REPERROR (DEFAULT, ABEND)']
    for t in p['tables']:
        fq=qname(t['schema'],t['table']);cols=[gg_identifier(x['name']) for x in t['columns']]
        conf+=['TABLE '+fq+', COLS ('+', '.join(cols)+');']
        rconf+=['MAP '+fq+', TARGET '+fq+', COLMAP ('+', '.join(x+' = '+x for x in cols)+');']
    managed={'autoStart':{'enabled':False},'autoRestart':{'enabled':False}}
    ex={'source':'tables' if initial else 'tranlogs','status':'stopped','description':marker,'credentials':{'alias':sa,'domain':'OracleGoldenGate'},'config':conf,'managedProcessSettings':managed}
    if not initial:ex.update(begin={'at':{'lsn':lsn}},targets=[{'name':trail,'path':'./dirdat','sizeMB':100}])
    checkpoint=c['goldengate']['schema']+'.'+n[key+'_checkpoint']
    return {'extract':{'name':extract,'document':ex},'path':{'name':path,'document':{
       'name':path,'description':marker,'status':'stopped','begin':{'sequence':0,'offset':0},
       'source':{'uri':'trail://localhost/services/v2/sources?trail=dirdat/'+trail},
       'target':{'uri':target_url.replace('https://','wss://',1).rstrip('/')+'/services/v2/targets?trail=dirdat/'+trail,'authenticationMethod':{'domain':'Network','alias':na}},
       'options':{'autoRestart':{'retries':0}}}},'replicat':{'name':rep,'document':{
       'description':marker,'status':'stopped','mode':{'type':'nonintegrated','parallel':False},'credentials':{'domain':'OracleGoldenGate','alias':ta},
       'source':{'name':trail,'path':'./dirdat'},'begin':{'sequence':0,'offset':0},'checkpoint':{'table':checkpoint},'config':rconf,'managedProcessSettings':managed}}}


def verify_lsn_schema(doc,lsn):
    begin=doc.get('properties',{}).get('response',{}).get('properties',{}).get('begin',{})
    for item in begin.get('oneOf',[]):
        if item.get('type')!='object' or item.get('required')!=['at']:continue
        for branch in item.get('properties',{}).get('at',{}).get('oneOf',[]):
            rule=branch.get('properties',{}).get('lsn')
            if not isinstance(rule,dict) or branch.get('required')!=['lsn']:continue
            require(branch.get('additionalProperties') is False and 'transaction begin lsn' in branch.get('description','').lower(),'Installed LSN positioning semantics differ.')
            require(rule.get('type')=='string' and isinstance(rule.get('pattern'),str) and re.fullmatch(rule['pattern'],lsn) is not None and rule.get('minLength',0)<=len(lsn)<=rule.get('maxLength',999),'Snapshot LSN does not satisfy installed Extract schema.')
            return {'lsn':lsn,'schema_sha256':digest(doc)}
    require(False,'Installed Extract schema has no verified transaction-begin LSN positioning support.')
