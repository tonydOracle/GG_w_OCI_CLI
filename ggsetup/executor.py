"""Staged setup executor. No rollback, destructive retry, replay or reposition."""
import base64
from copy import deepcopy
import datetime as dt
from pathlib import Path
import re
import time
from . import discovery,planner,verification
from .adapters import OCI,GG,SQL
from .common import require,SetupError,digest,now
from .config import names
from .execution_plan import STAGES,validate_plan,definitions,source_account_sql,source_settings_sql,target_account_sql,grants,sqlid,sqlstr,verify_lsn_schema


def subset(expected,actual,label):
    if isinstance(expected,dict):
        require(isinstance(actual,dict),label+' readback missing.')
        for k,v in expected.items():require(k in actual,label+' readback lacks '+k);subset(v,actual[k],label+'.'+k)
    else:require(expected==actual,label+' readback differs.')

def stamp(v):
    require(isinstance(v,str),'Missing execution timestamp.')
    return dt.datetime.fromisoformat(v.replace('Z','+00:00'))

class Executor:
    def __init__(self,c,config_path,plan,journal,oci=None,sql=None,gg_factory=GG):
        validate_plan(c,plan)
        self.c=c;self.path=config_path;self.plan=plan;self.p=plan['schema_plan'];self.s=plan['settings'];self.j=journal;self.oci=oci or OCI(c);self.gg_factory=gg_factory;self.admins={};self.requires_unlimited_lob=False
        sqlcfg=deepcopy(c);sqlcfg['source']['inspection_user']=self.s['source_admin_user'];sqlcfg['target']['inspection_user']=self.s['target_admin_user']
        self.sql=sql or SQL(sqlcfg,config_path)
        previous=journal.data.get('execution_sha256')
        unchanged=previous is None or previous==plan['execution_sha256']
        empty=not journal.data.get('intents') and not journal.data.get('resources') and not any(v=='completed' for v in journal.data.get('stages',{}).values())
        require(unchanged or empty,'Another execution plan with mutation history is bound to this journal. Preserve it and inspect before changing settings.')
    def bind(self):
        self.j.data['execution_sha256']=self.plan['execution_sha256'];self.j.data.setdefault('stages',{});self.j.data.setdefault('resources',{});self.j.data.setdefault('proofs',{});self.j.save()
    def once(self,key,payload,action):
        prior=self.j.data['intents'].get(key)
        if prior:
            require(prior['request_sha256']==digest(payload),'Saved operation payload differs: '+key)
            require(prior['status']=='acknowledged','Unresolved operation '+key+'. Observe/reconcile its outcome; no automatic retry.')
            return prior['evidence']
        token=self.j.intent(key,payload)
        result=action();require(isinstance(result,dict) and bool(result),'Operation returned no verifiable evidence.')
        self.j.acknowledge(key,token,result);return result
    def resource_matches(self,resource,payload,d):
        mapping={'compartmentId':'compartment-id','displayName':'display-name','cpuCoreCount':'cpu-core-count','isAutoScalingEnabled':'is-auto-scaling-enabled','licenseModel':'license-model','environmentType':'environment-type','subnetId':'subnet-id','deploymentType':'deployment-type','technologyType':'technology-type','host':'host','port':'port','databaseName':'database-name','username':'username','securityProtocol':'security-protocol','routingMethod':'routing-method','deploymentId':'deployment-id','sslMode':'ssl-mode','shouldValidateServerCertificate':'should-validate-server-certificate'}
        for source,target in mapping.items():
            if source in payload:require(d.get(target)==payload[source],'OCI resource readback differs: '+source)
        auth=d.get('ogg-data',{}) if resource=='deployment' else d
        if 'passwordSecretId' in payload:require(auth.get('password-secret-id')==payload['passwordSecretId'],'OCI password secret reference differs.')
        if resource=='deployment':
            require(d.get('is-public') is False,'Private deployment required.')
            require(auth.get('admin-username')==payload['adminUsername'] and auth.get('ogg-version')==payload['oggVersion'],'Deployment administrator/build differs.')
        return d
    def resource(self,key,resource,payload,existing=''):
        record=self.j.data['resources'].get(key)
        if record:
            pending=self.j.data['intents'].get('create:'+key)
            require(pending is None or pending['status']=='acknowledged','Recorded resource has an unresolved create request; inspect without another mutation.')
            d=self.oci.wait(resource,record['id']);require(d.get('compartment-id')==self.c['oci']['compartment_id'],'Resource compartment changed.');return self.resource_matches(resource,payload,d)
        if existing:
            d=self.oci.wait(resource,existing);require(d.get('compartment-id')==self.c['oci']['compartment_id'],'Reused deployment is in another compartment.')
        else:
            name=payload['displayName']
            require(not any(x.get('display-name')==name for x in self.oci.list(resource)),'A resource with this name already exists; no automatic adoption: '+name)
            command=payload.pop('_command', 'create')
            payload.setdefault('freeformTags',{'ggsetup_environment':self.c['environment'],'ggsetup_plan':self.plan['execution_sha256']})
            self.j.data.setdefault('resource_requests',{})[key]={'resource':resource,'payload':deepcopy(payload)};self.j.save()
            def create():
                data=self.oci.call(resource,command,payload=payload).get('data') or {};require(data.get('id'),'OCI returned no resource OCID; intent retained.')
                # Persist the ID BEFORE waiting; a wait timeout must never lose it.
                self.j.data['resources'][key]={'id':data['id'],'request_sha256':digest(payload)};self.j.save()
                return {'id':data['id']}
            r=self.once('create:'+key,payload,create);d=self.oci.wait(resource,r['id'])
        self.resource_matches(resource,payload,d)
        self.j.data['resources'][key]={'id':d['id'],'request_sha256':digest(payload)};self.j.save();return d
    def deployment(self,side):
        rec=self.j.data.get('resources',{}).get('deployment:'+side);require(rec,'Deployment not recorded: '+side)
        d=self.oci.wait('deployment',rec['id'])
        require(d.get('compartment-id')==self.c['oci']['compartment_id'] and d.get('deployment-type')==('DATABASE_MICROSOFT_SQLSERVER' if side=='source' else 'DATABASE_POSTGRESQL'),'Deployment identity/type changed.')
        require(d.get('is-public') is False,'A private deployment is required.')
        return d
    def gg(self,side):
        if side not in self.admins:
            d=self.deployment(side);password=discovery.hidden(side+' GoldenGate console password ('+self.s['console_user']+'): ')
            cafile=self.s['deployment_ca_file'] or None
            if cafile:
                p=Path(cafile).expanduser();cafile=str(p if p.is_absolute() else Path(self.path).absolute().parent/p)
            self.admins[side]=self.gg_factory(d['deployment-url'],self.s['console_user'],password,cafile)
        return self.admins[side]
    def source_identity(self):
        r=self.sql.query('source',discovery.SOURCE_QUERIES['identity'],1)
        require(len(r)==1 and r[0].get('database_name')==self.c['source']['database'],'Wrong source database.')
    def target_identity(self):
        r=self.sql.query('target',discovery.TARGET_QUERIES['identity'],1);tls=self.sql.query('target',discovery.TARGET_QUERIES['tls'],1)
        require(len(r)==1 and r[0].get('database_name')==self.c['target']['database'] and r[0].get('is_standby') is False and len(tls)==1 and tls[0].get('ssl') is True,'Target identity/TLS check failed.')
    def source_shape(self):
        self.source_identity()
        visibility=self.sql.query('source',discovery.SOURCE_QUERIES['visibility'],1)
        require(len(visibility)==1 and visibility[0].get('view_definition') in (True,1),'Complete source metadata visibility is required.')
        cols=self.sql.query('source',discovery.SOURCE_QUERIES['columns'],1000000);keys=self.sql.query('source',discovery.SOURCE_QUERIES['keys'],1000000)
        tables=self.sql.query('source',discovery.SOURCE_QUERIES['tables'],1000000);self.current_source_tables=tables
        scope=self.c['scope'];included=set(map(tuple,scope['include_tables']));excluded=set(map(tuple,scope['exclude_tables']));schemas=set(scope['exclude_schemas'])|{'sys','cdc','INFORMATION_SCHEMA',self.c['goldengate']['schema']}
        selected=[x for x in tables if x['schema_name'] not in schemas and (x['schema_name'],x['table_name']) not in excluded and (scope['mode']=='all' or (x['schema_name'],x['table_name']) in included)]
        require({(x['schema_name'],x['table_name']) for x in selected}=={(x['schema'],x['table']) for x in self.p['tables']},'Source table scope changed since planning.')
        for table in selected:
            for flag in ('is_memory_optimized','is_filetable','is_external','has_row_security'):require(planner.bit(table.get(flag),flag) is False,'Source table feature changed.')
            require(table.get('temporal_type')==0,'Temporal table change requires review.')
        for t in self.p['tables']:
            selected=sorted([x for x in cols if (x['schema_name'],x['table_name'])==(t['schema'],t['table'])],key=lambda x:x['ordinal'])
            require(len(selected)==len(t['columns']),'Source columns changed.')
            self.requires_unlimited_lob |= any(x.get('max_length')==-1 for x in selected)
            for a,e in zip(selected,t['columns']):
                require(a['column_name']==e['name'] and a['data_type']==e['source_type'] and planner.target_type(a)==e['target_type'] and bool(a['is_nullable'])==e['nullable'] and bool(a['is_identity'])==e['identity'],'Source column/type changed.')
            pk=sorted([x for x in keys if (x['schema_name'],x['table_name'])==(t['schema'],t['table']) and x['is_primary_key'] and not x['is_included_column']],key=lambda x:x['key_ordinal'])
            require([x['column_name'] for x in pk]==t['primary_key'] and all(not x['is_disabled'] and not x['has_filter'] for x in pk),'Source primary key changed.')
    def target_shape(self):
        self.target_identity()
        rows=self.sql.query('target',"SELECT n.nspname AS schema_name,c.relname AS table_name,a.attname AS column_name,a.attnum AS ordinal,pg_catalog.format_type(a.atttypid,a.atttypmod) AS data_type,a.attnotnull AS not_null,c.relkind,c.relrowsecurity FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p') AND n.nspname NOT LIKE 'pg_%' ORDER BY n.nspname,c.relname,a.attnum",1000000)
        for t in self.p['tables']:
            found=[x for x in rows if (x['schema_name'],x['table_name'])==(t['schema'],t['table'])]
            require(len(found)==len(t['columns']),'Target column count changed.')
            for a,e in zip(found,t['columns']):
                require(a['column_name']==e['name'] and a['data_type']==e['target_type'] and a['not_null']==(not e['nullable']) and a['relkind']=='r' and a['relrowsecurity'] is False,'Target type/nullability/table feature changed.')
            pgtext=lambda value: "E'"+value.replace('\\','\\\\').replace("'","''")+"'"
            user=pgtext(self.c['target']['apply_user']);fq=pgtext(planner.qname(t['schema'],t['table']))
            expression=' AND '.join('has_table_privilege('+user+','+fq+','+planner.literal(p)+')' for p in ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE'))
            permissions=self.sql.query('target','SELECT '+expression+' AS can_apply',1)
            require(len(permissions)==1 and permissions[0].get('can_apply') is True,'Apply table privileges are incomplete.')
        schema=pgtext(self.c['goldengate']['schema']);user=pgtext(self.c['target']['apply_user'])
        permissions=self.sql.query('target',"SELECT has_schema_privilege("+user+','+schema+",'USAGE') AS usable,has_schema_privilege("+user+','+schema+",'CREATE') AS creatable",1)
        require(len(permissions)==1 and permissions[0]=={'usable':True,'creatable':True},'Checkpoint schema privileges are incomplete.')
    def account_checks(self):
        u=sqlstr(self.c['source']['capture_user']);sch=sqlstr(self.c['goldengate']['schema'])
        r=self.sql.query('source',f"SELECT IS_ROLEMEMBER(N'db_owner',{u}) AS db_owner,IS_SRVROLEMEMBER(N'sysadmin',{u}) AS sysadmin,CASE WHEN SCHEMA_ID({sch}) IS NOT NULL THEN 1 ELSE 0 END AS has_schema,CASE WHEN EXISTS(SELECT 1 FROM msdb.sys.database_role_members m JOIN msdb.sys.database_principals p ON p.principal_id=m.member_principal_id JOIN msdb.sys.database_principals r ON r.principal_id=m.role_principal_id WHERE p.name={u} AND r.name=N'SQLAgentReaderRole') THEN 1 ELSE 0 END AS agent_reader",1)
        require(len(r)==1 and r[0]=={'db_owner':1,'sysadmin':0,'has_schema':1,'agent_reader':1},'Capture login/schema/roles differ from required nonsysadmin account.')
        userhex=self.c['target']['apply_user'].encode().hex()
        r=self.sql.query('target',"SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_catalog.pg_roles WHERE rolname=convert_from(decode('"+userhex+"','hex'),'UTF8')",1)
        require(len(r)==1 and r[0]=={'rolcanlogin':True,'rolsuper':False,'rolcreatedb':False,'rolcreaterole':False,'rolreplication':False},'Target apply role attributes differ.')
    def accounts(self):
        self.source_shape();self.target_identity()
        require(not any(x.get('is_tracked_by_cdc') is True for x in self.current_source_tables),'Existing CDC consumers/tables require a separate capture-sharing plan. Use an isolated source database for this release.')
        if self.s['accounts_mode']=='create':
            if 'accounts:source' not in self.j.data['intents']:
                u=sqlstr(self.c['source']['capture_user']);schema=sqlstr(self.c['goldengate']['schema'])
                existing=self.sql.query('source','SELECT CASE WHEN SUSER_ID('+u+') IS NOT NULL OR USER_ID('+u+') IS NOT NULL OR SCHEMA_ID('+schema+') IS NOT NULL THEN 1 ELSE 0 END AS account_exists',1)
                require(len(existing)==1 and existing[0].get('account_exists')==0,'Capture login/user/schema already exists; choose another name or preconfigure existing-account mode before execution.')
            if 'accounts:target' not in self.j.data['intents']:
                hexname=self.c['target']['apply_user'].encode().hex();hexschema=self.c['goldengate']['schema'].encode().hex()
                existing=self.sql.query('target',"SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=convert_from(decode('"+hexname+"','hex'),'UTF8')) OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=convert_from(decode('"+hexschema+"','hex'),'UTF8')) AS account_exists",1)
                require(len(existing)==1 and existing[0].get('account_exists') is False,'Apply role/schema already exists; choose another name or preconfigure existing-account mode before execution.')
            def new_password(key,label):
                if key in self.j.data['intents']:return None
                value=discovery.hidden('New '+label+' password (must match the provided Vault secret): ')
                require(value==discovery.hidden('Confirm '+label+' password: '),'Passwords differ; no mutation intent was recorded.')
                return value
            capture_password=new_password('accounts:source','capture')
            self.once('accounts:source',{'login':self.c['source']['capture_user'],'schema':self.c['goldengate']['schema']},lambda:self.sql.execute('source',source_account_sql(self.c,capture_password)))
            capture_password=None
            apply_password=new_password('accounts:target','apply')
            def apply():
                literal="E'"+apply_password.replace('\\','\\\\').replace("'","''")+"'"
                return self.sql.execute('target',target_account_sql(self.c).replace(":'new_apply_password'",literal))
            self.once('accounts:target',{'login':self.c['target']['apply_user'],'schema':self.c['goldengate']['schema']},apply)
            apply_password=None
        self.account_checks()
        sql=source_settings_sql(self.c);self.once('accounts:settings',{'sql':sql},lambda:self.sql.execute('source',sql))
        if self.s['configure_unlimited_lob']:
            sql="IF EXISTS(SELECT 1 FROM sys.configurations WHERE value<>value_in_use AND name<>N'max text repl size (B)') THROW 51000,'Other server settings are pending; no RECONFIGURE performed',1;\nEXEC sys.sp_configure N'max text repl size',-1; RECONFIGURE;\nGO\n"
            self.once('accounts:lob-limit',{'sql':sql},lambda:self.sql.execute('source',sql))
    def target_schema(self):
        self.source_shape();self.target_identity()
        sql=self.plan['target_sql']
        self.once('schema:create',{'sql':sql},lambda:self.sql.execute('target',sql))
        grant=grants(self.c,self.p);self.once('schema:grants',{'sql':grant},lambda:self.sql.execute('target',grant))
    def provision(self):
        for side,tech in (('source','DATABASE_MICROSOFT_SQLSERVER'),('target','DATABASE_POSTGRESQL')):
            prefix=self.c['goldengate']['prefix'];payload={'compartmentId':self.c['oci']['compartment_id'],
              'displayName':self.c['environment']+'_'+side+'_GG','deploymentName':prefix+('SQL' if side=='source' else 'PG'),
              'deploymentType':tech,'subnetId':self.c['goldengate']['subnet_id'],'nsgIds':self.s['nsg_ids'],
              'cpuCoreCount':self.s['ocpu_count'],'isAutoScalingEnabled':False,'isPublic':False,'licenseModel':self.s['license_model'],'environmentType':self.s['environment_type'],
              'credentialStore':'GOLDENGATE','adminUsername':self.s['console_user'],'passwordSecretId':self.s[side+'_admin_secret_id'],'oggVersion':self.s[side+'_version'],
              'freeformTags':{'ggsetup_environment':self.c['environment'],'ggsetup_plan':self.plan['execution_sha256']}}
            d=self.resource('deployment:'+side,'deployment',payload,self.c['goldengate'][side+'_deployment_id'])
            require(d.get('deployment-type')==tech and d.get('is-public') is False and d.get('subnet-id')==self.c['goldengate']['subnet_id'],'Deployment technology/private subnet mismatch.')
            for collection in ('extracts','replicats','sources'):
                require(self.gg(side).get('/services/v2/'+collection).get('items',[])==[],'Deployment has existing processes/paths; reuse of an active environment is blocked.')
            tasks=self.gg(side).get('/services/v2/tasks').get('items')
            require(isinstance(tasks,list),'Task collection is unavailable; cannot establish empty deployment safety.')
            for task in tasks:
                name=task.get('name');require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_-]+',name),'Invalid existing task name.')
                current=self.gg(side).get('/services/v2/tasks/'+name)
                require(current.get('command',{}).get('purgeType')!='changeData','Deployment has an existing CDC cleanup task; capture-sharing/adoption is not supported.')
    def connections(self):
        raw=Path(discovery.endpoint(self.c,'target',self.path)['ca_file']).read_bytes().decode('ascii')
        require('PRIVATE KEY' not in raw,'CA bundle contains private-key material; no connection request sent.')
        blocks=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',raw,re.S);require(bool(blocks),'CA must be a public PEM certificate bundle.')
        ca=('\n'.join(blocks)+'\n').encode('ascii')
        import ssl
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca.decode('ascii'))
        for label,side,command in (('source','source','create-microsoft-sqlserver-connection'),('target','target','create-postgresql-connection'),('network','source','create-goldengate-connection')):
            g=self.c['goldengate'];alias=g['network_alias' if label=='network' else label+'_alias']
            base={'displayName':alias,'compartmentId':self.c['oci']['compartment_id'],'doesUseSecretIds':True}
            if label=='network':base.update(technologyType='GOLDENGATE',deploymentId=self.deployment('target')['id'],username=self.s['console_user'],passwordSecretId=self.s['target_admin_secret_id'],routingMethod='SHARED_DEPLOYMENT_ENDPOINT')
            else:
                e=self.c[label];base.update(host=e['host'],port=e['port'],databaseName=e['database'],username=e['capture_user' if label=='source' else 'apply_user'],
                  securityProtocol='TLS',passwordSecretId=self.s['capture_secret_id' if label=='source' else 'apply_secret_id'],technologyType='MICROSOFT_SQLSERVER' if label=='source' else 'OCI_POSTGRESQL',
                  routingMethod='DEDICATED_ENDPOINT',subnetId=g['subnet_id'],nsgIds=self.s['nsg_ids'])
                if label=='source':base['shouldValidateServerCertificate']=not self.c['source']['trust_server_certificate']
                else:base.update(sslMode='VERIFY_FULL',sslCa=base64.b64encode(ca).decode())
            request=dict(base,_command=command);conn=self.resource('connection:'+label,'connection',request)
            payload={'connectionId':conn['id'],'deploymentId':self.deployment(side)['id']}
            key='assignment:'+label
            def assign():
                d=self.oci.call('connection-assignment','create',payload=payload).get('data') or {};require(d.get('id'),'No assignment OCID returned.')
                return {'id':d['id']}
            rec=self.once(key,payload,assign);assignment=self.oci.wait('connection-assignment',rec['id'])
            require(assignment.get('connection-id')==conn['id'] and assignment.get('deployment-id')==payload['deploymentId'] and assignment.get('alias-name')==alias,'Assignment identity or alias mismatch.')
            test=self.oci.call('connection-assignment','test',['--connection-assignment-id',rec['id']]).get('data') or {}
            require(test.get('result-type')=='SUCCEEDED','GoldenGate connection test did not succeed: '+label)
    def capture_schema(self):
        src=self.gg('source');route='/services/v2/config/files/GLOBALS'
        for k in ('extracts','replicats','sources'):require(src.get('/services/v2/'+k).get('items',[])==[],'Source deployment must be empty before GLOBALS changes.')
        lines=src.get(route).get('lines');require(isinstance(lines,list),'GLOBALS readback missing.')
        desired=self.c['goldengate']['schema'];matches=[i for i,x in enumerate(lines) if re.match(r'^\s*GGSCHEMA\s+',x,re.I)]
        require(len(matches)<=1,'Multiple GGSCHEMA values; manual review required.')
        after=list(lines)
        if matches:after[matches[0]]='GGSCHEMA '+desired
        else:after+=['GGSCHEMA '+desired]
        key='globals:update'
        if key in self.j.data['intents']:after=self.j.data['proofs']['globals_desired']
        else:self.j.data['proofs']['globals_desired']=after;self.j.save()
        payload={'$schema':'ogg:config','lines':after}
        self.once(key,payload,lambda:src.call('PUT',route,payload) or {'updated':True})
        require(src.get(route).get('lines')==after,'GLOBALS readback differs.')
        dep=self.deployment('source')['id']
        self.once('globals:stop',{'deployment':dep},lambda:self.oci.call('deployment','stop',['--deployment-id',dep]) or {'accepted':True})
        if 'globals:start' not in self.j.data['intents']:self.oci.wait('deployment',dep,desired=('INACTIVE',))
        self.once('globals:start',{'deployment':dep},lambda:self.oci.call('deployment','start',['--deployment-id',dep]) or {'accepted':True})
        self.oci.wait('deployment',dep);self.admins.pop('source',None)
        require(self.gg('source').get(route).get('lines')==after,'GLOBALS differs after restart.')
    def cleanup_definition(self):
        return {'$schema':'ogg:task','enabled':True,'description':self.marker(),
          'command':{'$schema':'ogg:command','name':'purge','purgeType':'changeData','credentials':{'domain':'OracleGoldenGate','alias':self.c['goldengate']['source_alias']},'keep':[{'type':'max','value':self.s['cleanup_days'],'units':'days'}]},'schedule':{'every':{'units':'minutes','value':10}}}
    def marker(self):return 'ggsetup:'+self.plan['execution_sha256']
    def logging(self):
        self.source_shape()
        owned={k[len('logging:'):] for k in self.j.data['intents'] if k.startswith('logging:')}
        require(all(x['schema_name']+'.'+x['table_name'] in owned for x in self.current_source_tables if x.get('is_tracked_by_cdc') is True),'Another CDC consumer appeared; no logging/cleanup changes were sent.')
        src=self.gg('source');base='/services/v2/connections/OracleGoldenGate.'+self.c['goldengate']['source_alias']+'/trandata/table'
        for t in self.p['tables']:
            payload={'$schema':'ogg:trandataTable','operation':'add','tableName':planner.qname(t['schema'],t['table'])}
            self.once('logging:'+t['schema']+'.'+t['table'],payload,lambda p=payload:src.call('POST',base,p) or {'request_completed':True})
            info=src.call('POST',base,dict(payload,operation='info'))
            tables=info.get('tables');require(isinstance(tables,list) and len(tables)==1 and tables[0].get('enabled') is True,'Table logging readback is not enabled.')
            require('.'.join(tables[0].get('tableName','').replace(chr(34),'').replace('[','').replace(']','').split('.')[-2:]).casefold()==(t['schema']+'.'+t['table']).casefold(),'Logging readback names a different table.')
        task=self.c['goldengate']['prefix']+'_CDC_CLEANUP';path='/services/v2/tasks/'+task;definition=self.cleanup_definition()
        self.once('cleanup:create',definition,lambda:src.call('POST',path,definition) or {'created':True})
        subset(definition,src.get(path),'cleanup')
        sql='USE '+sqlid(self.c['source']['database'])+";\nIF EXISTS(SELECT 1 FROM msdb.dbo.cdc_jobs WHERE database_id=DB_ID() AND job_type=N'cleanup') EXEC sys.sp_cdc_drop_job @job_type=N'cleanup';\nGO\n"
        self.once('cleanup:remove-native',{'sql':sql},lambda:self.sql.execute('source',sql))
        self.capture_checks(wait_job=True)
    def capture_checks(self,wait_job=False):
        self.account_checks()
        db=self.sql.query('source',discovery.SOURCE_QUERIES['database'],1);services=self.sql.query('source',discovery.SOURCE_QUERIES['services'])
        require(len(db)==1 and db[0].get('is_cdc_enabled') is True and db[0].get('snapshot_isolation_state')==1,'CDC/snapshot isolation is not enabled.')
        require(any('Agent' in x.get('servicename','') and x.get('status_desc')=='Running' for x in services),'SQL Server Agent is not running.')
        rows=self.sql.query('source',"SELECT job_type FROM msdb.dbo.cdc_jobs WHERE database_id=DB_ID()")
        require([r['job_type'] for r in rows].count('capture')==1 and all(r['job_type']!='cleanup' for r in rows),'Expected native capture and no native cleanup job.')
        subset(self.cleanup_definition(),self.gg('source').get('/services/v2/tasks/'+self.c['goldengate']['prefix']+'_CDC_CLEANUP'),'cleanup')
        capture=self.sql.query('source',"SELECT s.name AS schema_name,t.name AS table_name,ct.capture_instance,cc.column_name FROM cdc.change_tables ct JOIN sys.tables t ON t.object_id=ct.source_object_id JOIN sys.schemas s ON s.schema_id=t.schema_id JOIN cdc.captured_columns cc ON cc.object_id=ct.object_id",1000000)
        for t in self.p['tables']:
            selected=[x for x in capture if (x['schema_name'],x['table_name'])==(t['schema'],t['table'])]
            require(len({x['capture_instance'] for x in selected})==1 and {x['column_name'] for x in selected}=={x['name'] for x in t['columns']},'CDC capture instance/column coverage differs.')
        until=time.monotonic()+(120 if wait_job else 0)
        while True:
            enabled=self.sql.query('source',"SELECT j.enabled,CASE WHEN a.start_execution_date IS NOT NULL AND a.stop_execution_date IS NULL THEN 1 ELSE 0 END AS is_running FROM msdb.dbo.cdc_jobs c JOIN msdb.dbo.sysjobs j ON j.job_id=c.job_id LEFT JOIN msdb.dbo.sysjobactivity a ON a.job_id=j.job_id AND a.session_id=(SELECT MAX(session_id) FROM msdb.dbo.syssessions) WHERE c.database_id=DB_ID() AND c.job_type=N'capture'",1)
            require(len(enabled)==1 and enabled[0].get('enabled') in (True,1),'Native capture job missing/disabled.')
            if enabled[0].get('is_running') in (True,1):break
            require(time.monotonic()<until,'Native capture job is enabled but not running.')
            print('Waiting for native SQL Server capture job ...',flush=True);time.sleep(5)
        if self.requires_unlimited_lob:
            lob=self.sql.query('source',discovery.SOURCE_QUERIES['lob_limit'],1)
            require(len(lob)==1 and lob[0].get('running')==-1,'MAX/LOB columns require max text repl size=-1 for this execution release. Select the reviewed instance-setting option or configure it separately.')
        errors=self.sql.query('source',"SELECT entry_time,error_number FROM sys.dm_cdc_errors WHERE entry_time>=DATEADD(hour,-1,GETDATE())")
        require(not errors,'Recent SQL Server CDC errors require review.')
    def defs(self,kind):
        return definitions(self.c,self.p,self.deployment('target')['deployment-url'],kind,self.marker(),self.j.data['proofs'].get('snapshot',{}).get('lsn'))
    def point(self,kind,component):
        d=self.defs(kind)[component];collection={'extract':'extracts','path':'sources','replicat':'replicats'}[component]
        return '/services/v2/'+collection+'/'+d['name']
    def prepare(self,kind):
        self.source_shape();self.capture_checks();self.target_shape();self.recent_cleanup(wait=kind=='initial')
        if kind=='cdc':self.retention()
        d=self.defs(kind);target=self.gg('target');src=self.gg('source')
        for admin in (src,target):
            seq=admin.get('/services/adminsrvr/v2/trails/'+names(self.c)[kind+'_trail']+'/sequences?path=dirdat',optional=True)
            require(seq is None or (isinstance(seq.get('items'),list) and seq['items']==[]),'Matching trail prefix already has sequence files before pipeline preparation; no overwrite/adoption.')
        if kind=='cdc':
            proof=verify_lsn_schema(src.schema('extract'),self.j.data['proofs']['snapshot']['lsn'])
            self.j.data['proofs']['positioning_schema']=proof;self.j.save()
        cp=d['replicat']['document']['checkpoint']['table'];route='/services/v2/connections/OracleGoldenGate.'+self.c['goldengate']['target_alias']+'/tables/checkpoint'
        cpname=self.c['goldengate']['schema']+'.'+names(self.c)[kind+'_checkpoint']
        def checkpoint():
            lookup=self.sql.query('target',"SELECT to_regclass(convert_from(decode('"+planner.qname(self.c['goldengate']['schema'],names(self.c)[kind+'_checkpoint']).encode().hex()+"','hex'),'UTF8')) IS NOT NULL AS exists",1)
            require(len(lookup)==1 and lookup[0].get('exists') is False,'Checkpoint name already exists; no adoption.')
            return target.call('POST',route,{'operation':'add','name':cp}) or {'created':True}
        self.once(kind+':checkpoint',{'operation':'add','name':cp},checkpoint)
        fq=planner.qname(self.c['goldengate']['schema'],names(self.c)[kind+'_checkpoint'])
        comment='COMMENT ON TABLE '+fq+' IS '+planner.literal(self.marker())+';\n'
        writer=self.sql.as_user('target',self.c['target']['apply_user']) if kind+':checkpoint-comment' not in self.j.data['intents'] else None
        self.once(kind+':checkpoint-comment',{'sql':comment,'owner':self.c['target']['apply_user']},lambda:writer.execute('target',comment))
        for component in ('extract','path','replicat'):
            admin=target if component=='replicat' else src;path=self.point(kind,component);payload=d[component]['document']
            def create(a=admin,path=path,payload=payload):
                require(a.get(path,optional=True) is None,'Process/path name already exists; no adoption.')
                return a.call('POST',path,payload) or {'created':True}
            self.once(kind+':create:'+component,payload,create)
            actual=admin.get(path);wanted=deepcopy(payload);wanted.pop('status');wanted.pop('begin',None)
            if component!='path':
                if actual.get('config') is None:actual['config']=admin.get('/services/v2/config/files/'+d[component]['name']+'.prm').get('lines')
            else:
                for side in ('source','target'):
                    uri=actual.get(side,{}).get('uri')
                    if isinstance(uri,list) and len(uri)==1:actual[side]['uri']=uri[0]
            subset(wanted,actual,component)
            if kind=='cdc' and component=='extract':subset(payload['begin'],actual.get('begin'),'snapshot begin LSN')
            require(actual.get('status') in ('stopped','uninitialized'),'Prepared component already started.')
    def process_info(self,kind,component):
        admin=self.gg('target' if component=='replicat' else 'source');path=self.point(kind,component)
        info=admin.get(path+('/info' if component=='path' else '/info/status'))
        if component=='path':info=dict(info,status=admin.get(path).get('status'))
        return info
    def verify_current(self,kind,component):
        admin=self.gg('target' if component=='replicat' else 'source');path=self.point(kind,component)
        expected=deepcopy(self.defs(kind)[component]['document']);expected.pop('status');expected.pop('begin',None)
        actual=admin.get(path)
        if component!='path' and actual.get('config') is None:actual['config']=admin.get('/services/v2/config/files/'+self.defs(kind)[component]['name']+'.prm').get('lines')
        if component=='path':
            for side in ('source','target'):
                uri=actual.get(side,{}).get('uri')
                if isinstance(uri,list) and len(uri)==1:actual[side]['uri']=uri[0]
        subset(expected,actual,'live '+component)
        return actual
    def start(self,kind,component):
        admin=self.gg('target' if component=='replicat' else 'source');path=self.point(kind,component);key=kind+':start:'+component
        def run():
            actual=self.verify_current(kind,component);require(actual.get('status') in ('stopped','uninitialized'),'Fresh component is not stopped.')
            info=self.process_info(kind,component)
            require('lastStarted' in info and info['lastStarted'] is None,'Process/path has prior or unknown execution; no start/replay permitted.')
            if kind=='initial' and component=='extract':
                require(admin.get(path+'/info/history').get('history')==[],'Finite Extract already has execution history.')
            if component=='extract':
                trail=names(self.c)[kind+'_trail'];seq=admin.get('/services/adminsrvr/v2/trails/'+trail+'/sequences?path=dirdat',optional=True)
                require(seq is None or (isinstance(seq.get('items'),list) and seq['items']==[]),'Trail files already exist before first start; no replay or overwrite.')
            if component=='path':
                seq=self.gg('target').get('/services/adminsrvr/v2/trails/'+names(self.c)[kind+'_trail']+'/sequences?path=dirdat',optional=True)
                require(seq is None or (isinstance(seq.get('items'),list) and seq['items']==[]),'Target trail already exists before first distribution start; no overwrite.')
            admin.call('PATCH',path,{'status':'running'});return {'start_request_acknowledged':True}
        self.once(key,{'path':path,'status':'running'},run)
    def pin(self,kind,component):
        info=self.process_info(kind,component);key=kind+':start:'+component;intent=self.j.data['intents'].get(key)
        require(intent and intent['status']=='acknowledged','Missing acknowledged execution request.')
        require(info.get('lastStarted') and abs((stamp(info['lastStarted'])-stamp(intent['requested_at'])).total_seconds())<=300,'Execution does not match the saved request.')
        pid=info.get('processId');require(type(pid) is int and 0<pid<4294967295,'Execution PID not ready.')
        identity={'lastStarted':info['lastStarted'],'processId':pid};saved=self.j.data['proofs'].setdefault('executions',{})
        if key in saved:require(saved[key]==identity,'Process restarted or PID changed; no automatic adoption.')
        else:saved[key]=identity;self.j.save()
        return info
    def wait_pin(self,kind,component,timeout=60):
        until=time.monotonic()+timeout
        while True:
            info=self.process_info(kind,component);pid=info.get('processId')
            if info.get('lastStarted') and type(pid) is int and 0<pid<4294967295:return self.pin(kind,component)
            require(time.monotonic()<until,'Execution identity metadata is not ready; observe without repeating START.')
            time.sleep(2)
    def extract_initial(self):
        self.source_shape();self.capture_checks()
        proof=self.j.data['proofs']
        if 'baseline_counts' not in proof:
            proof['baseline_counts']=verification.counts(self.sql,self.p['tables'],'source');self.j.save()
        require(all(n==0 for n in verification.counts(self.sql,self.p['tables'],'target').values()),'Initial target tables are not empty.')
        self.start('initial','extract')
        admin=self.gg('source');path=self.point('initial','extract')
        until=time.monotonic()+1800
        while True:
            status=admin.get(path+'/info/status');history=admin.get(path+'/info/history').get('history')
            require(status.get('status') not in ('abended','killed'),'Initial Extract abended/killed; retain state.')
            if status.get('status')=='stopped' and isinstance(history,list) and len(history)==1 and history[0].get('finished'):break
            require(time.monotonic()<until,'Initial Extract observation timed out; never replay the start.')
            time.sleep(5)
        require(isinstance(history,list) and len(history)==1,'Expected one finite initial-load execution.')
        task=history[0];require(task.get('status')=='stopped' and type(task.get('exitCode')) is int and task['exitCode']==0 and not task.get('killedManually',False),'Initial Extract did not finish normally.')
        info=self.pin('initial','extract');require(info['processId']==task.get('processId'),'Task PID differs from Extract.')
        require(stamp(task['started'])<=stamp(info['lastStarted'])<=stamp(task['finished']),'Task/process timestamps differ.')
        lines=admin.get(path+'/info/reports/'+self.defs('initial')['extract']['name']+'.rpt').get('lines');require(isinstance(lines,list),'Missing initial report.')
        text='\n'.join(lines);require(not re.search(r'\b(?:ERROR|FATAL)\s+OGG-\d+',text),'Initial report contains an error.')
        require(re.findall(r'^\s*Process id:\s*(\d+)\s*$',text,re.M)==[str(info['processId'])] and self.marker() in text,'Initial report identity/ownership differs.')
        consistent=[x for x in lines if 'OGG-05381' in x and "database '"+self.c['source']['database']+"'" in x]
        require(len(consistent)==1,'Missing/ambiguous snapshot message.')
        matches=re.findall(r'at LSN\s+(0x[0-9A-Fa-f]{8}:[0-9A-Fa-f]{8}:[0-9A-Fa-f]{4})',consistent[0]);require(len(matches)==1,'Missing snapshot LSN.')
        lsn=matches[0].lower();require(int(lsn[2:].replace(':',''),16)>0,'Zero snapshot LSN.')
        positioning=[x for x in lines if 'OGG-05379' in x or 'OGG-05381' in x]
        values=[v.lower() for line in positioning for v in re.findall(r'0x[0-9a-fA-F]{8}:[0-9a-fA-F]{8}:[0-9a-fA-F]{4}',line)]
        require(values and set(values)=={lsn},'Snapshot consistent-point and CDC positioning messages disagree.')
        expected={t['schema']+'.'+t['table'] for t in self.p['tables']}
        processed=[x.split('OGG-02911',1)[1] for x in lines if 'OGG-02911' in x and 'Processing table' in x]
        processed=['.'.join(re.sub(r'^.*Processing table\s+','',x).strip().strip('.').replace(chr(34),'').split('.')[-2:]) for x in processed]
        require(len(processed)==len(expected) and set(processed)==expected,'Initial report does not show every selected table exactly once.')
        compact=re.sub(r'\s+','',text)
        require(all(re.sub(r'\s+','',x) in compact for x in self.defs('initial')['extract']['document']['config']),'Initial report parameter echo differs.')
        require(verification.counts(self.sql,self.p['tables'],'source')==proof['baseline_counts'],'Source row counts changed during snapshot extraction.')
        proof['snapshot']={'lsn':lsn,'execution':info,'report_sha256':digest(lines),'completed':True};self.j.save()
    def load_initial(self):
        stopping=any('initial:stop:'+x in self.j.data['intents'] for x in ('replicat','path'))
        if not stopping:
            self.start('initial','path');self.gg('source').wait(self.point('initial','path'),desired=('running',));self.wait_pin('initial','path')
            self.start('initial','replicat');self.gg('target').wait(self.point('initial','replicat')+'/info/status',desired=('running',));self.wait_pin('initial','replicat')
        until=time.monotonic()+7200;expected=self.j.data['proofs']['baseline_counts']
        while True:
            for component in ('path','replicat'):
                status=self.pin('initial',component).get('status')
                require(status=='running' or (stopping and status=='stopped'),'Initial delivery component stopped or abended.')
            counts=verification.counts(self.sql,self.p['tables'],'target')
            require(all(counts[k]<=expected[k] for k in expected),'Target has unexpected extra rows.')
            if counts==expected:break
            require(time.monotonic()<until,'Initial row delivery timed out; observe current execution without replay.')
            print('Initial rows: '+str(sum(counts.values()))+'/'+str(sum(expected.values())),flush=True);time.sleep(10)
        # Actual whole-value verification occurs before any CDC delivery is started.
        for component in ('replicat','path'):
            admin=self.gg('target' if component=='replicat' else 'source');path=self.point('initial',component)
            self.once('initial:stop:'+component,{'path':path},lambda a=admin,p=path:a.call('PATCH',p,{'status':'stopped'}) or {'stopped_request':True})
            admin.wait(path,desired=('stopped',))
    def verify_initial(self):
        self.source_shape();self.target_shape();expected=self.j.data['proofs']['baseline_counts']
        require(verification.counts(self.sql,self.p['tables'],'source')==expected,'Source counts changed.')
        for component in ('extract','path','replicat'):
            require(self.process_info('initial',component).get('status')=='stopped','Initial components must be stopped for comparison.');self.pin('initial',component)
        result=verification.compare(self.sql,self.p['tables'],expected)
        require(verification.counts(self.sql,self.p['tables'],'source')==expected,'Source counts changed during verification.')
        self.j.data['proofs']['initial_verification']=result;self.j.save()
    def retention(self):
        lsn=self.j.data['proofs'].get('snapshot',{}).get('lsn');require(lsn,'No snapshot boundary.')
        boundary=int(lsn[2:].replace(':',''),16)
        rows=self.sql.query('source',"SELECT s.name AS schema_name,t.name AS table_name,CONVERT(varchar(22),sys.fn_cdc_get_min_lsn(ct.capture_instance),1) AS min_lsn,CONVERT(varchar(22),sys.fn_cdc_get_max_lsn(),1) AS max_lsn FROM cdc.change_tables ct JOIN sys.tables t ON t.object_id=ct.source_object_id JOIN sys.schemas s ON s.schema_id=t.schema_id")
        self.j.data['proofs']['retention_observation']={'observed_at':now(),'snapshot_lsn':lsn,'windows':rows};self.j.save()
        for t in self.p['tables']:
            found=[x for x in rows if (x['schema_name'],x['table_name'])==(t['schema'],t['table'])]
            require(len(found)==1,'Missing or duplicate CDC retention bounds.')
            try:lo=int(found[0]['min_lsn'],16);hi=int(found[0]['max_lsn'],16)
            except (ValueError,TypeError):raise SetupError('Invalid CDC retention LSN.') from None
            require(0<lo<=boundary<=hi,'Snapshot LSN is outside retained/captured CDC coverage; do not reposition or force startup.')
    def recent_cleanup(self,wait=False):
        path='/services/v2/tasks/'+self.c['goldengate']['prefix']+'_CDC_CLEANUP';until=time.monotonic()+(900 if wait else 0)
        while True:
            current=self.gg('source').get(path);require(current.get('status') not in ('abended','killed'),'Cleanup task failed.')
            rows=self.gg('source').get(path+'/info/history').get('history')
            if rows is None and wait:rows=[]
            require(isinstance(rows,list),'Missing cleanup history.')
            successful=[x for x in rows if x.get('status')=='stopped' and type(x.get('exitCode')) is int and x['exitCode']==0 and not x.get('killedManually',False) and x.get('finished')]
            if any(0<=(stamp(now())-stamp(x['finished'])).total_seconds()<=1800 for x in successful):return
            require(time.monotonic()<until,'No successful cleanup within 30 minutes; inspect the ten-minute task schedule.')
            print('Waiting for the scheduled GoldenGate cleanup task to finish successfully ...',flush=True);time.sleep(5)
    def start_cdc(self):
        self.source_shape();self.capture_checks();require(self.j.data['proofs'].get('initial_verification',{}).get('matched') is True,'Initial content is not verified.')
        if 'cdc:start:extract' not in self.j.data['intents']:self.retention()
        for component in ('extract','path','replicat'):
            self.start('cdc',component);admin=self.gg('target' if component=='replicat' else 'source')
            admin.wait(self.point('cdc',component)+('/info/status' if component!='path' else ''),desired=('running',));self.wait_pin('cdc',component)
        self.health()
    def health(self):
        self.source_shape();self.capture_checks();self.recent_cleanup();self.target_shape();runtime={}
        for component in ('extract','path','replicat'):
            info=self.pin('cdc',component);require(info.get('status','running')=='running','CDC component not running.')
            require(type(info.get('lag')) is int and 0<=info['lag']<=60 and type(info.get('sinceLagReported')) is int and 0<=info['sinceLagReported']<=120,'CDC lag or telemetry age requires review.')
            runtime[component]=info
        result={'status':'execution_health_healthy','runtime':runtime,'scope':'Current runtime/source prerequisites/target TLS; not a new full content comparison.'}
        self.last_health=result;return result
    def observe(self):
        result={'status':'observed_no_remote_changes','execution_sha256':self.plan['execution_sha256'],'stages':self.j.data.get('stages',{}),'resources':{},'pending':{},'processes':{}}
        for key,item in self.j.data['intents'].items():
            if item['status']=='pending':result['pending'][key]={'requested_at':item['requested_at'],'request_sha256':item['request_sha256']}
        for key,item in self.j.data.get('resources',{}).items():
            resource=key.split(':',1)[0]
            try:
                d=self.oci.get(resource,item['id'])
                result['resources'][key]={k:d.get(k) for k in ('id','display-name','lifecycle-state','compartment-id','deployment-type','deployment-url')}
            except SetupError as exc:result['resources'][key]={'error':str(exc)}
        for kind in ('initial','cdc'):
            if kind=='cdc' and not self.j.data.get('proofs',{}).get('snapshot'):continue
            for component in ('extract','path','replicat'):
                if kind+':create:'+component not in self.j.data['intents']:continue
                try:
                    side='target' if component=='replicat' else 'source'
                    require(result['resources'].get('deployment:'+side,{}).get('lifecycle-state')=='ACTIVE','Deployment is not ACTIVE; runtime is unavailable and no start request was sent.')
                    admin=self.gg(side);path=self.point(kind,component)
                    result['processes'][kind+':'+component]={'document':admin.get(path,optional=True),'info':self.process_info(kind,component),'checkpoints':admin.get(path+'/info/checkpoints')}
                except SetupError as exc:result['processes'][kind+':'+component]={'error':str(exc)}
        return result
    def reconcile_resource(self,key,ocid):
        require(key.startswith(('deployment:','connection:')),'Only OCI deployment/connection creates can be reconciled here; other pending operations require diagnosis.')
        action='create:'+key;intent=self.j.data['intents'].get(action)
        require(intent and intent['status']=='pending','No pending create intent for '+key)
        request=self.j.data.get('resource_requests',{}).get(key)
        require(request and digest(request['payload'])==intent['request_sha256'],'Saved resource request is missing or changed.')
        d=self.oci.get(request['resource'],ocid)
        require(d.get('id')==ocid and d.get('lifecycle-state')=='ACTIVE','Candidate must be the explicit ACTIVE resource.')
        tags=d.get('freeform-tags') or {}
        require(tags.get('ggsetup_environment')==self.c['environment'] and tags.get('ggsetup_plan')==self.plan['execution_sha256'],'Candidate ownership tags do not match.')
        expected=request['payload']
        mapping={'compartmentId':'compartment-id','displayName':'display-name','subnetId':'subnet-id','deploymentType':'deployment-type','technologyType':'technology-type','host':'host','port':'port','databaseName':'database-name','username':'username','securityProtocol':'security-protocol','routingMethod':'routing-method','deploymentId':'deployment-id'}
        for source,target in mapping.items():
            if source in expected:require(d.get(target)==expected[source],'Candidate differs on '+source)
        actual=d.get('ogg-data',{}) if request['resource']=='deployment' else d
        if 'passwordSecretId' in expected:require(actual.get('password-secret-id')==expected['passwordSecretId'],'Candidate password secret reference differs.')
        if request['resource']=='deployment':require(d.get('is-public') is False,'Candidate is public.')
        self.j.data['resources'][key]={'id':ocid,'request_sha256':intent['request_sha256']}
        self.j.acknowledge(action,intent['token'],{'id':ocid,'reconciled_from_exact_active_readback':True});self.j.save()
        return {'status':'resource_reconciled_no_remote_mutation','key':key,'id':ocid}
    def execute(self,stage,approve,writes_paused):
        require(approve==self.plan['execution_sha256'],'Pass the exact reviewed execution plan SHA-256.')
        require(stage in STAGES and writes_paused,'Setup stages require an explicit --writes-paused declaration.')
        self.bind();index=STAGES.index(stage)
        require(all(self.j.data['stages'].get(x)=='completed' for x in STAGES[:index]),'Complete prior stages in order.')
        if self.j.data['stages'].get(stage)=='completed':return {'status':'already_completed','stage':stage,'no_mutations':True}
        self.j.data['in_progress_stage']=stage;self.j.save()
        method={'target-schema':self.target_schema,'capture-schema':self.capture_schema,'prepare-initial':lambda:self.prepare('initial'),
          'extract-initial':self.extract_initial,'prepare-cdc':lambda:self.prepare('cdc'),'load-initial':self.load_initial,
          'verify-initial':self.verify_initial,'start-cdc':self.start_cdc}.get(stage) or getattr(self,stage)
        method();self.j.data['stages'][stage]='completed';self.j.data['in_progress_stage']=None;self.j.event('stage_completed',{'stage':stage,'execution_sha256':approve})
        return {'status':'stage_completed','stage':stage}
