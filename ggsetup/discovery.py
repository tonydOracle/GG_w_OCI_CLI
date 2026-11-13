"""Read-only SQL metadata and OCI PostgreSQL identity collection."""
import getpass
import ipaddress
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import warnings
from . import _dbclient as client
from .common import require,now,SetupError
from .config import fingerprint

SOURCE_QUERIES={
'identity':"""SELECT DB_NAME() AS database_name,CONVERT(nvarchar(128),SERVERPROPERTY('ServerName')) AS server_name,
 CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS product_version,
 CONVERT(nvarchar(128),SERVERPROPERTY('Edition')) AS edition""",
'visibility':"""SELECT HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','VIEW DEFINITION') AS view_definition,
 IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin""",
'database':"""SELECT name,state_desc,is_cdc_enabled,snapshot_isolation_state,is_read_committed_snapshot_on,
 recovery_model_desc,collation_name FROM sys.databases WHERE database_id=DB_ID()""",
# Version 2016+ schema: unsupported earlier releases fail closed, no feature defaults.
'tables':"""SELECT s.name AS schema_name,t.name AS table_name,t.object_id,t.is_memory_optimized,
 t.temporal_type,t.is_filetable,t.is_tracked_by_cdc,
 CONVERT(bit,CASE WHEN EXISTS(SELECT 1 FROM sys.external_tables e WHERE e.object_id=t.object_id) THEN 1 ELSE 0 END) AS is_external,
 CONVERT(bit,CASE WHEN EXISTS(SELECT 1 FROM sys.security_predicates p WHERE p.target_object_id=t.object_id) THEN 1 ELSE 0 END) AS has_row_security
 FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name""",
'columns':"""SELECT s.name AS schema_name,t.name AS table_name,c.name AS column_name,c.column_id AS ordinal,
 ty.name AS data_type,ty.is_user_defined,ty.is_assembly_type,c.max_length,c.precision,c.scale,
 c.is_nullable,c.is_identity,c.is_computed,c.is_filestream,c.is_sparse,c.is_column_set,
 c.generated_always_type,c.encryption_type,c.is_hidden,cc.definition AS computed_expression
 FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id
 JOIN sys.columns c ON c.object_id=t.object_id JOIN sys.types ty ON ty.user_type_id=c.user_type_id
 LEFT JOIN sys.computed_columns cc ON cc.object_id=c.object_id AND cc.column_id=c.column_id
 WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name,c.column_id""",
'keys':"""SELECT s.name AS schema_name,t.name AS table_name,i.name AS index_name,
 i.is_primary_key,i.is_unique,i.is_disabled,i.has_filter,ic.key_ordinal,ic.is_included_column,c.name AS column_name
 FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id
 JOIN sys.indexes i ON i.object_id=t.object_id AND i.is_unique=1
 JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id
 JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
 WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name,i.name,ic.index_column_id""",
'services':"SELECT servicename,status_desc FROM sys.dm_server_services ORDER BY servicename",
'lob_limit':"SELECT name,CONVERT(bigint,value) AS configured,CONVERT(bigint,value_in_use) AS running FROM sys.configurations WHERE name=N'max text repl size (B)'",
}
TARGET_QUERIES={
'identity':"""SELECT current_database() AS database_name,current_user AS username,
 current_setting('server_version_num') AS version_number,pg_is_in_recovery() AS is_standby,
 current_setting('server_encoding') AS encoding""",
 'tls':"SELECT ssl,version,cipher,bits FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()",
 'tables':"""SELECT n.nspname AS schema_name,c.relname AS table_name,c.relkind
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('r','p','f','v','m') AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
 ORDER BY n.nspname,c.relname""",
}

def hidden(label):
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        try:value=getpass.getpass(label)
        except getpass.GetPassWarning:raise SetupError('An interactive terminal is required for hidden password entry.') from None
    require(bool(value) and '\0' not in value,'Password must be nonempty and contain no NUL.')
    return value

def query(endpoint,executable,password,sql,row_limit=10000,timeout=45):
    argv,env,wrapped=client.command(endpoint,executable,password,sql,row_limit,timeout)
    try:
        proc=subprocess.run(argv,input=wrapped,env=env,capture_output=True,text=True,encoding='utf-8',errors='strict',timeout=timeout+20,check=False)
        if proc.returncode:
            return {'status':'error','error':client.clean_error(proc.stderr or proc.stdout,password)}
        raw=proc.stdout
        if endpoint['database_type']=='sqlserver':raw=raw.replace('\r','').replace('\n','')
        data=json.loads(raw)
        require(isinstance(data,list) and all(isinstance(x,dict) for x in data),'Expected metadata JSON array.')
        return {'status':'truncated' if len(data)>row_limit else 'ok','rows':data[:row_limit],'row_limit':row_limit}
    except subprocess.TimeoutExpired:return {'status':'error','error':'Client timed out; no retry sent.'}
    except (OSError,UnicodeError,ValueError,SetupError):return {'status':'error','error':'Client unavailable or invalid metadata JSON; raw output omitted.'}

def endpoint(c,side,config_path):
    e=c[side]
    result={'database_type':'sqlserver' if side=='source' else 'postgresql','host':e['host'],'port':e['port'],
            'database_name':e['database'],'username':e['inspection_user']}
    if side=='source':result['trust_server_certificate']=e['trust_server_certificate']
    else:
        ca=Path(e['ca_file']).expanduser()
        if not ca.is_absolute():ca=Path(config_path).absolute().parent/ca
        result.update(sslmode='verify-full',ca_file=str(ca))
    return result

def inspect_sql(c,config_path,row_limit=10000,timeout=45,progress=print):
    result={}
    for side,queries in (('source',SOURCE_QUERIES),('target',TARGET_QUERIES)):
        e=endpoint(c,side,config_path);exe=client.find_client(e['database_type'])
        item={'connection':e,'queries':{},'status':'collecting'};result[side]=item
        if not exe:
            item.update(status='unavailable',error='Required '+e['database_type']+' client not found.');continue
        if side=='target':
            try:ssl.create_default_context(cafile=e['ca_file'])
            except (OSError,ssl.SSLError):
                item.update(status='unavailable',error='Target CA file missing or invalid. No verification bypass.');continue
        try:password=hidden(side+' inspection password ('+e['username']+'): ')
        except SetupError as exc:item.update(status='unavailable',error=str(exc));continue
        try:
            for label,sql in queries.items():
                progress('Reading '+side+'.'+label+' ...')
                item['queries'][label]=query(e,exe,password,sql,row_limit,timeout)
        finally:password=None
        item['status']='collected' if all(x['status']=='ok' for x in item['queries'].values()) else 'partial'
    return result

def oci_get(c,words,timeout=90):
    require(words[:3] in (['psql','db-system','get'],['psql','connection-details','get']),'Only approved OCI GETs are permitted.')
    cli=shutil.which('oci')
    if not cli:return {'status':'error','error':'OCI CLI not found.'}
    o=c['oci'];env={k:v for k,v in os.environ.items() if not k.startswith('OCI_CLI_')}
    # SDK credentials in the chosen profile remain available, while CLI env
    # endpoint/auth/query overrides cannot silently redirect this invocation.
    with tempfile.NamedTemporaryFile(mode='w',prefix='ggsetup-empty-rc-') as rc:
        argv=[cli,*words,'--profile',o['profile'],'--auth',o['auth'],'--region',o['region'],
              '--config-file',str(Path(o['config_file']).expanduser()),'--cli-rc-file',rc.name,'--output','json']
        try:
            proc=subprocess.run(argv,env=env,capture_output=True,text=True,encoding='utf-8',errors='strict',timeout=timeout,check=False)
            if proc.returncode:return {'status':'error','error':'OCI GET failed; verify profile/auth/region/permissions and DB system OCID. Raw output omitted.'}
            result=json.loads(proc.stdout)
            require(isinstance(result,dict) and isinstance(result.get('data'),dict),'OCI data is not an object.')
            return {'status':'ok','data':result['data']}
        except (OSError,UnicodeError,ValueError,SetupError,subprocess.TimeoutExpired):return {'status':'error','error':'OCI GET unavailable, timed out or returned invalid JSON.'}

def inspect(c,config_path,row_limit=10000,timeout=45):
    report={'schema_version':1,'report_type':'ggsetup_inspection','configuration_sha256':fingerprint(c),
            'environment':c['environment'],'started_at':now(),'read_only':True,'scope':'catalog metadata; no application row reads or replication changes'}
    # Only selected OCI metadata is saved; no CA/secret value bodies in report.
    meta=oci_get(c,['psql','db-system','get','--db-system-id',c['target']['db_system_id']])
    if meta['status']=='ok':
        d=meta['data'];meta['data']={k:d.get(k) for k in ('id','compartment-id','display-name','lifecycle-state','db-version')}
    details=oci_get(c,['psql','connection-details','get','--db-system-id',c['target']['db_system_id']])
    if details['status']=='ok':
        d=details['data'];details['data']={'primary-db-endpoint':d.get('primary-db-endpoint')}
    report['oci']={'destination':meta,'connection':details}
    report.update(inspect_sql(c,config_path,row_limit,timeout))
    report['completed_at']=now()
    report['status']='collected' if all(x.get('status')=='collected' for x in (report['source'],report['target'])) and all(x.get('status')=='ok' for x in report['oci'].values()) else 'partial'
    return report


def fetch_ca(c,config_path):
    """Fetch only a verified DB system's public CA; refuse any overwrite."""
    import base64
    import hashlib
    import re
    from .common import write_text
    meta=oci_get(c,['psql','db-system','get','--db-system-id',c['target']['db_system_id']])
    require(meta.get('status')=='ok','Cannot verify destination OCI identity; CA not saved.')
    require(meta['data'].get('id')==c['target']['db_system_id'] and meta['data'].get('compartment-id')==c['oci']['compartment_id'],'Destination DB system/compartment mismatch; CA not saved.')
    result=oci_get(c,['psql','connection-details','get','--db-system-id',c['target']['db_system_id']])
    require(result.get('status')=='ok','Cannot fetch destination connection details.')
    ep=result['data'].get('primary-db-endpoint') or {}
    require(str(ep.get('fqdn','')).rstrip('.').lower()==c['target']['host'].rstrip('.').lower() and ep.get('port')==c['target']['port'],'Configured target host/port must match OCI primary endpoint before fetching its CA.')
    raw=result['data'].get('ca-certificate')
    require(isinstance(raw,str) and 0<len(raw)<=1024*1024,'Missing or oversized CA response.')
    try:
        pem=raw.strip()
        if '-----BEGIN CERTIFICATE-----' not in pem:pem=base64.b64decode(pem,validate=True).decode('ascii').strip()
        require('PRIVATE KEY' not in pem,'CA response contains private-key material; rejected.')
        blocks=re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',pem,re.S)
        require(bool(blocks),'CA response is not a certificate bundle.')
        pem='\n'.join(blocks)+'\n'
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
    except (ValueError,UnicodeError,ssl.SSLError):raise SetupError('Invalid destination CA response; no file saved.') from None
    path=Path(endpoint(c,'target',config_path)['ca_file'])
    write_text(path,pem) # Atomic no-overwrite, private parent permissions.
    return {'file':str(path),'certificate_count':len(blocks),'sha256':hashlib.sha256(pem.encode('ascii')).hexdigest(),
            'note':'Saved public CA only. This does not prove DB reachability or hostname validation.'}
