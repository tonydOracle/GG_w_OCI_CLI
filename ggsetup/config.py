"""One explicit, secret-free configuration for each replication environment."""
import ipaddress
from pathlib import Path
import re
from .common import require,read_json,digest

AUTH={'api_key','security_token','instance_principal','resource_principal'}

def shape(value, keys, label):
    require(isinstance(value,dict),label+' must be an object.')
    require(set(value)==set(keys),label+' has missing or unknown properties: '+', '.join(sorted(set(value)^set(keys))))

def text(v,label,limit=256,empty=False):
    require(isinstance(v,str) and (bool(v) or empty) and len(v)<=limit and all(ord(c)>=32 and ord(c)!=127 for c in v),label+' must be a nonempty string without control characters.')
    return v

def identifier(v,label):
    text(v,label,128)
    require(len(v.encode('utf-8'))<=63,label+' exceeds PostgreSQL 63-byte limit.')
    return v

def ocid(v,kind,label,optional=False):
    if optional and v=='':return
    require(isinstance(v,str) and re.fullmatch(r'ocid1\.'+kind+r'\.[A-Za-z0-9_.-]+',v),label+' must be a '+kind+' OCID.')

def host(v,label):
    text(v,label)
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*',v) is not None,label+' must be a plain DNS name or IPv4 address, without a scheme or port suffix. IPv6 needs a tested client adapter.')

def validate(c):
    shape(c,('schema_version','environment','oci','source','target','goldengate','scope'), 'configuration')
    require(c['schema_version']==1,'Unsupported configuration schema_version.')
    require(isinstance(c['environment'],str) and re.fullmatch(r'[a-z][a-z0-9-]{1,39}',c['environment']), 'environment must be 2–40 lowercase letters/digits/hyphens, starting with a letter.')
    o=c['oci'];shape(o,('profile','auth','region','compartment_id','config_file'),'oci')
    text(o['profile'],'oci.profile',128)
    text(o['config_file'],'oci.config_file',4096)
    require(isinstance(o['auth'],str) and o['auth'] in AUTH,'Unsupported OCI authentication method.')
    require(isinstance(o['region'],str) and re.fullmatch(r'[a-z][a-z0-9-]+',o['region']),'Invalid OCI region.')
    ocid(o['compartment_id'],'compartment','oci.compartment_id')
    s=c['source'];shape(s,('host','port','database','inspection_user','capture_user','location','trust_server_certificate'),'source')
    host(s['host'],'source.host');identifier(s['database'],'source.database')
    for k in ('inspection_user','capture_user'):text(s[k],'source.'+k,128)
    require(s['location'] in ('oci','onprem','other'),'source.location must be oci/onprem/other.')
    require(type(s['trust_server_certificate']) is bool,'source.trust_server_certificate must be boolean.')
    t=c['target'];shape(t,('db_system_id','host','port','database','inspection_user','apply_user','ca_file'),'target')
    ocid(t['db_system_id'],'postgresqldbsystem','target.db_system_id')
    host(t['host'],'target.host');identifier(t['database'],'target.database')
    try:ipaddress.ip_address(t['host'])
    except ValueError:pass
    else:require(False,'Use the PostgreSQL service DNS hostname for verify-full TLS.')
    for k in ('inspection_user','apply_user'):identifier(t[k],'target.'+k)
    text(t['ca_file'],'target.ca_file',4096)
    for label,e in (('source',s),('target',t)):
        require(type(e['port']) is int and 1<=e['port']<=65535,label+'.port must be 1–65535.')
    g=c['goldengate'];shape(g,('prefix','schema','source_alias','target_alias','network_alias','subnet_id','vault_id','key_id','source_deployment_id','target_deployment_id'),'goldengate')
    require(isinstance(g['prefix'],str) and re.fullmatch(r'[A-Z][A-Z0-9]{1,3}',g['prefix']),'GoldenGate prefix must be 2–4 uppercase alphanumeric characters, starting with a letter.')
    identifier(g['schema'],'goldengate.schema')
    for key in ('source_alias','target_alias','network_alias'):
        require(isinstance(g[key],str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{1,63}',g[key]),'Invalid GoldenGate credential alias: '+key)
    require(len({g[k] for k in ('source_alias','target_alias','network_alias')})==3,'GoldenGate aliases must be distinct.')
    for key,kind in (('subnet_id','subnet'),('vault_id','vault'),('key_id','key'),('source_deployment_id','goldengatedeployment'),('target_deployment_id','goldengatedeployment')):
        ocid(g[key],kind,'goldengate.'+key,optional=True)
    if g['source_deployment_id'] and g['target_deployment_id']:
        require(g['source_deployment_id']!=g['target_deployment_id'],'Source and target technologies require distinct deployments.')
    scope=c['scope'];shape(scope,('mode','include_tables','exclude_tables','exclude_schemas'),'scope')
    require(scope['mode'] in ('all','selected'),'scope.mode must be all/selected.')
    require(isinstance(scope['exclude_schemas'],list),'exclude_schemas must be a list.')
    for name in scope['exclude_schemas']:identifier(name,'excluded schema')
    for k in ('include_tables','exclude_tables'):
        require(isinstance(scope[k],list),'scope.'+k+' must be a list.')
        for item in scope[k]:
            require(isinstance(item,list) and len(item)==2,'Table references must be [schema, table] pairs.')
            for x in item:identifier(x,'scope identifier')
        require(len(scope[k])==len({tuple(x) for x in scope[k]}),'Duplicate scope table.')
    require((scope['mode']=='selected')==bool(scope['include_tables']),'selected mode requires include_tables; all mode must leave it empty.')
    require(not(set(map(tuple,scope['include_tables'])) & set(map(tuple,scope['exclude_tables']))),'A table is both included and excluded.')
    require(g['schema'] in scope['exclude_schemas'],'Exclude the GoldenGate management schema from application scope.')
    return c

def load(path):
    return validate(read_json(path))

def fingerprint(c):return digest(c)

def names(c):
    p=c['goldengate']['prefix']
    # Allocate distinct trail prefixes deterministically from the full environment identity.
    seed=int(digest(c['environment'])[:8],16)%676
    trail=lambda n:chr(97+(n%676)//26)+chr(97+n%26)
    return {'initial_extract':p+'INIT','initial_path':p+'_INITIAL','initial_replicat':p+'LOAD',
            'cdc_extract':p+'CDC','cdc_path':p+'_CDC','cdc_replicat':p+'REP',
            'initial_trail':trail(seed),'cdc_trail':trail(seed+1),
            'initial_checkpoint':p.lower()+'_initial_cp','cdc_checkpoint':p.lower()+'_cdc_cp'}

def example(environment='demo'):
    return {'schema_version':1,'environment':environment,
        'oci':{'profile':'DEFAULT','auth':'api_key','region':'us-ashburn-1','compartment_id':'ocid1.compartment.oc1..REPLACE_ME','config_file':'~/.oci/config'},
        'source':{'host':'sqlserver.example.invalid','port':1433,'database':'AppDb','inspection_user':'metadata_reader','capture_user':'ggcapture','location':'onprem','trust_server_certificate':False},
        'target':{'db_system_id':'ocid1.postgresqldbsystem.oc1..REPLACE_ME','host':'postgresql.example.invalid','port':5432,'database':'AppDb','inspection_user':'admin','apply_user':'ggapply','ca_file':'destination-ca.pem'},
        'goldengate':{'prefix':'DEMO','schema':'ggschema','source_alias':'DemoSource','target_alias':'DemoTarget','network_alias':'DemoReceiver','subnet_id':'','vault_id':'','key_id':'','source_deployment_id':'','target_deployment_id':''},
        'scope':{'mode':'all','include_tables':[],'exclude_tables':[],'exclude_schemas':['ggschema','cdc','sys','INFORMATION_SCHEMA']}}
