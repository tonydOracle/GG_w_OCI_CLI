"""Bounded OCI/GoldenGate/SQL adapters. Secrets stay in process memory."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from . import discovery
from .common import require,SetupError


def content(doc):
    require(isinstance(doc,dict),'Expected a JSON object.')
    for value in doc.get('messages') or []:
        require(str(value.get('severity','')).upper() not in ('ERROR','FATAL'),'GoldenGate returned '+str(value.get('code','an error'))+'. Read its event/report logs; request outcome may be unknown.')
    value=doc.get('response',doc)
    require(isinstance(value,dict),'Expected a JSON object response.')
    return value

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

class OCI:
    ROUTES={('deployment','create'),('deployment','get'),('deployment','list'),('deployment','stop'),('deployment','start'),
            ('connection','create-microsoft-sqlserver-connection'),('connection','create-postgresql-connection'),('connection','create-goldengate-connection'),
            ('connection','get'),('connection','list'),
            ('connection-assignment','create'),('connection-assignment','get'),('connection-assignment','list'),('connection-assignment','test'),
            ('deployment-version','list')}
    def __init__(self,c):self.c=c
    def call(self,resource,operation,args=(),payload=None):
        require((resource,operation) in self.ROUTES,'OCI operation outside the supported executor routes.')
        cli=shutil.which('oci');require(cli,'OCI CLI not found.')
        o=self.c['oci'];env={k:v for k,v in os.environ.items() if not k.startswith('OCI_CLI_')}
        # CLI mutation retries are disabled. A timeout remains pending in the journal.
        with tempfile.TemporaryDirectory(prefix='ggsetup-request-') as tmp:
            root=Path(tmp);rc=root/'rc';rc.write_text('')
            argv=[cli,'goldengate',resource,operation,*args,'--profile',o['profile'],'--auth',o['auth'],
                '--region',o['region'],'--config-file',str(Path(o['config_file']).expanduser()),'--cli-rc-file',str(rc),
                '--output','json','--no-retry']
            if payload is not None:
                p=root/'payload.json';p.write_text(json.dumps(payload));p.chmod(0o600)
                argv += ['--from-json','file://'+str(p)]
            try:
                r=subprocess.run(argv,env=env,capture_output=True,text=True,encoding='utf-8',errors='strict',timeout=120,check=False)
                require(r.returncode==0,'OCI '+resource+' '+operation+' failed. Inspect resource/work requests; pending mutation is retained. Raw response omitted.')
                doc=json.loads(r.stdout or '{}');require(isinstance(doc,dict),'Invalid OCI response.')
                return doc
            except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired):
                raise SetupError('OCI response unavailable/unreadable; retain state and inspect before retrying.') from None
    def get(self,resource,ocid):
        return self.call(resource,'get',['--'+resource+'-id',ocid]).get('data') or {}
    def list(self,resource,extra=()):
        data=self.call(resource,'list',['--compartment-id',self.c['oci']['compartment_id'],'--all',*extra]).get('data') or {}
        values=data if isinstance(data,list) else data.get('items',[])
        require(isinstance(values,list),'Invalid OCI list response.');return values
    def wait(self,resource,ocid,desired=('ACTIVE',),timeout=1800):
        until=time.monotonic()+timeout
        while True:
            d=self.get(resource,ocid);status=d.get('lifecycle-state')
            if status in desired:return d
            require(status not in ('FAILED','DELETED','DELETING'),'Unexpected '+resource+' state '+str(status))
            require(time.monotonic()<until,'Timed out waiting for '+resource+'; creation intent is retained. Do not recreate.')
            print('Waiting for '+resource+': '+str(status),flush=True);time.sleep(5)

class GG:
    def __init__(self,url,user,password,ca_file=None):
        u=urllib.parse.urlsplit(url)
        require(u.scheme=='https' and bool(u.hostname) and not u.username and not u.password and u.path in ('','/') and u.port in (None,443) and not u.query and not u.fragment,'Expected a deployment HTTPS origin.')
        self.url=url.rstrip('/');self.password=password
        auth=base64.b64encode((user+':'+password).encode()).decode()
        self.headers={'Authorization':'Basic '+auth,'Accept':'application/json','Content-Type':'application/json'}
        self.opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    def call(self,method,path,payload=None,optional=False,accept='application/json'):
        require(method in ('GET','POST','PUT','PATCH') and path.startswith(('/services/v2/','/services/adminsrvr/v2/')) and '..' not in path and '\r' not in path and '\n' not in path,'Invalid GoldenGate route.')
        req=urllib.request.Request(self.url+path,data=None if payload is None else json.dumps(payload).encode(),headers=dict(self.headers,Accept=accept),method=method)
        try:
            with self.opener.open(req,timeout=90) as r:raw=r.read(8*1024*1024+1)
            require(len(raw)<=8*1024*1024,'GoldenGate response exceeded size limit.')
            return content(json.loads(raw or '{}'))
        except urllib.error.HTTPError as exc:
            if optional and method=='GET' and exc.code==404:return None
            raise SetupError('GoldenGate '+method+' '+path+' returned HTTP '+str(exc.code)+'. Mutation outcome may be unknown; retain state.') from None
        except (urllib.error.URLError,TimeoutError,UnicodeError,ValueError):
            raise SetupError('GoldenGate response unavailable/unreadable; retain state and inspect.') from None
    def get(self,path,optional=False):return self.call('GET',path,optional=optional)
    def schema(self,name):
        require(name in ('extract','replicat'),'Unsupported metadata schema request.')
        return self.call('GET','/services/adminsrvr/v2/metadata-catalog/'+name,accept='application/schema+json')
    def wait(self,path,key='status',desired=('running',),timeout=900):
        until=time.monotonic()+timeout
        while True:
            d=self.get(path);status=d.get(key)
            if status in desired:return d
            require(status not in ('abended','killed'),'GoldenGate process '+str(status)+'; keep reports/trails/state.')
            require(time.monotonic()<until,'GoldenGate observation timed out; no new start/stop was sent.')
            print('Waiting: '+path+' '+str(status),flush=True);time.sleep(5)

class SQL:
    def __init__(self,c,config_path):self.c=c;self.path=config_path;self.passwords={};self.users={}
    def endpoint(self,side):return discovery.endpoint(self.c,side,self.path)
    def password(self,side):
        if side not in self.passwords:
            e=self.endpoint(side);self.passwords[side]=discovery.hidden(side+' administrator/inspection password ('+e['username']+'): ')
        return self.passwords[side]
    def query(self,side,query,limit=10000):
        e=self.endpoint(side);exe=discovery.client.find_client(e['database_type']);require(exe,'SQL client missing.')
        r=discovery.query(e,exe,self.password(side),query,limit,90)
        require(r.get('status')=='ok','SQL query failed or was truncated; raw data omitted.')
        return r['rows']
    def as_user(self,side,username):
        require(side=='target','Only target-owner SQL sessions are supported.')
        key=(side,username)
        if key not in self.users:
            from copy import deepcopy
            config=deepcopy(self.c);config[side]['inspection_user']=username;other=SQL(config,self.path)
            identity=other.query(side,discovery.TARGET_QUERIES['identity'],1);tls=other.query(side,discovery.TARGET_QUERIES['tls'],1)
            require(len(identity)==1 and identity[0].get('database_name')==self.c[side]['database'] and identity[0].get('username')==username and len(tls)==1 and tls[0].get('ssl') is True,'Owner session identity/TLS failed before mutation.')
            self.users[key]=other
        return self.users[key]
    def execute(self,side,sql,username=None):
        if username is not None:return self.as_user(side,username).execute(side,sql)
        e=self.endpoint(side);exe=discovery.client.find_client(e['database_type']);require(exe,'SQL client missing.')
        password=self.password(side);argv,env,_=discovery.client.command(e,exe,password,'SELECT 1 AS unused',1,120)
        if side=='target':env['PGOPTIONS']='-c default_transaction_read_only=off -c statement_timeout=120000 -c lock_timeout=5000'
        try:
            r=subprocess.run(argv,input=sql,env=env,capture_output=True,text=True,encoding='utf-8',errors='strict',timeout=150,check=False)
            require(r.returncode==0,'SQL execution failed; operation intent retained. Inspect objects before retrying. Raw output omitted.')
        except (OSError,UnicodeError,subprocess.TimeoutExpired):raise SetupError('SQL outcome unknown; retain state and inspect before retrying.') from None
        return {'statement_completed':True}
