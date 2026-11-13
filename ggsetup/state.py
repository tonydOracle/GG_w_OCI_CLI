"""Exclusive per-environment journal with immutable binding and mutation intents."""
import fcntl
import os
from pathlib import Path
import uuid
from .common import require,read_json,write_json,private_directory,now,digest
from .config import fingerprint

class Journal:
    def __init__(self,directory,config):
        self.directory=Path(directory);self.config=config;self.lock=None
    def __enter__(self):
        private_directory(self.directory)
        lockpath=self.directory/'.lock'
        fd=os.open(str(lockpath),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
        self.lock=os.fdopen(fd,'r+')
        try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close();raise RuntimeError('Another process owns this environment state lock.') from None
        try:
            self.path=self.directory/'journal.json'
            require(not self.path.is_symlink(),'Journal cannot be a symlink.')
            if self.path.exists():
                self.data=read_json(self.path)
                require(self.data.get('schema_version')==1 and self.data.get('environment')==self.config['environment'] and self.data.get('configuration_sha256')==fingerprint(self.config),'State belongs to another configuration/environment. Do not edit it; use a fresh state directory for a new setup.')
                require(isinstance(self.data.get('events'),list) and isinstance(self.data.get('intents'),dict),'Invalid journal format.')
            else:
                self.data={'schema_version':1,'run_id':uuid.uuid4().hex,'environment':self.config['environment'],'configuration_sha256':fingerprint(self.config),'created_at':now(),'events':[],'intents':{}}
                write_json(self.path,self.data)
            return self
        except BaseException:
            self.__exit__(None,None,None);raise
    def __exit__(self,*args):
        if self.lock and not self.lock.closed:
            fcntl.flock(self.lock,fcntl.LOCK_UN);self.lock.close()
    def save(self):write_json(self.path,self.data,replace=True)
    def event(self,kind,details):
        self.data['events'].append({'at':now(),'kind':kind,'details':details});self.save()
    def intent(self,key,payload):
        # Future adapters must use this BEFORE mutation; unknown outcomes cannot be retried.
        require(key not in self.data['intents'],'Operation already has intent; inspect/reconcile before another request.')
        token=uuid.uuid4().hex
        self.data['intents'][key]={'token':token,'request_sha256':digest(payload),'status':'pending','requested_at':now()}
        self.save();return token
    def acknowledge(self,key,token,evidence):
        item=self.data['intents'].get(key)
        require(item is not None and item['token']==token and item['status']=='pending','Intent identity/status mismatch.')
        require(isinstance(evidence,dict) and bool(evidence),'Completion requires structured evidence.')
        item.update(status='acknowledged',completed_at=now(),evidence=evidence);self.save()
