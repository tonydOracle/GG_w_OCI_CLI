"""Strict private JSON IO and deterministic configuration fingerprints."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

class SetupError(Exception):
    pass

def require(condition, message):
    if not condition:
        raise SetupError(message)

def now():
    return datetime.now(timezone.utc).isoformat()

def digest(value):
    return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def read_json(path):
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result,'Duplicate JSON property: '+k)
            result[k]=v
        return result
    p=Path(path)
    require(p.stat().st_size<=32*1024*1024,'JSON file exceeds 32 MiB limit.')
    try:
        return json.loads(p.read_text(encoding='utf-8'),object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(SetupError('Non-finite JSON number.')))
    except (ValueError,UnicodeError):
        raise SetupError('Invalid UTF-8 JSON: '+str(p)) from None

def private_directory(path):
    p=Path(path)
    # Reject symlink components, including the final directory.
    absolute=p.absolute()
    for parent in [absolute,*absolute.parents]:
        require(not parent.is_symlink(),'Symlink paths are not supported: '+str(parent))
    p.mkdir(mode=0o700,parents=True,exist_ok=True)
    require(p.is_dir(),'Not a directory: '+str(p))
    # Do not silently chmod an existing shared directory; refuse it.
    require(p.stat().st_mode & 0o077 == 0,'Private directory must have mode 0700: '+str(p))
    return p

def write_json(path, value, replace=False):
    write_text(path,json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',replace)

def write_text(path, value, replace=False):
    path=Path(path)
    private_directory(path.parent)
    require(not path.is_symlink(),'Refusing symlink output.')
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=str(path.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            os.chmod(tmp,0o600);f.write(value);f.flush();os.fsync(f.fileno())
        if replace:
            os.replace(tmp,path)
        else:
            # Atomic create without overwriting an existing file.
            os.link(tmp,path);os.unlink(tmp)
        dfd=os.open(str(path.parent),os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
