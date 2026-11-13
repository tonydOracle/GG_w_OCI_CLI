"""Whole-value comparison for the supported execution subset, without row logs."""
import datetime
from decimal import Decimal
import hashlib
import json
import re
import sqlite3
import tempfile
from .common import require,digest,SetupError
from .execution_plan import sqlid
from .planner import quote,qname

NUMERIC={'decimal','numeric','money','smallmoney'}
TEMPORAL={'date','datetime','smalldatetime','datetime2','time'}
INTEGER={'int','bigint','smallint','tinyint'}
TEXT={'char','nchar','varchar','nvarchar'}

def expr(col,source):
    x=(sqlid if source else quote)(col['name']);typ=col['source_type']
    if typ in ('binary','varbinary'):return 'LOWER(CONVERT(varchar(max),'+x+',2))' if source else "encode("+x+",'hex')"
    if typ=='uniqueidentifier':return 'LOWER(CONVERT(varchar(36),'+x+'))' if source else 'lower('+x+'::text)'
    if typ in NUMERIC:
        if source:
            m=re.fullmatch(r'numeric\((\d+),(\d+)\)',col['target_type']);require(m is not None,'Missing exact numeric mapping.')
            return 'CONVERT(varchar(100),CONVERT(decimal('+m[1]+','+m[2]+'),'+x+'))'
        return x+'::text'
    if typ in INTEGER:return 'CONVERT(varchar(40),'+x+')' if source else x+'::text'
    if typ=='bit':return 'CONVERT(varchar(1),'+x+')' if source else "CASE WHEN "+x+" IS NULL THEN NULL WHEN "+x+" THEN '1' ELSE '0' END"
    if typ in TEMPORAL:
        if source:return 'CONVERT(varchar(40),'+x+',126)'
        fmt='YYYY-MM-DD' if typ=='date' else ('HH24:MI:SS.US' if typ=='time' else 'YYYY-MM-DD"T"HH24:MI:SS.US')
        return "to_char("+x+",'"+fmt+"')"
    require(typ in TEXT,'No exact comparison adapter for '+typ)
    if source:return 'CONVERT(nvarchar(max),'+x+')'
    if typ in ('char','nchar'):
        m=re.fullmatch(r'character\((\d+)\)',col['target_type']);require(m is not None,'Missing fixed character width.')
        return 'rpad('+x+'::text,'+m[1]+",' ')"
    return x+'::text'

def canonical(col,v):
    if v is None:return None
    require(isinstance(v,str),'Expected text/null comparison value.')
    typ=col['source_type']
    if typ in INTEGER:require(re.fullmatch(r'-?\d+',v) is not None,'Invalid integer.');return str(int(v))
    if typ in NUMERIC:
        require(re.fullmatch(r'-?\d+(?:\.\d+)?',v) is not None,'Invalid decimal.')
        n=Decimal(v);value=format(n,'f');return '0' if n==0 else (value.rstrip('0').rstrip('.') if '.' in value else value)
    if typ=='bit':require(v in ('0','1'),'Invalid boolean.');return v
    if typ in ('binary','varbinary'):require(len(v)%2==0 and re.fullmatch(r'[0-9a-fA-F]*',v) is not None,'Invalid binary.');return v.lower()
    if typ=='uniqueidentifier':
        require(re.fullmatch(r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}',v) is not None,'Invalid UUID.');return v.lower()
    if typ=='date':datetime.date.fromisoformat(v);return v
    if typ in TEMPORAL:
        pattern=r'(\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?' if typ=='time' else r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?'
        m=re.fullmatch(pattern,v);require(m is not None,'Invalid timestamp/time precision.')
        if typ=='time':datetime.time.fromisoformat(v)
        else:datetime.datetime.fromisoformat(v)
        return m[1]+'.'+(m[2] or '').ljust(6,'0')
    require(typ in TEXT,'Unsupported comparison type.')
    require('\0' not in v,'Text NUL requires an alternate target representation; value omitted.')
    try:v.encode('utf-8')
    except UnicodeError:raise SetupError('Invalid Unicode requires a reviewed conversion adapter; value omitted.') from None
    return v

def page(t,source,offset,batch):
    require(type(offset) is int and offset>=0 and type(batch) is int and 1<=batch<=1000,'Invalid page size.')
    qi=sqlid if source else quote
    fq=qi(t['schema'])+'.'+qi(t['table'])
    cols=', '.join(expr(col,source)+' AS '+qi('c'+str(i)) for i,col in enumerate(t['columns']))
    order=', '.join(qi(k) for k in t['primary_key'])
    if source:return 'SELECT * FROM (SELECT '+cols+' FROM '+fq+' ORDER BY '+order+' OFFSET '+str(offset)+' ROWS FETCH NEXT '+str(batch)+' ROWS ONLY) AS cmp'
    return 'SELECT * FROM (SELECT '+cols+' FROM '+fq+' ORDER BY '+order+' OFFSET '+str(offset)+' LIMIT '+str(batch)+') AS cmp'

def counts(sql,tables,side):
    qi=sqlid if side=='source' else quote
    result={}
    for t in tables:
        fq=qi(t['schema'])+'.'+qi(t['table']);rows=sql.query(side,'SELECT '+('COUNT_BIG' if side=='source' else 'count')+'(*) AS n FROM '+fq,1)
        require(len(rows)==1 and type(rows[0].get('n')) is int and rows[0]['n']>=0,'Invalid row count.')
        result[t['schema']+'.'+t['table']]=rows[0]['n']
    return result

def compare(sql,tables,expected,batch=500):
    reports=[]
    with tempfile.TemporaryDirectory(prefix='ggsetup-compare-') as tmp:
        db=sqlite3.connect(tmp+'/hashes.sqlite')
        try:
            for t in tables:
                label=t['schema']+'.'+t['table'];n=expected[label]
                db.execute('DROP TABLE IF EXISTS cells');db.execute('CREATE TABLE cells(k TEXT PRIMARY KEY,v TEXT NOT NULL,seen INTEGER NOT NULL)')
                nr={}
                for side in ('source','target'):
                    offset=0
                    while True:
                        rows=sql.query(side,page(t,side=='source',offset,batch),batch)
                        require(len(rows)<=batch and offset+len(rows)<=n,'Unexpected comparison row count; writes may not be paused.')
                        for row in rows:
                            require(set(row)=={'c'+str(i) for i in range(len(t['columns']))},'Comparison columns differ.')
                            vals={col['name']:canonical(col,row['c'+str(i)]) for i,col in enumerate(t['columns'])}
                            key=[vals[x] for x in t['primary_key']];require(all(x is not None for x in key),'NULL comparison key.')
                            k=digest(key);v=digest(vals)
                            if side=='source':db.execute('INSERT INTO cells VALUES(?,?,0)',(k,v))
                            else:
                                found=db.execute('SELECT v,seen FROM cells WHERE k=?',(k,)).fetchone()
                                require(found is not None and found==(v,0),'Missing/extra/different row or duplicate key in '+label+' (row values omitted).')
                                db.execute('UPDATE cells SET seen=1 WHERE k=?',(k,))
                        offset+=len(rows);db.commit()
                        if len(rows)<batch:break
                    require(offset==n,'Comparison row count differs for '+label);nr[side]=offset
                require(db.execute('SELECT count(*) FROM cells WHERE seen=0').fetchone()[0]==0,'Missing target rows.')
                h=hashlib.sha256()
                for k,v in db.execute('SELECT k,v FROM cells ORDER BY k'):h.update((k+v).encode())
                reports.append({'table':label,'source_rows':nr['source'],'target_rows':nr['target'],'content_sha256':h.hexdigest(),'matched':True})
            return {'tables':reports,'matched':True,'total_rows':sum(expected.values())}
        except sqlite3.IntegrityError:raise SetupError('Duplicate comparison key; data may have changed. Row values omitted.') from None
        finally:db.close()
