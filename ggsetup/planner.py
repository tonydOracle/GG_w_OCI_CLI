"""Metadata-driven SQL mirror planning. No DDL/DML/API mutations are executed."""
from collections import defaultdict
import re
from .common import require,SetupError,digest,now
from .config import fingerprint,names,identifier


def quote(v):
    identifier(v,'SQL identifier')
    return '"'+v.replace('"','""')+'"'

def literal(v):return "'"+v.replace("'","''")+"'"
def qname(s,t):return quote(s)+'.'+quote(t)
def bit(value,label):
    require(type(value) in (int,bool) and value in (0,1),label+' metadata is missing or invalid.')
    return bool(value)
def integer(value,label,lo,hi):
    require(type(value) is int and lo<=value<=hi,label+' metadata is out of range.')
    return value

def target_type(col):
    for flag in ('is_user_defined','is_assembly_type','is_filestream','is_sparse','is_column_set','is_hidden'):
        require(not bit(col.get(flag),flag),'Unsupported column feature: '+flag)
    require(integer(col.get('generated_always_type'),'generated_always_type',0,8)==0,'Generated-always/temporal/ledger columns require a reviewed adapter.')
    require(col.get('encryption_type') is None,'Encrypted columns require a reviewed adapter.')
    require(not bit(col.get('is_computed'),'is_computed'),'Computed column needs a reviewed transaction-exact strategy. No row fetch or automatic expression translation is permitted.')
    typ=col.get('data_type');require(isinstance(typ,str),'Missing source data type.')
    simple={'tinyint':'smallint','smallint':'smallint','int':'integer','bigint':'bigint','bit':'boolean',
            'money':'numeric(19,4)','smallmoney':'numeric(10,4)','real':'real','float':'double precision',
            'date':'date','datetime':'timestamp(6) without time zone','smalldatetime':'timestamp(6) without time zone','uniqueidentifier':'uuid'}
    if typ in simple:return simple[typ]
    if typ in ('decimal','numeric'):
        p=integer(col.get('precision'),'precision',1,38);s=integer(col.get('scale'),'scale',0,p)
        return 'numeric(%d,%d)'%(p,s)
    if typ in ('datetime2','time'):
        scale=integer(col.get('scale'),'scale',0,7)
        require(scale<=6,'Seven-digit fractional seconds cannot be represented exactly by PostgreSQL timestamps/time. Review an alternate representation.')
        return ('timestamp(%d) without time zone' if typ=='datetime2' else 'time(%d) without time zone')%scale
    if typ in ('varchar','nvarchar','char','nchar'):
        width=col.get('max_length');integer(width,'max_length',-1,8000)
        require(width!=0,'Zero-length character metadata.')
        if width==-1:
            require(typ in ('varchar','nvarchar'),'Fixed-width MAX type is invalid.')
            return 'text'
        if typ in ('nvarchar','nchar'):
            require(width%2==0,'Odd Unicode byte length.');width//=2
        return ('character' if typ in ('char','nchar') else 'character varying')+'('+str(width)+')'
    if typ in ('binary','varbinary'):
        width=integer(col.get('max_length'),'max_length',-1,8000)
        require(width!=0 and (width!=-1 or typ=='varbinary'),'Invalid binary length.')
        return 'bytea'
    raise SetupError('Unsupported source type: '+typ+'. A verified mapping is required.')

def gg_identifier(v):
    # Restrict the first release to names whose parameter syntax is unambiguous.
    require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_ $]*',v) is not None,'GoldenGate parameter identifier needs a tested quoting adapter: '+repr(v))
    return quote(v)

def resource_name(c,table,label):
    return c['goldengate']['prefix'].lower()+'_'+label+'_'+digest(table)[:16]

def build(c,report):
    require(report.get('schema_version')==1 and report.get('report_type')=='ggsetup_inspection','Use a generated ggsetup inspection report for this environment.')
    require(report.get('configuration_sha256')==fingerprint(c) and report.get('environment')==c['environment'],'Inspection belongs to a different configuration/environment.')
    findings=[];warnings=[]
    def error(code,where,message):findings.append({'code':code,'object':where,'message':message})
    def rows(side,key):
        q=report.get(side,{}).get('queries',{}).get(key,{})
        if q.get('status')!='ok' or not isinstance(q.get('rows'),list) or not all(isinstance(x,dict) for x in q['rows']):
            error('METADATA_INCOMPLETE',side+'.'+key,'Metadata must be complete and untruncated.');return []
        return q['rows']
    srcid=rows('source','identity');vis=rows('source','visibility')
    if len(srcid)!=1 or srcid[0].get('database_name')!=c['source']['database']:
        error('SOURCE_IDENTITY','source','Exactly one matching SQL Server database identity is required.')
    else:
        try:major=int(str(srcid[0]['product_version']).split('.')[0])
        except (ValueError,KeyError):major=0
        if major<13:error('SOURCE_VERSION','source','Metadata discovery requires SQL Server 2016 or later; vendor support still needs separate confirmation.')
    if len(vis)!=1 or vis[0].get('view_definition') not in (True,1):error('SOURCE_VISIBILITY','source','Database VIEW DEFINITION is required for complete metadata.')
    dstid=rows('target','identity');tls=rows('target','tls');target_tables=rows('target','tables')
    if len(dstid)!=1 or dstid[0].get('database_name')!=c['target']['database'] or dstid[0].get('is_standby') is not False:
        error('TARGET_IDENTITY','target','A matching writable PostgreSQL primary database is required.')
    if dstid:
        try:version=int(dstid[0].get('version_number','0'))
        except (ValueError,TypeError):version=0
        if version<150000:error('TARGET_VERSION','target','This schema planner requires PostgreSQL 15+ for reviewed nullable unique-index syntax.')
        if dstid[0].get('encoding')!='UTF8':error('TARGET_ENCODING','target','UTF8 target encoding is required.')
    if len(tls)!=1 or tls[0].get('ssl') is not True:error('TARGET_TLS','target','Verified target TLS connection evidence is required.')
    oci=report.get('oci',{})
    meta=oci.get('destination',{});conn=oci.get('connection',{})
    if meta.get('status')!='ok' or meta.get('data',{}).get('id')!=c['target']['db_system_id'] or meta.get('data',{}).get('compartment-id')!=c['oci']['compartment_id']:
        error('OCI_IDENTITY','target','Destination OCI DB system/compartment lookup does not match configuration.')
    ep=(conn.get('data') or {}).get('primary-db-endpoint') or {}
    if conn.get('status')!='ok' or str(ep.get('fqdn','')).rstrip('.').lower()!=c['target']['host'].rstrip('.').lower() or ep.get('port')!=c['target']['port']:
        error('OCI_ENDPOINT','target','OCI primary FQDN/port must match the configured target.')
    tables=rows('source','tables');columns=rows('source','columns');keys=rows('source','keys')
    by_table=defaultdict(list);by_keys=defaultdict(list)
    for col in columns:by_table[(col.get('schema_name'),col.get('table_name'))].append(col)
    for col in keys:by_keys[(col.get('schema_name'),col.get('table_name'))].append(col)
    identities=[(t.get('schema_name'),t.get('table_name')) for t in tables]
    if len(identities)!=len(set(identities)):error('DUPLICATE_TABLE','source','Duplicate table metadata.')
    scope=c['scope'];include=set(map(tuple,scope['include_tables']));exclude=set(map(tuple,scope['exclude_tables']))
    excluded_schemas=set(scope['exclude_schemas'])|{'sys','cdc','INFORMATION_SCHEMA',c['goldengate']['schema']}
    selected=[t for t in tables if (scope['mode']=='all' or (t.get('schema_name'),t.get('table_name')) in include) and t.get('schema_name') not in excluded_schemas and (t.get('schema_name'),t.get('table_name')) not in exclude]
    wanted={(t.get('schema_name'),t.get('table_name')) for t in selected}
    for missing in sorted(include-wanted):error('MISSING_SCOPE',repr(missing),'Included table was not discovered or conflicts with an excluded schema.')
    if not selected:error('EMPTY_SCOPE','scope','No application tables selected.')
    # Avoid accidentally overlaying existing target objects during initial planning.
    existing={(t.get('schema_name'),t.get('table_name')) for t in target_tables}
    for item in sorted(wanted&existing):error('TARGET_OBJECT_EXISTS',repr(item),'Initial-load planning requires absent target objects; existing-object adoption is not implemented.')
    manifest=[]
    for table in sorted(selected,key=lambda x:(str(x.get('schema_name')),str(x.get('table_name')))):
        schema=table.get('schema_name');name=table.get('table_name');label=str(schema)+'.'+str(name)
        before=len(findings)
        try:
            gg_identifier(schema);gg_identifier(name)
            for flag in ('is_memory_optimized','is_filetable','is_external','has_row_security'):
                require(not bit(table.get(flag),flag),'Unsupported table feature: '+flag)
            require(integer(table.get('temporal_type'),'temporal_type',0,2)==0,'Temporal/history tables need a reviewed adapter.')
        except (SetupError,TypeError) as exc:error('TABLE_UNSUPPORTED',label,str(exc));continue
        cols=by_table[(schema,name)];mapped=[]
        if not cols:error('MISSING_COLUMNS',label,'No columns were returned for the selected table.')
        try:
            ordinals=[integer(x.get('ordinal'),'ordinal',1,1024) for x in cols]
            require(len(set(ordinals))==len(ordinals) and len({x.get('column_name') for x in cols})==len(cols),'Duplicate column ordinal/name.')
            # SQL Server ordinals may have gaps after DROP COLUMN; do not require contiguity.
            for col in sorted(cols,key=lambda x:x['ordinal']):
                cname=col.get('column_name');gg_identifier(cname)
                try:
                    mapped.append({'name':cname,'ordinal':col['ordinal'],'source_type':col['data_type'],
                        'target_type':target_type(col),'nullable':bit(col.get('is_nullable'),'is_nullable'),
                        'identity':bit(col.get('is_identity'),'is_identity')})
                except SetupError as exc:error('COLUMN_UNSUPPORTED',label+'.'+str(cname),str(exc))
        except (SetupError,TypeError) as exc:error('COLUMN_METADATA',label,str(exc))
        idxgroups=defaultdict(list)
        for row in by_keys[(schema,name)]:idxgroups[row.get('index_name')].append(row)
        primary=[];unique=[]
        for idx,parts in idxgroups.items():
            try:
                require(isinstance(idx,str) and idx,'Index name is missing.')
                head=parts[0]
                for flag in ('is_primary_key','is_unique','is_disabled','has_filter'):
                    values=[bit(x.get(flag),flag) for x in parts]
                    require(len(set(values))==1,'Index flags are inconsistent.')
                require(bit(head['is_unique'],'is_unique'),'Unexpected non-unique index metadata.')
                require(not bit(head['is_disabled'],'is_disabled') and not bit(head['has_filter'],'has_filter'),'Filtered or disabled unique index requires manual design.')
                main=[x for x in parts if not bit(x.get('is_included_column'),'is_included_column')]
                ords=[integer(x.get('key_ordinal'),'key_ordinal',1,32) for x in main]
                require(ords and sorted(ords)==list(range(1,len(ords)+1)),'Invalid index key ordinal metadata.')
                names_=[x['column_name'] for x in sorted(main,key=lambda x:x['key_ordinal'])]
                require(len(names_)==len(set(names_)) and all(x in {v.get('column_name') for v in cols} for x in names_),'Index references missing or duplicate columns.')
                if head['is_primary_key']:primary.append(names_)
                else:unique.append({'source_name':idx,'columns':names_})
            except (SetupError,KeyError,TypeError) as exc:error('INDEX_UNSUPPORTED',label+'.'+str(idx),str(exc))
        if len(primary)!=1:error('PRIMARY_KEY',label,'Exactly one enabled unfiltered primary key is required; automatic key selection is not implemented.')
        elif any(x.get('nullable') for x in mapped if x['name'] in primary[0]):error('PRIMARY_KEY_NULLABLE',label,'Primary-key metadata cannot be nullable.')
        if len(findings)==before:
            manifest.append({'schema':schema,'table':name,'columns':mapped,'primary_key':primary[0],'unique_indexes':unique})
    for side in ('source','target'):
        for label,item in report.get(side,{}).get('queries',{}).items():
            if isinstance(item,dict) and item.get('status')!='ok':warnings.append('Collection incomplete for '+side+'.'+label+'; operational readiness is not established.')
    warnings.extend([
      'This is a schema/mapping plan, not replication readiness or vendor certification.',
      'SQL Server functions/procedures, collations, defaults, identities, foreign keys and CHECK constraints are not migrated; the PostgreSQL target is a source-driven data mirror.',
      'Validate actual values (including text NULs, encoding, binary/LOB limits and datetime conversions) before enabling replication.',
      'An initial load will require application writes paused, a fresh verified snapshot LSN and retained CDC coverage. No LSN is invented by this planner.',
      'Trail prefixes are finite and may collide on shared deployments. Live resource/name/report/trail collision checks are required before mutation.',
    ])
    if c['source']['trust_server_certificate']:warnings.append('SQL Server encryption required but certificate verification explicitly disabled in this configuration.')
    if any(x['identity'] for t in manifest for x in t['columns']):warnings.append('Source identity values will be replicated into ordinary target columns; no target sequence is created.')
    n=names(c)
    plan={'schema_version':1,'report_type':'ggsetup_schema_plan','created_at':now(),'environment':c['environment'],
          'configuration_sha256':fingerprint(c),'inspection_sha256':digest(report),
          'status':'blocked' if findings else 'schema_plan_ready','remote_changes_performed':False,
          'replication_ready':False,'selected_table_count':len(selected),'planned_table_count':len(manifest),
          'planned_column_count':sum(len(t['columns']) for t in manifest),'names':n,
          'tables':manifest,'blockers':findings,'warnings':warnings,
          'execution_gates':['version_edition_service_certification','network_and_IAM','account_privileges_and_table_CDC',
              'managed_cleanup_and_snapshot_settings','actual_value_conversion_tests','installed_GoldenGate_schema_validation',
              'fresh_snapshot_boundary_and_CDC_retention','full_initial_content_verification','CDC_transaction_delivery_and_restart_tests']}
    return plan

def artifacts(c,plan):
    require(plan.get('configuration_sha256')==fingerprint(c),'Plan belongs to a different configuration.')
    require(plan['status']=='schema_plan_ready' and not plan['blockers'],'Blocked plans cannot produce executable SQL/mapping artifacts.')
    lines=['-- REVIEW ONLY: generated mirror DDL; this toolkit does not execute it.',
           '-- Collations, routines, defaults, foreign keys and CHECK constraints are not migrated.',
           '\\set ON_ERROR_STOP on','BEGIN;',
           "DO $ggsetup_guard$ BEGIN IF current_database() <> convert_from(decode('"+c['target']['database'].encode('utf-8').hex()+"','hex'),'UTF8') THEN RAISE EXCEPTION 'Wrong target database'; END IF; END $ggsetup_guard$;",
           'SET LOCAL search_path = pg_catalog;']
    for schema in sorted({t['schema'] for t in plan['tables']}):lines.append('CREATE SCHEMA IF NOT EXISTS '+quote(schema)+';')
    maps=[];captures=[]
    for t in plan['tables']:
        fq=qname(t['schema'],t['table']);cols=t['columns']
        definitions=['  '+quote(x['name'])+' '+x['target_type']+('' if x['nullable'] else ' NOT NULL') for x in cols]
        keyname=resource_name(c,[t['schema'],t['table']],'pk')
        definitions.append('  CONSTRAINT '+quote(keyname)+' PRIMARY KEY ('+', '.join(quote(x) for x in t['primary_key'])+')')
        lines.append('CREATE TABLE '+fq+' (\n'+',\n'.join(definitions)+'\n);')
        for u in t['unique_indexes']:
            idx=resource_name(c,[t['schema'],t['table'],u['source_name']],'uq')
            lines.append('CREATE UNIQUE INDEX '+quote(idx)+' ON '+fq+' ('+', '.join(quote(x) for x in u['columns'])+') NULLS NOT DISTINCT;')
        captures.append('TABLE '+fq+', COLS ('+', '.join(gg_identifier(x['name']) for x in cols)+');')
        maps.append('MAP '+fq+', TARGET '+fq+', COLMAP ('+', '.join(gg_identifier(x['name'])+' = '+gg_identifier(x['name']) for x in cols)+');')
    lines.extend(['COMMIT;',''])
    # Fragments intentionally lack EXTRACT/REPLICAT/BEGIN/EXTTRAIL commands.
    # Installed schema/build validation and fresh snapshot positioning come later.
    return {'target-schema.review.sql':'\n'.join(lines),
            'capture-tables.review.prm':'-- REVIEW ONLY: table fragments, not a runnable Extract.\n'+'\n'.join(captures)+'\n',
            'apply-maps.review.prm':'-- REVIEW ONLY: map fragments, not a runnable Replicat.\n'+'\n'.join(maps)+'\n'}
