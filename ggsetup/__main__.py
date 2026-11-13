"""Unified entry point: python3 -m ggsetup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
from . import __version__
from . import config,discovery,planner
from .common import SetupError,require,now,digest,private_directory,read_json,write_json,write_text
from .state import Journal
from . import execution_plan
from .executor import Executor


def prompt(label,default=''):
    value=input(label+(' ['+str(default)+']' if default!='' else '')+': ').strip()
    return value if value else default

def wizard(environment):
    c=config.example(environment)
    for side in ('oci','source','target'):
        print('\n'+side.upper())
        for key in c[side]:
            if key=='trust_server_certificate':continue  # Verified source TLS is always the wizard default.
            value=prompt(key,c[side][key])
            if key=='port':
                try:value=int(value)
                except ValueError:raise SetupError('Port must be an integer.') from None
            c[side][key]=value
    print('\nGOLDENGATE (optional OCIDs may be left blank for later planning)')
    for key in c['goldengate']:c['goldengate'][key]=prompt(key,c['goldengate'][key])
    c['scope']['exclude_schemas']=sorted(set(c['scope']['exclude_schemas'])|{c['goldengate']['schema']})
    return config.validate(c)

def state_path(path):return Path(path).absolute().parent/'state'

def cmd_init(args):
    c=config.example(args.environment) if args.template else wizard(args.environment)
    # Templates intentionally contain placeholders and are not a verified environment.
    config.validate(c)
    out=Path(args.directory).absolute();private_directory(out)
    write_json(out/'environment.json',c)
    print('Created '+str(out/'environment.json'))
    print('Edit placeholders and review scope before inspection. No cloud/database changes performed.')
    return 0

def doctor(c,path):
    checks={}
    for kind in ('sqlserver','postgresql'):
        value=discovery.client.find_client(kind);checks[kind+'_client']={'ok':bool(value),'path':value}
    checks['oci_cli']={'ok':bool(shutil.which('oci')),'path':shutil.which('oci')}
    ep=discovery.endpoint(c,'target',path)
    try:
        ssl.create_default_context(cafile=ep['ca_file'])
        checks['target_ca']={'ok':True,'path':ep['ca_file'],'sha256':hashlib.sha256(Path(ep['ca_file']).read_bytes()).hexdigest()}
    except (OSError,ssl.SSLError):checks['target_ca']={'ok':False,'path':ep['ca_file'],'reason':'Missing or invalid CA; no bypass will be used.'}
    checks['placeholder_values']={'ok':'REPLACE_ME' not in json.dumps(c) and '.invalid' not in json.dumps(c),'reason':'Replace template OCIDs and example.invalid endpoints.'}
    print(json.dumps({'checks':checks,'scope':'local prerequisites only; no network/client-version certification'},indent=2))
    return 0 if all(v['ok'] for v in checks.values()) else 2

def run(args):
    if args.command=='init':return cmd_init(args)
    if args.command=='execution-template':
        write_json(args.output,execution_plan.example());print('Created execution settings template: '+args.output);return 0
    c=config.load(args.config)
    if args.command=='validate':
        print(json.dumps({'status':'configuration_valid','configuration_sha256':config.fingerprint(c),'names':config.names(c),'note':'Structure only; connectivity and support not verified.'},indent=2));return 0
    if args.command=='doctor':return doctor(c,args.config)
    if args.command=='fetch-ca':
        print(json.dumps(discovery.fetch_ca(c,args.config),indent=2));return 0
    state=state_path(args.config)
    if args.command=='status':
        path=state/'journal.json'
        require(not path.is_symlink(),'Journal cannot be a symlink.')
        if not path.exists():print('No state has been created for this configuration.');return 0
        # Status is observational; no new journal is created.
        data=read_json(path)
        require(data.get('configuration_sha256')==config.fingerprint(c),'State/configuration mismatch.')
        print(json.dumps(data,indent=2));return 0
    if args.command=='execution-plan':
        schema=read_json(args.schema_plan);settings=read_json(args.settings)
        result=execution_plan.build(c,schema,settings);out=Path(args.output).absolute()
        require(not out.exists(),'Execution plan output directory must be new.')
        private_directory(out);write_json(out/'execution-plan.json',result)
        write_text(out/'target-schema.review.sql',result['target_sql'])
        write_text(out/'source-account.review.sql',result['source_sql_preview'])
        print('Execution plan: '+str(out/'execution-plan.json'))
        print('Review all settings, stages, prerequisites and SQL before execution. SHA-256: '+result['execution_sha256'])
        return 0
    if args.command in ('execute-stage','execute-all','execution-observe','execution-health','reconcile-resource'):
        plan=execution_plan.validate_plan(c,read_json(args.execution_plan))
        with Journal(state,c) as journal:
            runner=Executor(c,args.config,plan,journal)
            output=state/('execution-'+now().replace(':','').replace('-','').replace('+','')+'.json')
            try:
                if args.command=='execute-stage':result=runner.execute(args.stage,args.approve_sha256,args.writes_paused)
                elif args.command=='execute-all':
                    for stage in execution_plan.STAGES[:execution_plan.STAGES.index(args.until)+1]:
                        print('Execution stage: '+stage,flush=True);runner.execute(stage,args.approve_sha256,args.writes_paused)
                    result={'status':'execution_stages_completed','through_stage':args.until,'stages':journal.data['stages']}
                    if args.until=='start-cdc':result['health']=getattr(runner,'last_health',None) or runner.health()
                elif args.command=='execution-observe':result=runner.observe()
                elif args.command=='execution-health':result=runner.health()
                else:
                    require(args.approve_sha256==plan['execution_sha256'],'Reviewed execution SHA-256 required for reconciliation.')
                    result=runner.reconcile_resource(args.key,args.resource_id)
                write_json(output,result)
            except (SetupError,OSError,RuntimeError) as exc:
                write_json(output,{'status':'stopped_for_review','error':str(exc),'stage':journal.data.get('in_progress_stage',getattr(args,'stage',None)),'pending':[k for k,v in journal.data['intents'].items() if v['status']=='pending']})
                print('Report: '+str(output));raise
        print(json.dumps(result,indent=2));print('Report: '+str(output));return 0
    if args.command=='inspect':
        require('REPLACE_ME' not in json.dumps(c) and '.invalid' not in json.dumps(c),'Replace example config values before a live inspection.')
        with Journal(state,c) as journal:
            output=state/('inspection-'+now().replace(':','').replace('-','').replace('+','')+'.json')
            report=discovery.inspect(c,args.config,args.max_rows,args.timeout)
            write_json(output,report)
            journal.event('inspection_saved',{'path':str(output),'sha256':digest(report),'status':report['status']})
        print('Status: '+report['status']+'\nInspection: '+str(output));return 0 if report['status']=='collected' else 2
    if args.command=='plan':
        with Journal(state,c) as journal:
            report=read_json(args.inspection);plan=planner.build(c,report)
            output=Path(args.output).absolute()
            require(not output.exists(),'Plan output directory must be new.')
            private_directory(output);write_json(output/'plan.json',plan)
            if plan['status']=='schema_plan_ready':
                for name,text in planner.artifacts(c,plan).items():write_text(output/name,text)
            journal.event('schema_plan_saved',{'path':str(output/'plan.json'),'sha256':digest(plan),'status':plan['status']})
        print('Status: '+plan['status']+'\nPlan: '+str(output/'plan.json'))
        print(str(plan['planned_table_count'])+'/'+str(plan['selected_table_count'])+' tables planned; '+str(len(plan['blockers']))+' blockers.')
        for issue in plan['blockers']:print(issue['code']+' '+issue['object']+': '+issue['message'])
        print('No remote changes performed. Planning itself does not configure replication; reviewed execution commands are separate.')
        return 0 if plan['status']=='schema_plan_ready' else 2
    raise SetupError('Unknown command.')

def main(argv=None):
    os.umask(0o077)
    p=argparse.ArgumentParser(prog='python3 -m ggsetup',description='OCI SQL Server → PostgreSQL setup: environment discovery and safe schema planning. Experimental staged execution available; review the execution runbook before use.')
    p.add_argument('--version',action='version',version=__version__)
    subs=p.add_subparsers(dest='command',required=True)
    init=subs.add_parser('init',help='Interactive secret-free configuration (or an editable template)')
    init.add_argument('--environment',required=True);init.add_argument('--directory',required=True);init.add_argument('--template',action='store_true')
    template=subs.add_parser('execution-template',help='Write editable secret-ID execution settings')
    template.add_argument('--output',required=True)
    for name in ('validate','fetch-ca','doctor','inspect','plan','status','execution-plan','execute-stage','execute-all','execution-observe','execution-health','reconcile-resource'):
        s=subs.add_parser(name);s.add_argument('--config',required=True)
        if name=='inspect':
            s.add_argument('--max-rows',type=int,default=10000);s.add_argument('--timeout',type=int,default=45)
        if name=='plan':s.add_argument('--inspection',required=True);s.add_argument('--output',required=True)
        if name=='execution-plan':
            s.add_argument('--schema-plan',required=True);s.add_argument('--settings',required=True);s.add_argument('--output',required=True)
        if name in ('execute-stage','execute-all','execution-observe','execution-health','reconcile-resource'):
            s.add_argument('--execution-plan',required=True)
        if name in ('execute-stage','execute-all'):
            if name=='execute-stage':s.add_argument('--stage',choices=execution_plan.STAGES,required=True)
            else:s.add_argument('--until',choices=execution_plan.STAGES,default='start-cdc')
            s.add_argument('--approve-sha256',required=True);s.add_argument('--writes-paused',action='store_true')
        if name=='reconcile-resource':
            s.add_argument('--key',required=True);s.add_argument('--resource-id',required=True);s.add_argument('--approve-sha256',required=True)
    args=p.parse_args(argv)
    if args.command=='inspect' and (not 1<=args.max_rows<=1000000 or not 1<=args.timeout<=600):p.error('max-rows must be 1–1000000 and timeout 1–600 seconds.')
    try:return run(args)
    except KeyboardInterrupt:
        print('Interrupted. Existing files, trails and state retained. Observe uncertain outcomes before another execution request.',file=sys.stderr);return 130
    except (SetupError,OSError,RuntimeError) as exc:
        print('Stopped: '+str(exc),file=sys.stderr);return 2
    except (KeyError,TypeError,ValueError,UnicodeError) as exc:
        print('Stopped: invalid input/state/metadata structure ('+type(exc).__name__+'). Preserve state; no automatic retry.',file=sys.stderr);return 2

if __name__=='__main__':sys.exit(main())
