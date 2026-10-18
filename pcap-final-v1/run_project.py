"""Final entry: read-only program analysis, bounded local tool selection, and saved reports."""
from __future__ import annotations
import argparse
import asyncio
from contextlib import asynccontextmanager,contextmanager
from dataclasses import asdict
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4
import zipfile

import pc_shared as s
import pc_planner as native
from pc_lock import RunLock

HERE=Path(__file__).resolve().parent
DIRECT={'http':'inspect_http_requests','dns':'inspect_dns_queries','tls':'check_tls_posture','tcp':'list_conversations'}

def bundle_checked():
    wanted=s.read(HERE/'source-sha256.json')
    s.require(isinstance(wanted,dict) and bool(wanted),'Release source inventory missing')
    for name,digest in wanted.items():
        p=HERE/name
        s.require(p.resolve().is_relative_to(HERE) and s.sha(p)==digest,'Release source changed: '+name)
    return wanted

def load():
    sys.path.insert(0,str(HERE/'runtime'))
    from pcap_mcp import agent,config,verify
    from pcap_mcp.research import ResearchAudit
    s.require(Path(agent.__file__).resolve().parent==HERE/'runtime/pcap_mcp','Wrong core runtime imported')
    return agent,config,verify,ResearchAudit

@contextmanager
def configured(config,allowed):
    values={'PCAP_MCP_ALLOWED_DIRS':str(allowed),'PCAP_MCP_REDACT':'on','PCAP_MCP_MAX_ROWS':'200',
            'PCAP_MCP_MAX_RESULT_CHARS':'50000'}
    old={k:os.environ.get(k) for k in values};os.environ.update(values);config.reset_settings()
    try:yield
    finally:
        for k,v in old.items():
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v
        config.reset_settings()

@asynccontextmanager
async def session_for(modules):
    agent=modules[0]
    env={**os.environ,'PYTHONPATH':str(HERE/'runtime')+os.pathsep+os.environ.get('PYTHONPATH','')}
    params=agent.StdioServerParameters(command=sys.executable,args=['-B','-m','pcap_mcp.server'],env=env)
    async with agent.stdio_client(params) as (read,write):
        async with agent.ClientSession(read,write) as session:
            await session.initialize();tools=(await session.list_tools()).tools
            s.require([t.name for t in tools]==['summarize_capture',*s.ANALYSIS_TOOLS],'MCP registry differs')
            yield session,tools

def versions(modules):
    settings=modules[1].get_settings();result={}
    for name,program in [('tshark',settings.tshark),('capinfos',settings.capinfos)]:
        p=subprocess.run([program,'--version'],capture_output=True,timeout=20)
        s.require(p.returncode==0,name+' version probe failed')
        result[name]=p.stdout.decode('utf-8',errors='replace')[:4000]
    return result

async def registry_check(modules):
    async with session_for(modules) as (_,tools):return [t.name for t in tools]

def check(project):
    bundle_checked();modules=load()
    with configured(modules[1],Path(project).resolve()):
        return {'status':'ready','versions':versions(modules),'mcp_tools':asyncio.run(registry_check(modules)),
                'model_requests':0,'model_service_checked':False,'scope':'dependencies, parser and live MCP registry'}

def payload(evidence):
    from pcap_mcp.evidence_io import parse_tool_payload
    value=parse_tool_payload(evidence['result'])
    if evidence.get('error') or evidence.get('truncated') or not isinstance(value,dict) or 'error' in value:
        return None
    return value

async def direct(capture,selected,modules):
    agent=modules[0];evidence=[]
    async with session_for(modules) as (session,_):
        for name in ['summarize_capture',*[DIRECT[t] for t in selected]]:
            args={'path':str(capture)}
            if name=='inspect_http_requests':args['evidence_mode']='field'
            text=agent._tool_text(await session.call_tool(name,args))
            evidence.append(asdict(agent._evidence(f'E{len(evidence)+1:02d}',name,args,text)))
    return evidence

async def agent_case(capture,goal,run,transport,identity,modules):
    agent,_,_,ResearchAudit=modules
    folder=run/'calls/01';folder.mkdir(parents=True,exist_ok=True)
    api=run/'api'/uuid4().hex[:8]/'01';api.mkdir(parents=True)
    client=native.PlannerClient(folder,api,transport,identity,s.sha(capture),'B')
    audit=ResearchAudit(folder/'evidence.json',folder/'audit.json')
    async with session_for(modules) as (session,tools):
        s.once(folder/'mcp-tools.json',s.encoded([{'name':t.name,'description':t.description,'inputSchema':t.inputSchema} for t in tools]))
        outcome=await agent.investigate(client,session,s.MODEL,str(capture),goal,tools,
            max_calls=2,max_rounds=2,report_format='guarded',max_format_retries=0,seed=19,audit=audit)
    audit.finish('completed')
    s.once(run/'audit.json',s.encoded(audit.data))
    return [asdict(e) for e in outcome.evidence]

def make_observations(capture,evidence,modules):
    usable=[];excluded=[];proof=None
    http=[e for e in evidence if e['tool']=='inspect_http_requests' and payload(e) is not None]
    if http:proof=modules[2].verify_evidence(capture,http)
    for e in evidence:
        value=payload(e)
        reason='incomplete_or_error_tool_output' if value is None else None
        if e['tool']=='inspect_http_requests' and value is not None and value.get('capture_sha256')!=s.sha(capture):
            reason='HTTP_capture_binding_differs'
        if e['tool']=='inspect_http_requests' and value is not None and value.get('field_records') and (proof is None or proof['all_records_match'] is not True):
            reason='HTTP_source_reextraction_not_verified'
        if reason:excluded.append({'evidence_id':e['id'],'tool':e['tool'],'reason':reason})
        else:usable.append({'evidence_id':e['id'],'tool':e['tool'],'security_warning':e['security_warning'],'payload':value})
    from pcap_mcp.reporting import generate_report
    verified_http=[e for e in http if any(o['evidence_id']==e['id'] for o in usable) and payload(e).get('field_records')]
    program=generate_report(verified_http) if verified_http else None
    return {'schema':'pcap-final-program-observations-v1','observations':usable,'excluded':excluded,
            'http_program_report':program,
            'http_source_verification':proof,'goal_adequacy':'not_semantically_scored',
            'model_prose_published':False,'automatic_semantic_acceptance':False,
            'scope':'bounded program outputs; HTTP exported-record reextraction, other protocols parser outputs'}

def markdown(plan,result,summary):
    lines=['# PCAP程序观察报告','',f"模式：{plan['mode']}；运行编号：{plan['run_id']}",
        f"状态：{summary['status']}；模型尝试：{summary['model_attempts']}/{plan['model_attempt_cap']}",'',
        '调查目标：','',*['    '+line for line in plan.get('goal','').splitlines()], '',
        '内容由程序工具输出组成，模型正文未发布。工具选择是否足以回答目标，需用户判断。',
        '工具输出可能有采样边界；字段及转换来源不等于对行为意图、攻击成功或自然语言语义的证明。','']
    if summary.get('tool_call_rejections',0):
        lines.extend([f"控制器拒绝了{summary['tool_call_rejections']}个调用；请查看audit.json中的参数和原因。",''])
    if result.get('http_program_report'):
        from pcap_mcp.reporting import render_report
        rendered=render_report(result['http_program_report'],include_model_prose=False)
        rendered=rendered.replace('原抓包重提取须另行执行，正文语义未经核验。',
            '本入口已另行执行原包字段复核，结果见来源证明；正文语义未经核验。')
        lines.extend([rendered,''])
    for item in result['observations']:
        lines.extend([f"## {item['evidence_id']} · {item['tool']}",''])
        if item['security_warning']:lines.extend(['检测到不可信文本风险，具体字段及处理标记见保存结果。',''])
        # Indent JSON as a code block. Capture strings cannot terminate a fence.
        lines.extend('    '+line for line in s.encoded(item['payload']).decode('utf-8').splitlines())
        lines.append('')
    if result['excluded']:
        lines.extend(['## 未发布的输出','',*['    '+line for line in s.encoded(result['excluded']).decode('utf-8').splitlines()],''])
    return '\n'.join(lines)

def replay_checked(run):
    receipt=s.read(run/'receipt.json')
    s.require({'plan.json','evidence.json','program-result.json','versions.json'}<=set(receipt),'Run receipt coverage differs')
    current={p.relative_to(run).as_posix() for p in run.rglob('*') if p.is_file()}
    s.require(current==set(receipt)|{'receipt.json','SUMMARY.json','REPORT.md','return-sha256.json'},'Saved inventory coverage differs')
    for name,digest in receipt.items():
        p=run/name
        s.require(p.resolve().is_relative_to(run) and s.sha(p)==digest,'Saved run changed: '+name)
    return s.read(run/'program-result.json')

def export(run,plan,result,failure=None):
    attempts=len(list((run/'calls').glob('*/dispatch-intent.json')))
    decisions=s.read(run/'audit.json').get('tool_decisions',[]) if (run/'audit.json').exists() else []
    rejections=sum(d.get('status')=='rejected' for d in decisions)
    status='failed' if failure else 'partial_observations' if result['excluded'] or rejections else 'observations_ready'
    summary={'schema':'pcap-final-run-summary-v1','run_id':plan['run_id'],'mode':plan['mode'],'status':status,
             'model_attempts':attempts,'model_attempt_cap':plan['model_attempt_cap'],'tool_call_rejections':rejections,
             'published_tool_outputs':len(result['observations']),'goal_adequacy':'not_semantically_scored',
             'automatic_retry':False,'model_prose_published':False,'failure':failure}
    s.require(attempts<=plan['model_attempt_cap'],'Model budget exceeded')
    (run/'SUMMARY.json').write_bytes(s.encoded(summary))
    (run/'REPORT.md').write_bytes(markdown(plan,result,summary).encode('utf-8'))
    manifest=run/'return-sha256.json'
    manifest.write_bytes(s.encoded({p.relative_to(run).as_posix():s.sha(p) for p in sorted(run.rglob('*')) if p.is_file() and p!=manifest}))
    archive=run.with_suffix('.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in sorted(run.rglob('*')):
            if p.is_file():z.write(p,p.relative_to(run).as_posix())
    return {**summary,'return_zip':str(archive)}

def execute(project,mode,run_id,capture=None,goal='',selected=('http','dns','tls','tcp'),transport=None):
    s.require(mode in {'analyze','agent','report'},'Unknown execution mode')
    s.require(isinstance(run_id,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',run_id),'RunId: 1-64 ASCII letters, digits, underscore or hyphen')
    s.require(len(goal)<=4000,'Goal exceeds limit')
    s.require(len(selected)==len(set(selected)) and all(t in DIRECT for t in selected),'Unknown/duplicate direct tool')
    project=Path(project).resolve();run=project/'baseline-runs'/('final-'+run_id)
    locks=project/'baseline-runs/final-locks'/run_id;locks.mkdir(parents=True,exist_ok=True)
    with RunLock(locks):
        if mode=='report':
            bundle_checked();load()
            plan=s.read(run/'plan.json')
            original=s.read(run/'SUMMARY.json')
            if (run/'receipt.json').exists():result=replay_checked(run)
            else:
                s.require(original.get('failure') is not None,'Incomplete run has no verified result; cannot publish')
                result={'schema':'pcap-final-program-observations-v1','observations':[],'excluded':[],
                        'goal_adequacy':'not_semantically_scored','model_prose_published':False,'automatic_semantic_acceptance':False}
            return export(run,plan,result,original.get('failure'))
        source=bundle_checked();modules=load();capture=Path(capture).resolve()
        with configured(modules[1],capture.parent):
            from pcap_mcp.tshark import resolve_capture
            capture=resolve_capture(str(capture))
        run.mkdir(parents=True,exist_ok=True)
        plan={'schema':'pcap-final-run-plan-v1','run_id':run_id,'mode':mode,'capture_name':capture.name,
              'capture_sha256':s.sha(capture),'source_sha256':source,'goal':goal,'selected_direct_tools':list(selected),
              'model_attempt_cap':1 if mode=='agent' else 0,'model':s.MODEL if mode=='agent' else None,
              'model_digest':s.DIGEST if mode=='agent' else None,'model_options':native.OPTIONS if mode=='agent' else None,
              'repeat_policy':'same_RunId_exports_saved_result_or_failure; never_dispatch_again_after_intent'}
        s.once(run/'plan.json',s.encoded(plan))
        if (run/'receipt.json').exists():
            result=replay_checked(run);old=s.read(run/'SUMMARY.json')
            return export(run,plan,result,old.get('failure'))
        if (run/'calls/01/dispatch-intent.json').exists():
            result={'schema':'pcap-final-program-observations-v1','observations':[],'excluded':[],
                    'goal_adequacy':'not_semantically_scored','model_prose_published':False,'automatic_semantic_acceptance':False}
            return export(run,plan,result,{'type':'ReservedAttempt','message':'Prior dispatch has no complete saved result; no retry'})
        failure=None
        try:
            frozen=run/'input'/capture.name;s.once(frozen,capture.read_bytes())
            for name in source:s.once(run/'tools'/name,(HERE/name).read_bytes())
            with configured(modules[1],frozen.parent):
                s.once(run/'versions.json',s.encoded(versions(modules)))
                if mode=='analyze':evidence=asyncio.run(direct(frozen,selected,modules))
                else:
                    s.require(bool(goal.strip()),'Agent mode requires a goal')
                    transport=transport or s.wire.LocalHTTP('http://127.0.0.1:11434',240)
                    api=run/'api'/uuid4().hex[:8];api.mkdir(parents=True)
                    identity=s.wire.identity(transport,api/'preflight',s.MODEL)
                    s.require(identity['digest']==s.DIGEST,'Pinned local model differs; no model is downloaded')
                    s.once(run/'identity.json',s.encoded(identity))
                    evidence=asyncio.run(agent_case(frozen,goal,run,transport,identity,modules))
                s.require(s.sha(frozen)==plan['capture_sha256'],'Capture changed during analysis')
                s.once(run/'evidence.json',s.encoded(evidence))
                result=make_observations(frozen,evidence,modules)
                s.once(run/'program-result.json',s.encoded(result))
                s.require(bundle_checked()==source,'Source changed during analysis')
                s.once(run/'receipt.json',s.encoded({p.relative_to(run).as_posix():s.sha(p) for p in sorted(run.rglob('*'))
                    if p.is_file() and p.relative_to(run).as_posix() not in {'receipt.json','SUMMARY.json','REPORT.md','return-sha256.json'}}))
        except (Exception,KeyboardInterrupt) as exc:
            cause=modules[0]._root_error(exc)
            failure={'type':type(cause).__name__,'message':str(cause)}
            s.once(run/('failure-'+uuid4().hex[:8]+'.json'),s.encoded(failure))
            result={'schema':'pcap-final-program-observations-v1','observations':[],'excluded':[],
                    'goal_adequacy':'not_semantically_scored','model_prose_published':False,'automatic_semantic_acceptance':False}
        return export(run,plan,result,failure)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['check','analyze','agent','report','serve'],default='check')
    parser.add_argument('--project',type=Path,default=HERE.parent)
    parser.add_argument('--capture',type=Path);parser.add_argument('--goal',default='');parser.add_argument('--run-id')
    parser.add_argument('--tools',default='all');parser.add_argument('--allowed-dir',type=Path)
    args=parser.parse_args()
    try:
        if args.mode=='check':
            ready=check(args.project)
            print(f"Ready: {len(ready['mcp_tools'])} MCP tools; model requests: 0")
            for name,value in ready['versions'].items():print(name+': '+value.splitlines()[0])
            return 0
        if args.mode=='serve':
            s.require(args.allowed_dir is not None and args.allowed_dir.is_dir(),'Serve requires an existing --allowed-dir')
            bundle_checked();modules=load()
            with configured(modules[1],args.allowed_dir.resolve()):
                from pcap_mcp.server import main as serve
                serve()
            return 0
        s.require(args.run_id is not None,'Supply --run-id; it protects each Agent attempt against repeat dispatch')
        s.require(args.mode=='report' or args.capture is not None,'Supply --capture')
        selected=tuple(DIRECT) if args.tools=='all' else () if args.tools=='overview' else tuple(args.tools.split(','))
        result=execute(args.project,args.mode,args.run_id,args.capture,args.goal,selected)
        print(f"Status: {result['status']}; model attempts: {result['model_attempts']}/{result['model_attempt_cap']}")
        print('Report: '+str(Path(result['return_zip']).with_suffix('')/'REPORT.md'))
        print('Saved ZIP: '+result['return_zip'])
        return 1 if result['status'] in {'failed','partial_observations'} else 0
    except (Exception,KeyboardInterrupt) as exc:
        print('Stopped: '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
