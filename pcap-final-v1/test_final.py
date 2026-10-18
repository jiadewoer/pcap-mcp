"""Release entry checks: real MCP/tshark, synthetic inputs, simulated model only."""
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import pytest

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import run_project as r
from test_data import samples

@pytest.fixture(autouse=True)
def gbk_default(monkeypatch):
    original=Path.open
    def gbk(self,mode='r',buffering=-1,encoding=None,errors=None,newline=None):
        if 'b' not in mode and encoding in (None,'locale'):encoding='gbk'
        return original(self,mode,buffering,encoding,errors,newline)
    monkeypatch.setattr(Path,'open',gbk)

@pytest.fixture
def project(tmp_path):
    root=tmp_path/'中文项目';inputs=root/'captures';inputs.mkdir(parents=True)
    for name,data in samples().items():(inputs/name).write_bytes(data)
    return root,inputs

class Transport:
    def __init__(self,mode=None):self.posts=0;self.mode=mode
    def call(self,method,path,body,destination):
        if path=='/api/version':value={'version':'simulated-0.24.0'}
        elif path=='/api/tags':value={'models':[{'name':r.s.MODEL,'digest':r.s.DIGEST,'details':{'format':'gguf'}}]}
        elif path=='/api/ps':value={'models':[{'name':r.s.MODEL,'digest':r.s.DIGEST,'context_length':8192}]}
        else:
            assert path=='/api/chat' and method=='POST';self.posts+=1
            request=r.s.wire.decode(body);r.native.validate_request(request,'B')
            assert len(request['tools'])==11 and len(request['messages'])==2
            assert 'field_records' not in str(request['messages'])
            if self.mode=='timeout':destination.write_bytes(b'partial');raise TimeoutError('simulated timeout')
            calls=[{'function':{'name':'inspect_http_requests','arguments':{'fields_csv':'http.user_agent'} if self.mode=='invalid' else {}}},
                   {'function':{'name':'list_conversations','arguments':{'protocol':'tcp','top_n':1}}}]
            value={'model':r.s.MODEL,'done':True,'done_reason':'stop','message':{'role':'assistant',
                'content':'SIMULATED MODEL PROSE MUST NOT APPEAR IN REPORT','tool_calls':calls}}
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(r.s.encoded(value));return value

def test_default_check_is_zero_generation_and_live_registry(project):
    ready=r.check(project[0]);assert ready['status']=='ready' and ready['model_requests']==0
    assert len(ready['mcp_tools'])==12 and ready['model_service_checked'] is False

def test_program_analysis_and_saved_report(project):
    root,inputs=project;t=Transport()
    result=r.execute(root,'analyze','program-http',inputs/'ws-http.pcap',selected=('http',),transport=t)
    assert result['status']=='observations_ready' and result['model_attempts']==0 and t.posts==0
    run=Path(result['return_zip']).with_suffix('');obj=r.s.read(run/'program-result.json')
    assert obj['http_source_verification']['all_records_match'] and len(obj['http_program_report']['facts'])==44
    assert '| 记录 | 属性 | 值 |' in (run/'REPORT.md').read_text(encoding='utf-8')
    again=r.execute(root,'report','program-http',transport=t)
    assert again['status']=='observations_ready' and t.posts==0

def test_empty_http_is_program_observation_not_a_failed_field_proof(project):
    root,inputs=project
    result=r.execute(root,'analyze','dns-only',inputs/'dns.cap')
    assert result['status']=='observations_ready',result
    obj=r.s.read(Path(result['return_zip']).with_suffix('')/'program-result.json')
    assert len(obj['observations'])==5 and obj['http_program_report'] is None
    dns=next(x['payload'] for x in obj['observations'] if x['tool']=='inspect_dns_queries')
    assert dns['unique_names_in_sample']==1 and dns['nxdomain_count_in_sample']==1

def test_agent_one_attempt_repeated_run_and_report_do_not_dispatch(project):
    root,inputs=project;t=Transport();goal='查看HTTP字段和数据量最多的一条TCP会话'
    result=r.execute(root,'agent','agent-good',inputs/'ws-http.pcap',goal,transport=t)
    assert result['status']=='observations_ready' and result['model_attempts']==t.posts==1
    run=Path(result['return_zip']).with_suffix('')
    assert 'SIMULATED MODEL PROSE' not in (run/'REPORT.md').read_text(encoding='utf-8')
    assert r.execute(root,'agent','agent-good',inputs/'ws-http.pcap',goal,transport=t)['model_attempts']==1
    assert r.execute(root,'report','agent-good',transport=t)['status']=='observations_ready'
    assert t.posts==1

def test_invalid_call_stays_rejected_valid_partial_evidence_is_retained(project):
    root,inputs=project;t=Transport('invalid')
    result=r.execute(root,'agent','invalid-args',inputs/'ws-http.pcap','HTTP与TCP',transport=t)
    assert result['status']=='partial_observations' and result['tool_call_rejections']==1 and t.posts==1
    run=Path(result['return_zip']).with_suffix('');obj=r.s.read(run/'program-result.json')
    assert [x['tool'] for x in obj['observations']]==['summarize_capture','list_conversations']
    assert r.s.read(run/'audit.json')['tool_decisions'][0]['status']=='rejected'

def test_timeout_is_reserved_once_and_failed_report_exports_without_retry(project):
    root,inputs=project;t=Transport('timeout')
    result=r.execute(root,'agent','timeout',inputs/'ws-http.pcap','HTTP',transport=t)
    assert result['status']=='failed' and result['model_attempts']==t.posts==1
    again=r.execute(root,'agent','timeout',inputs/'ws-http.pcap','HTTP',transport=t)
    assert again['status']=='failed' and t.posts==1
    assert r.execute(root,'report','timeout',transport=t)['status']=='failed' and t.posts==1

@pytest.mark.parametrize('run_id',['../outside','bad.name','中文','a'*65])
def test_bad_run_id_rejected_before_request(project,run_id):
    t=Transport()
    with pytest.raises(ValueError):r.execute(project[0],'agent',run_id,project[1]/'ws-http.pcap','HTTP',transport=t)
    assert t.posts==0

def test_saved_evidence_tamper_is_rejected(project):
    root,inputs=project
    result=r.execute(root,'analyze','tamper',inputs/'ws-http.pcap',selected=('http',))
    run=Path(result['return_zip']).with_suffix('');(run/'evidence.json').write_bytes(b'[]')
    with pytest.raises(ValueError,match='Saved run changed'):r.execute(root,'report','tamper')

def test_cli_program_mode_works_on_unicode_path(project):
    root,inputs=project
    p=subprocess.run([sys.executable,'-X','utf8','-B',str(HERE/'run_project.py'),'--mode','analyze','--project',str(root),
        '--capture',str(inputs/'dns.cap'),'--run-id','cli-dns','--tools','dns'],capture_output=True,timeout=30)
    assert p.returncode==0,(p.stdout,p.stderr)
    assert b'model attempts: 0/0' in p.stdout

def test_cli_truncated_tool_is_excluded_and_returns_nonzero(project):
    from test_data import pcap
    root,inputs=project
    question=b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
    capture=inputs/'large-dns.pcap';capture.write_bytes(pcap(17,[question]*201,53))
    p=subprocess.run([sys.executable,'-X','utf8','-B',str(HERE/'run_project.py'),'--mode','analyze','--project',str(root),
        '--capture',str(capture),'--run-id','limited','--tools','dns'],capture_output=True,timeout=30)
    assert p.returncode==1 and b'partial_observations' in p.stdout,(p.stdout,p.stderr)
    result=r.s.read(root/'baseline-runs/final-limited/program-result.json')
    assert any(e['tool']=='inspect_dns_queries' for e in result['excluded'])
    assert all(e['tool']!='inspect_dns_queries' for e in result['observations'])

def test_release_serve_mode_is_live_and_directory_scoped(project):
    root,inputs=project;modules=r.load();agent=modules[0]
    outside=root/'outside.pcap';outside.write_bytes(samples()['ws-http.pcap'])
    async def run():
        params=agent.StdioServerParameters(command=sys.executable,args=['-X','utf8','-B',str(HERE/'run_project.py'),
            '--mode','serve','--allowed-dir',str(inputs)],env=dict(os.environ))
        async with agent.stdio_client(params) as (read,write):
            async with agent.ClientSession(read,write) as session:
                await session.initialize();assert len((await session.list_tools()).tools)==12
                valid=agent._tool_text(await session.call_tool('summarize_capture',{'path':str(inputs/'dns.cap')}))
                denied=agent._tool_text(await session.call_tool('summarize_capture',{'path':str(outside)}))
                assert not agent._is_error(valid) and agent._is_error(denied)
    asyncio.run(run())
