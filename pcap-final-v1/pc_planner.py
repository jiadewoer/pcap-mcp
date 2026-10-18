"""One native Ollama decision with eleven competing schemas; no final model prose."""
from __future__ import annotations
import copy
import json
from types import SimpleNamespace
import pc_shared as s

OPTIONS = {"temperature": 0, "seed": 19, "num_ctx": 8192, "num_predict": 1024}
SYSTEM_APPEND = ("\nThis is a one-shot routing comparison. Choose zero, one, or two focused tools "
    "in this single response. If the initial overview already answers the whole goal, stop with no tool calls. "
    "If two distinct analyses are needed, select both tools now. There will be no second model response "
    "and no model-written final report. Use each tool's default arguments unless the goal requires otherwise.\n")

def contract_note(condition, tools):
    s.require(condition in {'A','B'}, 'Unknown condition')
    if condition == 'A':return ''
    allowed = {t['function']['name']: sorted(t['function']['parameters'].get('properties', {})) for t in tools}
    return ('\nParameter-contract display condition: use only parameter keys declared for the selected tool. '
        'An empty list means arguments must be {}. Never borrow keys from another tool. '
        'The controller supplies the file path and evidence mode. Read any non-default requested value '
        'from the goal. Do not invent a field-selection parameter. This applies to every tool. '
        'Declared keys (same schemas as above): '+json.dumps(allowed,sort_keys=True,separators=(',',':'))+'\n')

class ToolMessage:
    def __init__(self, raw):
        s.require(isinstance(raw,dict) and raw.get("role")=="assistant"
                  and raw.get("thinking") in (None, "") and isinstance(raw.get("content",""),str),
                  "Unexpected native model message")
        self.content = raw.get("content", "")
        self.tool_calls = []
        calls = raw.get("tool_calls", [])
        s.require(isinstance(calls,list) and len(calls)<=2, "Invalid/too many tool calls")
        for index,row in enumerate(calls):
            s.require(isinstance(row,dict) and isinstance(row.get("function"),dict), "Invalid tool call")
            function = row["function"]
            s.require(row.get("type","function")=="function"
                      and isinstance(function.get("name"),str)
                      and isinstance(function.get("arguments"),dict), "Invalid native function")
            arguments = json.dumps(function["arguments"],ensure_ascii=False,allow_nan=False)
            s.require(len(arguments)<=4000, "Tool arguments exceed limit")
            self.tool_calls.append(SimpleNamespace(id=f"call-{index}", type="function",
                function=SimpleNamespace(name=function["name"],arguments=arguments)))

    def model_dump(self, exclude_none=True):
        result = {"role":"assistant", "content":self.content}
        if self.tool_calls:
            result["tool_calls"] = [{"id":x.id,"type":"function","function":{
                "name":x.function.name,"arguments":x.function.arguments}} for x in self.tool_calls]
        return result

def validate_request(request, condition=None):
    s.require(set(request)=={"model","stream","think","keep_alive","options","messages","tools"}
              and request["model"]==s.MODEL and request["stream"] is False and request["think"] is False
              and request["keep_alive"]=="10m" and request["options"]==OPTIONS,
              "Native request settings differ")
    tools = request["tools"]
    s.require([t["function"]["name"] for t in tools]==list(s.ANALYSIS_TOOLS), "Tool inventory differs")
    for tool in tools:
        schema = tool["function"]["parameters"]
        s.require(schema.get("additionalProperties") is False
                  and "path" not in schema.get("properties",{})
                  and "evidence_mode" not in schema.get("properties",{}), "Offered schema is not closed")
    s.require(isinstance(request["messages"],list) and len(request["messages"])==2
              and [m.get("role") for m in request["messages"]]==["system","user"],
              "Only the goal and initial overview may precede this decision")
    choices=[condition] if condition is not None else ['A','B']
    s.require(any(request['messages'][0]['content'].endswith(SYSTEM_APPEND+contract_note(c,tools)) for c in choices),
              'Condition-specific protocol instruction missing')

class PlannerClient:
    def __init__(self,folder,metadata,transport,identity,capture_sha,condition):
        self.folder,self.metadata,self.transport,self.identity = folder,metadata,transport,identity
        self.capture_sha,self.used = capture_sha,False
        self.condition=condition
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    async def create(self,**kwargs):
        s.require(not self.used and set(kwargs)=={"model","messages","temperature","seed","tools","tool_choice"}
                  and kwargs["model"]==s.MODEL and kwargs["temperature"]==0 and kwargs["seed"]==19
                  and kwargs["tool_choice"]=="auto", "Only one decision per case is allowed")
        self.used=True
        request={"model":s.MODEL,"stream":False,"think":False,"keep_alive":"10m",
                 "options":OPTIONS,"messages":copy.deepcopy(kwargs["messages"]),
                 "tools":copy.deepcopy(kwargs["tools"])}
        request['messages'][0]['content'] += SYSTEM_APPEND+contract_note(self.condition,request['tools'])
        validate_request(request,self.condition)
        s.once(self.folder/"request.json",s.encoded(request))
        s.wire.identity(self.transport,self.metadata/"before",s.MODEL,self.identity)
        s.once(self.folder/"dispatch-intent.json",s.encoded({
            "state":"reserved_before_dispatch_outcome_may_be_unknown",
            "capture_sha256":self.capture_sha,"request_sha256":s.sha(self.folder/"request.json"),
            "metadata":self.metadata.relative_to(self.folder.parents[1]).as_posix()}))
        response=self.transport.call("POST","/api/chat",s.encoded(request),self.folder/"response.raw.json")
        s.wire.identity(self.transport,self.metadata/"after",s.MODEL,self.identity)
        s.wire.runtime(self.transport,self.metadata,self.identity,OPTIONS["num_ctx"])
        s.once(self.folder/"receipt.json",s.encoded({
            "files":{n:s.sha(self.folder/n) for n in ("request.json","response.raw.json")},
            "metadata":{p.relative_to(self.metadata).as_posix():s.sha(p) for p in self.metadata.rglob("*.json")}}))
        s.require(response.get("model")==s.MODEL and response.get("done") is True
                  and response.get("done_reason")=="stop", "Incomplete/wrong-model decision")
        return SimpleNamespace(choices=[SimpleNamespace(message=ToolMessage(response.get("message")),finish_reason="stop")])
