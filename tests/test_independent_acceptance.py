"""独立验收报告中的反例，覆盖数据入口、授权与结论语义。"""
import json
from datetime import timedelta
from types import SimpleNamespace
import pytest
from api.datasource import DatasetReplaySource, LogQuery, LogQueryResult
from api.evidence_check import registry
from ai_engine.investigation import InvestigationSession
from ai_engine.results_schema import load_example
from ai_engine.verify import verify_triage
from test_w2_context_usage import _log, _profile, _asset, _session

@pytest.mark.parametrize("value", ["_After_", "Scan_After_", "none_After_SQL_Injection"])
def test_bad_classification(value):
    data=load_example(); data["attack_type"]=value
    assert not verify_triage(data).ok

def test_unknown_scenario_never_broadens(replay_backend):
    result=DatasetReplaySource().query(LogQuery(case_id="CHAIN-DOES-NOT-EXIST"))
    assert result.total == 0
    session=InvestigationSession(case_id="AUDIT",seed_trace_id="MISSING-TRACE")
    final=session.run()
    assert final.attack_type == "insufficient_evidence"
    assert not final.evidence_log_ids
    assert all(c.args.get("trace_id")=="MISSING-TRACE" for c in session.calls if c.tool=="query_logs")

@pytest.mark.parametrize("overrides", [{"log_id":" "},{"src_ip":None}])
def test_bad_rows_never_register(overrides,monkeypatch,client):
    from api import app
    row=_log("BAD",attack_stage_hint="benign"); row.update(overrides)
    source=SimpleNamespace(query=lambda q:LogQueryResult(items=[row],total=1,data_source="dataset_replay"))
    monkeypatch.setattr(app,"_log_source",lambda:source)
    response=client.post("/tools/query_logs",json={"case_id":"AUDIT","trace_id":"SCENE-1"})
    assert response.status_code == 503
    assert registry.known_log_ids(case_id="AUDIT") == [] or not registry.known_log_ids(case_id="AUDIT")
    assert not registry.check([row["log_id"]],case_id="AUDIT").ok

def test_registry_rejects_blank_independently():
    registry.register([" "],case_id="AUDIT")
    assert not registry.check([" "],case_id="AUDIT").ok

def test_jsonl_preserves_fractional_window(tmp_path):
    rows=[_log("OLD",timestamp="2026-10-29T14:00:00.400Z"),_log("NEW",timestamp="2026-10-29T14:01:00.500Z")]
    (tmp_path/"scene.jsonl").write_text("\n".join(json.dumps(r) for r in rows),encoding="utf-8")
    result=DatasetReplaySource(tmp_path).query(LogQuery(trace_id="SCENE-1",window=timedelta(minutes=1)))
    assert [r["log_id"] for r in result.items]==["NEW"]

@pytest.mark.parametrize("changes",[{"src_ip":None,"asset_id":None},{"asset_id":"backup-01"}])
def test_authorization_requires_actual_subject(changes):
    log=_log("L",attack_stage_hint="benign");log.update(changes)
    assert _session([log],profile=_profile(),asset=_asset()).run().attack_type=="insufficient_evidence"

def test_service_account_cannot_ssh():
    profile=_profile(user="svc_backup",account_type="service",is_service_account=True)
    assert _session([_log("L",user="svc_backup",attack_stage_hint="benign")],profile=profile,asset=_asset()).run().attack_type=="insufficient_evidence"

@pytest.mark.parametrize("payload",["approved backup health beacon; conn_state=SF","beacon disabled; prev_conn_state=SF; conn_state=S0"])
def test_beacon_words_do_not_prove_c2(payload):
    log=_log("L",payload_summary=payload,attack_stage_hint="benign",user_agent="Mozilla",uri_or_target="/")
    assert not _session([log],profile=_profile(),asset=_asset()).run().is_malicious

def test_web_copy_not_auth_failure():
    logs=[_log(str(i),log_source="nginx_access",payload_summary="failed password recovery",attack_stage_hint="benign",user_agent="Mozilla") for i in range(5)]
    assert not _session(logs,profile=_profile(),asset=_asset()).run().is_malicious

def test_sort_command_not_upload():
    log=_log("L",uri_or_target="/products?cmd=sort",payload_summary="",attack_stage_hint="benign",user_agent="Mozilla")
    assert not _session([log],profile=_profile(),asset=_asset()).run().is_malicious

def test_chronology_follows_timestamps():
    logs=[_log("SQL",timestamp="2026-10-29T18:10:00Z",payload_summary="UNION SELECT",attack_stage_hint="benign"),_log("SCAN",timestamp="2026-10-29T18:11:00Z",user_agent="nmap",attack_stage_hint="benign")]
    assert _session(logs,profile=_profile(),asset=_asset()).run().attack_type=="Scan_After_SQL_Injection"

def test_backend_error_not_zero_hits():
    session=InvestigationSession(case_id="E",seed_trace_id="X",tools={"query_logs":lambda args:{"code":"backend_unavailable","message":"driver missing"}})
    result=session.run()
    assert "driver missing" in result.unknown_items
    assert "调用失败" in result.attack_chain_summary


def test_linked_callback_requires_current_successful_connection():
    shell=_log("SHELL", timestamp="2026-10-29T18:10:00Z", uri_or_target="/shell.php", log_source="nginx_access", payload_summary="curl 198.51.100.8", user_agent="Mozilla", attack_stage_hint="benign")
    for state, expected in [("SF", True),("S0", False)]:
        connection=_log("CONN", timestamp="2026-10-29T18:11:00Z", log_source="zeek_conn", src_ip="10.0.0.15", dest_ip="198.51.100.8", payload_summary=f"beacon;prev_conn_state=SF;conn_state={state}", uri_or_target="/", user_agent="Mozilla", status_code=None,attack_stage_hint="benign")
        session=_session([shell,connection],profile=_profile(),asset=_asset())
        session.run()
        assert bool(session._behavior_facts()["c2"]) is expected


@pytest.mark.parametrize("mode", ["mock", "dataset_replay"])
@pytest.mark.parametrize("case", ["chain-does-not-exist", "CHAIN-DOES-NOT-EXIST"])
def test_unknown_case_uniform_backends(mode, case, monkeypatch, client):
    from api import app
    monkeypatch.setenv("SECLOG_DATA_SOURCE", mode); app.reset_source_cache()
    response=client.post("/tools/query_logs",json={"case_id":case,"limit":1})
    assert response.status_code==200
    assert response.json()["meta"]["total"]==0
    assert not registry.known_log_ids(case_id=case)

def test_cleaner_ssh_service_login_is_not_authorized():
    import runpy
    cleaner=runpy.run_path("scripts/log_cleaners/normalize_logs.py")
    row=cleaner["parse_auth_line"]("2026-10-29T18:10:00Z host sshd[123]: Accepted password for svc_backup from 10.0.0.20 port 2222 ssh2", "SCENE-1", "web-prod-01", dest_ip="10.0.0.15", dest_port=22)
    assert row["action_or_method"]=="login_success" and row["uri_or_target"]=="sshd"
    row.update(log_id="SSH",attack_stage_hint="benign")
    profile=_profile(user="svc_backup",account_type="service",is_service_account=True,common_src_ips=["10.0.0.20"])
    assert _session([row],profile=profile,asset=_asset()).run().attack_type=="insufficient_evidence"

@pytest.mark.parametrize("path,status,time",[("/download?file=shell.php",404,"2026-10-29T18:09:00Z"),("/shell.php",200,"2026-10-29T18:10:00.100000Z")])
def test_unrelated_or_later_shell_not_c2(path,status,time):
    prior=_log("P",timestamp=time,uri_or_target=path,status_code=status,log_source="nginx_access",payload_summary="curl 198.51.100.8")
    conn=_log("C",timestamp="2026-10-29T18:10:00Z",src_ip="10.0.0.15",dest_ip="198.51.100.8",log_source="zeek_conn",payload_summary="beacon;conn_state=SF")
    session=_session([prior,conn],profile=_profile(),asset=_asset()); session.run()
    assert not session._behavior_facts()["c2"]

def test_fractional_chronology():
    logs=[_log("SQL",timestamp="2026-10-29T18:10:00Z",payload_summary="UNION SELECT"),_log("SCAN",timestamp="2026-10-29T18:10:00.100000Z",user_agent="nmap")]
    assert _session(logs,profile=_profile(),asset=_asset()).run().attack_type=="Scan_After_SQL_Injection"

def test_runner_jsonl_discovery_and_redaction(tmp_path):
    import runpy
    module=runpy.run_path("tests/run_v1_traces.py")
    (tmp_path/"scene.jsonl").write_text(json.dumps(_log("L")),encoding="utf-8")
    module["list_scenarios"].__globals__["DATASET"]=tmp_path
    assert module["list_scenarios"]()==["SCENE-1"]
    redacted=module["_redact"]({"items":[{"payload_summary":"user=x&password=secret123;reason=bad", "password":"secret456"}]})
    text=json.dumps(redacted)
    assert "secret123" not in text and "secret456" not in text
    assert "reason=bad" in text

def test_retrieval_error_is_not_zero_hits():
    session=_session([_log("L",payload_summary="UNION SELECT",attack_stage_hint="exploitation")],profile=_profile(),asset=_asset())
    session.tools["search_knowledge"]=lambda args:{"code":"backend_unavailable","message":"dependency unavailable"}
    result=session.run()
    assert "dependency unavailable" in result.unknown_items
    assert "零命中" not in result.unknown_items


@pytest.mark.parametrize("target,matched",[("198.51.100.80",False),("198.51.100.8",True)])
def test_c2_payload_ip_exact_match(target,matched):
    prior=_log("P",timestamp="2026-10-29T18:09:00Z",uri_or_target="/shell.php",log_source="nginx_access",payload_summary=f"curl http://{target}:8080/a")
    conn=_log("C",timestamp="2026-10-29T18:10:00Z",src_ip="10.0.0.15",dest_ip="198.51.100.8",log_source="zeek_conn",payload_summary="beacon;conn_state=SF")
    result=_session([prior,conn],profile=_profile(),asset=_asset()).run()
    assert ("C2_Exfiltration" in result.attack_type) is matched
    assert "Malicious_Upload" in result.attack_type

@pytest.mark.parametrize("valid_peer",[False,True])
def test_malformed_candidate_keeps_other_evidence(valid_peer):
    from ai_engine.results_schema import validate_results
    bad=_log("BAD",timestamp="2026-10-29T18:08:00Z",uri_or_target="http://[broken",log_source="nginx_access",payload_summary="curl 198.51.100.8")
    good=_log("GOOD",timestamp="2026-10-29T18:09:00Z",uri_or_target="/shell.php",log_source="nginx_access",payload_summary="curl 198.51.100.8")
    conn=_log("C",timestamp="2026-10-29T18:10:00Z",src_ip="10.0.0.15",dest_ip="198.51.100.8",log_source="zeek_conn",payload_summary="beacon;conn_state=SF")
    result=_session([bad]+([good] if valid_peer else [])+[conn],profile=_profile(),asset=_asset()).run()
    validate_results(result.to_results())
    assert ("C2_Exfiltration" in result.attack_type) is valid_peer
    assert "BAD" in result.unknown_items and "解析" in result.unknown_items

@pytest.mark.parametrize("key",["password","passwd","pwd"])
@pytest.mark.parametrize("style",["json","quoted","plain","single"])
def test_complete_password_payload_redaction(key,style):
    import runpy
    redact=runpy.run_path("tests/run_v1_traces.py")["_redact"]
    payload={
        "json":'{"'+key+'":"audit_dummy extra","next":"keep"}',
        "quoted":key+'="audit_dummy extra";next=keep',
        "single":key+"='audit_dummy extra';next=keep",
        "plain":key+'=audit_dummy;next=keep',
    }[style]
    actual=redact({"payload_summary":payload})["payload_summary"]
    expected=payload.replace("audit_dummy extra","***").replace("audit_dummy","***")
    assert actual==expected


@pytest.mark.parametrize("payload,destination,matched",[
    ("curl http://[2001:db8::198.51.100.8]:8080/a","198.51.100.8",False),
    ("curl http://[2001:db8::198.51.100.8]:8080/a","2001:db8::c633:6408",True),
    ("curl http://[2001:db8::8]:8080/a","2001:db8::8",True),
    ("curl http://198.51.100.8:8080/a","198.51.100.8",True),
])
def test_c2_complete_address_unit(payload,destination,matched):
    prior=_log("P",timestamp="2026-10-29T18:09:00Z",uri_or_target="/shell.php",log_source="nginx_access",payload_summary=payload)
    conn=_log("C",timestamp="2026-10-29T18:10:00Z",src_ip="10.0.0.15",dest_ip=destination,log_source="zeek_conn",payload_summary="beacon;conn_state=SF")
    result=_session([prior,conn],profile=_profile(),asset=_asset()).run()
    assert ("C2_Exfiltration" in result.attack_type) is matched


def test_run_one_masks_backend_error_everywhere(monkeypatch,replay_backend):
    import runpy
    from fastapi.responses import JSONResponse
    from api import app
    message='retrieval failed password="audit_dummy extra";next=keep'
    monkeypatch.setattr(app,"search_knowledge",lambda req:JSONResponse(status_code=503,content={"code":"backend_unavailable","message":message,"details":{"reason":message}}))
    result=runpy.run_path("tests/run_v1_traces.py")["run_one"]("CHAIN-CASE-01")
    for output in [result["result"],result["trace"]]:
        serialized=json.dumps(output,ensure_ascii=False)
        assert "audit_dummy" not in serialized and "extra" not in serialized
        assert "next=keep" in serialized
    assert "检索调用失败" in result["result"]["unknown_items"]
    step=next(s for s in result["trace"]["trace"]["steps"] if s["tool"]=="search_knowledge")
    assert step["status"]=="error" and step["error"]["code"]=="backend_unavailable"


@pytest.mark.parametrize("stage",["connect","query"])
def test_run_one_clickhouse_error_removes_dsn_credentials(stage,monkeypatch):
    import runpy,sys,types
    from api import app
    dsn="http://audit_user:audit_dsn_dummy@127.0.0.1:8123"
    monkeypatch.setenv("SECLOG_DATA_SOURCE","clickhouse")
    monkeypatch.setenv("CLICKHOUSE_DSN",dsn)
    app.reset_source_cache()
    class FakeClient:
        def query(self,sql,**kwargs):
            if sql=="SELECT 1": return None
            raise RuntimeError(f'query failed {dsn}; password="audit_key_dummy extra"; next=keep')
    def get_client(**kwargs):
        assert kwargs["dsn"]==dsn
        if stage=="connect":
            raise RuntimeError(f'connect failed {dsn}; password="audit_key_dummy extra"; next=keep')
        return FakeClient()
    module=types.ModuleType("clickhouse_connect");module.get_client=get_client
    monkeypatch.setitem(sys.modules,"clickhouse_connect",module)
    output=runpy.run_path("tests/run_v1_traces.py")["run_one"]("CHAIN-CASE-01")
    for value in (output["result"],output["trace"]):
        text=json.dumps(value,ensure_ascii=False)
        assert "audit_dsn_dummy" not in text and "audit_user" not in text
        assert "audit_key_dummy" not in text and "extra" not in text
        assert "127.0.0.1:8123" in text and "next=keep" in text
    step=output["trace"]["trace"]["steps"][0]
    assert step["status"]=="error" and step["error"]["code"]=="backend_unavailable"
    assert step["error"]["details"]["stage"]==stage
    assert step["error"]["details"]["dsn"]=="http://127.0.0.1:8123"
    assert output["result"]["attack_type"]=="insufficient_evidence"
    assert "调用失败" in output["result"]["attack_chain_summary"]
