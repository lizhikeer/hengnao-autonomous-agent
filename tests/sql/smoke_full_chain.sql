-- 冒烟测试：验证 full_chain_logs 写入、物化视图聚合与攻击链视图可用。
-- 用法：
--   docker exec -i seclog-clickhouse clickhouse-client --user seclog --password "$PW" \
--     --database log_ai --multiquery < tests/sql/smoke_full_chain.sql
-- 说明：数据全部为文档保留网段（198.51.100.0/24、10.0.0.0/24），不含真实资产。

INSERT INTO full_chain_logs
(log_id, trace_id, timestamp, log_source, src_ip, src_port, dest_ip, dest_port,
 asset_id, user_name, session_id, action_or_method, uri_or_target, payload_summary,
 status_code, bytes_out, user_agent, attack_stage_hint)
VALUES
('LOG-20261101-9001','CHAIN-990',now64(3),'nginx_access','198.51.100.23',54321,'10.0.0.15',80,
 'web-prod-01','','sess-smoke-1','GET','/.env','',404,153,'sqlmap/1.7.2','recon'),
('LOG-20261101-9002','CHAIN-990',now64(3),'nginx_access','198.51.100.23',54322,'10.0.0.15',80,
 'web-prod-01','','sess-smoke-1','POST','/admin/login.php','username=admin&password=***',401,40,'python-requests/2.31.0','brute_force'),
('LOG-20261101-9003','CHAIN-990',now64(3),'nginx_access','198.51.100.23',54323,'10.0.0.15',80,
 'web-prod-01','admin','sess-smoke-1','POST','/admin/login.php','password=*** OR 1=1--',200,4520,'sqlmap/1.7.2','exploitation'),
('LOG-20261101-9004','CHAIN-990',now64(3),'zeek_conn','10.0.0.15',49812,'203.0.113.9',4444,
 'web-prod-01','','sess-smoke-1','tcp','203.0.113.9:4444','SF/ShADadFf',200,2048,'','c2_callback');

-- 1) 原始事实：应返回 4 行，攻击阶段覆盖 recon → brute_force → exploitation → c2_callback
SELECT trace_id, log_source, attack_stage_hint, status_code
FROM full_chain_logs
WHERE trace_id = 'CHAIN-990'
ORDER BY timestamp;

-- 2) 攻击链视图：应按时间串起 4 个阶段
SELECT attack_stage_hint, action_or_method, uri_or_target, status_code
FROM v_attack_chain_timeline
WHERE trace_id = 'CHAIN-990';

-- 3) 会话汇总视图：同一 session 必须折叠成 1 行，event_count = 4
--    （不要直接查 session_rollup —— SummingMergeTree 在后台 merge 前会返回多行部分和）
SELECT session_id, asset_id, src_ips, event_count, error_count, bytes_out_sum, stages
FROM v_session_summary
WHERE session_id = 'sess-smoke-1';

-- 4) 数据清理（保留表结构，避免污染后续统计）
ALTER TABLE full_chain_logs DELETE WHERE trace_id = 'CHAIN-990' SETTINGS mutations_sync = 1;
ALTER TABLE session_rollup DELETE WHERE session_id = 'sess-smoke-1' SETTINGS mutations_sync = 1;
