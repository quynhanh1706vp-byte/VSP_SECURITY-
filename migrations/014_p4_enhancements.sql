-- SBOM scan results table
CREATE TABLE IF NOT EXISTS p4_sbom_scans (
    id          SERIAL PRIMARY KEY,
    scan_date   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total       INT NOT NULL DEFAULT 0,
    critical    INT NOT NULL DEFAULT 0,
    high        INT NOT NULL DEFAULT 0,
    medium      INT NOT NULL DEFAULT 0,
    low         INT NOT NULL DEFAULT 0,
    clean       INT NOT NULL DEFAULT 0,
    ntia_pct    FLOAT NOT NULL DEFAULT 100.0,
    components  JSONB,
    violations  JSONB,
    scanner     TEXT DEFAULT 'trivy',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- VN Standards compliance table
CREATE TABLE IF NOT EXISTS p4_vn_standards (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    framework   TEXT NOT NULL,
    scope       TEXT,
    score       INT NOT NULL DEFAULT 0,
    max_score   INT NOT NULL DEFAULT 100,
    status      TEXT NOT NULL DEFAULT 'pending',
    items       JSONB,
    notes       TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ATO tracking
ALTER TABLE p4_ato_packages
    ADD COLUMN IF NOT EXISTS authorization_date TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expiration_date    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS conmon_score       INT DEFAULT 94;

-- Seed VN Standards
INSERT INTO p4_vn_standards (id, name, framework, scope, score, max_score, status, items) VALUES
('TT17-2017', 'TT17/2017/TT-BTTTT', 'VN_GOV', 'VN Gov IT Systems', 100, 100, 'passed',
 '[
   {"id":"TT17-1","name":"Cấp độ 3 — Hệ thống quan trọng","done":true},
   {"id":"TT17-2","name":"Kiểm tra ATTT định kỳ hàng năm","done":true},
   {"id":"TT17-3","name":"Mã hóa dữ liệu truyền tải (TLS 1.3)","done":true},
   {"id":"TT17-4","name":"Nhật ký hệ thống lưu tối thiểu 90 ngày","done":true},
   {"id":"TT17-5","name":"Xác thực đa yếu tố (MFA)","done":true}
 ]'::jsonb),
('TCVN-11943', 'TCVN 11943:2017', 'VN_ISO27001', 'VN ISO27001 equivalent', 80, 100, 'partial',
 '[
   {"id":"A9","name":"A.9 — Kiểm soát truy cập","done":true},
   {"id":"A10","name":"A.10 — Mã hóa thông tin","done":true},
   {"id":"A12","name":"A.12 — An toàn vận hành","done":true},
   {"id":"A16","name":"A.16 — Quản lý sự cố ATTT","done":false,"note":"Cần bổ sung quy trình"},
   {"id":"A18","name":"A.18 — Tuân thủ pháp lý","done":true}
 ]'::jsonb),
('BKAV-SCORE', 'BKAV SecurityScorecard', 'VN_PRIVATE', 'VN Private Sector', 88, 100, 'passed',
 '[
   {"id":"B1","name":"Phát hiện mã độc & APT","done":true},
   {"id":"B2","name":"Giám sát lưu lượng mạng (NTA)","done":true},
   {"id":"B3","name":"Quét lỗ hổng định kỳ (DAST/SAST)","done":true},
   {"id":"B4","name":"Phản ứng sự cố < 4h (IR SLA)","done":true},
   {"id":"B5","name":"Báo cáo định kỳ cho VNCERT","done":false,"note":"Pending Q2 2026"}
 ]'::jsonb),
('VIETTEL-SOC', 'Viettel CyberSec SOC Standard', 'VN_SOC', 'VN SOC Operations', 88, 100, 'passed',
 '[
   {"id":"V1","name":"SIEM tích hợp — thu thập log 24/7","done":true},
   {"id":"V2","name":"Threat Intelligence tích hợp IOC","done":true},
   {"id":"V3","name":"Playbook ứng phó tự động (SOAR)","done":true},
   {"id":"V4","name":"Mean Time to Detect < 15 phút","done":true},
   {"id":"V5","name":"Drill test & Red Team hàng quý","done":false,"note":"Q3 2026"}
 ]'::jsonb),
('LATM-2015', 'Luật ATTTM 2015 (Luật 86/2015/QH13)', 'VN_LAW', 'VN Cybersecurity Law', 95, 100, 'passed',
 '[
   {"id":"L1","name":"Điều 21 — Bảo vệ thông tin cá nhân","done":true},
   {"id":"L2","name":"Điều 22 — Ứng cứu sự cố ATTTM","done":true},
   {"id":"L3","name":"Điều 24 — Kiểm tra, đánh giá ATTTM","done":true},
   {"id":"L4","name":"Điều 26 — Lưu trữ thông tin trong nước","done":true},
   {"id":"L5","name":"Điều 45 — Báo cáo sự cố cho VNCERT","done":false,"note":"Process pending"}
 ]'::jsonb),
('ND13-2023', 'Nghị định 13/2023/NĐ-CP', 'VN_LAW', 'VN Personal Data Protection', 85, 100, 'partial',
 '[
   {"id":"N1","name":"Điều 9 — Đồng ý xử lý dữ liệu cá nhân","done":true},
   {"id":"N2","name":"Điều 10 — Điều kiện xử lý dữ liệu nhạy cảm","done":true},
   {"id":"N3","name":"Điều 23 — Đánh giá tác động xử lý dữ liệu","done":false,"note":"DPIA pending"},
   {"id":"N4","name":"Điều 24 — Chuyển dữ liệu ra nước ngoài","done":true},
   {"id":"N5","name":"Điều 27 — Thông báo vi phạm dữ liệu","done":true}
 ]'::jsonb)
ON CONFLICT (id) DO UPDATE SET
    score = EXCLUDED.score,
    status = EXCLUDED.status,
    items = EXCLUDED.items,
    updated_at = NOW();

-- Seed initial SBOM scan
INSERT INTO p4_sbom_scans (total, critical, high, medium, low, clean, ntia_pct, scanner, components, violations)
VALUES (412, 0, 1, 3, 5, 411, 100.0, 'trivy',
 '[
   {"name":"go","version":"1.22.3","type":"language","license":"BSD-3-Clause","cves":0,"ntia_compliant":true},
   {"name":"chi","version":"5.0.12","type":"framework","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"zerolog","version":"1.33.0","type":"library","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"pgx","version":"5.5.5","type":"library","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"jwt-go","version":"5.2.1","type":"library","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"viper","version":"1.18.2","type":"library","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"alpine","version":"3.19.1","type":"os","license":"GPL-2.0","cves":0,"ntia_compliant":true},
   {"name":"openssl","version":"3.3.1","type":"library","license":"Apache-2.0","cves":0,"ntia_compliant":true},
   {"name":"libexpat","version":"2.6.2","type":"library","license":"MIT","cves":2,"severity":"HIGH","ntia_compliant":true},
   {"name":"curl","version":"8.8.0","type":"library","license":"MIT","cves":0,"ntia_compliant":true},
   {"name":"redis-client","version":"9.5.1","type":"library","license":"BSD-2-Clause","cves":0,"ntia_compliant":true},
   {"name":"asynq","version":"0.24.1","type":"library","license":"MIT","cves":0,"ntia_compliant":true}
 ]'::jsonb,
 '["1 HIGH CVEs require remediation within 30 days"]'::jsonb)
ON CONFLICT DO NOTHING;
