# Compliance Audit — Nghiên cứu & Lộ trình (làm sau)

> Mục tiêu: biến ForensicHub thành công cụ **audit readiness** cho ISO 27001 / SOC 2 / PCI-DSS / NIST.
> Hiện đã có: **Compliance Audit checklist** (profile thứ 2 trong trang Evidence & Compliance) — thu thập bằng chứng cấu hình theo control, Windows + Linux.

## Hiện trạng
- ✅ Thu thập bằng chứng theo control (read-only queries, map ISO/SOC2/PCI/NIST).
- ✅ Lọc theo standard, export report, import vào case, AI Analysis.
- ✅ Audit log nội bộ (model `AuditLog`).
- ❌ Chưa có: đánh giá đạt/không đạt, ma trận phủ control, báo cáo chính thức theo chuẩn, audit định kỳ, theo dõi khắc phục.

## Khoảng trống & ưu tiên

| # | Hạng mục | Vì sao cần | Tận dụng | Ưu tiên |
|---|---|---|---|---|
| 1 | **Pass/Fail/NA tự động** | Output thô chưa kết luận đạt/không | AI Analysis đọc output + baseline → verdict | Cao |
| 2 | **Ma trận phủ control** | Auditor hỏi "control X có bằng chứng?" | Field `control` mỗi item → bảng coverage theo chuẩn | Cao |
| 3 | **Compliance report theo chuẩn** | Báo cáo: control → status → evidence → gap → remediation | Mở rộng export + AI sinh báo cáo | Cao |
| 4 | **Toàn vẹn & lưu giữ bằng chứng** | Cần hash + timestamp + retention + người thu thập | Output đã lưu DB; thêm hash chain + retention | Trung bình |
| 5 | **Audit định kỳ + drift detection** | Compliance là liên tục, so với lần trước | Cần scheduler; so baseline | Trung bình |
| 6 | **Theo dõi khắc phục (POA&M)** | NIST/ISO cần plan: owner, hạn, trạng thái | Tái dùng Case/Timeline | Trung bình |
| 7 | **Phạm vi tài sản (scoping)** | PCI cần xác định CDE; tag agent theo scope | Agent + thêm tag/scope | Thấp |
| 8 | **So với CIS Benchmark** | Chuẩn hóa "đạt/chưa" theo hardening baseline | Thêm giá trị baseline kỳ vọng mỗi check | Thấp |

## Đề xuất đợt 1
Làm **#1 + #2 + #3** — biến dữ liệu thô thành kết quả audit dùng được ngay, tận dụng AI Analysis + control mapping sẵn có.

### Phác thảo kỹ thuật đợt 1
- **#1 Pass/Fail:** thêm endpoint `POST /cases/:id/compliance/assess` — AI đọc output từng batch + baseline kỳ vọng → trả `{control, status: compliant|non_compliant|partial|na, rationale}`. Lưu model mới `ComplianceFinding`.
- **#2 Coverage matrix:** từ `ComplianceFinding` + control mapping → bảng theo từng framework (control → status → evidence ref → gap).
- **#3 Report:** trang/endpoint xuất báo cáo (MD/PDF) theo framework, nhóm theo control, kèm remediation gợi ý.

---
*Tài liệu này để thực hiện sau. Playbook chi tiết: xem [docs/playbooks/](playbooks/).*
