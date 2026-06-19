# Nghiên cứu: Case Manager & Attack Timeline — logic & hiệu quả

> Mục tiêu: làm Case Manager + Timeline hoạt động thật sự logic, hiệu quả; phân định rõ phần nào cần AI, phần nào KHÔNG.

## Nguyên tắc AI vs non-AI

| Dùng **non-AI (xác định, reproducible)** | Dùng **AI (hiểu văn bản, phán đoán)** |
|---|---|
| Đếm/tổng hợp/sắp xếp/lọc | Trích sự kiện từ log/output **phi cấu trúc** |
| Ingest timestamp **có sẵn** (ELK @timestamp, job start/finish) | Chuẩn hoá văn phong, gộp trùng "mờ" |
| Khử trùng theo khoá chính xác (time+host+title) | Tóm tắt diễn biến (narrative) |
| Export CSV/JSON, trạng thái case, liên kết | Suy luận MITRE technique, đánh giá rủi ro |

**Quy tắc vàng:** dữ liệu đã có cấu trúc/mốc thời gian → xử lý xác định (không AI). Chỉ dùng AI khi phải *hiểu* văn bản tự do. AI luôn ở chế độ **đề xuất → analyst xác nhận** (lưu provenance: ai/elk/manual).

---

## A. Attack Timeline

### Đã có
- Nguồn: manual · ELK promote (timestamp thật) · AI extract từ job · AI rebuild · **AI extract từ evidence file (gắn host)** ✨.
- Lọc host/severity, gom theo ngày, MITRE tactic/technique.

### Đề xuất cải tiến

**Non-AI (ưu tiên — rẻ, chắc chắn):**
1. **Auto-ingest mốc thao tác:** job start/finish, checklist run, deployment → tự thành event "operational" (màu nhạt) để có khung thời gian. (xác định)
2. **Swimlane theo host:** mỗi máy 1 làn ngang → nhìn ra lateral movement. (render thuần)
3. **Truy vết nguồn:** click event → mở evidence/job/ELK hit gốc (đã có `source_ref`, chỉ cần link). (xác định)
4. **Khử trùng khi rebuild:** so (time+host+title) tránh nhân đôi khi extract nhiều lần. (xác định)
5. **Export timeline** CSV/JSON/Markdown cho báo cáo. (xác định)
6. **Provenance badge:** đánh dấu event do AI/ELK/manual + nút "✓ verified" để analyst chốt. (xác định)

**AI (đúng chỗ):**
7. **Correlate + narrative:** AI đọc các event đã gom → viết diễn biến "kẻ tấn công làm gì, theo trình tự" (đã có AI Rebuild, mở rộng thêm bản tường thuật).
8. **Suy luận MITRE** cho event thiếu mapping (AI gợi ý, analyst sửa).

---

## B. Case Manager (tổng thể)

### Đã có
- Case = container; tabs Activity/Attack Timeline, Hunting Results, Compliance, Offline Bundle.
- Agent gắn case; jobs (online + offline import); checklist; evidence file.

### Đề xuất cải tiến

**Non-AI:**
1. **Header tóm tắt case:** số host · số evidence · compliance score · khoảng thời gian timeline · số mục cần khắc phục. Nhìn 1 dòng biết tình trạng. (tổng hợp)
2. **Vòng đời case rõ hơn:** New → Investigating → Contained → Eradicated → Closed (+ severity/priority) thay vì chỉ open/closed. Giúp triage & ưu tiên. (workflow)
3. **Host-centric view (quan trọng):** pivot theo **máy** — mỗi host gom jobs + evidence + timeline event + compliance finding. DFIR vốn xoay quanh từng máy. (tổng hợp)
4. **Unified Evidence view:** 1 nơi liệt kê MỌI evidence (job output, offline import, file upload, checklist) theo host — hiện đang rải rác nhiều tab. (tổng hợp)
5. **Notes/collaboration & tasks:** ghi chú điều tra + giao việc (mở rộng POA&M ra toàn case). (CRUD)
6. **Liên kết case** (cùng chiến dịch). (quan hệ)

**AI:**
7. **AI Case Report:** sinh báo cáo sự cố tổng hợp từ timeline + findings + evidence (Executive Summary + diễn biến + IOC + khuyến nghị). Tận dụng AI Analysis sẵn có.
8. **AI triage gợi ý:** từ evidence ban đầu → đề xuất loại sự cố + playbook phù hợp + severity (analyst quyết).

---

## Lộ trình đề xuất (ưu tiên cao → thấp)
1. **Host-centric / Unified Evidence view** (non-AI) — tăng hiệu quả điều tra nhiều nhất.
2. **Header tóm tắt + vòng đời case** (non-AI).
3. **Truy vết nguồn + provenance + export timeline** (non-AI).
4. **Swimlane theo host** (non-AI).
5. **AI Case Report** (AI) — chốt hạ một báo cáo.
6. **AI triage gợi ý playbook** (AI).

> Tinh thần: làm chắc phần **xác định (non-AI)** trước để dữ liệu sạch & truy vết được; AI chỉ phủ lên lớp *diễn giải* (narrative, report, gợi ý) — luôn cho analyst chỉnh.
