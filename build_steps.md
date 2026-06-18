# ForensicHub v2 — Tài liệu Đặc tả Hệ thống

---

## 1. Bối cảnh & Nhu cầu

Hệ thống được xây dựng để phục vụ quy trình **Digital Forensics & Incident Response (DFIR)**, giải quyết các nhu cầu cốt lõi sau:

- **Thu thập evidence** trên các máy chủ/endpoint gặp sự cố.
- **Playbook-driven actions**: Từ loại sự cố → lựa chọn playbook → xác định data/evidence cần thu thập → kích hoạt bộ công cụ tương ứng (ví dụ: Webshell Playbook).
- **Trực quan hóa kết quả phân tích** tổng hợp từ nhiều agent:
  - Dashboard tập trung quản lý toàn bộ output data.
  - Hiển thị attack timeline.
- **Tra cứu nhanh** thông tin lỗ hổng bảo mật.
- **Tích hợp SIEM** để tìm kiếm và xác minh IOC từ evidence thu thập được.

---

## 2. Yêu cầu Hệ thống

| Yêu cầu | Mô tả |
|---|---|
| Hỗ trợ agent online/offline | Agent online nhận lệnh từ server; agent offline đóng gói sẵn tool (bundle all-in-one). |
| Minh bạch thu thập thông tin | Ghi log rõ ràng mọi hành động thu thập, không thu thập ngoài phạm vi đã định. |
| Định dạng output chuẩn | Tool output hỗ trợ JSON / CSV / TXT. |
| Không ảnh hưởng hiệu suất server | Agent chạy full-load không được làm ảnh hưởng hoạt động của server mục tiêu. |
| Tập trung hóa tool & output | Toàn bộ công cụ và kết quả được quản lý tập trung trên server ForensicHub. |

---

## 3. Tính năng Cốt lõi (Core Features)

### 3.1 Quản lý Agent
- Kết nối, theo dõi và điều phối lệnh đến agent (online/offline).
- Hỗ trợ agent dạng **offline bundle**: đóng gói nhiều tool vào một file duy nhất, cho phép chọn tool cần chạy trước khi triển khai.
- Hỗ trợ **import output** từ agent offline sau khi thu thập.

### 3.2 Kho Công cụ (Tool Repository)
Kho công cụ chia thành hai nhóm:

**General** *(thông tin bắt buộc phải thu thập trong mọi sự cố)*:
- Loki
- Redline
- DumpIt
- Network Miner
- TCPView
- FTK Imager
- MBAR (Malwarebytes Anti-Rootkit)
- Autoruns

**Order** *(công cụ bổ sung, chọn theo từng loại sự cố)*:
- Phân loại theo category / hạng mục công việc (Malware, Network, Memory, Disk, Log Analysis, ...).

### 3.3 Quản lý Case
- Một case có thể bao gồm nhiều máy/endpoint.
- Theo dõi trạng thái thu thập và phân tích theo từng case.

### 3.4 Phân tích Evidence
- Hỗ trợ xử lý và phân tích các file evidence đã import.
- Định nghĩa **usecase** cho dashboard: cần hiển thị thông tin gì, theo góc nhìn nào.

### 3.5 Dashboard
- Dashboard tổng hợp output từ nhiều agent/tool.
- Hiển thị **attack timeline**.
- Giao diện theo usecase: tùy chỉnh theo loại sự cố và nhu cầu phân tích.

---

## 4. Extensions & Add-ons

- **Tra cứu nhanh thông tin bảo mật**: tìm kiếm CVE, lỗ hổng, kỹ thuật tấn công.
- **Tích hợp tìm kiếm IOC**: kết nối SIEM/threat intel để xác minh indicator từ evidence.
- **Quản lý agent nâng cao**: theo dõi trạng thái, lịch sử lệnh, scheduling.

---

## 5. Quy trình Sử dụng (Workflow)

```
1. Xác định loại sự cố & phân tích nhu cầu
        ↓
2. Chọn playbook phù hợp
        ↓
3. Xác định data cần phân tích & công cụ thu thập tương ứng
        ↓
4. Triển khai agent → tiến hành thu thập evidence
        ↓
5. Import data đã thu thập về server
        ↓
6. Phân tích data, xem dashboard & attack timeline
        ↓
7. Đưa ra kết luận & báo cáo
```

---

## 6. Ghi chú Phát triển

- Ưu tiên hoàn thiện **agent offline bundle** trước (tính năng cần cập nhật gấp).
- Dashboard cần xác định rõ usecase trước khi thiết kế (tránh làm lại).
- Tích hợp SIEM là tính năng mở rộng, không phải MVP.
