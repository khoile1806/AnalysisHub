# Plugin Release Watch

Theo dõi kho plugin WordPress và báo tin khi có **plugin mới** hoặc **bản cập
nhật**, ưu tiên những bản có dấu hiệu **vá bảo mật**. Kết quả đẩy thẳng vào
bảng tin threat intel của AnalysisHub (tab **WordPress Plugin Releases**).

Đây là công cụ **báo tin**, không phải công cụ phân tích. Nó không đọc mã nguồn
và không kết luận plugin nào có lỗ hổng — việc của nó là chỉ ra bản phát hành
nào đáng đọc trước.

## Vì sao thời điểm phát hành lại quan trọng

Vendor bị báo lỗ hổng thường chỉ vá **đúng hàm được nêu trong report** và không
rà các hàm anh em. Ví dụ thật: Wordfence cấp CVE-2026-4298 cho một hàm của
*DSGVO All in one for WP* vì thiếu nonce và thiếu kiểm quyền; bản 5.0 thêm cả
hai vào **đúng hàm đó**, còn hàm ngay bên cạnh vẫn không có gì.

Cửa sổ đó rộng nhất trong vài ngày đầu sau khi phát hành, trước khi người khác
kịp diff. Một dòng changelog ghi *"Security: fixed ..."* chính là vendor tự chỉ
cho bạn biết phải mở file nào.

## Cài đặt

```bash
cd tools/plugin-release-watch
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -e .
```

## Dùng nhanh

```bash
# tao danh sach theo doi
plugin-release-watch add wpforo mycred dsgvo-all-in-one-for-wp

# chay mot luot
plugin-release-watch run --watchlist watchlist.txt

# chi bao ban co dau hieu va bao mat
plugin-release-watch run --watchlist watchlist.txt --security-only

# lay slug tu mot corpus co san, khong can chep lai danh sach
plugin-release-watch run --from-dir "F:/Claude Code Work Place/wp-cve-hunt/targets"

# them plugin vua xuat hien tren wp.org
plugin-release-watch run --watchlist watchlist.txt --discover-new
```

**Lần chạy đầu chỉ ghi mốc, không báo gì.** Đây là cố ý: nếu không, mỗi lần thêm
một slug mới sẽ sinh cảnh báo giả cho bản phát hành từ nhiều tháng trước, và một
bộ theo dõi kêu oan ngày đầu thì đến ngày thứ ba không ai đọc nữa.

### Mã thoát

| Mã | Nghĩa |
|----|-------|
| `0` | Không có bản vá bảo mật nào |
| `2` | **Có bản vá bảo mật** — dùng để kích hoạt bước tiếp theo trong scheduler/CI |

## Tích hợp vào bảng tin AnalysisHub

Bàn giao qua **file**, không qua HTTP: công cụ chạy theo lịch và có thể không
chạy chút nào, nên worker đọc file sẽ suy biến thành "không có tin plugin" thay
vì treo chờ một service không tồn tại.

```
service plugin_watch  (docker compose, chạy liên tục)
        │  mỗi PLUGIN_WATCH_INTERVAL giây (mặc định 120)
        ▼
backend/data/plugin-watch/report.json   (report CUỘN, ghi nguyên tử)
        │
        ▼
backend/internal/news/pluginwatch.go    (đọc + chuyển thành NewsArticle)
        │
        ▼
handlers.syncPluginWatch()              (ticker riêng, mỗi 1 phút)
        │
        ▼
tab "Plugin Releases" trên giao diện
```

Độ trễ tổng từ lúc wp.org công bố đến lúc bài xuất hiện: **dưới ~3 phút** trong
trường hợp xấu nhất (≤120s chu kỳ hỏi + ≤60s chu kỳ nạp). Đo thực tế phần nạp:
43 giây từ khi report được ghi đến khi API trả bài.

Đường dẫn mặc định backend tìm là `data/plugin-watch/report.json`, đổi được bằng
biến môi trường:

```bash
PLUGIN_WATCH_REPORT=/duong/dan/khac/report.json
```

### Vì sao report là *cuộn*, không phải delta một lần chạy

Công cụ và backend chạy trên hai đồng hồ độc lập. Nếu file chỉ chứa delta của lần
chạy gần nhất, **mọi event sinh ra giữa hai lần backend đọc sẽ bị ghi đè và mất
vĩnh viễn** — và loại event dễ mất nhất chính là cụm phát hành dồn dập, đúng lúc
bảng tin có giá trị nhất.

Nên `write_json` giữ lại các event còn trong `--keep-hours` (mặc định 24h) và ghi
nguyên tử. Backend đọc muộn, đọc hai lần, hay không đọc một lúc lâu đều không mất
gì; khử trùng theo `ArticleID` = `slug@version` khiến đọc lại không sinh bài trùng.

### Phạm vi theo dõi

| Chế độ | Cờ | Phạm vi |
|--------|----|---------|
| Watchlist | mặc định | Chỉ các slug trong `watchlist.txt` — đọc kỹ, luôn kiểm |
| **Toàn kho** | `--repo` | **Mọi plugin trên wp.org vừa đổi phiên bản** |
| Plugin mới | `--discover-new` | Plugin vừa xuất hiện lần đầu |

Chế độ `watch` (service) bật cả ba. Toàn kho là thứ khiến công cụ không còn phụ
thuộc vào việc *đã nghĩ ra* phải theo dõi plugin nào: bản phát hành đáng đọc
thường nằm ở plugin chưa ai đưa vào danh sách.

Hai tầng gọi API là cố ý: danh sách `browse=updated` rẻ nhưng **không kèm
changelog**, nên tầng một chỉ dùng để phát hiện phiên bản đổi (1 request/100
plugin), tầng hai mới lấy đầy đủ cho đúng những slug đã đổi. Kho công bố khoảng
15–20 bản/giờ nên một trang 100 phủ ~6 giờ: mất mạng vài giờ vẫn bắt kịp, không
sót.

### Hợp đồng dữ liệu

`report.json` là bản tuần tự hoá của `WatchResult` trong
[`watcher/models.py`](watcher/models.py). Phía Go khai báo cùng cấu trúc trong
[`backend/internal/news/pluginwatch.go`](../../backend/internal/news/pluginwatch.go).
**Đổi tên trường ở một bên là thay đổi phá vỡ ở bên kia** — hai file test đang
giữ hợp đồng này:

```bash
python -m pytest                       # 16 test phia cong cu
cd ../../backend && go test ./internal/news/   # 8 test phia backend
```

Bài tin sinh ra mang tag `wordpress`, `plugin`, `security-fix`,
`incomplete-fix-candidate` để lọc trên giao diện.

## Chạy theo lịch

**Windows Task Scheduler:**

```
schtasks /create /tn "plugin-release-watch" /sc daily /st 09:00 /tr ^
 "cmd /c cd /d F:\Claude Code Work Place\AnalysisHub\tools\plugin-release-watch && .venv\Scripts\python.exe -m watcher.cli run --watchlist watchlist.txt --json ..\..\backend\data\plugin-watch\report.json --quiet"
```

**cron:**

```cron
0 9 * * * cd /opt/analysishub/tools/plugin-release-watch && \
  .venv/bin/plugin-release-watch run --watchlist watchlist.txt \
  --json /opt/analysishub/backend/data/plugin-watch/report.json --quiet
```

## Sau khi có tin thì làm gì

Bài tin nào cũng kèm sẵn lệnh tiếp theo, vì giá trị của cảnh báo nằm ở bước diff
sau đó chứ không phải ở bản thân cảnh báo:

| Loại | Bước tiếp theo |
|------|----------------|
| Vá bảo mật | `incomplete_fix.py <slug>` — tìm handler anh em vendor quên vá |
| Bản mới thường | `diff_versions.py <slug> --from A --to B` — xem vendor lặng lẽ thêm kiểm soát nào |
| Plugin mới | `fetch_plugin.py <slug>` — tải về đọc |

Ba script đó nằm ở `wp-cve-hunt/tools/`.

## Cấu trúc

```
watcher/
  models.py     kiểu dữ liệu — cũng là hợp đồng tích hợp
  sources.py    client API wordpress.org (chỉ endpoint công khai, chỉ metadata)
  detect.py     nhận diện dòng changelog nói về bảo mật
  state.py      mốc phiên bản lần trước, ghi nguyên tử
  runner.py     ghép các bước, không dính CLI để backend gọi trực tiếp được
  report.py     kết xuất console / JSON / HTML tự chứa
  cli.py        giao diện dòng lệnh
```

## Giới hạn cần biết

- Nhận diện bảo mật dựa trên **từ khoá trong changelog**. Vendor vá lặng lẽ mà
  không ghi gì thì công cụ không thấy — đó là lý do vẫn cần `diff_versions.py`
  cho các bản phát hành thường.
- Chỉ gọi endpoint công khai của wordpress.org, chỉ lấy metadata. Không đụng tới
  bất kỳ site nào.
- Mặc định nghỉ 0.25 giây giữa hai lần gọi API. Theo dõi vài trăm plugin thì nên
  chạy theo lịch chứ đừng chạy tay.
