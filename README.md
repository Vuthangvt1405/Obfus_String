# Malware String Decryptor (Speakeasy / Unicorn Engine)

Đây là một framework phân tích mã độc bằng Python, sử dụng kỹ thuật giả lập (emulation) thông qua **Speakeasy v2** (dựa trên Unicorn Engine) để tự động bắt và giải mã các chuỗi bị làm mờ (obfuscated) trong file PE mã độc.

## Cài đặt

Do thư viện `speakeasy-emu` cũ trên PyPI không còn hoạt động ổn định, dự án yêu cầu tải bản mới nhất (v2) trực tiếp từ source code của Mandiant trên GitHub thông qua môi trường ảo (Virtual Environment).

1. Đảm bảo bạn đã cài đặt Python 3.8+.
2. Khởi tạo và kích hoạt môi trường ảo (Virtual Environment):

```bash
# Trên Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Trên Windows
python -m venv venv
venv\Scripts\activate
```

3. Cài đặt các thư viện yêu cầu (pefile, capstone) và tự động kéo Speakeasy v2 từ GitHub:

```bash
pip install -r requirements.txt
pip install git+https://github.com/mandiant/speakeasy.git
```

*(Lưu ý: Bạn cũng có thể cài đặt trực tiếp nhánh Speakeasy mới nhất mà không cần tải qua pip nếu yêu cầu custom mã nguồn)*

## Cấu trúc Dự án

- `main.py`: Entry point nhận tham số từ terminal.
- `core/emulator.py`: Quản lý vòng đời chạy của Speakeasy engine. Đảm bảo bẫy lỗi và giới hạn timeout.
- `core/extractor.py`: Các bộ lọc Heuristics để trích xuất chỉ những chuỗi hợp lệ (ASCII, UTF-16LE, Regex matching).
- `hooks/mem_hooks.py`: Chặn `MEM_WRITE` từ Speakeasy engine để thu thập kết quả của các vòng lặp XOR/RC4 được malware thao tác và ghi xuống bộ nhớ.
- `hooks/api_hooks.py`: Bẫy tham số từ các hàm Windows (như `VirtualAlloc`, `lstrcpyA`, `lstrcpyW`) để hứng chuỗi cực sạch trực tiếp từ Windows API.

## Cách sử dụng

Sau khi kích hoạt môi trường ảo (đã cài đặt speakeasy), bạn chạy file thực thi (`main.py`) bằng lệnh Python:

```bash
# Phân tích căn bản tệp mã độc (Mặc định tự động nhận dạng kiến trúc x86/x64)
python main.py -f malware_sample.exe

# Phân tích tệp DLL và bật luồng thông tin gỡ lỗi (Debug Console) 
# Chế độ này in ra thông tin rất chi tiết như PE Headers, Virtual Memory Map
python main.py -f payload.dll -d

# Chỉ định thời gian giả lập tối đa 120s và thay đổi tên file lưu báo cáo chuỗi
python main.py -f packed_malware.exe -t 120 -o unpacked_strings.json
```

## Cách hoạt động

Luồng chạy chính bắt đầu ở `main.py` và đi qua các bước sau:

1. **Nhận tham số CLI:** `main.py` đọc đường dẫn mẫu PE (`-f`), timeout (`-t`), kiến trúc mong muốn (`-a`), file output (`-o`) và chế độ debug (`-d`).
2. **Khởi tạo emulator:** `MalwareEmulator` tạo `StringExtractor`, `WriteTracker`, cấu hình timeout cho Speakeasy, rồi tạo sandbox Speakeasy tách biệt với hệ thống thật.
3. **Nạp mẫu PE:** `load_sample()` gọi `se.load_module()` để nạp file PE vào không gian bộ nhớ giả lập. Khi bật debug, loader in thêm image base, entry point và section layout.
4. **Đăng ký hook:** `register_hooks()` cắm hai nhóm cảm biến:
   - `hooks/mem_hooks.py`: theo dõi các vùng nhớ bị ghi (`MEM_WRITE`) bằng `WriteTracker`.
   - `hooks/api_hooks.py`: hook các Windows API có tham số chuỗi để lấy chuỗi trực tiếp từ API arguments.
5. **Chạy giả lập:** `run()` gọi `se.run_module()`. Nếu Speakeasy gặp API chưa hỗ trợ hoặc timeout, script ghi log và vẫn cố thu thập dữ liệu đã quan sát được.
6. **Thu thập chuỗi:** Sau khi chạy, emulator lấy chuỗi từ Speakeasy JSON report, rồi đọc lại các vùng nhớ đã bị ghi để scan chuỗi ASCII và UTF-16LE theo từng chunk.
7. **Lọc và gắn nhãn:** `StringExtractor` bỏ chuỗi nhiễu phổ biến, loại chuỗi quá ngắn, deduplicate theo `content`, gắn `source` (`api_hook`, `deferred_scan`, `mem_write`) và tag regex khi thấy IP, URL, domain hoặc registry path.
8. **Xuất báo cáo:** `ReportGenerator` ghi JSON gồm `timestamp`, `total_strings` và danh sách `strings` ra file output, mặc định là `report.json`.

Kết quả phụ thuộc vào đường thực thi thực tế trong emulator. Script không giải mã tĩnh toàn bộ binary; nó chỉ thu được chuỗi xuất hiện trong report Speakeasy, memory writes hoặc API calls đã được hook trong lúc chạy.

## Quy trình bắt chuỗi lúc chạy (Deferred Memory Tracking)

Để tránh xử lý từng byte khi malware giải mã chuỗi và để giảm chi phí hiệu năng, framework dùng mô hình thu thập bộ nhớ trì hoãn:

- **Gộp vùng ghi bằng WriteTracker:** Memory hook (`MEM_WRITE`) chỉ lưu tuple nhẹ `(start, end)` thay vì giải mã ngay từng byte. Các vùng nhớ liền kề hoặc chồng lấn được gộp lại trong phạm vi nhìn ngược nhỏ (tối đa 10 vùng gần nhất).
- **Trích xuất sau khi chạy:** Sau khi Speakeasy hoàn tất, `MalwareEmulator._extract_tracked_memory()` duyệt các vùng nhớ đã gộp, đọc theo chunk tối đa 4KB và đưa dữ liệu đã giải mã vào bộ lọc regex.
- **Đọc theo chunk và bỏ qua lỗi:** Bộ nhớ đã theo dõi được đọc theo từng chunk, giới hạn tối đa mỗi vùng bẩn khoảng 8192 byte. Nếu `se.mem_read()` lỗi vì vùng nhớ không hợp lệ, script ghi debug log và tiếp tục vùng khác.
- **Giới hạn theo vùng PE:** Tracking chỉ phục vụ chuỗi xuất hiện trong quá trình giả lập. Script không cam kết giải mã tĩnh toàn bộ binary; khả năng thu hồi phụ thuộc vào đường chạy và hook quan sát được.

## Phạm vi API hook

API hook được cài trong `hooks/api_hooks.py`. Mỗi hook chỉ đọc các tham số con trỏ chuỗi đã cấu hình, dùng ANSI (`A`, width 1) hoặc UTF-16LE wide (`W`, width 2). Nếu Speakeasy không hỗ trợ một API nào đó, lỗi cài hook chỉ được ghi cảnh báo và quá trình giả lập vẫn tiếp tục.

| Module | API hook | Tham số chuỗi được bắt | Giá trị phân tích |
|---|---|---|---|
| `kernel32` | `lstrcpyA`, `lstrcpyW` | Con trỏ chuỗi nguồn | Bắt chuỗi được copy sau khi unpack hoặc giải mã lúc chạy. |
| `kernel32` | `VirtualAlloc` | Không bắt chuỗi; chỉ log size/protection | Hỗ trợ debug hành vi cấp phát bộ nhớ khi unpack/giải mã. |
| `wininet` | `InternetConnectA/W` | Server name | Bắt host/domain C2 truyền vào WinINet. |
| `wininet` | `InternetOpenA/W` | User-agent | Bắt chuỗi user-agent HTTP của malware. |
| `wininet` | `HttpOpenRequestA/W` | HTTP verb, object/path | Bắt method request và đường dẫn URI. |
| `urlmon` | `URLDownloadToFileA/W` | URL, tên file output | Bắt URL tải xuống và đường dẫn lưu file. |
| `winhttp` | `WinHttpOpen`, `WinHttpOpenA/W` | User-agent, proxy, proxy bypass | Bắt chuỗi cấu hình phiên WinHTTP. |
| `winhttp` | `WinHttpConnect`, `WinHttpConnectA/W` | Server name | Bắt hostname C2 dùng qua WinHTTP. |
| `winhttp` | `WinHttpOpenRequest`, `WinHttpOpenRequestA/W` | Verb, path, HTTP version, referrer | Bắt metadata request và endpoint path. |
| `winhttp` | `WinHttpGetProxyForUrl`, `WinHttpGetProxyForUrlA/W` | URL | Bắt URL dùng cho proxy discovery. |
| `winhttp` | `WinHttpSendRequest`, `WinHttpSendRequestA/W` | Headers | Bắt header HTTP outbound. |
| `kernel32` | `CreateProcessA/W` | Application name, command line | Bắt đường dẫn tiến trình con và command line. |
| `shell32` | `ShellExecuteA/W` | File/executable path | Bắt payload hoặc lệnh được mở qua shell. |
| `advapi32` | `RegOpenKeyExA/W` | Registry subkey | Bắt registry key dùng cho persistence hoặc đọc cấu hình. |
| `kernel32` | `CreateFileA/W` | File name/path | Bắt file được mở, drop hoặc đọc bởi mẫu. |

Factory hook chung sẽ chuyển chuỗi bắt được vào `StringExtractor.process_api_string()`. Nếu chuỗi vượt qua bộ lọc, kết quả được lưu với `encoding: "API_ARG"` và `source: "api_hook"`.

## Ý nghĩa output cho analyst

Output mặc định loại bỏ các chuỗi scaffold và chuỗi nhiễu phổ biến để báo cáo tập trung vào giá trị nhiều khả năng do malware kiểm soát, thay vì artifact của emulator hoặc test harness. Chuỗi quan sát qua API có thể có thêm metadata provenance như `source_detail`, nhưng schema JSON vẫn tương thích với consumer chỉ đọc các field cơ bản. Điều này không đồng nghĩa với giải mã tĩnh hoàn hảo, vì khả năng thu hồi vẫn phụ thuộc vào đường thực thi và hook quan sát được lúc runtime.

## Kiểm chứng và kiểm thử

Chạy Pytest để kiểm chứng offline:

```bash
# Chạy toàn bộ unit test
pytest tests/unit/

# Chạy test theo marker
pytest -m unit
pytest -m integration
pytest -m speakeasy

# Chạy riêng smoke test
pytest tests/unit/test_smoke.py

# Chạy test cho extractor và reporter
pytest tests/unit/test_extractor.py
pytest tests/unit/test_reporter.py

# In output chi tiết
pytest -v
```
