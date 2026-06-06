# Malware String Emulator

`malstring_emu` là công cụ phân tích PE bằng Python dùng **Speakeasy v2** để quan sát và trích xuất chuỗi có giá trị trong quá trình giả lập. Mục tiêu của dự án là tăng khả năng bắt chuỗi theo hướng **best-effort, bounded**: lấy chuỗi runtime sinh ra trên stack/heap, chuỗi bị ghi đè nhanh, chuỗi nằm sau con trỏ trong register, và chuỗi truyền qua một số Windows API phổ biến. Raw/static file bytes are not reported unless observed qua behavior runtime hoặc self-decode thật sự làm lộ plaintext.

Công cụ này không cố khôi phục thuật toán decode. Kết quả phụ thuộc vào **behavior path** mà Speakeasy thật sự đi qua, hook có được cắm thành công hay không, và dữ liệu còn đọc được trong bộ nhớ tại thời điểm quan sát.

## Tính năng chính

- **Runtime dirty-memory scan**: memory hook ghi nhận vùng bộ nhớ bị write, gộp vùng dirty, rồi cuối run đọc lại theo chunk có giới hạn để bắt chuỗi sinh ra trong lúc chạy. Kết quả thường đi qua `deferred_scan` hoặc `mem_write`.
- **Pre-overwrite stack/heap capture**: `WriteTracker` giữ `overwrite_history` dạng bounded candidate snapshots để không mất chuỗi vừa được build trên stack hoặc heap rồi bị logic khác ghi đè.
- **Execute-after-write short-window capture**: khi code hook thấy execution đi vào vùng memory vừa bị write, `WriteTracker` giữ snapshot ngắn có giới hạn và gắn `execute_after_write`. Đây là best-effort cho cửa sổ decode ngắn, không phải full unpacking.
- **Tight-loop Safe-Stop**: `timeout` và `--max-instructions` dừng giả lập an toàn khi mẫu chạy vòng lặp dài. Sau khi dừng, công cụ vẫn drain Speakeasy report, register scan và dirty-region scan.
- **Function-decoded output capture**: nếu function thật sự chạy và plaintext xuất hiện trong memory, API argument, Speakeasy report hoặc register pointer candidate, công cụ có thể bắt qua các output path đó. `hooks/register_hooks.py` cung cấp `register_scan` bounded để dereference register-held pointers.
- **API argument hooks**: `hooks/api_hooks.py` bắt chuỗi ANSI/Wide từ một số Windows API như `lstrcpyA/W`, WinINet, WinHTTP, `CreateProcessA/W`, `CreateFileA/W`, `RegOpenKeyExA/W`.
- **Behavior tracing best-effort**: gom API call quan sát được và chuỗi/IOC runtime để suy luận hành vi như network, file, registry persistence, process execution, possible injection và anti-analysis. Đây là tóm tắt theo path đã emulation, không phải kết luận tuyệt đối.
- **GUI local web workbench**: `gui.py` mở giao diện web cục bộ để chọn sample, chạy emulation, xem live logs, lọc strings, xem behavior summary/IOC và export CSV mà không cần thêm dependency ngoài stdlib.
- **JSON output tương thích ngược**: report vẫn giữ `timestamp`, `total_strings`, `strings`; các field provenance như `source`, `source_detail`, `execution_constraints`, `behavior` là optional.

## Cài đặt

Yêu cầu Python 3.8+ và môi trường ảo riêng.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Trên Windows:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` cài Speakeasy từ GitHub của Mandiant, cùng `pefile`, `capstone` và `pytest`.

## Cách sử dụng

### CLI

Chạy CLI chính qua `main.py`:

```bash
# Phân tích mẫu PE với cấu hình mặc định
python main.py -f sample.exe

# Chỉ định output JSON
python main.py -f sample.exe -o report.json

# Bật debug để xem thông tin loader, section và hook
python main.py -f sample.exe -d

# Giới hạn runtime bằng timeout
python main.py -f packed_sample.exe -t 120 -o packed_strings.json

# Chặn tight-loop bằng trần lệnh
python main.py -f tight_loop_sample.exe -t 30 --max-instructions 1000000 -o tight_loop_strings.json

# Chạy với kiến trúc x86 hoặc x64
python main.py -f payload.dll -a x64 -o payload_strings.json

# Lọc noise và chỉ xuất kết quả confidence cao
python main.py -f sample.exe --clean-output --min-confidence 70 -o report.json
```

Một số lab sample có thể kiểm tra biến môi trường safety gate. Tool xử lý gate này bên trong emulator hook khi thấy `getenv("LAB_MALWARE_ALLOWED")`, nên không cần truyền host env var để chạy sample test.

CLI flags chính:

| Flag | Ý nghĩa |
|---|---|
| `-f`, `--file` | Đường dẫn file PE cần phân tích. Bắt buộc. |
| `-a`, `--arch` | Nhãn kiến trúc `x86` hoặc `x64`; mặc định `x86`. |
| `-t`, `--timeout` | Thời gian giả lập tối đa, tính bằng giây. |
| `--max-instructions` | Số lệnh tối đa trước khi Safe-Stop. |
| `-o`, `--output` | File JSON output; mặc định `report.json`. |
| `--clean-output` | Ẩn một số chuỗi `deferred_scan` nhiễu khi đã có evidence tự tin hơn. |
| `--min-confidence` | Chỉ xuất chuỗi có confidence lớn hơn hoặc bằng ngưỡng này. |
| `-d`, `--debug` | Bật log debug. |

### GUI local web

Chạy GUI bằng Python trong cùng virtualenv:

```bash
python gui.py
```

Mặc định GUI chạy tại:

```text
http://127.0.0.1:8765/
```

Tùy chọn:

```bash
# Không tự mở browser
python gui.py --no-browser

# Chọn port khác
python gui.py --port 9000
```

GUI hỗ trợ:

- Form cấu hình sample, output, arch, timeout, max instructions, clean output, min confidence.
- Live logs từ subprocess `main.py`.
- Bảng strings có search, source filter và export CSV.
- Behavior tab gồm verdict, risk score, summary, IOC buckets và event timeline.

## Cấu trúc dự án

| Path | Vai trò |
|---|---|
| `main.py` | CLI entrypoint: parse args, tạo `MalwareEmulator`, chạy phân tích và ghi report. |
| `gui.py` | Local web GUI dùng Python stdlib, chạy `main.py` qua subprocess và render report JSON. |
| `core/emulator.py` | Orchestrator của Speakeasy: load sample vào emulator, register hooks, run, safe-stop, gom kết quả. |
| `core/extractor.py` | Bộ lọc và dedupe chuỗi: ASCII, UTF-16LE, tag URL/IP/domain/registry, source priority. |
| `core/behavior.py` | Behavior tracer/classifier: network, file, registry, process, injection, evasion, IOC buckets và risk summary. |
| `hooks/mem_hooks.py` | Memory-write tracking, hot-region snapshot, bounded `overwrite_history`, dirty regions. |
| `hooks/register_hooks.py` | Bounded register pointer scan và optional code hook registration. |
| `hooks/api_hooks.py` | Windows API string argument capture cho ANSI/Wide arguments. |
| `utils/reporter.py` | Ghi JSON report tương thích với consumer cũ. |
| `tests/unit/` | Unit tests cho extractor, reporter, register hooks, docs guardrails. |
| `tests/integration/` | Integration tests cho runtime scan, register capture, tight-loop strategies. |

## Luồng xử lý

1. `main.py` đọc CLI arguments và tạo `MalwareEmulator` với `timeout`, `max_instructions`, `debug`.
2. `MalwareEmulator.load_sample()` nạp mẫu thẳng vào Speakeasy qua `se.load_module()` rồi để runtime hooks và report quan sát chuỗi trong lúc emulation chạy.
3. `register_hooks()` cắm memory hooks, API hooks và register hooks nếu engine hỗ trợ.
4. `run()` gọi `se.run_module()` và phân loại trạng thái kết thúc: `completed`, `timeout`, `max_instructions`, `unsupported_api`, hoặc `error`.
5. Dù run bị safe-stop, `finally` vẫn chạy final `register_scan`, drain Speakeasy JSON report, drain `execute_after_write`/`overwrite_history`, rồi đọc lại dirty regions.
6. `StringExtractor` lọc nhiễu, dedupe theo `content`, gắn source/provenance và tag regex.
7. `BehaviorTracer` phân loại API/string đã quan sát thành behavior events, IOC buckets, risk score và analyst summary theo hướng best-effort.
8. `ReportGenerator` ghi JSON output.

## Phạm vi bắt chuỗi hiện tại

| Loại chuỗi | Có xử lý không? | Cách hoạt động | Giới hạn |
|---|---|---|---|
| Static string | Không báo cáo từ raw file | Raw/static file bytes are not reported như nguồn riêng. Chỉ khi runtime hoặc self-decode behavior làm lộ plaintext trong memory, register, API argument hoặc report thì chuỗi mới xuất hiện. | Raw/static bytes ở ngoài phạm vi trực tiếp, nên chuỗi mã hóa hoặc nén vẫn phụ thuộc behavior path. |
| Stack string | Có, theo runtime | Khi malware build chuỗi trên stack hoặc heap, memory hook ghi nhận vùng bị write. `overwrite_history` giữ bounded pre-overwrite candidates khi buffer bị ghi đè, dirty-region scan đọc lại vùng bẩn cuối run, và API hook bắt nếu chuỗi được truyền vào Windows API. | Best-effort và bounded: phụ thuộc branch đã chạy, vùng nhớ còn đọc được, giới hạn history/snapshot, và thời điểm chuỗi bị ghi đè. |
| Tight string / tight-loop decrypted string | Có, best-effort | `timeout` và `--max-instructions` chặn vòng lặp dài bằng Safe-Stop. `WriteTracker` đếm vùng ghi lặp; khi vùng đủ hot, hook đọc snapshot có giới hạn và scan ngay, rồi cuối run scan lại các dirty regions. | Không vượt qua mọi vòng lặp giải mã và không hứa hẹn giải mọi thuật toán. Snapshot bị giới hạn kích thước để tránh treo emulator. |
| Execute-after-write self-decode window | Có, best-effort | Nếu malware ghi plaintext vào memory, execution đi vào vùng vừa ghi, rồi ghi đè lại vùng đó, code hook có thể giữ snapshot ngắn trước khi plaintext biến mất. | Không phải full unpacker: chỉ bắt path đã chạy, snapshot bytes/số snapshot/số code-hook scan đều bị giới hạn, và không dump decoded PE hoàn chỉnh. |
| Function-decoded string | Có nếu function thật sự chạy | Không có detector riêng cho hàm decode. Nếu hàm decode được emulation đi qua và output plaintext ra memory, Speakeasy report, dirty/deferred scan, API hook, hoặc bounded `register_scan` có thể bắt plaintext còn nằm trong register/pointer ứng viên. | Nếu function không được gọi, bị anti-emulation chặn, register không đọc được, hoặc plaintext bị xóa quá nhanh, report có thể thiếu chuỗi đó. Không bảo đảm khôi phục decoder. |
| Runtime string-method deobfuscation observed at output boundary | Có nếu plaintext runtime lộ ra | Với pattern kiểu .NET `String.Replace`/`String.Remove` tạo plaintext từ chuỗi có homoglyph, ký tự đặc biệt hoặc method-name junk, công cụ chỉ bắt kết quả cuối khi behavior path thật sự đưa plaintext ra memory, API argument, report hoặc register pointer. | This is not static .NET deobfuscation: không parse CIL, không strip homoglyph từ raw bytes, không mô phỏng `Replace`/`Remove` trên chuỗi tĩnh, và không bảo đảm mọi obfuscation kiểu này đều bị bắt. |

## Behavior tracing

Behavior report là lớp suy luận best-effort từ API calls đã quan sát và IOC strings đã extract. Nó không thay thế sandbox đầy đủ và không khẳng định toàn bộ capability của mẫu.

Các category chính:

| Category | Ý nghĩa |
|---|---|
| `network.*` | HTTP/WinINet/WinHTTP/socket/DNS hoặc network indicators. |
| `file.*` | Mở, tạo, ghi, copy, move hoặc xóa file, hoặc file path indicators. |
| `registry.*` | Đọc/ghi registry thông thường. |
| `persistence.*` | Registry Run/RunOnce/service/startup indicators có khả năng persistence. |
| `process.*` | Spawn process, enumerate/open process hoặc process/script indicators. |
| `injection.*` | API chain hoặc API đơn lẻ thường gặp trong remote injection. |
| `evasion.*` | Debugger/timing/tool-detection indicators. |

Report gồm `verdict`, `risk_score`, `summary`, `tactics`, `iocs`, `events` và `execution_note`. Với string-only evidence, confidence thấp hơn API-observed behavior.

## Source labels trong output

Các kết quả có thể có `source` để analyst biết chuỗi đến từ đâu:

| Source | Ý nghĩa |
|---|---|
| `deferred_scan` | Chuỗi đọc lại từ dirty memory region sau khi run dừng. |
| `overwrite_history` | Chuỗi được giữ lại từ bounded pre-overwrite candidate history. |
| `mem_write` | Chuỗi bắt trực tiếp từ memory-write path. |
| `execute_after_write` | Chuỗi từ snapshot ngắn khi execution đi vào vùng memory vừa bị write. |
| `register_scan` | Chuỗi tìm thấy khi dereference register-held pointer candidate. |
| `api_hook` | Chuỗi bắt từ tham số Windows API hook. |

## JSON output

Report mặc định có dạng:

```json
{
  "timestamp": "2026-05-30T09:00:00Z",
  "total_strings": 2,
  "strings": [
    {
      "content": "http://example.com/payload",
      "encoding": "ASCII",
      "location": "0x401000",
      "source": "api_hook",
      "tags": ["URL"]
    }
  ],
  "execution_constraints": {
    "stop_reason": "max_instructions"
  },
  "behavior": {
    "verdict": "medium",
    "risk_score": 43,
    "summary": ["Observed behavior indicates possible network communication or payload download"],
    "tactics": ["Command and Control"],
    "iocs": {
      "urls": ["http://example.com/payload"],
      "domains": ["example.com"],
      "ips": [],
      "files": [],
      "registry_keys": [],
      "processes": []
    },
    "events": [
      {
        "api": "InternetOpenUrlA",
        "category": "network.download",
        "description": "Opens or downloads from a remote URL",
        "indicators": ["http://example.com/payload"],
        "confidence": 90,
        "source": "api_hook",
        "time": null
      }
    ],
    "execution_note": "Behavior is path-limited; emulation stopped due to max_instructions."
  }
}
```

Consumer cũ chỉ cần đọc `timestamp`, `total_strings`, `strings`. Các metadata khác là optional.

## Giới hạn cần nhớ

- Kết quả là **not static** theo nghĩa không chứng minh toàn bộ binary đã được hiểu hết. Raw/static bytes chỉ xuất hiện nếu behavior path làm lộ chúng trong quan sát runtime.
- Không có bảo đảm rằng mọi branch, mọi API path hoặc mọi decoder function sẽ được Speakeasy chạy qua.
- Không bảo đảm khôi phục decoder hoặc suy luận thuật toán giải mã.
- Packed/encrypted data chỉ xuất hiện nếu behavior path làm lộ plaintext trong memory, register, API argument hoặc report.
- Các giới hạn bounded cố ý được đặt để tránh OOM/hang: dirty-region scan giới hạn chunk, register scan giới hạn số lần đọc và kích thước đọc, overwrite history và execute-after-write đều giới hạn số candidate/snapshot.

## Kiểm thử

Chạy toàn bộ test offline:

```bash
pytest tests/unit/
pytest tests/integration/
```

Chạy theo marker:

```bash
pytest -m unit
pytest -m integration
pytest -m speakeasy
pytest -m tight_loop
```

Một số lệnh hữu ích khi sửa logic bắt chuỗi hoặc behavior:

```bash
pytest tests/unit/test_register_hooks.py -q
pytest tests/unit/test_behavior.py -q
pytest tests/unit/test_docs.py -q
pytest tests/integration/test_runtime_e2e.py -q
```

Validate sample expected strings:

```bash
python tools/validate_expected.py -r report.json -e "sample/Hidden Strings.txt"
```

Docs guardrails nằm trong `tests/unit/test_docs.py`; chúng giúp README không vô tình hứa hẹn quá mức về extraction, decoder recovery hoặc loop handling.
