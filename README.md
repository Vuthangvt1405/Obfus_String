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

1. **Loader:** Không chọc vào đĩa hệ thống thật, nạp PE PE an toàn vào Sandbox bộ nhớ cấu trúc cô lập của Python. Cấu trúc tự động nhận diện kiến trúc 32-bit hay 64-bit.
2. **Execution:** Malware tưởng mình đang ở môi trường Windows thật. Nó chạy các quy trình unpack/giải mã lên bộ nhớ cấp phát ảo.
3. **Extraction:** Mỗi khi malware ghi một byte xuống memory ảo hoặc chạy hàm Copy Chuỗi hệ điều hành (lstrcpy), module sẽ bắt lại và decode thử. Nếu là ASCII hoặc Wide String hợp lệ, đoạn dữ liệu sẽ được parse thành Regex Label và lưu ra file JSON.
