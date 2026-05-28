import os
import json
import pytest
import subprocess
from pathlib import Path

# Thư mục gốc chứa mã nguồn dự án
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Đường dẫn đến file test.c đã được biên dịch giả định (nếu có)
TEST_SAMPLE = PROJECT_ROOT / "test.c" # Mặc dù file .c không thể chạy trực tiếp, Speakeasy hỗ trợ xử lý PE, có thể cần build

@pytest.fixture
def run_cli():
    """Hàm hỗ trợ chạy main.py thông qua subprocess."""
    def _run(*args):
        cli_path = PROJECT_ROOT / "main.py"
        cmd = ["python3", str(cli_path)] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result
    return _run

@pytest.mark.integration
@pytest.mark.speakeasy
def test_runtime_capture_e2e(run_cli, tmp_path):
    """
    Test E2E toàn bộ luồng chạy của chương trình thông qua main.py.
    Yêu cầu file test hợp lệ (pe_fixture.exe) để giả lập.
    Nếu không tìm thấy mẫu, skip test này (theo yêu cầu không thất bại tùy tiện).
    """
    # Hiện tại chưa có file PE thật trong repo (.c chưa build).
    # Chúng ta sử dụng một file giả nếu có thể, hoặc bỏ qua nếu không tồn tại file test hợp lệ.
    pe_file = PROJECT_ROOT / "test_fixture.exe"
    
    if not pe_file.exists():
        pytest.skip(f"Mẫu phân tích {pe_file} không tồn tại. Yêu cầu build test.c thành exe để test e2e.")
        
    output_json = tmp_path / "test_report.json"
    
    # 1. Chạy CLI
    result = run_cli("-f", str(pe_file), "-a", "x86", "-t", "5", "-o", str(output_json))
    
    # Ghi log output CLI ra file như yêu cầu
    with open("task-12-cli-run.txt", "w", encoding="utf-8") as f:
        f.write(f"STDOUT:\n{result.stdout}\n")
        f.write(f"STDERR:\n{result.stderr}\n")
    
    # 2. Kiểm tra tiến trình không bị crash
    assert result.returncode == 0, f"CLI trả về lỗi: {result.stderr}"
    
    # 3. Mở log json (nếu có chuỗi được phát hiện)
    assert output_json.exists(), "File báo cáo JSON không được tạo ra!"
    
    with open(output_json, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Ghi log json assertions ra file
    with open("task-12-json-assert.txt", "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2))
        
    # 4. Kiểm tra dữ liệu đầu ra JSON
    assert "total_strings" in data
    assert "strings" in data
    assert data["total_strings"] >= 1, "Phải tìm thấy ít nhất 1 chuỗi giải mã từ quá trình chạy"
    
    # Kiểm tra miền (domain) "thecyberyeti.com" có tồn tại hay không
    found_yeti = False
    for s_info in data["strings"]:
        if "thecyberyeti.com" in s_info.get("content", ""):
            found_yeti = True
            break
            
    assert found_yeti, "Không tìm thấy chuỗi mong đợi 'thecyberyeti.com' trong báo cáo."

@pytest.mark.integration
def test_runtime_e2e_missing_file_handled(run_cli):
    """
    Kiểm tra xử lý lỗi khi nạp một mẫu không tồn tại qua command line.
    """
    result = run_cli("-f", "file_not_exist_xyz.exe")
    
    # Lưu stdout/stderr ra file log
    with open("task-12-cli-run.txt", "a", encoding="utf-8") as f:
        f.write("\n--- TEST MISSING FILE ---\n")
        f.write(f"STDOUT:\n{result.stdout}\n")
        f.write(f"STDERR:\n{result.stderr}\n")
        f.write(f"RETURN_CODE: {result.returncode}\n")
        
    # main.py gọi sys.exit(1) khi không nạp được (load_sample trả về False/raise)
    assert result.returncode == 1
    # Check string log, log báo lỗi nạp mẫu
    assert "thất bại" in result.stderr or "không nạp được" in result.stderr or "Nạp mẫu" in result.stderr or "Lỗi nghiêm trọng" in result.stderr or "Dừng chương trình" in result.stderr
