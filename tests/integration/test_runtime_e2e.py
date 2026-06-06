# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUntypedFunctionDecorator=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportAny=false, reportUnusedCallResult=false, reportImplicitStringConcatenation=false
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Thư mục gốc chứa mã nguồn dự án
PROJECT_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def run_cli():
    """Hàm hỗ trợ chạy main.py thông qua subprocess."""
    def _run(*args):
        cli_path = PROJECT_ROOT / "main.py"
        cmd = [sys.executable, str(cli_path)] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result
    return _run


@pytest.mark.integration
@pytest.mark.speakeasy
@pytest.mark.requires_fixture("xor_self_decrypt_fixture.exe")
def test_runtime_capture_e2e(run_cli, tmp_path, fixture_path):
    """
    Test E2E toàn bộ luồng chạy của chương trình thông qua main.py.
    Sử dụng benign fixture tự giải mã XOR (thecyberyeti.com).
    Tự động skip nếu fixture hoặc Speakeasy không có sẵn.
    """
    pe_file = fixture_path  # Resolved by conftest.py requires_fixture marker
    
    output_json = tmp_path / "test_report.json"
    
    # 1. Chạy CLI
    result = run_cli("-f", str(pe_file), "-a", "x86", "-t", "60", "-o", str(output_json))
    
    cli_log = tmp_path / "task-12-cli-run.txt"
    cli_log.write_text(
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}\n",
        encoding="utf-8",
    )

    # 2. Kiểm tra tiến trình không bị crash
    assert result.returncode == 0, f"CLI trả về lỗi: {result.stderr}"
    
    # 3. Mở log json (nếu có chuỗi được phát hiện)
    assert output_json.exists(), "File báo cáo JSON không được tạo ra!"
    
    with open(output_json, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    json_assert_log = tmp_path / "task-12-json-assert.txt"
    json_assert_log.write_text(json.dumps(data, indent=2), encoding="utf-8")

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
def test_runtime_e2e_missing_file_handled(run_cli, tmp_path):
    """
    Kiểm tra xử lý lỗi khi nạp một mẫu không tồn tại qua command line.
    """
    result = run_cli("-f", "file_not_exist_xyz.exe")
    
    cli_log = tmp_path / "task-12-cli-run.txt"
    cli_log.write_text(
        "\n--- TEST MISSING FILE ---\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}\n"
        f"RETURN_CODE: {result.returncode}\n",
        encoding="utf-8",
    )

    # main.py gọi sys.exit(1) khi không nạp được (load_sample trả về False/raise)
    assert result.returncode == 1
    # Check string log, log báo lỗi nạp mẫu
    assert "thất bại" in result.stderr or "không nạp được" in result.stderr or "Nạp mẫu" in result.stderr or "Lỗi nghiêm trọng" in result.stderr or "Dừng chương trình" in result.stderr
