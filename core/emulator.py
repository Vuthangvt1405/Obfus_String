# -*- coding: utf-8 -*-
import logging
import json
import speakeasy
from speakeasy.errors import SpeakeasyError, NotSupportedError
from hooks.mem_hooks import setup_memory_hooks
from hooks.api_hooks import setup_api_hooks
from core.extractor import StringExtractor

logger = logging.getLogger(__name__)

class MalwareEmulator:
    def __init__(self, arch="x86", timeout=60, max_instructions=5000000, debug=False):
        """
        Khởi tạo môi trường giả lập Speakeasy.
        Speakeasy v2 tự phát hiện kiến trúc từ PE header.
        """
        self.arch = arch
        self.timeout = timeout
        self.max_instructions = max_instructions
        self.debug = debug
        self.module = None
        self.extractor = StringExtractor()
        
        # Thêm tracker để ghi log địa chỉ được ghi (nhỏ gọn, không tốn performance)
        from hooks.mem_hooks import WriteTracker
        self.tracker = WriteTracker()

        config_dict = speakeasy.config.get_default_config_dict()
        config_dict['timeout'] = self.timeout
        self.se = speakeasy.Speakeasy(config=config_dict)
        logger.debug(f"[Emulator] Khởi tạo Speakeasy (timeout={self.timeout}s)")

    def load_sample(self, file_path):
        """
        Phân tích và nạp module PE vào không gian bộ nhớ ảo.
        """
        try:
            logger.info(f"[Loader] Đang đọc file PE: {file_path}")
            self.module = self.se.load_module(file_path)

            base_addr = self.module.base
            oep = self.module.get_ep()
            logger.info(f"[Loader] SUCCESS: Image Base = {hex(base_addr)} | OEP = {hex(oep)}")

            if self.debug:
                logger.debug("[Loader] --- PE Sections ---")
                for sec in self.module.sections:
                    name = getattr(sec, 'name', 'UNKNOWN')
                    vaddr = getattr(sec, 'virtual_address', 0)
                    vsize = getattr(sec, 'virtual_size', 0)
                    logger.debug(f"  + {name} | VAddr: {hex(vaddr)} | VSize: {hex(vsize)}")

            return self.module

        except SpeakeasyError as e:
            logger.error(f"[Loader] Speakeasy từ chối file này: {e}")
            return None
        except Exception as e:
            logger.error(f"[Loader] Lỗi ngoại lệ khi nạp mẫu: {e}")
            return None

    def register_hooks(self):
        """
        Đăng ký Memory Hooks và API Hooks.
        """
        logger.info("[Emulator] Đang cắm các cảm biến Hooks (Mem & API)...")
        setup_memory_hooks(self.se, self.extractor, tracker=self.tracker)
        setup_api_hooks(self.se, self.extractor)

    def run(self):
        """
        Thực thi giả lập an toàn.
        """
        if not self.module:
            return

        try:
            self.se.run_module(self.module)
        except NotSupportedError as err:
            logger.warning(f"[Emulator] Thiếu API hỗ trợ: {err}")
        except Exception as e:
            err_str = str(e)
            if "Timeout" in err_str or "timeout" in err_str:
                logger.info("[Emulator] Đã đạt giới hạn Timeout an toàn.")
            else:
                logger.error(f"[Emulator] Bị gián đoạn: {e}")

        self._extract_from_report()
        # Xử lý các vùng nhớ đã tracker sau khi giả lập kết thúc
        self._extract_tracked_memory()

    def _extract_tracked_memory(self):
        tracker_regions = self.tracker.get_regions()
        if not tracker_regions:
            return
            
        logger.info(f"[Emulator] Queuing {len(tracker_regions)} coalesced dirty regions for regex scan.")
        
        MAX_CHUNK_SIZE = 4096
        MAX_TOTAL_SCAN_PER_REGION = 8192 # cap per block per instructions
        
        for start_addr, end_addr in tracker_regions:
            total_size = end_addr - start_addr
            if total_size <= 0:
                continue
                
            total_size = min(total_size, MAX_TOTAL_SCAN_PER_REGION)
            
            offset = 0
            while offset < total_size:
                chunk_size = min(MAX_CHUNK_SIZE, total_size - offset)
                current_addr = start_addr + offset
                try:
                    mem_data = self.se.mem_read(current_addr, chunk_size)
                    if mem_data:
                        self.extractor.scan_buffer(current_addr, mem_data)
                except Exception as e:
                    logger.debug(f"[Emulator] Lỗi đọc dirty region {hex(current_addr)}: {e}")
                
                offset += chunk_size

    # Known scaffold/environment noise strings from Speakeasy's built-in
    # stub DLLs and emulator scaffolding that are never useful for malware
    # analysis.  These are exact-match only — no substring matching — to
    # avoid over-filtering legitimate malware strings.
    _SPEAKEASY_SCAFFOLD_NOISE = frozenset({
        # Stub DLL paths injected by the Speakeasy loader
        "C:\\Windows\\system32\\ntdll.dll",
        "C:\\Windows\\system32\\kernel32.dll",
        "C:\\Windows\\system32\\kernelbase.dll",
        "C:\\Windows\\system32\\ws2_32.dll",
        "C:\\Windows\\system32\\wininet.dll",
        "C:\\Windows\\system32\\winhttp.dll",
        "C:\\Windows\\system32\\advapi32.dll",
        "C:\\Windows\\system32\\user32.dll",
        "C:\\Windows\\system32\\gdi32.dll",
        "C:\\Windows\\system32\\msvcrt.dll",
        "C:\\Windows\\system32\\shell32.dll",
        "C:\\Windows\\system32\\shlwapi.dll",
        "C:\\Windows\\system32\\urlmon.dll",
        "C:\\Windows\\system32\\dnsapi.dll",
        "C:\\Windows\\system32\\CRYPT32.dll",
        "C:\\Windows\\system32\\WTSAPI32.dll",
        "C:\\Windows\\system32\\dbghelp.dll",
        "C:\\Windows\\system32\\advpack.dll",
        "C:\\Windows\\system32\\psapi.dll",
        "C:\\Windows\\system32\\hal.dll",
        "C:\\Windows\\system32\\mscoree.dll",
        # Stub module names (without path)
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "ws2_32.dll",
        "wininet.dll",
        "winhttp.dll",
        "advapi32.dll",
        "user32.dll",
        "gdi32.dll",
        "msvcrt.dll",
        "shell32.dll",
        "shlwapi.dll",
        "urlmon.dll",
        "dnsapi.dll",
        "CRYPT32.dll",
        "WTSAPI32.dll",
        "dbghelp.dll",
        "advpack.dll",
        "psapi.dll",
        "hal.dll",
        "mscoree.dll",
    })

    def _is_scaffold_noise(self, s):
        """Return True if *s* is an exact match against known Speakeasy
        scaffold/environment noise strings (stub DLL names/paths)."""
        return s in self._SPEAKEASY_SCAFFOLD_NOISE

    def _extract_from_report(self):
        """
        Trích xuất thêm chuỗi từ Speakeasy built-in report.

        Speakeasy report-derived strings (API args, in-memory decoded
        strings) are passed through ``process_api_string()`` which applies
        the global noise filter (``_is_noise`` — repetitive padding,
        standard alphabets, Base64 constants) and the scaffold-noise
        pre-filter (``_is_scaffold_noise``) before being recorded.
        """
        try:
            report_json = json.loads(self.se.get_json_report())

            # ── API call arguments (flat list, older Speakeasy format) ──
            for entry in report_json.get('entry_points', []):
                for api_call in entry.get('apis', []):
                    api_name = api_call.get('api_name', '')
                    for arg in api_call.get('args', []):
                        val = str(arg)
                        if len(val) >= 4 and val.isprintable():
                            self.extractor.process_api_string(api_name, val)

            # ── In-memory decoded strings (Speakeasy v2 report level) ──
            strings = report_json.get('strings') or {}
            in_memory = strings.get('in_memory') or {}

            for bucket_key in ('ansi', 'unicode'):
                for s in in_memory.get(bucket_key, []):
                    if isinstance(s, str) and len(s) >= 4:
                        # Pre-filter known scaffold noise before it reaches
                        # the global filter — these are exact-match DLL
                        # names/paths from the emulator's stub loader.
                        if self._is_scaffold_noise(s):
                            continue
                        self.extractor.process_api_string(
                            'speakeasy_report', s,
                        )

        except Exception as e:
            logger.debug(f"[Emulator] Không thể trích xuất từ report: {e}")

    def get_extracted_strings(self):
        return self.extractor.get_results()
