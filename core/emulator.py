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
        for start_addr, end_addr in tracker_regions:
            size_to_read = min(end_addr - start_addr, 4096) # Giới hạn 4KB mỗi block để an toàn
            try:
                mem_data = self.se.mem_read(start_addr, size_to_read)
                self.extractor.process_memory_write(hex(start_addr), mem_data)
            except Exception as e:
                logger.debug(f"[Emulator] Lỗi đọc dirty region {hex(start_addr)}: {e}")

    def _extract_from_report(self):
        """
        Trích xuất thêm chuỗi từ Speakeasy built-in report (API calls, strings).
        """
        try:
            report = self.se.get_report()
            report_json = json.loads(self.se.get_json_report())

            for entry in report_json.get('entry_points', []):
                for api_call in entry.get('apis', []):
                    api_name = api_call.get('api_name', '')
                    for arg in api_call.get('args', []):
                        val = str(arg)
                        if len(val) >= 4 and val.isprintable():
                            self.extractor.process_api_string(api_name, val)

                for s in entry.get('strings', {}).get('in_memory', []):
                    if isinstance(s, str) and len(s) >= 4:
                        self.extractor.process_api_string('speakeasy_report', s)

        except Exception as e:
            logger.debug(f"[Emulator] Không thể trích xuất từ report: {e}")

    def get_extracted_strings(self):
        return self.extractor.get_results()
