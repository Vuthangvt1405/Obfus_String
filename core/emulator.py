# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false
import logging
import json
import speakeasy
from speakeasy.errors import SpeakeasyError, NotSupportedError
from hooks.mem_hooks import WriteTracker, setup_memory_hooks
from hooks.api_hooks import setup_api_hooks
from hooks.register_hooks import scan_register_candidates, setup_register_hooks
from core.extractor import StringExtractor
from core.static_scanner import scan_file

logger = logging.getLogger(__name__)

DEFAULT_MAX_RESULTS = 10000
MAX_DEFERRED_CHUNK_SIZE = 4096
MAX_DEFERRED_SCAN_PER_REGION = 8192
MAX_DEFERRED_CHUNK_READS = 256

class MalwareEmulator:
    def __init__(self, arch="x86", timeout=60, max_instructions=5000000, debug=False, max_results=DEFAULT_MAX_RESULTS):
        """
        Purpose:
        Initialize the Speakeasy-backed malware emulation environment.

        How it works:
        Stores runtime limits, creates capped extractors/trackers, builds the
        public Speakeasy config dict, and retries without ``max_instructions``
        only when the installed Speakeasy version rejects that config key.

        Parameters:
        - arch: Requested CPU architecture label retained for reporting/config.
        - timeout: Maximum emulation runtime in seconds.
        - max_instructions: Maximum instruction count before Speakeasy stops.
        - debug: Enables extra loader logging when True.
        - max_results: Maximum unique strings to retain from high-recall capture.

        Returns:
        None; initializes instance fields and ``self.se``.
        """
        self.arch = arch
        self.timeout = timeout
        self.max_instructions = max_instructions
        self.debug = debug
        self.module = None
        self.extractor = StringExtractor(max_results=max_results)
        self.execution_status = None
        
        # Thêm tracker để ghi log địa chỉ được ghi (nhỏ gọn, không tốn performance)
        self.tracker = WriteTracker()

        config_dict = speakeasy.config.get_default_config_dict()
        config_dict['timeout'] = self.timeout
        config_dict['max_instructions'] = self.max_instructions

        try:
            self.se = speakeasy.Speakeasy(config=config_dict)
        except Exception as err:
            if 'max_instructions' not in config_dict or 'max_instructions' not in str(err):
                raise
            fallback_config = dict(config_dict)
            fallback_config.pop('max_instructions', None)
            logger.warning(
                "[Emulator] Speakeasy config does not support max_instructions; continuing with timeout only."
            )
            self.se = speakeasy.Speakeasy(config=fallback_config)

        logger.debug(f"[Emulator] Khởi tạo Speakeasy (timeout={self.timeout}s, max_instructions={self.max_instructions})")

    def load_sample(self, file_path):
        """
        Purpose:
        Static-scan the sample bytes, then load the PE into Speakeasy memory.

        How it works:
        Reads the file through the static scanner into the shared
        StringExtractor, treats scanner errors as non-fatal, then delegates to
        Speakeasy.load_module() and logs loader metadata.

        Parameters:
        - file_path: path to the sample PE or binary blob being analyzed.

        Returns:
        The loaded Speakeasy module, or None if Speakeasy rejects loading.
        """
        try:
            logger.info(f"[Loader] Đang đọc file PE: {file_path}")
            try:
                static_findings = scan_file(file_path, self.extractor)
                if static_findings:
                    logger.info(
                        f"[Loader] Static scan captured {len(static_findings)} strings before emulation."
                    )
            except Exception as e:
                logger.debug(f"[Loader] Static scan skipped after error: {e}")

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
        Purpose:
        Register all runtime capture hooks supported by the current engine.

        How it works:
        Installs memory-write tracking, API argument capture, and optional
        register code-hook scanning. Register hook setup is non-fatal when the
        engine lacks code-hook support because run() also performs a final scan.

        Parameters:
        None.

        Returns:
        None.
        """
        logger.info("[Emulator] Đang cắm các cảm biến Hooks (Mem, API & Register)...")
        setup_memory_hooks(self.se, self.extractor, tracker=self.tracker)
        setup_api_hooks(self.se, self.extractor)
        setup_register_hooks(self.se, self.extractor)

    def run(self):
        """
        Purpose:
        Execute the loaded sample while preserving strings observed before a
        safe resource stop.

        How it works:
        Marks the run as completed by default, calls Speakeasy, then classifies
        timeout and max-instruction stops from exception class names or messages.
        Resource stops are swallowed so analysis can continue, while unrelated
        exceptions are re-raised after the extraction ``finally`` block runs. The
        finalization path always performs one bounded register scan before other
        report and dirty-memory extraction phases.

        Parameters:
        None.

        Returns:
        None.
        """
        if not self.module:
            return

        self.execution_status = "completed"
        try:
            self.se.run_module(self.module)
        except NotSupportedError as err:
            self.execution_status = "unsupported_api"
            logger.warning(f"[Emulator] Thiếu API hỗ trợ: {err}")
        except Exception as e:
            err_text = f"{e.__class__.__name__}: {e}".lower()
            if "timeout" in err_text:
                self.execution_status = "timeout"
                logger.info("[Emulator] Đã đạt giới hạn Timeout an toàn.")
            elif (
                "maxinstruction" in err_text
                or "max_instruction" in err_text
                or "max instructions" in err_text
                or "maximum instructions" in err_text
                or "instruction limit" in err_text
            ):
                self.execution_status = "max_instructions"
                logger.info("[Emulator] Đã đạt giới hạn lệnh an toàn.")
            else:
                self.execution_status = "error"
                logger.error(f"[Emulator] Bị gián đoạn: {e}")
                raise
        finally:
            self._scan_registers()
            self._extract_from_report()
            # Xử lý các vùng nhớ đã tracker sau khi giả lập kết thúc
            self._extract_tracked_memory()

        if self.execution_status and self.execution_status != "completed":
            logger.info(f"Execution constrained: {self.execution_status}")

    def _scan_registers(self):
        """
        Purpose:
        Capture strings reachable through register-held pointers at run finalization.

        How it works:
        Calls the bounded register candidate scanner against the current
        Speakeasy engine and treats scanner failures as non-fatal so final
        report and dirty-memory extraction can still proceed.

        Parameters:
        None.

        Returns:
        None.
        """
        try:
            _ = scan_register_candidates(self.se, self.extractor)
        except Exception as e:
            logger.debug(f"[Emulator] Register scan skipped after error: {e}")

    def _extract_tracked_memory(self):
        """
        Purpose:
        Drain bounded memory-write observations after emulation stops.

        How it works:
        First scans retained overwrite candidates and labels newly discovered
        strings as overwrite_history, then scans coalesced dirty regions in
        capped chunks as the existing deferred-scan fallback.

        Parameters:
        None.

        Returns:
        None.
        """
        tracker_candidates = self.tracker.get_candidates()
        for candidate_addr, candidate_data in tracker_candidates:
            before_count = len(self.extractor.get_results())
            self.extractor.scan_buffer(candidate_addr, candidate_data)
            for result in self.extractor.get_results()[before_count:]:
                if result.get('source') == 'deferred_scan':
                    result['source'] = 'overwrite_history'

        tracker_regions = self.tracker.get_regions()
        if not tracker_regions:
            return
            
        logger.info(f"[Emulator] Queuing {len(tracker_regions)} coalesced dirty regions for regex scan.")
        
        chunk_reads = 0
        
        for start_addr, end_addr in tracker_regions:
            total_size = end_addr - start_addr
            if total_size <= 0:
                continue
                
            total_size = min(total_size, MAX_DEFERRED_SCAN_PER_REGION)
            
            offset = 0
            while offset < total_size and chunk_reads < MAX_DEFERRED_CHUNK_READS:
                chunk_size = min(MAX_DEFERRED_CHUNK_SIZE, total_size - offset)
                current_addr = start_addr + offset
                try:
                    mem_data = self.se.mem_read(current_addr, chunk_size)
                    chunk_reads += 1
                    if mem_data:
                        self.extractor.scan_buffer(current_addr, mem_data)
                except Exception as e:
                    logger.debug(f"[Emulator] Lỗi đọc dirty region {hex(current_addr)}: {e}")
                
                offset += chunk_size
            if chunk_reads >= MAX_DEFERRED_CHUNK_READS:
                logger.info("[Emulator] Deferred dirty-memory scan reached chunk-read cap.")
                break

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
