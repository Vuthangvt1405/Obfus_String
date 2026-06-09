# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false
import logging
import json
import re
import speakeasy
from speakeasy.errors import SpeakeasyError, NotSupportedError
from hooks.mem_hooks import WriteTracker, setup_memory_hooks
from hooks.api_hooks import setup_api_hooks
from hooks.register_hooks import scan_register_candidates, setup_register_hooks
from core.extractor import StringExtractor
from core.behavior import BehaviorTracer

logger = logging.getLogger(__name__)

DEFAULT_MAX_RESULTS = 10000
MAX_DEFERRED_CHUNK_SIZE = 4096
MAX_DEFERRED_SCAN_PER_REGION = 8192
MAX_DEFERRED_CHUNK_READS = 256
STATIC_OBFUSCATED_MAX_RUN = 256

class MalwareEmulator:
    def __init__(self, arch="x86", timeout=60, max_instructions=5000000, debug=False, max_results=DEFAULT_MAX_RESULTS, bypass_evasion=True):
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
        self.sample_path = None
        self.extractor = StringExtractor(max_results=max_results)
        self.execution_status = None
        self.behavior_tracer = BehaviorTracer()
        self.bypass_evasion = bypass_evasion
        
        # Thêm tracker để ghi log địa chỉ được ghi (nhỏ gọn, không tốn performance)
        self.tracker = WriteTracker()

        config_dict = speakeasy.config.get_default_config_dict()
        config_dict['timeout'] = self.timeout
        config_dict['max_instructions'] = self.max_instructions

        config_dict.setdefault('env', {})

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
        Load the sample into Speakeasy memory for runtime emulation.

        How it works:
        Delegates directly to Speakeasy.load_module() and logs loader metadata
        after Speakeasy accepts the module.

        Parameters:
        - file_path: path to the sample PE or binary blob being analyzed.

        Returns:
        The loaded Speakeasy module, or None if Speakeasy rejects loading.
        """
        try:
            logger.info(f"[Loader] Đang đọc file PE: {file_path}")
            self.sample_path = file_path
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

            if self.bypass_evasion:
                self._apply_evasion_bypasses()

            self._extract_static_obfuscated_strings(file_path)

            return self.module

        except SpeakeasyError as e:
            logger.error(f"[Loader] Speakeasy từ chối file này: {e}")
            return None
        except Exception as e:
            logger.error(f"[Loader] Lỗi ngoại lệ khi nạp mẫu: {e}")
            return None

    def _apply_evasion_bypasses(self):
        """
        Purpose:
        Apply bounded, analysis-only patches that keep known anti-analysis gates
        from terminating emulation before the payload path is reached.

        How it works:
        Currently patches the common MinGW x64 pattern used by malware4's
        FullEvasionCheck(): ``test al, al; je clean_return; ... ExitProcess``.
        Replacing the conditional jump with an unconditional jump skips only the
        evasion-report/ExitProcess block, preserving the rest of main(). This is
        applied in emulated memory, never to the host file on disk.
        """
        if not self.module:
            return

        patches = 0
        for sec in getattr(self.module, 'sections', []) or []:
            name = getattr(sec, 'name', '')
            if name and '.text' not in str(name).lower():
                continue
            vaddr = getattr(sec, 'virtual_address', 0)
            vsize = getattr(sec, 'virtual_size', 0)
            if not vaddr or not vsize:
                continue
            start = self.module.base + vaddr
            try:
                data = self.se.mem_read(start, vsize)
            except Exception as err:
                logger.debug(f"[EvasionBypass] Cannot read code section {name}: {err}")
                continue

            # malware4 / MinGW x64 FullEvasionCheck:
            #   84 c0                    test al, al
            #   0f 84 b8 00 00 00        je  clean_return
            #   48 8d 45 f7              lea rax, [rbp-9]   ; begin debug string path
            pattern = b'\x84\xc0\x0f\x84\xb8\x00\x00\x00\x48\x8d\x45\xf7'
            idx = data.find(pattern)
            while idx != -1:
                patch_addr = start + idx + 2
                # jmp +0xb9; nop => target is the same clean-return epilogue as
                # the original JE, but the jump is now unconditional.
                try:
                    self.se.mem_write(patch_addr, b'\xe9\xb9\x00\x00\x00\x90')
                    patches += 1
                    logger.info(f"[EvasionBypass] Patched anti-analysis exit branch at {hex(patch_addr)}")
                except Exception as err:
                    logger.warning(f"[EvasionBypass] Failed to patch {hex(patch_addr)}: {err}")
                idx = data.find(pattern, idx + 1)

        if patches == 0:
            logger.info("[EvasionBypass] No known anti-analysis branch pattern matched.")

    _STATIC_PRINTABLE_RE = re.compile(rb'[\x09\x0a\x0b\x0c\x0d\x20-\x7e]{4,256}')

    @staticmethod
    def _decode_reverse_shift(candidate: bytes) -> str | None:
        """
        Decode strings obfuscated as reverse(+1), where runtime decrypt does
        char-1 for every byte and then reverses the buffer. This is intentionally
        generic and bounded so samples that hide config in static C strings can
        still be covered when emulation does not reach their payload path.
        """
        if not candidate:
            return None
        try:
            decoded_bytes = bytes(((b - 1) & 0xff) for b in candidate)[::-1]
            return decoded_bytes.decode('ascii', errors='ignore').strip('\x00')
        except Exception:
            return None

    @staticmethod
    def _looks_like_analyst_string(value: str) -> bool:
        if not value or len(value) < 4:
            return False
        lowered = value.lower()
        if re.search(r'(?:\d{1,3}\.){3}\d{1,3}', value):
            return True
        if re.fullmatch(r'\d{2,5}', value):
            return True
        indicators = (
            '.dll', '.exe', 'software\\', 'currentversion\\run', 'hkey_',
            'vmware', 'virtualbox', 'malware', 'mutex', 'keylog', 'clipboard', 'webcam',
            'evasion', 'c2', 'cmd.', '\\run'
        )
        return any(item in lowered for item in indicators)

    def _extract_static_obfuscated_strings(self, file_path):
        """
        Best-effort static fallback for simple runtime decryptors. It does not
        replace emulation; it supplements it when a sample stores config strings
        as printable reverse+shift blobs but Speakeasy stops before the decode
        function reaches payload logic.
        """
        try:
            data = open(file_path, 'rb').read()
        except Exception as err:
            logger.debug(f"[StaticObf] Cannot read sample bytes: {err}")
            return

        before = len(self.extractor.get_results())
        seen: set[bytes] = set()
        for match in self._STATIC_PRINTABLE_RE.finditer(data):
            raw = match.group(0)[:STATIC_OBFUSCATED_MAX_RUN]
            # C-string extraction regex can include leading control bytes used
            # to encode a plaintext trailing newline. Try both full and stripped
            # variants so '[...\\n' logs are still recovered without the newline.
            for candidate in (raw, raw.strip(b'\x09\x0a\x0b\x0c\x0d')):
                if len(candidate) < 4 or candidate in seen:
                    continue
                seen.add(candidate)
                decoded = self._decode_reverse_shift(candidate)
                if decoded and self._looks_like_analyst_string(decoded):
                    self.extractor.ingest_candidate(
                        decoded,
                        source='static_obfuscated',
                        location=f"file+0x{match.start():x}",
                        source_detail='reverse_shift_minus1',
                    )
        added = len(self.extractor.get_results()) - before
        if added:
            logger.info(f"[StaticObf] Recovered {added} reverse+shift candidate strings from static bytes.")

    def register_hooks(self):
        """
        Purpose:
        Register all runtime capture hooks supported by the current engine.

        How it works:
        Installs memory-write tracking, API argument capture, optional
        execute-after-write snapshots, and register code-hook scanning. Register
        hook setup is non-fatal when the engine lacks code-hook support because
        run() also performs a final scan.

        Parameters:
        None.

        Returns:
        None.
        """
        logger.info("[Emulator] Đang cắm các cảm biến Hooks (Mem, API & Register)...")
        setup_memory_hooks(self.se, self.extractor, tracker=self.tracker)
        setup_api_hooks(self.se, self.extractor, behavior_tracer=getattr(self, 'behavior_tracer', None))
        setup_register_hooks(
            self.se,
            self.extractor,
            execute_after_write_tracker=self.tracker,
        )

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
            scan_register_candidates(self.se, self.extractor)
        except Exception as e:
            logger.debug(f"[Emulator] Register scan skipped after error: {e}")

    def _extract_tracked_memory(self):
        """
        Purpose:
        Drain bounded memory-write observations after emulation stops.

        How it works:
        First scans retained execute-after-write snapshots and labels newly
        discovered strings as execute_after_write. Then it scans retained
        overwrite candidates as overwrite_history and coalesced dirty regions in
        capped chunks as the existing deferred-scan fallback.

        Parameters:
        None.

        Returns:
        None.
        """
        self._scan_candidate_buffers(
            self.tracker.get_execute_after_write_candidates(),
            source_label='execute_after_write',
        )
        self._scan_candidate_buffers(
            self.tracker.get_candidates(),
            source_label='overwrite_history',
        )

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

    def _scan_candidate_buffers(self, candidates, source_label):
        for candidate_addr, candidate_data in candidates:
            before_count = len(self.extractor.get_results())
            self.extractor.scan_buffer(candidate_addr, candidate_data)
            for result in self.extractor.get_results()[before_count:]:
                if result.get('source') == 'deferred_scan':
                    result['source'] = source_label

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
            behavior_tracer = getattr(self, 'behavior_tracer', None)
            if behavior_tracer is not None:
                behavior_tracer.ingest_speakeasy_report(report_json)

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

    def get_extracted_strings(self, clean=False, min_confidence=None):
        return self.extractor.get_results(
            clean=clean,
            min_confidence=min_confidence,
        )

    def get_behavior_report(self, strings=None):
        """Return best-effort behavior summary for the observed emulation path."""
        if strings is None:
            strings = self.get_extracted_strings()
        behavior_tracer = getattr(self, 'behavior_tracer', None)
        if behavior_tracer is None:
            behavior_tracer = BehaviorTracer()
        return behavior_tracer.build_report(
            strings=strings,
            stop_reason=self.execution_status,
        )
