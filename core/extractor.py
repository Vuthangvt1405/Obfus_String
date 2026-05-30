# -*- coding: utf-8 -*-
import string
import re
import logging

logger = logging.getLogger(__name__)

class StringExtractor:
    def __init__(self, min_length=4, max_results=0):
        """
        Purpose:
        Initialise the StringExtractor with configurable minimum string length,
        result-size cap, and printable-character set.

        How it works:
        Sets up the printable ASCII filter set, compiles heuristic regex patterns
        for IPs/URLs/domains/registry paths, and records an optional result cap
        (0 = unlimited).

        Parameters:
        - min_length: minimum character length for a string to be retained.
        - max_results: maximum number of unique results to store (0 = unlimited).

        Returns:
        void
        """
        self.min_length = min_length
        self.max_results = max_results
        self.valid_chars = set(string.printable.encode('ascii'))
        self.results = []
        
        # Một số Regex cơ bản để phát hiện chuỗi có ý nghĩa (IP, URL, Registry, Paths)
        self.patterns = [
            re.compile(br'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'),          # IPv4
            re.compile(br'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'), # URL
            re.compile(br'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),         # Domain
            re.compile(br'(?:HKLM|HKCU|Software|ControlSet|CurrentVersion)\\', re.IGNORECASE) # Registry
        ]

    def process_memory_write(self, address, data):
        """
        Phân tích mảng byte được đưa vào bộ nhớ. Nếu là chuỗi hợp lệ thì lưu lại.
        """
        if not data or len(data) < self.min_length:
            return

        # 1. Thử giải mã ASCII
        str_val = self._extract_ascii(data)
        if str_val:
            self._add_result(address, str_val, "ASCII", source='mem_write')
            return

        # 2. Thử giải mã Unicode (UTF-16 LE)
        # Nếu malware ghi wide string, byte rác 0x00 xen kẽ rất nhiều
        str_val = self._extract_unicode(data)
        if str_val:
            self._add_result(address, str_val, "UTF-16LE", source='mem_write')

    def process_api_string(self, api_name, str_val, source_detail=None):
        """
        Ghi nhận chuỗi lấy trực tiếp từ tham số API (rất sạch).

        Parameters:
        - source_detail: optional metadata describing the specific API hook
          family or variant (e.g. "WinHttpConnect", "InternetConnectA").
          Stored verbatim in the result entry for reporters.
        """
        if str_val and len(str_val) >= self.min_length:
             self._add_result(f"API_{api_name}", str_val, "API_ARG",
                              source='api_hook', source_detail=source_detail)

    def ingest_candidate(self, content, source, location=None, source_detail=None):
        """
        Purpose:
        Record a candidate string with explicit provenance, without tying it
        to a specific capture path (mem_write / api_hook / deferred_scan).

        How it works:
        Validates the string meets min_length, delegates to _add_result with
        encoding "CANDIDATE" and the given source/location/source_detail.
        Dedup and result-cap logic inside _add_result apply uniformly.

        Parameters:
        - content: the candidate string.
        - source: provenance tag (e.g. 'static_scan', 'overwrite_history',
          'register_scan').
        - location: optional source identifier (defaults to "candidate").
        - source_detail: optional metadata string for reporters.

        Returns:
        void
        """
        if not content or len(content) < self.min_length:
            return
        loc = location if location is not None else "candidate"
        self._add_result(loc, content, "CANDIDATE", source=source,
                         source_detail=source_detail)

    def _extract_ascii(self, data):
        # Lấy dải ký tự in được liên tiếp
        ascii_bytes = bytearray()
        for b in data:
            if b in self.valid_chars:
                ascii_bytes.append(b)
            elif b == 0:
                break # C-string kết thúc bằng null
            else:
                return None # Chứa byte rác không in được -> loại
                
        if len(ascii_bytes) >= self.min_length:
            return ascii_bytes.decode('ascii')
        return None

    def _extract_unicode(self, data):
        """
        Purpose:
        Decode a byte sequence as UTF-16LE and return the string if all
        characters are printable and the result meets min_length.

        How it works:
        Strips trailing null bytes, ensures even length for UTF-16LE,
        decodes, then filters out non-printable characters.

        Parameters:
        - data: raw bytes to attempt UTF-16LE decoding on.

        Returns:
        The decoded string if valid, or None.
        """
        try:
            # Strip trailing null bytes
            clean_data = data.rstrip(b'\x00')
            if not clean_data:
                return None
            # UTF-16LE requires even number of bytes
            if len(clean_data) % 2 != 0:
                clean_data = clean_data + b'\x00'
            decoded = clean_data.decode('utf-16-le')

            # Check all characters are printable
            if all(c in string.printable for c in decoded):
                if len(decoded) >= self.min_length:
                    return decoded
        except (UnicodeDecodeError, ValueError):
            pass
        return None

    def scan_buffer(self, base_address, data):
        """
        Purpose:
        Scan a larger memory buffer for all embedded printable ASCII and
        UTF-16LE substrings, even when surrounded by cipher noise.

        How it works:
        Walks the buffer byte-by-byte collecting runs of printable ASCII
        characters. Each run that meets min_length is emitted. After the
        ASCII pass, a second pass looks for UTF-16LE runs (printable byte
        followed by 0x00) of sufficient length.

        Parameters:
        - base_address: base virtual address of the buffer (for location labels).
        - data: raw bytes (may be large, noisy memory dump).

        Returns:
        None — results are appended to self.results via _add_result.
        """
        if not data:
            return

        # --- ASCII scan ---
        run_start = None
        run_bytes = bytearray()
        for i, b in enumerate(data):
            if b in self.valid_chars:
                if run_start is None:
                    run_start = i
                run_bytes.append(b)
            else:
                if len(run_bytes) >= self.min_length:
                    self._add_result(
                        base_address + run_start,
                        run_bytes.decode('ascii'),
                        "ASCII",
                        source='deferred_scan',
                    )
                run_start = None
                run_bytes = bytearray()
        # flush trailing run
        if len(run_bytes) >= self.min_length:
            self._add_result(
                base_address + run_start,
                run_bytes.decode('ascii'),
                "ASCII",
                source='deferred_scan',
            )

        # --- UTF-16LE scan ---
        i = 0
        length = len(data)
        while i < length - 1:
            char_byte = data[i]
            null_byte = data[i + 1]
            if char_byte in self.valid_chars and null_byte == 0x00:
                u16_start = i
                u16_chars = []
                while i < length - 1:
                    cb = data[i]
                    nb = data[i + 1]
                    if cb in self.valid_chars and nb == 0x00:
                        u16_chars.append(chr(cb))
                        i += 2
                    else:
                        break
                if len(u16_chars) >= self.min_length:
                    self._add_result(
                        base_address + u16_start,
                        ''.join(u16_chars),
                        "UTF-16LE",
                        source='deferred_scan',
                    )
            else:
                i += 1

    # Canonical noise strings: standard alphabets and Base64 charset
    _NOISE_STRINGS = frozenset({
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    })

    _SOURCE_PRIORITY = {
        "static_scan": 10,
        "deferred_scan": 20,
        "overwrite_history": 30,
        "mem_write": 40,
        "register_scan": 50,
        "api_hook": 60,
    }

    def _is_noise(self, content):
        """
        Purpose:
        Determine whether a decoded string is noise (repetitive padding,
        standard alphabets, or Base64 character-set constants).

        How it works:
        Returns True for single-unique-char repetition (e.g. '((((') or
        exact matches against known alphabet / Base64 constants.

        Parameters:
        - content: the decoded string to check.

        Returns:
        True if the string should be discarded as noise, False otherwise.
        """
        if len(set(content)) == 1:
            return True
        if content in self._NOISE_STRINGS:
            return True
        return False

    def _add_result(self, location, content, encoding, source=None,
                    source_detail=None):
        """
        Purpose:
        Record an extracted string result, deduplicating by content and
        elevating provenance when a higher-priority source re-submits
        the same content.

        How it works:
        Rejects noise via _is_noise(). On duplicate content, compares the
        configured provenance priority for the existing and new source; when
        the new source is higher confidence, it replaces the stored source
        and any provided source_detail. Same-priority duplicates can fill a missing
        source_detail. New unique results still get regex tags and optional
        provenance metadata.

        Parameters:
        - location: virtual address or API name where the string was found.
        - content: the decoded string value.
        - encoding: "ASCII", "UTF-16LE", or "API_ARG".
        - source: optional provenance tag (None = omitted from entry).
        - source_detail: optional metadata string describing the specific
          API hook or family (e.g. "WinHttpConnect"). Stores None = omitted.

        Returns:
        None — results are appended to self.results.
        """
        # Reject noise strings (padding, alphabets, base64 constants)
        if self._is_noise(content):
            return

        for res in self.results:
            if res['content'] == content:
                current_priority = self._SOURCE_PRIORITY.get(res.get('source'), 0)
                new_priority = (
                    self._SOURCE_PRIORITY.get(source, 0)
                    if source is not None
                    else 0
                )
                if new_priority > current_priority and source is not None:
                    res['source'] = source
                    if source_detail is not None:
                        res['source_detail'] = source_detail
                elif (
                    new_priority == current_priority
                    and source_detail is not None
                    and 'source_detail' not in res
                ):
                    res['source_detail'] = source_detail
                return

        # Respect result cap — only check when we would append a new entry
        if self.max_results > 0 and len(self.results) >= self.max_results:
            return

        # Đánh label nếu khớp regex
        tags = []
        try:
             content_bytes = content.encode('utf-8')
             for p in self.patterns:
                 if p.search(content_bytes):
                     tags.append("Matched_Regex")
                     break
        except:
             pass

        entry = {
            "location": str(location),
            "encoding": encoding,
            "content": content,
            "tags": tags
        }
        if source is not None:
            entry["source"] = source
        if source_detail is not None:
            entry["source_detail"] = source_detail
        self.results.append(entry)
        logger.debug(f"[Extractor] Đã bắt được chuỗi: '{content}' (Tại: {location})")

    def get_results(self):
        return self.results
