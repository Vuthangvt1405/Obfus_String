# -*- coding: utf-8 -*-
import string
import re
import logging

logger = logging.getLogger(__name__)

class StringExtractor:
    def __init__(self, min_length=4):
        """
        Bộ lọc chuỗi (Heuristics)
        """
        self.min_length = min_length
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
            self._add_result(address, str_val, "ASCII")
            return

        # 2. Thử giải mã Unicode (UTF-16 LE)
        # Nếu malware ghi wide string, byte rác 0x00 xen kẽ rất nhiều
        str_val = self._extract_unicode(data)
        if str_val:
            self._add_result(address, str_val, "UTF-16LE")

    def process_api_string(self, api_name, str_val):
        """
        Ghi nhận chuỗi lấy trực tiếp từ tham số API (rất sạch).
        """
        if str_val and len(str_val) >= self.min_length:
             self._add_result(f"API_{api_name}", str_val, "API_ARG")

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
        # UTF-16LE đơn giản: char, 0x00, char, 0x00
        # Thử decode
        try:
            # Xóa các byte null dư thừa ở cuối
            clean_data = data.split(b'\x00\x00\x00')[0] + b'\x00\x00' 
            decoded = clean_data.decode('utf-16-le')
            
            # Kiểm tra xem có đều là ký tự in được không
            if all(c in string.printable for c in decoded):
                if len(decoded) >= self.min_length:
                    return decoded
        except:
             pass
        return None

    def _add_result(self, location, content, encoding):
        # Loại trùng lặp
        for res in self.results:
            if res['content'] == content:
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
        self.results.append(entry)
        logger.debug(f"[Extractor] Đã bắt được chuỗi: '{content}' (Tại: {location})")

    def get_results(self):
        return self.results
