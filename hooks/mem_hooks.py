# -*- coding: utf-8 -*-
import logging

logger = logging.getLogger(__name__)

def setup_memory_hooks(se, extractor):
    """
    Đăng ký callback chặn các lệnh (mov, stos...) ghi vào bộ nhớ.
    Sử dụng Speakeasy v2 API: se.add_mem_write_hook(cb, begin, end)
    """

    def hook_mem_write(emu, access, address, size, value):
        try:
            data_bytes = value.to_bytes(size, byteorder='little')
            try:
                target_data = se.mem_read(address, 64)
                extractor.process_memory_write(hex(address), target_data)
            except Exception:
                extractor.process_memory_write(hex(address), data_bytes)
        except OverflowError:
            pass

    try:
        se.add_mem_write_hook(hook_mem_write)
        logger.info("[Hook] Đã cắm Memory Write hook qua Speakeasy API.")
    except Exception as e:
        logger.error(f"[Hook] Lỗi móc bộ nhớ: {e}")
