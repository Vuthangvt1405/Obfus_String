# -*- coding: utf-8 -*-
import logging

logger = logging.getLogger(__name__)

def setup_api_hooks(se, extractor):
    """
    Theo dõi thao tác strings trực tiếp qua API thay vì quét memory.
    Sử dụng Speakeasy v2 API: se.add_api_hook(cb, module, api_name, argc)
    """

    def my_lstrcpyA(emu, api_name, func, argv):
        if len(argv) >= 2:
            src_ptr = argv[1]
            try:
                string_val = emu.read_mem_string(src_ptr, width=1)
                extractor.process_api_string('lstrcpyA', string_val)
            except Exception:
                pass

    def my_lstrcpyW(emu, api_name, func, argv):
        if len(argv) >= 2:
            src_ptr = argv[1]
            try:
                string_val = emu.read_mem_string(src_ptr, width=2)
                extractor.process_api_string('lstrcpyW', string_val)
            except Exception:
                pass

    def my_VirtualAlloc(emu, api_name, func, argv):
        if len(argv) >= 4:
            dwSize = argv[1]
            flProtect = argv[3]
            logger.debug(f"[Hook] VirtualAlloc(Size={hex(dwSize)}, Protect={hex(flProtect)})")

    try:
        se.add_api_hook(my_lstrcpyA, 'kernel32', 'lstrcpyA')
        se.add_api_hook(my_lstrcpyW, 'kernel32', 'lstrcpyW')
        se.add_api_hook(my_VirtualAlloc, 'kernel32', 'VirtualAlloc')
        logger.info("[Hook] Đã cài đặt API hooks (lstrcpyA/W, VirtualAlloc).")
    except Exception as e:
        logger.warning(f"[Hook] Không thể cài đặt một số API hooks: {e}")
