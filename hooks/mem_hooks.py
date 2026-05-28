# -*- coding: utf-8 -*-
import logging

logger = logging.getLogger(__name__)

class WriteTracker:
    """
    Theo dõi các vùng bộ nhớ bị ghi (dirty ranges) để xử lý sau thay vì 
    làm giảm hiệu năng khi gọi extractor trên từng byte.
    """
    def __init__(self):
        self.regions = []
        
    def add_write(self, address, size):
        start = address
        end = address + size
        
        # Duyệt ngược để merge (coalesce) với các khoảng gần đây nhất.
        # Giới hạn tìm kiếm O(1) (tối đa 10 vùng) để giữ performance cực cao.
        for i in range(len(self.regions) - 1, max(-1, len(self.regions) - 11), -1):
            r_start, r_end = self.regions[i]
            # Kiểm tra giao nhau hoặc liền kề
            if start <= r_end and end >= r_start:
                self.regions[i][0] = min(r_start, start)
                self.regions[i][1] = max(r_end, end)
                return
                
        # Nếu không merge được với các khoảng gần đây, thêm mới
        self.regions.append([start, end])
        
    def get_regions(self):
        return [(r[0], r[1]) for r in self.regions]


def setup_memory_hooks(se, extractor, tracker=None):
    """
    Đăng ký callback chặn các lệnh (mov, stos...) ghi vào bộ nhớ.
    Sử dụng Speakeasy v2 API: se.add_mem_write_hook(cb, begin, end)
    """

    def hook_mem_write(emu, access, address, size, value):
        if tracker:
            tracker.add_write(address, size)

    try:
        se.add_mem_write_hook(hook_mem_write)
        logger.info("[Hook] Đã cắm Memory Write hook qua Speakeasy API (Lightweight Tracking).")
    except Exception as e:
        logger.error(f"[Hook] Lỗi móc bộ nhớ: {e}")
