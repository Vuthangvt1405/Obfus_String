# -*- coding: utf-8 -*-
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path

    def save(self, data_list, metadata=None):
        """
        Lưu danh sách chuỗi trích xuất được ra file JSON.

        Parameters:
        - data_list: list of string entry dicts to save.
        - metadata: optional dict injected under the "execution_constraints"
          key at the report root. Pass None (default) to omit the key.

        Returns:
        None
        """
        if not data_list:
            logger.warning("[Reporter] Không có dữ liệu để kết xuất.")
            return

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_strings": len(data_list),
            "strings": data_list
        }

        if metadata is not None:
            report["execution_constraints"] = metadata

        try:
            # Đảm bảo thư mục đích tồn tại
            os.makedirs(os.path.dirname(os.path.abspath(self.output_path)), exist_ok=True)
            
            with open(self.output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
                
            logger.info(f"[Reporter] Đã ghi thành công báo cáo JSON tại {self.output_path}")
        except Exception as e:
            logger.error(f"[Reporter] Lỗi khi ghi báo cáo: {e}")
