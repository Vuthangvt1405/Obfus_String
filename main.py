#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import logging
from core.emulator import MalwareEmulator
from core.hash_layer import calculate_sample_identity
from core.vt_layer import lookup_virustotal, upload_file_to_virustotal
from utils.reporter import ReportGenerator

def parse_args(argv=None):
    """
    Purpose:
    Parse command-line arguments for the malware string decryption tool.

    How it works:
    Creates an ArgumentParser and registers all CLI flags. If *argv* is
    provided (e.g. during testing) it is forwarded to ``parse_args``;
    otherwise ``sys.argv[1:]`` is used.

    Parameters:
    - argv: Optional list of argument strings (for testing/contract checks).

    Returns:
    The parsed ``argparse.Namespace``.
    """
    parser = argparse.ArgumentParser(description="Tự động giải mã chuỗi mã độc bằng kỹ thuật Emulation (với Speakeasy).")
    parser.add_argument("-f", "--file", required=True, help="Đường dẫn đến file PE mã độc (.exe, .dll)")
    parser.add_argument("-a", "--arch", choices=["x86", "x64"], default="x86", help="Kiến trúc CPU (mặc định: x86)")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Thời gian giả lập tối đa (giây).")
    parser.add_argument("--max-instructions", type=int, help="Số lệnh tối đa trước khi dừng giả lập (ghi đè timeout nếu đạt trước).")
    parser.add_argument("-o", "--output", default="report.json", help="File xuất báo cáo JSON chứa các chuỗi đã giải mã.")
    parser.add_argument("--clean-output", action="store_true", help="Ẩn các chuỗi deferred_scan nhiễu khi đã có evidence tự tin hơn.")
    parser.add_argument("--min-confidence", type=int, help="Chỉ xuất chuỗi có confidence >= giá trị này.")
    parser.add_argument("-d", "--debug", action="store_true", help="Bật chế độ Debug để xem chi tiết PE load")
    parser.add_argument("--vt-lookup", action="store_true", help="Enrich report with VirusTotal by SHA256. Requires VIRUSTOTAL_API_KEY env var or .env.")
    parser.add_argument("--vt-upload", action="store_true", help="If VT hash lookup is not_found, upload the sample to VirusTotal for remote analysis. Analyst opt-in only.")
    parser.add_argument("--bypass-evasion", action="store_true", help="Apply emulator-only anti-analysis bypasses to reach guarded payload paths. Enabled by default; kept for compatibility.")
    parser.add_argument("--no-bypass-evasion", action="store_true", help="Disable emulator-only anti-analysis bypasses for baseline comparison.")
    return parser.parse_args(argv)

def main():
    """
    Purpose:
    Run the command-line malware string emulation workflow.

    How it works:
    Parses CLI options, configures logging, initializes MalwareEmulator with
    timeout and instruction limits, runs hooks/emulation, and saves a report.

    Parameters:
    None; arguments are read from ``sys.argv`` through ``parse_args``.

    Returns:
    None; exits the process with status 1 on fatal analysis failures.
    """
    args = parse_args()

    # Thiết lập Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s | %(levelname)-7s | %(message)s'
    )
    logger = logging.getLogger(__name__)

    logger.info(f"[*] Bắt đầu phân tích mẫu: {args.file}")

    try:
        max_instructions = args.max_instructions if args.max_instructions is not None else 5000000

        # 1. Khởi tạo Emulator
        emu = MalwareEmulator(
            arch=args.arch,
            timeout=args.timeout,
            max_instructions=max_instructions,
            debug=args.debug,
            bypass_evasion=not args.no_bypass_evasion,
        )

        # 2. Tải mẫu PE
        if not emu.load_sample(args.file):
            logger.error("[-] Quá trình nạp mẫu thất bại. Dừng chương trình.")
            sys.exit(1)

        # 3. Đăng ký Hooks (Can thiệp bộ nhớ & API)
        emu.register_hooks()

        # 4. Thực thi giả lập
        logger.info("[*] Đang thực thi môi trường giả lập (Emulation)...")
        emu.run()
        logger.info("[+] Giả lập hoàn tất hoặc đã đạt giới hạn an toàn.")

        # 5. Xuất báo cáo
        sample_identity = calculate_sample_identity(args.file)
        hashes = sample_identity.get("hashes", {})
        logger.info(f"[*] Sample SHA256: {hashes.get('sha256', 'n/a')}")
        if args.vt_lookup:
            logger.info("[*] Querying VirusTotal by SHA256...")
            sample_identity["virustotal"] = lookup_virustotal(hashes.get("sha256", ""))
            vt_status = sample_identity["virustotal"].get("status")
            logger.info(f"[*] VirusTotal status: {vt_status}")
            if args.vt_upload and vt_status == "not_found":
                logger.warning("[*] Uploading sample bytes to VirusTotal because --vt-upload was requested.")
                sample_identity["virustotal"]["upload"] = upload_file_to_virustotal(args.file)
                logger.info(f"[*] VirusTotal upload status: {sample_identity['virustotal']['upload'].get('status')}")
        extracted_strings = emu.get_extracted_strings(
            clean=args.clean_output,
            min_confidence=args.min_confidence,
        )
        behavior_report = emu.get_behavior_report(strings=extracted_strings)
        has_behavior_events = bool(behavior_report.get("events"))
        if has_behavior_events:
            logger.info(f"[*] Behavior verdict: {behavior_report.get('verdict')} | risk={behavior_report.get('risk_score')}")
            for item in behavior_report.get("summary", [])[:5]:
                logger.info(f"    - {item}")
        if extracted_strings or has_behavior_events:
            reporter = ReportGenerator(args.output)
            metadata = {"stop_reason": emu.execution_status} if emu.execution_status else None
            reporter.save(
                extracted_strings,
                metadata=metadata,
                behavior=behavior_report,
                sample=sample_identity,
                allow_empty=has_behavior_events,
            )
            event_count = len(behavior_report.get('events', []))
            logger.info(
                f"[+] Báo cáo {len(extracted_strings)} chuỗi và {event_count} "
                f"behavior events đã được lưu tại: {args.output}"
            )
        else:
            logger.warning("[-] Không tìm thấy chuỗi hoặc behavior event hợp lệ nào.")

    except Exception as e:
        logger.critical(f"[!] Lỗi nghiêm trọng: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
