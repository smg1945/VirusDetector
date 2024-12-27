import requests
import os
import time
from tqdm import tqdm
from typing import List, Dict

from src.file_handler import collect_files, update_scan_history
from src.logger import logger


API_KEY = os.getenv("API_KEY")

URL = "https://www.virustotal.com/api/v3/files"

headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
}

RATE_LIMIT_PER_MINUTE = 4
WAIT_TIME = 60 / RATE_LIMIT_PER_MINUTE


def main():
    scan_dir = input("Enter directory path to scan: ").strip()
    logger.info("Starting virus scan in directory: %s", scan_dir)

    # 스캔 매니저 초기화
    manager = ScanManager()

    try:
        # 검사할 파일 수집
        files_to_scan = list(collect_files(scan_dir))
        if not files_to_scan:
            logger.warning("No files found to scan!")
            return
    
        logger.info("Found %d files to scan", len(files_to_scan))

        # 진행 상황 표시와 함께 파일 스캔
        with tqdm(total=len(files_to_scan), desc="Scanning files") as pbar:
            for file_path in files_to_scan:
                try:
                    logger.debug("Scanning file: %s", file_path)
                    # 파일 제출
                    scan_response = submit_file_for_scan(file_path)
                    analysis_id = scan_response["data"]["id"]
                    # API 제한 관리
                    time.sleep(WAIT_TIME)
                    # 결과 조회
                    result = get_scan_results(analysis_id)
                    # 결과 처리
                    manager.process_scan_result(file_path, result)
                    # 검사 이력 업데이트
                    update_scan_history(file_path)
                
                except Exception as e:
                    logger.error("Error scanning %s: %s", file_path, str(e))
                    continue
                finally:
                    pbar.update(1)
        
        manager.print_summary()
        logger.info("Scan completed successfully")
    
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
    except Exception as e:
        logger.error("An error occurred: %s", str(e), exc_info=True)
    finally:
        logger.info("Scan process finished")


if __name__ == "__main__":
    main()


def submit_file_for_scan(file_path: str) -> Dict:
    # 파일을 API에 제출하여 스캔을 요청
    try:
        files = {"file": open(file_path, "rb")}
        response = requests.post(
            f"{URL}/files",
            headers=headers,
            files=files
        )
        response.raise_for_status()
        return response.json()
    finally:
        files["file"].close()


def get_scan_results(analysis_id: str) -> Dict:
    # 분석 ID로 스캔 결과를 조회
    response = requests.get(
        f"{URL}/analyses/{analysis_id}",
        headers=headers
    )
    response.raise_for_status()
    return response.json()


class ScanManager:
    
    def __init__(self):
        self.results: Dict[str, Dict] = {}
        self.suspicious_files: List[str] = []
    
    def process_scan_result(self, file_path: str, result: Dict) -> None:
        # 스캔 결과 처리 후 의심스러운 파일 기록
        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            self.suspicious_files.append(
                f"{file_path}: {stats.get("malicious", 0)} malicious, "
                f"{stats.get("suspicious", 0)} suspicious detections"
            )
        self.results[file_path] = result
    
    def print_summary(self) -> None:
        # 스캔 결과 요약 출력
        print("\n=== Scan Summary ===")
        print(f"Total files scanned: {len(self.results)}")
        print(f"Suspicious files found: {len(self.suspicious_files)}")
        if self.suspicious_files:
            print("\nSuspicious Files:")
            for file in self.suspicious_files:
                print(file)