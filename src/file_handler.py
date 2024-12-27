import os
import json
from typing import Dict, Generator
import hashlib
from pathlib import Path
from datetime import datetime
import win32api


MAX_FILE_SIZE = 650 * 1024 * 1024
SKIP_EXTENSIONS = {".sys", ".dll", ".tmp"}
HISTORY_FILE = Path('data/scan_history.json')



def collect_files(directory: str) -> Generator[str, None, None]:
    """
    지정된 디렉토리에서 바이러스 검사할 파일들을 수집.
    
    이 함수는 제너레이터로 구현되어 메모리를 효율적으로 사용.
    대용량 디렉토리를 처리할 때도 모든 파일 목록을 한 번에 메모리에 
    로드하지 않고, 필요할 때마다 한 파일씩 반환.
    
    처리 과정:
    1. 디렉토리를 재귀적으로 순회
    2. 각 파일에 대해:
       - 파일 크기 검사
       - 시스템/숨김 파일 여부 검사
       - 이전 검사 이력 확인
    
    Args:
        directory: 검사할 디렉토리 경로
        
    Yields:
        str: 검사 대상 파일의 절대 경로
        
    Example:
        for file_path in collect_files("/path/to/directory"):
            scan_file(file_path)
    """
    try:
        # 디렉토리 경로를 절대 경로로 변환
        base_dir = Path(directory).resolve()
        
        # 디렉토리가 존재하지 않으면 종료
        if not base_dir.exists() or not base_dir.is_dir():
            return
            
        # 디렉토리 순회
        for root, _, files in os.walk(base_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                # 각종 검사 수행
                if should_skip_file(file_path):
                    continue
                    
                if not is_file_size_valid(file_path):
                    continue
                    
                if is_already_scanned(file_path):
                    continue
                    
                # 모든 검사를 통과한 파일만 반환
                yield file_path
                
    except Exception as e:
        # 오류가 발생해도 진행 가능한 파일들은 계속 처리
        print(f"Error while collecting files: {e}")    


def is_file_size_valid(file_path: str) -> bool:
    try:
        return os.path.getsize(file_path) <= MAX_FILE_SIZE
    except OSError:
        return False


def should_skip_file(file_path: str) -> bool:
    try:
        # 파일이 존재하는지 확인
        if not os.path.exists(file_path):
            return True
        
        # 파일 확장자 확인
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in SKIP_EXTENSIONS:
            return True

        # 파일 속성 확인
        try:
            attrs = win32api.GetFileAttributes(file_path)
            if attrs & (2 | 4): # 숨김 또는 시스템 파일
                return True
        except win32api.error:
            return True
        
        # 파일 읽기 권한 확인
        if not os.access(file_path, os.R_OK):
            return True

        return False # 모든 검사를 통과하면 검사 대상
    
    except Exception as e:
        return True # 안전을 위해 문제가 있는 파일은 건너뜀


def is_already_scanned(file_path):
    try:
        # 검사 이력 파일이 없으면 생성
        if not HISTORY_FILE.exists():
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            return False
        
        # 현재 파일 정보 수집
        file_hash = get_file_hash(file_path)
        mod_time = os.path.getmtime(file_path)

        # 검사 이력 로드
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)

        # 파일 검사 여부 확인
        if file_hash in history:
            # 해시는 같지만 수정 시간이 다르면 재검사 필요
            return history[file_hash]['mod_time'] == mod_time
    
        return False
    
    except Exception as e:
        # 이력 확인 중 오류 발생 시 재검사하도록 False 반환
        return False
    

def get_file_hash(file_path: str) -> str:
    
    # 파일의 SHA-256 해시값 계산
    # 대용량 파일을 고려하여 청크 단위로 읽음 
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def update_scan_history(file_path: str) -> None:

    # 검사한 파일의 정보를 이력에 추가

    try:
        # 현재 파일 정보 수집
        file_hash = get_file_hash(file_path)
        mod_time = os.path.getmtime(file_path)

        # 기존 이력 로드 또는 새로 생성
        history: Dict = {}
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)

        # 새로운 검사 정보 추가
        history[file_hash] = {
            'file_path': file_path,
            'mod_time': mod_time,
            'scan_time': datetime.now().isoformat()
        }
        
        # 이력 저장
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
            
    except Exception as e:
        # 이력 업데이트 실패는 프로그램 실행에 치명적이지 않으므로 계속 진행
        pass