"""
대상 서비스 API Rate Limiting 테스트
- 짧은 시간 내 다량 요청 시 차단 여부 확인
"""

import requests
import time
import sys
from datetime import datetime

URL = "https://www.example-target.com/api_renewal/ko/expert_search"

# 로그 파일 설정
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = open(f"logs/test01_rate_limit_{timestamp}.log", "w", encoding="utf-8")

def log_print(message):
    """콘솔과 파일에 동시 출력"""
    print(message)
    log_file.write(message + "\n")
    log_file.flush()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}

PAYLOAD = {
    "query_string": "AD : ( 20250101 ~ 20250201 )",
    "search_type": "general",
    "page": 1,
    "size": 200,
    "checkbox_registration_status_filter": ["출원", "공고", "등록", "소멸", "취하", "포기", "거절", "무효"],
    "checkbox_trademark_types_filter": ["문자", "도형", "문자+도형", "입체", "색채", "소리", "홀로그램", "기타"]
}


def test_rate_limit(num_requests=50, delay=0):
    """
    Rate Limiting 테스트
    - num_requests: 총 요청 횟수
    - delay: 요청 간 대기시간 (0이면 연속 요청)
    """
    log_print(f"=== Rate Limiting 테스트 ===")
    log_print(f"요청 횟수: {num_requests}, 딜레이: {delay}초")
    log_print(f"시작 시간: {datetime.now().strftime('%H:%M:%S')}\n")
    
    results = {
        'success': 0,
        'failed': 0,
        'status_codes': {},
        'response_times': []
    }
    
    for i in range(num_requests):
        start_time = time.time()
        
        try:
            response = requests.post(URL, headers=HEADERS, json=PAYLOAD, timeout=10)
            elapsed = round(time.time() - start_time, 3)
            status = response.status_code
            
            results['response_times'].append(elapsed)
            results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
            
            if status == 200:
                results['success'] += 1
                log_print(f"[{i+1:3d}] ✓ 200 OK ({elapsed}s)")
            else:
                results['failed'] += 1
                log_print(f"[{i+1:3d}] ✗ {status} ({elapsed}s) - {response.text[:100]}")

        except requests.exceptions.Timeout:
            results['failed'] += 1
            log_print(f"[{i+1:3d}] ✗ TIMEOUT")

        except Exception as e:
            results['failed'] += 1
            log_print(f"[{i+1:3d}] ✗ ERROR: {str(e)[:50]}")
        
        if delay > 0:
            time.sleep(delay)
    
    # 결과 요약
    log_print(f"\n{'='*50}")
    log_print(f"=== 테스트 결과 ===")
    log_print(f"성공: {results['success']}/{num_requests}")
    log_print(f"실패: {results['failed']}/{num_requests}")
    log_print(f"상태 코드 분포: {results['status_codes']}")

    if results['response_times']:
        avg_time = sum(results['response_times']) / len(results['response_times'])
        max_time = max(results['response_times'])
        min_time = min(results['response_times'])
        log_print(f"응답 시간 - 평균: {avg_time:.3f}s, 최소: {min_time:.3f}s, 최대: {max_time:.3f}s")

    # 취약점 판단
    log_print(f"\n=== 판단 ===")
    if results['failed'] == 0:
        log_print("⚠️  Rate Limiting 없음 - 모든 요청 성공")
        log_print("   → 무제한 요청 가능, DDoS 공격에 취약할 수 있음")
    elif 429 in results['status_codes']:
        log_print("✓ Rate Limiting 적용됨 (429 Too Many Requests)")
    else:
        log_print(f"△ 일부 요청 실패 - 원인 분석 필요")
    
    return results


if __name__ == "__main__":
    try:
        # 테스트 1: 딜레이 없이 연속 50회 요청
        log_print("\n" + "="*60)
        log_print("테스트 1: 딜레이 없이 연속 50회 요청")
        log_print("="*60 + "\n")
        test_rate_limit(num_requests=50, delay=0)

        time.sleep(3)

        # 테스트 2: 딜레이 없이 연속 100회 요청
        log_print("\n" + "="*60)
        log_print("테스트 2: 딜레이 없이 연속 100회 요청")
        log_print("="*60 + "\n")
        test_rate_limit(num_requests=100, delay=0)

        log_print(f"\n로그 파일: logs/test01_rate_limit_{timestamp}.log")

    finally:
        log_file.close()