"""
대상 서비스 API 입력값 검증 테스트
- 비정상적인 파라미터 입력 시 서버 반응 확인
- SQL Injection, XSS 등 공격 벡터 테스트
"""

import requests
import json
import sys
from datetime import datetime

URL = "https://www.example-target.com/api_renewal/ko/expert_search"

# 로그 파일 설정
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = open(f"logs/test02_input_validation_{timestamp}.log", "w", encoding="utf-8")

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

BASE_PAYLOAD = {
    "query_string": "AD : ( 20250101 ~ 20250201 )",
    "search_type": "general",
    "page": 1,
    "size": 200,
    "checkbox_registration_status_filter": ["출원", "공고", "등록", "소멸", "취하", "포기", "거절", "무효"],
    "checkbox_trademark_types_filter": ["문자", "도형", "문자+도형", "입체", "색채", "소리", "홀로그램", "기타"]
}


def test_request(test_name, payload):
    """테스트 요청 실행"""
    log_print(f"\n{'='*60}")
    log_print(f"테스트: {test_name}")
    log_print(f"{'='*60}")
    
    try:
        response = requests.post(URL, headers=HEADERS, json=payload, timeout=15)

        log_print(f"상태 코드: {response.status_code}")

        try:
            data = response.json()

            # 에러 메시지 확인
            if 'error' in data:
                log_print(f"에러 메시지: {data['error']}")
            if 'message' in data:
                log_print(f"메시지: {data['message']}")

            # 결과 수 확인
            if 'results' in data:
                log_print(f"결과 수: {len(data['results'])}")
            if 'pagination' in data:
                log_print(f"페이지네이션: {data['pagination']}")

            # 전체 응답 (처음 500자)
            response_str = json.dumps(data, ensure_ascii=False)
            if len(response_str) > 500:
                log_print(f"응답 미리보기: {response_str[:500]}...")
            else:
                log_print(f"응답: {response_str}")

        except json.JSONDecodeError:
            log_print(f"JSON 파싱 실패 - 응답: {response.text[:500]}")

    except requests.exceptions.Timeout:
        log_print("⚠️ 타임아웃 발생")
    except Exception as e:
        log_print(f"에러: {str(e)}")


def run_tests():
    """모든 입력값 검증 테스트 실행"""
    
    # ============================================
    # 1. page 파라미터 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 1. page 파라미터 테스트")
    log_print("#"*60)
    
    # 음수 페이지
    payload = BASE_PAYLOAD.copy()
    payload['page'] = -1
    test_request("page = -1 (음수)", payload)
    
    # 0 페이지
    payload = BASE_PAYLOAD.copy()
    payload['page'] = 0
    test_request("page = 0", payload)
    
    # 매우 큰 페이지
    payload = BASE_PAYLOAD.copy()
    payload['page'] = 999999
    test_request("page = 999999 (초과)", payload)
    
    # 문자열 페이지
    payload = BASE_PAYLOAD.copy()
    payload['page'] = "abc"
    test_request("page = 'abc' (문자열)", payload)
    
    # ============================================
    # 2. size 파라미터 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 2. size 파라미터 테스트")
    log_print("#"*60)
    
    # 음수 size
    payload = BASE_PAYLOAD.copy()
    payload['size'] = -1
    test_request("size = -1 (음수)", payload)
    
    # 0 size
    payload = BASE_PAYLOAD.copy()
    payload['size'] = 0
    test_request("size = 0", payload)
    
    # 매우 큰 size (서버 부하 테스트)
    payload = BASE_PAYLOAD.copy()
    payload['size'] = 10000
    test_request("size = 10000 (과도한 요청)", payload)
    
    # 더 큰 size
    payload = BASE_PAYLOAD.copy()
    payload['size'] = 100000
    test_request("size = 100000 (매우 과도함)", payload)
    
    # ============================================
    # 3. query_string SQL Injection 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 3. SQL Injection 테스트")
    log_print("#"*60)
    
    sql_payloads = [
        "AD : ( 20250101 ~ 20250201 ) OR 1=1",
        "AD : ( 20250101 ~ 20250201 ); DROP TABLE users;--",
        "AD : ( 20250101 ~ 20250201 ) UNION SELECT * FROM users--",
        "' OR '1'='1",
        "1; SELECT * FROM information_schema.tables--",
        "AD : ( 20250101 ~ 20250201 )' AND SLEEP(5)--",
    ]
    
    for sql in sql_payloads:
        payload = BASE_PAYLOAD.copy()
        payload['query_string'] = sql
        test_request(f"SQL: {sql[:50]}...", payload)
    
    # ============================================
    # 4. XSS 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 4. XSS 테스트")
    log_print("#"*60)
    
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "{{constructor.constructor('alert(1)')()}}",
    ]
    
    for xss in xss_payloads:
        payload = BASE_PAYLOAD.copy()
        payload['query_string'] = xss
        test_request(f"XSS: {xss[:40]}...", payload)
    
    # ============================================
    # 5. 타입 오류 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 5. 타입 오류 테스트")
    log_print("#"*60)
    
    # 배열 대신 문자열
    payload = BASE_PAYLOAD.copy()
    payload['checkbox_registration_status_filter'] = "출원"
    test_request("filter를 문자열로", payload)
    
    # 빈 배열
    payload = BASE_PAYLOAD.copy()
    payload['checkbox_registration_status_filter'] = []
    test_request("filter를 빈 배열로", payload)
    
    # null 값
    payload = BASE_PAYLOAD.copy()
    payload['query_string'] = None
    test_request("query_string = null", payload)
    
    # 필수 필드 누락
    payload = {"page": 1, "size": 10}
    test_request("최소 필드만 전송", payload)
    
    # ============================================
    # 6. 특수문자 및 인코딩 테스트
    # ============================================
    log_print("\n" + "#"*60)
    log_print("# 6. 특수문자 테스트")
    log_print("#"*60)
    
    special_chars = [
        "AD : ( 20250101 ~ 20250201 ) \x00\x00\x00",  # Null bytes
        "AD : ( 20250101 ~ 20250201 ) %00%00",  # URL encoded null
        "AD : ( 20250101 ~ 20250201 ) \n\r\n",  # CRLF
        "AD : ( 20250101 ~ 20250201 ) ../../../etc/passwd",  # Path traversal
        "A" * 10000,  # 매우 긴 문자열
    ]
    
    for char in special_chars:
        payload = BASE_PAYLOAD.copy()
        payload['query_string'] = char
        test_request(f"특수문자: {char[:30]}...", payload)


if __name__ == "__main__":
    try:
        log_print("="*60)
        log_print("대상 서비스 API 입력값 검증 테스트")
        log_print("="*60)
        run_tests()

        log_print("\n" + "="*60)
        log_print("테스트 완료!")
        log_print(f"로그 파일: logs/test02_input_validation_{timestamp}.log")
        log_print("="*60)

    finally:
        log_file.close()