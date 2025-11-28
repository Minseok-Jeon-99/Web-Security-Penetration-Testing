"""
대상 서비스 API 에러 핸들링 및 민감정보 노출 테스트
- 에러 발생 시 스택트레이스 노출 여부
- 500 에러 메시지에 내부 정보 포함 여부
- 응답 헤더에 민감 정보 노출
- 디버그 모드 활성화 여부
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "https://www.example-target.com"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}

# 통계 정보 저장
test_statistics = {
    "total_tests": 0,
    "status_codes": {},
    "response_times": [],
    "unexpected_200": [],
    "errors": [],
    "warnings": []
}


def test_endpoint(method, url, payload=None, headers=HEADERS, test_name="", expected_status=None):
    """엔드포인트 테스트 및 상세 응답 분석"""
    print(f"\n{'='*70}")
    print(f"테스트: {test_name}")
    print(f"{'='*70}")

    test_statistics["total_tests"] += 1
    start_time = time.time()

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=15)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=payload, timeout=15)
        else:
            response = requests.request(method, url, headers=headers, json=payload, timeout=15)

        # 응답 시간 측정
        response_time = time.time() - start_time
        test_statistics["response_times"].append({
            "test": test_name,
            "time": response_time
        })

        # 상태 코드 통계
        status = response.status_code
        test_statistics["status_codes"][status] = test_statistics["status_codes"].get(status, 0) + 1

        print(f"상태 코드: {status}")
        print(f"응답 시간: {response_time:.3f}초")

        # 예상치 못한 200 응답 체크
        if expected_status and status != expected_status:
            if status == 200:
                warning = f"⚠️  예상치 못한 200 응답: {test_name}"
                print(warning)
                test_statistics["unexpected_200"].append(warning)

        # 비정상적으로 긴 응답 시간
        if response_time > 5.0:
            warning = f"⚠️  긴 응답 시간 ({response_time:.2f}초): {test_name}"
            print(warning)
            test_statistics["warnings"].append(warning)

        # 전체 응답 헤더 출력
        print(f"\n[응답 헤더]")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        # 응답 본문
        print(f"\n[응답 본문]")
        try:
            data = response.json()
            response_str = json.dumps(data, ensure_ascii=False, indent=2)
            print(response_str[:1500] if len(response_str) > 1500 else response_str)
        except:
            print(response.text[:1500] if len(response.text) > 1500 else response.text)

        # 민감 정보 패턴 검사
        check_sensitive_info(response)

        return response

    except Exception as e:
        error_msg = f"에러: {str(e)}"
        print(error_msg)
        test_statistics["errors"].append({
            "test": test_name,
            "error": str(e)
        })
        return None


def check_sensitive_info(response):
    """응답에서 민감 정보 패턴 검사"""
    text = response.text.lower()
    headers_str = str(response.headers).lower()
    
    sensitive_patterns = {
        # 스택트레이스/디버그 정보
        "traceback": "스택트레이스 노출",
        "stacktrace": "스택트레이스 노출",
        "exception": "예외 정보 노출",
        "error in": "상세 에러 노출",
        "line ": "코드 라인 정보 노출",
        "file \"": "파일 경로 노출",
        
        # 서버/프레임워크 정보
        "django": "Django 프레임워크 노출",
        "flask": "Flask 프레임워크 노출",
        "fastapi": "FastAPI 프레임워크 노출",
        "express": "Express 프레임워크 노출",
        "laravel": "Laravel 프레임워크 노출",
        "spring": "Spring 프레임워크 노출",
        
        # 데이터베이스 정보
        "mysql": "MySQL 정보 노출",
        "postgresql": "PostgreSQL 정보 노출",
        "mongodb": "MongoDB 정보 노출",
        "elasticsearch": "Elasticsearch 정보 노출",
        "redis": "Redis 정보 노출",
        "sql syntax": "SQL 구문 오류 노출",
        "query error": "쿼리 오류 노출",
        
        # 경로/환경 정보
        "/home/": "서버 경로 노출",
        "/var/": "서버 경로 노출",
        "/usr/": "서버 경로 노출",
        "/app/": "애플리케이션 경로 노출",
        "c:\\": "Windows 경로 노출",
        
        # 인증 정보
        "password": "비밀번호 관련 정보",
        "secret": "시크릿 키 관련 정보",
        "api_key": "API 키 관련 정보",
        "token": "토큰 관련 정보",
        
        # 내부 IP/호스트
        "127.0.0.1": "로컬 IP 노출",
        "localhost": "로컬호스트 노출",
        "192.168.": "내부 IP 노출",
        "10.0.": "내부 IP 노출",
        "172.16.": "내부 IP 노출",
    }
    
    found = []
    for pattern, description in sensitive_patterns.items():
        if pattern in text or pattern in headers_str:
            found.append(f"⚠️  {description}: '{pattern}' 발견")
    
    if found:
        print(f"\n[민감 정보 검사 결과]")
        for item in found:
            print(f"  {item}")
    else:
        print(f"\n[민감 정보 검사 결과]")
        print("  ✓ 민감 정보 패턴 미발견")


def run_error_tests():
    """에러 핸들링 테스트 실행"""
    
    # ============================================
    # 1. 잘못된 JSON 형식
    # ============================================
    print("\n" + "#"*70)
    print("# 1. 잘못된 JSON 형식 테스트")
    print("#"*70)
    
    # 깨진 JSON
    headers_text = {**HEADERS, "Content-Type": "application/json"}
    
    malformed_jsons = [
        ('{"query_string": "test"', "닫히지 않은 JSON"),
        ('{"query_string": }', "빈 값"),
        ('not json at all', "JSON이 아닌 텍스트"),
        ('null', "null 값"),
        ('[]', "빈 배열"),
        ('', "빈 문자열"),
    ]
    
    for payload, name in malformed_jsons:
        print(f"\n{'='*70}")
        print(f"테스트: {name}")
        print(f"{'='*70}")
        try:
            response = requests.post(
                f"{BASE_URL}/api_renewal/ko/expert_search",
                headers=headers_text,
                data=payload,
                timeout=15
            )
            print(f"상태 코드: {response.status_code}")
            print(f"응답: {response.text[:500]}")
            check_sensitive_info(response)
        except Exception as e:
            print(f"에러: {str(e)}")
    
    # ============================================
    # 2. 극단적인 입력값
    # ============================================
    print("\n" + "#"*70)
    print("# 2. 극단적인 입력값 테스트")
    print("#"*70)
    
    extreme_payloads = [
        # 매우 큰 페이지 번호 (이전에 500 에러 발생)
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "page": 999999, "size": 10}, "매우 큰 page"),
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "page": 2147483647, "size": 10}, "INT 최대값 page"),
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "page": 9999999999999, "size": 10}, "매우 큰 숫자 page"),
        
        # 매우 긴 문자열
        ({"query_string": "A" * 100000, "page": 1, "size": 10}, "10만자 query_string"),
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "search_type": "A" * 10000}, "1만자 search_type"),
        
        # 특수 값
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "page": float('inf')}, "무한대 값"),
        ({"query_string": "AD : ( 20250101 ~ 20250201 )", "page": None, "size": None}, "None 값들"),
        
        # 중첩 객체
        ({"query_string": {"nested": {"deep": {"very": "deep"}}}}, "중첩 객체"),
        
        # 유니코드 특수문자
        ({"query_string": "테스트\x00\x01\x02\x03"}, "제어 문자"),
        ({"query_string": "테스트" + "🎉" * 1000}, "이모지 1000개"),
    ]
    
    for payload, name in extreme_payloads:
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search", payload, HEADERS, name)
    
    # ============================================
    # 3. Content-Type 변조
    # ============================================
    print("\n" + "#"*70)
    print("# 3. Content-Type 변조 테스트")
    print("#"*70)
    
    content_types = [
        "text/plain",
        "text/html",
        "application/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/javascript",
        "",
        "invalid/type",
    ]
    
    payload = {"query_string": "AD : ( 20250101 ~ 20250201 )", "page": 1, "size": 10}
    
    for ct in content_types:
        headers = {**HEADERS, "Content-Type": ct} if ct else {k: v for k, v in HEADERS.items() if k != "Content-Type"}
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search", payload, headers, f"Content-Type: {ct or '없음'}")
    
    # ============================================
    # 4. HTTP 메서드별 에러 응답
    # ============================================
    print("\n" + "#"*70)
    print("# 4. HTTP 메서드별 에러 응답")
    print("#"*70)
    
    methods = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    
    for method in methods:
        test_endpoint(method, f"{BASE_URL}/api_renewal/ko/expert_search", None, HEADERS, f"{method} 메서드")
    
    # ============================================
    # 5. 존재하지 않는 엔드포인트
    # ============================================
    print("\n" + "#"*70)
    print("# 5. 존재하지 않는 엔드포인트")
    print("#"*70)
    
    not_found_endpoints = [
        "/api_renewal/ko/nonexistent",
        "/api_renewal/ko/admin",
        "/api/random/path/here",
        "/asdf",
        "/api_renewal/ko/" + "a" * 1000,
        "/api_renewal/ko/expert_search/../../etc/passwd",
    ]
    
    for endpoint in not_found_endpoints:
        test_endpoint("GET", f"{BASE_URL}{endpoint}", None, HEADERS, f"404 테스트: {endpoint[:50]}")
    
    # ============================================
    # 6. 인증 에러 응답 분석
    # ============================================
    print("\n" + "#"*70)
    print("# 6. 인증 에러 응답 상세 분석")
    print("#"*70)
    
    auth_endpoints = [
        "/api/admin",
        "/api/user/info",
        "/api/ko/expert_search",
    ]
    
    for endpoint in auth_endpoints:
        test_endpoint("GET", f"{BASE_URL}{endpoint}", None, HEADERS, f"인증 에러: {endpoint}")
    
    # ============================================
    # 7. 응답 헤더 보안 검사
    # ============================================
    print("\n" + "#"*70)
    print("# 7. 응답 헤더 보안 검사")
    print("#"*70)
    
    response = requests.get(f"{BASE_URL}/", headers=HEADERS, timeout=15)
    
    print(f"\n[전체 응답 헤더]")
    for key, value in response.headers.items():
        print(f"  {key}: {value}")
    
    # 보안 헤더 검사
    security_headers = {
        "X-Content-Type-Options": "MIME 스니핑 방지",
        "X-Frame-Options": "클릭재킹 방지",
        "X-XSS-Protection": "XSS 필터",
        "Strict-Transport-Security": "HTTPS 강제",
        "Content-Security-Policy": "CSP",
        "Referrer-Policy": "리퍼러 정책",
        "Permissions-Policy": "권한 정책",
    }
    
    print(f"\n[보안 헤더 검사]")
    for header, description in security_headers.items():
        if header in response.headers:
            print(f"  ✓ {header}: {response.headers[header]}")
        else:
            print(f"  ✗ {header} 누락 ({description})")
    
    # 불필요한 정보 노출 검사
    print(f"\n[불필요한 정보 노출 검사]")
    info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    for header in info_headers:
        if header in response.headers:
            print(f"  ⚠️  {header}: {response.headers[header]} (노출됨)")


def print_statistics():
    """테스트 통계 출력"""
    print("\n" + "="*70)
    print("테스트 통계 및 요약")
    print("="*70)

    print(f"\n총 테스트 수: {test_statistics['total_tests']}")

    print(f"\n[상태 코드 분포]")
    for code, count in sorted(test_statistics['status_codes'].items()):
        percentage = (count / test_statistics['total_tests']) * 100
        print(f"  {code}: {count}회 ({percentage:.1f}%)")

    if test_statistics['response_times']:
        times = [t['time'] for t in test_statistics['response_times']]
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        print(f"\n[응답 시간]")
        print(f"  평균: {avg_time:.3f}초")
        print(f"  최소: {min_time:.3f}초")
        print(f"  최대: {max_time:.3f}초")

        # 가장 느린 5개 테스트
        slowest = sorted(test_statistics['response_times'], key=lambda x: x['time'], reverse=True)[:5]
        print(f"\n[가장 느린 테스트 TOP 5]")
        for i, test in enumerate(slowest, 1):
            print(f"  {i}. {test['test']}: {test['time']:.3f}초")

    if test_statistics['unexpected_200']:
        print(f"\n[⚠️  예상치 못한 200 응답: {len(test_statistics['unexpected_200'])}건]")
        for warning in test_statistics['unexpected_200']:
            print(f"  {warning}")

    if test_statistics['warnings']:
        print(f"\n[⚠️  경고: {len(test_statistics['warnings'])}건]")
        for warning in test_statistics['warnings']:
            print(f"  {warning}")

    if test_statistics['errors']:
        print(f"\n[❌ 에러: {len(test_statistics['errors'])}건]")
        for error in test_statistics['errors']:
            print(f"  {error['test']}: {error['error']}")


if __name__ == "__main__":
    print("="*70)
    print("대상 서비스 API 에러 핸들링 및 민감정보 노출 테스트")
    print("="*70)

    run_error_tests()

    print("\n" + "="*70)
    print("테스트 완료!")
    print("="*70)

    # 통계 출력
    print_statistics()