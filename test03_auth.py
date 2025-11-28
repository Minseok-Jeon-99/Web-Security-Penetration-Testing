"""
대상 서비스 API 인증/인가 테스트
- 인증 없이 API 접근 가능 여부
- 권한 우회 가능성
- 숨겨진 엔드포인트 탐색
"""

import requests
import json

BASE_URL = "https://www.example-target.com"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}

HEADERS_NO_REFERER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json"
}


def test_endpoint(method, url, payload=None, headers=HEADERS, test_name=""):
    """엔드포인트 테스트"""
    print(f"\n{'='*70}")
    print(f"테스트: {test_name}")
    print(f"요청: {method} {url}")
    print(f"{'='*70}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=payload, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=payload, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=payload, timeout=10)
        elif method == "OPTIONS":
            response = requests.options(url, headers=headers, timeout=10)
        else:
            print(f"지원하지 않는 메서드: {method}")
            return None
        
        print(f"상태 코드: {response.status_code}")
        print(f"응답 헤더:")
        for key in ['Server', 'X-Powered-By', 'Access-Control-Allow-Origin', 'Set-Cookie']:
            if key in response.headers:
                print(f"  {key}: {response.headers[key]}")
        
        # 응답 내용
        try:
            data = response.json()
            response_str = json.dumps(data, ensure_ascii=False)
            if len(response_str) > 500:
                print(f"응답: {response_str[:500]}...")
            else:
                print(f"응답: {response_str}")
        except:
            if len(response.text) > 500:
                print(f"응답: {response.text[:500]}...")
            else:
                print(f"응답: {response.text}")
        
        return response
        
    except requests.exceptions.Timeout:
        print("⚠️ 타임아웃")
        return None
    except Exception as e:
        print(f"에러: {str(e)}")
        return None


def run_auth_tests():
    """인증/인가 테스트 실행"""
    
    search_payload = {
        "query_string": "AD : ( 20250101 ~ 20250201 )",
        "search_type": "general",
        "page": 1,
        "size": 10,
        "checkbox_registration_status_filter": ["출원"],
        "checkbox_trademark_types_filter": ["문자"]
    }
    
    # ============================================
    # 1. 인증 없이 API 접근
    # ============================================
    print("\n" + "#"*70)
    print("# 1. 인증 없이 API 접근 테스트")
    print("#"*70)
    
    # 기본 검색 API (인증 없이)
    test_endpoint(
        "POST",
        f"{BASE_URL}/api_renewal/ko/expert_search",
        search_payload,
        HEADERS,
        "검색 API - 인증 없이 접근"
    )
    
    # Referer 없이
    test_endpoint(
        "POST",
        f"{BASE_URL}/api_renewal/ko/expert_search",
        search_payload,
        HEADERS_NO_REFERER,
        "검색 API - Referer 헤더 없이"
    )
    
    # 빈 헤더로
    test_endpoint(
        "POST",
        f"{BASE_URL}/api_renewal/ko/expert_search",
        search_payload,
        {"Content-Type": "application/json"},
        "검색 API - 최소 헤더만"
    )
    
    # ============================================
    # 2. HTTP 메서드 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 2. HTTP 메서드 테스트")
    print("#"*70)
    
    methods = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"]
    for method in methods:
        test_endpoint(
            method,
            f"{BASE_URL}/api_renewal/ko/expert_search",
            search_payload if method in ["PUT", "PATCH"] else None,
            HEADERS,
            f"검색 API - {method} 메서드"
        )
    
    # ============================================
    # 3. 다른 국가 엔드포인트 탐색
    # ============================================
    print("\n" + "#"*70)
    print("# 3. 다른 국가/언어 엔드포인트 탐색")
    print("#"*70)
    
    country_endpoints = [
        "/api_renewal/en/expert_search",
        "/api_renewal/jp/expert_search",
        "/api_renewal/cn/expert_search",
        "/api_renewal/us/expert_search",
        "/api_renewal/eu/expert_search",
        "/api/ko/expert_search",
        "/api/expert_search",
    ]
    
    for endpoint in country_endpoints:
        test_endpoint(
            "POST",
            f"{BASE_URL}{endpoint}",
            search_payload,
            HEADERS,
            f"엔드포인트: {endpoint}"
        )
    
    # ============================================
    # 4. 관리자/내부 API 탐색
    # ============================================
    print("\n" + "#"*70)
    print("# 4. 관리자/내부 API 탐색")
    print("#"*70)
    
    admin_endpoints = [
        "/api/admin",
        "/api/admin/users",
        "/api/users",
        "/api/user/info",
        "/api_renewal/admin",
        "/api_renewal/ko/admin",
        "/admin",
        "/admin/api",
        "/api/config",
        "/api/settings",
        "/api/debug",
        "/api/test",
        "/api/internal",
        "/api/private",
        "/swagger",
        "/swagger-ui",
        "/api-docs",
        "/docs",
        "/redoc",
        "/graphql",
        "/graphiql",
    ]
    
    for endpoint in admin_endpoints:
        test_endpoint(
            "GET",
            f"{BASE_URL}{endpoint}",
            None,
            HEADERS,
            f"관리자 엔드포인트: {endpoint}"
        )
    
    # ============================================
    # 5. 사용자 정보 관련 API
    # ============================================
    print("\n" + "#"*70)
    print("# 5. 사용자 정보 관련 API")
    print("#"*70)
    
    user_endpoints = [
        "/api/me",
        "/api/profile",
        "/api/user/profile",
        "/api/account",
        "/api_renewal/ko/user",
        "/api_renewal/ko/user/info",
        "/api_renewal/ko/mypage",
        "/api_renewal/ko/bookmark",
        "/api_renewal/ko/history",
    ]
    
    for endpoint in user_endpoints:
        test_endpoint(
            "GET",
            f"{BASE_URL}{endpoint}",
            None,
            HEADERS,
            f"사용자 API: {endpoint}"
        )
    
    # ============================================
    # 6. CORS 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 6. CORS 설정 테스트")
    print("#"*70)
    
    cors_headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json",
        "Origin": "https://evil-site.com"
    }
    
    test_endpoint(
        "OPTIONS",
        f"{BASE_URL}/api_renewal/ko/expert_search",
        None,
        cors_headers,
        "CORS - 악의적 Origin으로 preflight"
    )
    
    test_endpoint(
        "POST",
        f"{BASE_URL}/api_renewal/ko/expert_search",
        search_payload,
        cors_headers,
        "CORS - 악의적 Origin으로 실제 요청"
    )
    
    # ============================================
    # 7. 인증 우회 시도
    # ============================================
    print("\n" + "#"*70)
    print("# 7. 인증 우회 시도")
    print("#"*70)
    
    # 가짜 인증 토큰
    auth_bypass_headers = [
        {"Authorization": "Bearer admin"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
        {"X-Auth-Token": "admin"},
        {"X-API-Key": "admin"},
        {"Cookie": "session=admin; role=admin"},
    ]
    
    for extra_header in auth_bypass_headers:
        headers = {**HEADERS, **extra_header}
        header_name = list(extra_header.keys())[0]
        test_endpoint(
            "POST",
            f"{BASE_URL}/api_renewal/ko/expert_search",
            search_payload,
            headers,
            f"인증 우회 시도: {header_name}"
        )


if __name__ == "__main__":
    print("="*70)
    print("대상 서비스 API 인증/인가 테스트")
    print("="*70)
    
    run_auth_tests()
    
    print("\n" + "="*70)
    print("테스트 완료!")
    print("="*70)