# 대상 서비스 API 보안 테스트 스위트

대상 서비스(TargetApp) API에 대한 종합 보안 침투 테스트 도구 모음입니다.

## 📋 테스트 목록

### ✅ test01_rate_limit.py
**Rate Limiting 테스트**
- 짧은 시간 내 대량 요청 시 차단 여부 확인
- DDoS 공격 취약점 검증
- 연속 50회, 100회 요청 테스트

**실행 방법:**
```bash
python3 test01_rate_limit.py
```

---

### ✅ test02_input_validation.py
**입력값 검증 테스트**
- page, size 파라미터 경계값 테스트
- 기본 SQL Injection 패턴
- 기본 XSS 패턴
- 타입 오류 및 특수문자 처리

**실행 방법:**
```bash
python3 test02_input_validation.py
```

---

### ✅ test02_xss_deep.py
**XSS 심층 테스트**
- 70+ 개의 XSS 공격 벡터
  - 기본 XSS (script, img, svg 태그)
  - 이스케이프 우회 (대소문자 혼합, 중첩 태그, 인코딩)
  - 이벤트 핸들러 기반 XSS
  - DOM 기반 XSS (템플릿 인젝션)
  - Unicode/인코딩 우회
- 응답 내 이스케이프 검증
- 프론트엔드 XSS 취약점 가이드 제공

**실행 방법:**
```bash
python3 test02_xss_deep.py
```

---

### ✅ test03_auth.py
**인증/인가 기본 테스트**
- 기본 인증 우회 시도
- 토큰 없이 API 접근
- 권한 확인

**실행 방법:**
```bash
python3 test03_auth.py
```

---

### ✅ test03_auth_deep.py
**인증/인가 심층 테스트**
1. **API 버전/경로 우회** - v1, v2, 대소문자 변형, 인코딩 우회
2. **숨겨진 파라미터 탐색** - debug, admin, bypass_auth 등 25+ 파라미터
3. **JWT 조작** - 알고리즘 none 공격, 빈 시그니처
4. **쿠키 조작** - session, auth_token 등
5. **HTTP 헤더 인젝션** - X-Forwarded-For, X-Real-IP 등 18+ 헤더
6. **IDOR 테스트** - ID 기반 직접 접근
7. **HTTP Parameter Pollution** - 배열 형태 중복 값
8. **내부 서비스 탐색** - Elasticsearch, actuator, health 등
9. **민감 파일 접근** - .env, .git, config 파일

**실행 방법:**
```bash
python3 test03_auth_deep.py
```

---

### ✅ test04_error_handling.py
**에러 핸들링 및 민감정보 노출 테스트**
1. **잘못된 JSON 형식** - 닫히지 않은 JSON, 빈 값, null
2. **극단적 입력값** - INT 최대값, 10만자 문자열, 제어 문자
3. **Content-Type 변조** - text/plain, application/xml 등
4. **HTTP 메서드별 에러** - GET, PUT, DELETE, TRACE 등
5. **존재하지 않는 엔드포인트** - 404 테스트, Path traversal
6. **인증 에러 분석** - 401 응답 상세 분석
7. **보안 헤더 검사** - HSTS, CSP, X-Frame-Options 등

**개선 사항:**
- ✅ 응답 시간 측정 (DoS 취약점 확인)
- ✅ 상태 코드별 통계
- ✅ 예상치 못한 200 응답 자동 플래그
- ✅ 가장 느린 테스트 TOP 5

**실행 방법:**
```bash
python3 test04_error_handling.py
```

---

### 🆕 test05_injection.py
**Injection 공격 종합 테스트**

#### 1. SQL Injection (30+ 패턴)
- 기본 OR 구문, UNION SELECT
- Boolean/Time-based Blind SQL Injection
- Stacked Queries
- 에러 기반 SQL Injection
- 이스케이프 우회 (URL 인코딩, 백슬래시)

#### 2. NoSQL Injection (Elasticsearch)
- match_all 쿼리
- bool must 쿼리
- JSON 구조 탈출
- 정규식 인젝션
- Script 인젝션 (Groovy/Painless)
- MongoDB 스타일 연산자 ($gt, $ne, $where)

#### 3. Path Traversal
- Unix/Windows 경로 (../../../etc/passwd)
- URL 인코딩, 이중 인코딩
- Null byte 우회
- 설정 파일 접근 (.env, config.json)

#### 4. Command Injection
- Unix 커맨드 (ls, cat, id, whoami)
- Windows 커맨드 (dir, type)
- 시간 지연 (Blind 검증)
- 다중 커맨드 체이닝

#### 5. LDAP Injection
- 와일드카드 (*)
- OR/AND 조건
- objectClass 조회

**실행 방법:**
```bash
python3 test05_injection.py
```

---

## 📁 로그 파일

모든 테스트는 `logs/` 디렉토리에 타임스탬프와 함께 자동 저장됩니다:
```
logs/
├── test01_rate_limit_YYYYMMDD_HHMMSS.log
├── test02_input_validation_YYYYMMDD_HHMMSS.log
├── test03_auth_deep_YYYYMMDD_HHMMSS.log
├── test04_error_handling_YYYYMMDD_HHMMSS.log
└── test05_injection_YYYYMMDD_HHMMSS.log
```

## 🔧 수정된 문제점

### 1. ✅ HPP 테스트 버그 수정
**문제:** Python 딕셔너리는 중복 키를 허용하지 않음
```python
# 이전 (작동 안 함)
{"page": 1, "page": -1}

# 수정 후 (작동함)
{"page": [1, -1]}
```

### 2. ✅ 응답 분석 자동화
- 응답 시간 측정 및 통계
- 상태 코드 분포 자동 집계
- 예상치 못한 200 응답 자동 감지
- 가장 느린 테스트 TOP 5 표시

### 3. ✅ 로그 파일 저장
모든 테스트에 로그 저장 기능 추가 (test01, test02, test03, test04, test05)

### 4. ✅ 누락된 테스트 추가
- SQL Injection 전문 테스트 (30+ 패턴)
- NoSQL Injection (Elasticsearch 전용)
- Path Traversal (query_string 포함)
- Command Injection
- LDAP Injection

## 🎯 테스트 커버리지

| 공격 유형 | 테스트 파일 | 패턴 수 | 상태 |
|----------|------------|--------|------|
| Rate Limiting | test01 | 2 | ✅ |
| Input Validation | test02 | 30+ | ✅ |
| XSS | test02_xss_deep | 70+ | ✅ |
| Authentication/Authorization | test03, test03_deep | 100+ | ✅ |
| Error Handling | test04 | 50+ | ✅ |
| SQL Injection | test05 | 30+ | 🆕 |
| NoSQL Injection | test05 | 12+ | 🆕 |
| Path Traversal | test05 | 20+ | 🆕 |
| Command Injection | test05 | 15+ | 🆕 |
| LDAP Injection | test05 | 6+ | 🆕 |
| **총계** | **6개 파일** | **350+** | **완료** |

## 📊 테스트 결과 요약

### 주요 발견 사항 (기존 로그 기준)

#### ✅ 양호한 보안 설정
- JSON 파싱 오류 적절히 처리 (422 상태 코드)
- 잘못된 HTTP 메서드 차단 (405 Method Not Allowed)
- HSTS 헤더 적용됨 (max-age=31536000)
- 대부분의 민감 정보 패턴 미발견

#### ⚠️ 개선 필요 사항
1. **보안 헤더 누락**
   - X-Content-Type-Options (MIME 스니핑 방지)
   - X-Frame-Options (클릭재킹 방지)
   - Content-Security-Policy
   - Referrer-Policy
   - Permissions-Policy

2. **서버 정보 노출**
   - Server: nginx/1.21.4
   - X-Powered-By: Next.js

3. **500 에러 발생**
   - 매우 큰 page 값 (999999, INT_MAX) 입력 시 500 에러
   - 내부 서버 오류 메시지만 반환 (상세 정보는 미노출)

4. **토큰 관련 정보 노출**
   - 401 응답에 "Access token not found or invalid" 메시지
   - 공격자가 인증 메커니즘을 파악할 수 있음

## 🚀 실행 순서 권장

```bash
# 1. 기본 테스트
python3 test01_rate_limit.py       # 5-10분
python3 test02_input_validation.py # 2-3분

# 2. 심층 테스트
python3 test02_xss_deep.py         # 3-5분
python3 test03_auth_deep.py        # 10-15분
python3 test05_injection.py        # 5-10분

# 3. 에러 핸들링
python3 test04_error_handling.py   # 3-5분

# 전체 실행 시간: 약 30-50분
```

## ⚠️ 주의사항

1. **권한 있는 테스트만 수행**
   - 반드시 테스트 대상 시스템의 소유자 승인 필요
   - 무단 침투 테스트는 불법입니다

2. **프로덕션 환경 주의**
   - 가능하면 개발/스테이징 환경에서 테스트
   - Rate Limiting 테스트는 서비스 부하 유발 가능

3. **로그 보관**
   - 모든 테스트 로그는 증거자료로 보관
   - 발견된 취약점은 즉시 보고

## 📝 보고서 작성 가이드

테스트 완료 후 다음 정보를 포함한 보고서 작성:

1. **요약**
   - 테스트 일시, 대상 시스템
   - 발견된 취약점 개수 (Critical/High/Medium/Low)

2. **상세 결과**
   - 각 취약점별 재현 방법
   - 위험도 평가
   - 권장 조치사항

3. **첨부 자료**
   - 로그 파일
   - 스크린샷 (필요 시)

## 📚 참고 자료

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Burp Suite Documentation: https://portswigger.net/burp/documentation

## 🔄 업데이트 이력

- **2025-01-27**: 초기 테스트 (test01-04)
- **2025-01-27**: 수정 및 개선
  - HPP 테스트 버그 수정
  - 응답 분석 자동화 추가
  - 로그 저장 기능 전체 적용
  - test05_injection.py 추가 (SQL, NoSQL, Path Traversal, Command, LDAP)

---

**작성자:** Security Testing Team
**최종 수정:** 2025-01-27
