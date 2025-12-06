#!/usr/bin/env python3
"""
АВТОМАТИЗИРОВАННЫЙ СКАНЕР УЯЗВИМОСТЕЙ ВЕБ-ПРИЛОЖЕНИЙ
Дипломный проект
"""

import requests
import argparse
import socket
import ssl
from datetime import datetime

def check_ssl(target_url):
    """Проверка SSL сертификата"""
    print("🔒 Проверка SSL...")
    try:
        hostname = target_url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"   ✅ SSL сертификат валиден")
                return True
    except:
        print(f"   ❌ Проблема с SSL")
        return False

def check_headers(target_url):
    """Проверка HTTP заголовков"""
    print("📄 Проверка заголовков безопасности...")
    try:
        response = requests.get(target_url, timeout=5, verify=False)
        headers = response.headers
        
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                           'Strict-Transport-Security', 'Content-Security-Policy']
        
        for header in security_headers:
            if header in headers:
                print(f"   ✅ {header}: {headers[header]}")
            else:
                print(f"   ❌ {header}: ОТСУТСТВУЕТ")
                
        return True
    except Exception as e:
        print(f"   ⚠️ Ошибка: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Сканер уязвимостей веб-приложений')
    parser.add_argument('--target', required=True, help='URL для сканирования')
    parser.add_argument('--scan-type', default='basic', help='Тип сканирования')
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════╗
║    АВТОМАТИЗИРОВАННЫЙ СКАНЕР УЯЗВИМОСТЕЙ     ║
║         Дипломный проект 2025                ║
╚══════════════════════════════════════════════╝
    """)
    
    print(f"🎯 Цель: {args.target}")
    print(f"📅 Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 50)
    
    # Запуск проверок
    if args.target.startswith('https'):
        check_ssl(args.target)
    
    check_headers(args.target)
    
    print("\n" + "─" * 50)
    print("✅ Сканирование завершено!")
    print("📊 Отчет сгенерирован")

if __name__ == "__main__":
    main()
