"""
Модуль для проверки HTTP заголовков безопасности
"""

import requests

class HeaderScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.name = "Header Security Scanner"
        self.description = "Проверка HTTP заголовков безопасности"
    
    def scan(self):
        """Основной метод сканирования заголовков"""
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            headers = response.headers
            
            # Проверяем важные заголовки безопасности
            security_headers = [
                ('X-Frame-Options', 'Защита от clickjacking атак'),
                ('X-Content-Type-Options', 'Защита от MIME-sniffing'),
                ('Strict-Transport-Security', 'Принудительное использование HTTPS'),
                ('Content-Security-Policy', 'Политика безопасности контента'),
                ('X-XSS-Protection', 'Защита от XSS атак'),
                ('Referrer-Policy', 'Контроль передачи Referrer'),
                ('Permissions-Policy', 'Контроль разрешений браузера'),
            ]
            
            for header, description in security_headers:
                if header in headers:
                    results['info'].append(f"✅ {header}: {headers[header]} ({description})")
                else:
                    results['warnings'].append(f"⚠️ {header} отсутствует: {description}")
            
            # Проверка Server заголовка
            if 'Server' in headers:
                server_info = headers['Server']
                results['info'].append(f"🖥️ Server: {server_info}")
                
                # Проверка на откровение информации
                sensitive_servers = ['Apache', 'nginx', 'IIS', 'Tomcat']
                if any(server in server_info for server in sensitive_servers):
                    results['warnings'].append(f"ℹ️ Server заголовок раскрывает информацию: {server_info}")
            
            # Проверка cookies
            if 'Set-Cookie' in headers:
                cookies = headers.get_all('Set-Cookie')
                for cookie in cookies:
                    if 'HttpOnly' not in cookie:
                        results['warnings'].append("🍪 Cookie без флага HttpOnly")
                    if 'Secure' not in cookie and self.target_url.startswith('https'):
                        results['warnings'].append("🍪 Cookie без флага Secure на HTTPS сайте")
            
        except Exception as e:
            results['warnings'].append(f"Ошибка проверки заголовков: {str(e)}")
        
        return results
