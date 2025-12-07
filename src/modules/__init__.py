import requests
import ssl
import socket
from urllib.parse import urlparse

class HeaderScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.name = "HTTP Security Headers Scanner"
        self.description = "Проверка HTTP заголовков безопасности"
        
    def check_ssl_certificate(self):
        """Проверка SSL сертификата"""
        try:
            parsed_url = urlparse(self.target_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                'valid': True,
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'expires': cert.get('notAfter', '')
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def check_security_headers(self):
        """Проверка HTTP заголовков безопасности"""
        security_headers = {
            'Strict-Transport-Security': 'Защищает от SSL stripping атак',
            'Content-Security-Policy': 'Защита от XSS и инъекций',
            'X-Frame-Options': 'Защита от clickjacking',
            'X-Content-Type-Options': 'Предотвращение MIME-спуфинга',
            'Referrer-Policy': 'Контроль передачи referrer',
            'Permissions-Policy': 'Контроль доступа к функциям браузера'
        }
        
        results = []
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            headers = response.headers
            
            for header, description in security_headers.items():
                if header in headers:
                    results.append({
                        'header': header,
                        'present': True,
                        'value': headers[header],
                        'description': description
                    })
                else:
                    results.append({
                        'header': header,
                        'present': False,
                        'description': f'Отсутствует: {description}'
                    })
                    
        except Exception as e:
            results.append({'error': f'Ошибка при проверке заголовков: {str(e)}'})
        
        return results
    
    def scan(self):
        """Основной метод сканирования"""
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Проверяем SSL
        ssl_info = self.check_ssl_certificate()
        if ssl_info.get('valid'):
            results['info'].append(f"SSL сертификат валиден: {ssl_info.get('subject', {}).get('commonName', 'N/A')}")
        else:
            results['warnings'].append(f"Проблема с SSL: {ssl_info.get('error', 'Неизвестная ошибка')}")
        
        # Проверяем заголовки
        headers = self.check_security_headers()
        missing_headers = [h for h in headers if not h.get('present', True)]
        
        if missing_headers:
            results['vulnerabilities'].extend([
                {
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'medium',
                    'description': f"Отсутствует заголовок безопасности: {h['header']}",
                    'details': h['description']
                }
                for h in missing_headers[:3]  # Первые 3 отсутствующих
            ])
            results['info'].append(f"Найдено отсутствующих заголовков: {len(missing_headers)}")
        
        # Добавляем информацию о найденных заголовках
        present_headers = [h for h in headers if h.get('present', False)]
        if present_headers:
            results['info'].append(f"Найдено security заголовков: {len(present_headers)}")
        
        return results
