import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode

class AdvancedXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.name = "Advanced XSS Scanner"
        self.description = "Расширенная проверка на XSS уязвимости"
        
        # Payload для тестирования XSS
        self.xss_payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Bypass attempts
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x OneRrOr=alert('XSS')>",
            
            # Encoded payloads
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            'html': ['"><script>alert(1)</script>', "'><script>alert(1)</script>"],
            'attribute': ['" onmouseover="alert(1)', "' onmouseover='alert(1)"],
            'javascript': ['\';alert(1);//', '";alert(1);//'],
        }
    
    def test_reflected_xss(self):
        """Тестирование на Reflected XSS"""
        results = []
        
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return results
        
        print("   🔍 Тестирование параметров на Reflected XSS...")
        
        for param in query_params:
            original_value = query_params[param][0]
            
            for payload in self.xss_payloads[:3]:  # Тестируем только 3 payload
                # Создаем тестовый URL
                test_params = query_params.copy()
                test_params[param] = [payload]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params, doseq=True)
                
                try:
                    response = requests.get(
                        test_url, 
                        timeout=5, 
                        verify=False,
                        headers={'User-Agent': 'XSS-Scanner/1.0'}
                    )
                    
                    # Проверяем, отобразился ли payload в ответе
                    if payload in response.text:
                        results.append({
                            'type': 'REFLECTED_XSS',
                            'severity': 'high',
                            'description': f'Reflected XSS в параметре {param}',
                            'details': f'Payload отражается в ответе: {payload[:50]}...',
                            'url': test_url[:100] + '...'
                        })
                        break  # Один payload достаточно
                        
                except Exception as e:
                    continue
        
        return results
    
    def analyze_input_vectors(self):
        """Анализ потенциальных векторов для XSS"""
        vectors = []
        
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            html = response.text
            
            # Ищем все формы
            form_pattern = r'<form[^>]*>.*?</form>'
            forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
            
            if forms:
                vectors.append(f"Найдено форм: {len(forms)}")
                
                # Анализируем каждую форму
                for i, form in enumerate(forms, 1):
                    # Ищем метод и action
                    method_match = re.search(r'method=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
                    action_match = re.search(r'action=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
                    
                    method = method_match.group(1) if method_match else 'GET'
                    action = action_match.group(1) if action_match else ''
                    
                    # Ищем поля ввода
                    inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
                    textareas = re.findall(r'<textarea[^>]*>', form, re.IGNORECASE)
                    
                    input_types = []
                    for inp in inputs:
                        type_match = re.search(r'type=["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                        name_match = re.search(r'name=["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                        
                        if type_match and name_match:
                            input_types.append(f"{name_match.group(1)} ({type_match.group(1)})")
                    
                    if input_types:
                        vectors.append(f"  Форма {i}: method={method}, inputs={', '.join(input_types[:3])}")
            
            # Ищем другие потенциальные векторы
            script_tags = len(re.findall(r'<script[^>]*>', html, re.IGNORECASE))
            if script_tags > 0:
                vectors.append(f"Найдено тегов <script>: {script_tags}")
            
            # Проверяем Content-Type
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                vectors.append(f"⚠️ Нестандартный Content-Type: {content_type}")
                    
        except Exception as e:
            vectors.append(f"Ошибка анализа: {str(e)}")
        
        return vectors
    
    def scan(self):
        """Основной метод сканирования"""
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Тестируем Reflected XSS
        xss_results = self.test_reflected_xss()
        if xss_results:
            results['vulnerabilities'].extend(xss_results)
            results['info'].append(f"Найдено Reflected XSS уязвимостей: {len(xss_results)}")
        else:
            results['info'].append("Reflected XSS не обнаружены")
        
        # Анализируем векторы
        vectors = self.analyze_input_vectors()
        results['info'].extend(vectors)
        
        # Проверяем наличие CSP (защита от XSS)
        try:
            response = requests.get(self.target_url, timeout=3, verify=False)
            csp = response.headers.get('Content-Security-Policy', '')
            
            if csp:
                results['info'].append(f"Найден Content-Security-Policy: {csp[:50]}...")
            else:
                results['warnings'].append("Content-Security-Policy отсутствует (повышает риск XSS)")
                
        except:
            results['warnings'].append("Не удалось проверить CSP")
        
        # Рекомендации
        if any('форма' in str(v).lower() for v in vectors):
            results['info'].append("Рекомендация: Для полной проверки XSS необходим тест форм с payload")
        
        return results
