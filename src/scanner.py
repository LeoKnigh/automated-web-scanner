#!/usr/bin/env python3
"""
АВТОМАТИЗИРОВАННЫЙ СКАНЕР УЯЗВИМОСТЕЙ ВЕБ-ПРИЛОЖЕНИЙ
Дипломный проект 2025
"""

import requests
import argparse
import socket
import ssl
import json
from datetime import datetime
from modules.header_scanner import HeaderScanner
from modules.advanced_xss_scanner import AdvancedXSSScanner
from modules.sql_scanner import AdvancedSQLScanner
from utils.html_reporter import HTMLReporter


class Scanner:
    def __init__(self, target_url):
        """Инициализация сканера"""
        self.target_url = target_url
        self.scan_results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }

        # Инициализация модулей сканирования
        self.modules = [
            HeaderScanner(target_url),
            AdvancedSQLScanner(target_url),  # Используем улучшенный SQL сканер
            AdvancedXSSScanner(target_url)   # Используем улучшенный XSS сканер
        ]

    def run_scan(self):
        """Запуск всех модулей сканирования"""
        print("🚀 Запуск сканирования...")
        print("─" * 50)
        
        # Запуск всех модулей
        for module in self.modules:
            print(f"🔍 Запуск модуля: {module.name}")
            print(f"   📝 {module.description}")
            
            try:
                result = module.scan()
                
                # Собираем результаты
                if 'vulnerabilities' in result:
                    self.scan_results['vulnerabilities'].extend(result['vulnerabilities'])
                
                if 'warnings' in result:
                    self.scan_results['warnings'].extend(result['warnings'])
                
                if 'info' in result:
                    self.scan_results['info'].extend(result['info'])
                
                print(f"   ✅ Модуль завершил работу")
                
            except Exception as e:
                print(f"   ❌ Ошибка в модуле {module.name}: {str(e)}")
        
        # Добавляем базовые проверки
        self._run_basic_checks()
        
        print("\n📊 Результаты сканирования:")
        print(f"   Уязвимости: {len(self.scan_results['vulnerabilities'])}")
        print(f"   Предупреждения: {len(self.scan_results['warnings'])}")
        print(f"   Информация: {len(self.scan_results['info'])}")
        
        return self.scan_results
    
    def _run_basic_checks(self):
        """Выполнение базовых проверок"""
        # Проверка SSL
        if self.target_url.startswith('https'):
            ssl_result = self._check_ssl()
            if not ssl_result:
                self.scan_results['warnings'].append("Проблемы с SSL сертификатом")
        
        # Проверка заголовков
        headers_result = self._check_headers()
        if headers_result:
            self.scan_results['info'].append("Проверка заголовков безопасности выполнена")
    
    def _check_ssl(self):
        """Проверка SSL сертификата"""
        try:
            hostname = self.target_url.split("//")[-1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return True
        except Exception as e:
            return False
    
    def _check_headers(self):
        """Проверка HTTP заголовков"""
        try:
            response = requests.get(self.target_url, timeout=5, verify=False)
            headers = response.headers
            
            missing_headers = []
            security_headers = [
                ('X-Frame-Options', 'Защита от clickjacking'),
                ('X-Content-Type-Options', 'Защита от MIME-sniffing'),
                ('Strict-Transport-Security', 'Принудительное использование HTTPS'),
                ('Content-Security-Policy', 'Политика безопасности контента'),
                ('X-XSS-Protection', 'Защита от XSS')
            ]
            
            for header, description in security_headers:
                if header not in headers:
                    missing_headers.append(f"{header}: {description}")
            
            if missing_headers:
                self.scan_results['warnings'].extend(missing_headers)
            
            return True
        except Exception as e:
            self.scan_results['warnings'].append(f"Ошибка проверки заголовков: {str(e)}")
            return False
    
    def generate_report(self, format='console'):
        """Генерация отчета в различных форматах"""
        if format == 'json':
            return json.dumps(self.scan_results, indent=2, ensure_ascii=False)
        
        elif format == 'html':
            reporter = HTMLReporter(self.scan_results)
            filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            reporter.generate_report(filename)
            return f"✅ HTML отчет сохранен в файл: {filename}"
        
        # Консольный вывод (по умолчанию)
        else:
            return self._generate_console_report()
    
    def _generate_console_report(self):
        """Генерация консольного отчета"""
        report_lines = []
        
        report_lines.append("=" * 60)
        report_lines.append("               ОТЧЕТ СКАНИРОВАНИЯ")
        report_lines.append("=" * 60)
        report_lines.append(f"Цель: {self.scan_results['target']}")
        report_lines.append(f"Время: {self.scan_results['timestamp']}")
        report_lines.append("-" * 60)
        
        # Уязвимости
        if self.scan_results['vulnerabilities']:
            report_lines.append("\n🚨 ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ:")
            for i, vuln in enumerate(self.scan_results['vulnerabilities'], 1):
                report_lines.append(f"\n  {i}. [{vuln.get('severity', 'MEDIUM').upper()}] {vuln.get('type', 'UNKNOWN')}")
                report_lines.append(f"     📝 {vuln.get('description', 'Без описания')}")
                if 'details' in vuln:
                    report_lines.append(f"     ℹ️  {vuln['details']}")
                if 'url' in vuln:
                    report_lines.append(f"     🔗 {vuln['url']}")
        
        # Предупреждения
        if self.scan_results['warnings']:
            report_lines.append("\n⚠️  ПРЕДУПРЕЖДЕНИЯ:")
            for warning in self.scan_results['warnings']:
                report_lines.append(f"  • {warning}")
        
        # Информация
        if self.scan_results['info']:
            report_lines.append("\nℹ️  ИНФОРМАЦИЯ:")
            for info in self.scan_results['info'][:10]:  # Первые 10 записей
                report_lines.append(f"  • {info}")
        
        # Статистика
        report_lines.append("\n" + "-" * 60)
        report_lines.append("📊 СТАТИСТИКА:")
        report_lines.append(f"  Всего уязвимостей: {len(self.scan_results['vulnerabilities'])}")
        
        # Группировка по серьезности
        severity_count = {}
        for vuln in self.scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'medium')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        for severity, count in severity_count.items():
            report_lines.append(f"  Уязвимости уровня {severity}: {count}")
        
        report_lines.append("=" * 60)
        
        return "\n".join(report_lines)


def main():
    """Основная функция запуска сканера"""
    parser = argparse.ArgumentParser(
        description='Автоматизированный сканер уязвимостей веб-приложений',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python3 scanner.py --target http://example.com
  python3 scanner.py --target https://example.com --format html --output report.html
  python3 scanner.py --target http://localhost:3000 --format json
        """
    )
    
    parser.add_argument('--target', required=True, help='URL для сканирования')
    parser.add_argument('--format', default='console', choices=['console', 'json', 'html'],
                       help='Формат отчета (по умолчанию: console)')
    parser.add_argument('--output', help='Файл для сохранения отчета')
    parser.add_argument('--scan-type', default='full', choices=['basic', 'full'],
                       help='Тип сканирования (по умолчанию: full)')
    
    args = parser.parse_args()
    
    # Вывод заголовка
    print(f"""
╔══════════════════════════════════════════════╗
║    АВТОМАТИЗИРОВАННЫЙ СКАНЕР УЯЗВИМОСТЕЙ     ║
║         Дипломный проект 2025                ║
╚══════════════════════════════════════════════╝
    """)
    
    print(f"🎯 Цель сканирования: {args.target}")
    print(f"📅 Дата запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📁 Формат отчета: {args.format}")
    print("─" * 50)
    
    # Создание и запуск сканера
    try:
        scanner = Scanner(args.target)
        scanner.run_scan()
        
        # Генерация отчета
        report = scanner.generate_report(format=args.format)
        
        # Сохранение или вывод отчета
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n📁 Отчет сохранен в файл: {args.output}")
        else:
            print("\n" + report)
        
        # Дополнительная информация
        print("\n" + "─" * 50)
        print("✅ Сканирование успешно завершено!")
        
        # Рекомендации
        if args.format == 'html':
            print(f"\n🌐 Для просмотра отчета откройте файл в браузере:")
            print(f"   file://$(pwd)/{args.output if args.output else 'scan_report_*.html'}")
        
    except KeyboardInterrupt:
        print("\n\n❌ Сканирование прервано пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка при сканировании: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
