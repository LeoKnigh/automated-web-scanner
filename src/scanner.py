#!/usr/bin/env python3
"""
Основной модуль сканера уязвимостей
Дипломный проект - Автоматизированный веб-сканер
"""

import argparse
import json
import sys
from datetime import datetime

# Импорты модулей
from modules.header_scanner import HeaderScanner
from modules.advanced_xss_scanner import AdvancedXSSScanner
from modules.sql_scanner import AdvancedSQLScanner
from utils.reporter import Reporter
from utils.html_reporter import HTMLReporter

class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.scan_results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }
        
        # Инициализация модулей
        self.modules = [
            HeaderScanner(target_url),
            AdvancedSQLScanner(target_url),
            AdvancedXSSScanner(target_url)
        ]
        
        # Сканируем доступность модулей
        self.scan_results['info'].append(f"Инициализировано модулей: {len(self.modules)}")
    
    def run_scan(self):
        """Запуск всех модулей сканирования"""
        print(f"\n🔍 Начинаем сканирование: {self.target_url}")
        print("=" * 60)
        
        for module in self.modules:
            try:
                print(f"\n📊 Модуль: {module.name}")
                print(f"   Описание: {module.description}")
                
                # Запускаем сканирование модуля
                module_results = module.scan()
                
                # Объединяем результаты
                if 'vulnerabilities' in module_results:
                    self.scan_results['vulnerabilities'].extend(module_results['vulnerabilities'])
                
                if 'warnings' in module_results:
                    self.scan_results['warnings'].extend(module_results['warnings'])
                
                if 'info' in module_results:
                    self.scan_results['info'].extend(module_results['info'])
                
                print(f"   ✅ Завершено")
                
            except Exception as e:
                error_msg = f"Ошибка в модуле {module.name}: {str(e)}"
                self.scan_results['warnings'].append(error_msg)
                print(f"   ❌ Ошибка: {str(e)[:50]}...")
        
        print("\n" + "=" * 60)
        print(f"📊 Сканирование завершено!")
        print(f"   Найдено уязвимостей: {len(self.scan_results['vulnerabilities'])}")
        print(f"   Предупреждений: {len(self.scan_results['warnings'])}")
        print("=" * 60)
        
        return self.scan_results
    
    def generate_report(self, format='console', output_file=None):
        """Генерация отчета в указанном формате"""
        if format == 'json':
            reporter = Reporter(self.scan_results)
            filename = output_file or 'scan_report.json'
            reporter.generate_json_report(filename)
            return f"JSON отчет сохранен в: {filename}"
        
        elif format == 'html':
            try:
                reporter = HTMLReporter(self.scan_results)
                filename = output_file or 'scan_report.html'
                reporter.generate_report(filename)
                return f"HTML отчет сохранен в: {filename}"
            except Exception as e:
                return f"Ошибка генерации HTML отчета: {str(e)}"
        
        else:  # console
            reporter = Reporter(self.scan_results)
            return reporter.generate_console_report()

def main():
    parser = argparse.ArgumentParser(
        description='Автоматизированный сканер уязвимостей веб-приложений',
        epilog='Дипломный проект 2024 - Информационная безопасность'
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='URL целевого веб-приложения (пример: http://example.com)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['console', 'json', 'html'],
        default='console',
        help='Формат вывода отчета (по умолчанию: console)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Имя файла для сохранения отчета'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Подробный вывод'
    )
    
    args = parser.parse_args()
    
    # Создаем и запускаем сканер
    scanner = Scanner(args.target)
    
    try:
        # Запускаем сканирование
        scanner.run_scan()
        
        # Генерируем отчет
        report = scanner.generate_report(
            format=args.format,
            output_file=args.output
        )
        
        # Выводим отчет
        print(report)
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Сканирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
