#!/bin/bash
# Скрипт для подготовки отчетов для Windows
# Автоматически создает удобную структуру для диплома

echo "╔══════════════════════════════════════════════╗"
echo "║  ПОДГОТОВКА ОТЧЕТОВ ДЛЯ WINDOWS              ║"
echo "║  Дипломный проект 2025                      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Создаем временную папку
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="diploma_report_$TIMESTAMP"
mkdir -p "$REPORT_DIR"

echo "📁 Создаем структуру отчетов в: $REPORT_DIR/"
mkdir -p "$REPORT_DIR/security_reports"
mkdir -p "$REPORT_DIR/screenshots"
mkdir -p "$REPORT_DIR/source_code"

# 1. Копируем security отчеты
echo "📋 Копируем security отчеты..."
cp -r security_reports/* "$REPORT_DIR/security_reports/" 2>/dev/null || echo "⚠️ Нет security отчетов"

# 2. Копируем важные файлы проекта
echo "📦 Копируем исходный код..."
cp -r src/ "$REPORT_DIR/source_code/"
cp requirements.txt "$REPORT_DIR/"
cp docker-compose-vuln.yml "$REPORT_DIR/"
cp custom-opengrep-rules.yml "$REPORT_DIR/"

# 3. Создаем README для Windows
echo "📝 Создаем инструкцию..."
cat > "$REPORT_DIR/README_WINDOWS.md" << 'EOF'
# 📊 ОТЧЕТЫ ДИПЛОМНОГО ПРОЕКТА

## 🎯 Автоматизированный веб-сканер уязвимостей

### 📁 Структура папки:

1. **security_reports/** - Результаты сканирования
   - `bandit_report.html` - HTML отчет Bandit
   - `bandit_report.json` - JSON отчет Bandit
   - `comparison_report.md` - Сравнение Bandit vs OpenGrep
   - `opengrep_*.json` - Отчеты OpenGrep/Semgrep

2. **source_code/** - Исходный код проекта
   - `src/` - Основной код сканера
   - `scripts/` - Вспомогательные скрипты

3. **screenshots/** - (заполните вручную скриншотами)

### 🚀 Как использовать:

1. **Открыть HTML отчет:** `security_reports/bandit_report.html` в браузере
2. **Просмотреть JSON:** Использовать Notepad++ или онлайн JSON viewer
3. **Исходный код:** Для демонстрации в дипломе

### 📋 Для дипломной работы:

1. Вставить скриншоты в раздел "Результаты"
2. Привести примеры найденных уязвимостей из `bandit_report.json`
3. Показать сравнение инструментов из `comparison_report.md`

### 📅 Дата генерации: TIMESTAMP_PLACEHOLDER
EOF

# Заменяем плейсхолдер
sed -i "s/TIMESTAMP_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/" "$REPORT_DIR/README_WINDOWS.md"

# 4. Создаем главный HTML файл для удобного просмотра
cat > "$REPORT_DIR/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчеты дипломного проекта</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 10px; }
        .section { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .file-list { list-style: none; padding: 0; }
        .file-list li { padding: 10px; border-bottom: 1px solid #eee; }
        .file-list a { color: #3498db; text-decoration: none; }
        .file-list a:hover { text-decoration: underline; }
        .btn { display: inline-block; padding: 10px 20px; background: #3498db; color: white; border-radius: 5px; text-decoration: none; margin: 5px; }
        .btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Отчеты дипломного проекта</h1>
            <h2>Автоматизированный веб-сканер уязвимостей</h2>
            <p>Дата генерации: TIMESTAMP_PLACEHOLDER</p>
        </div>
        
        <div class="section">
            <h3>📁 Security отчеты</h3>
            <ul class="file-list" id="security-reports">
                <!-- Файлы будут добавлены скриптом -->
            </ul>
        </div>
        
        <div class="section">
            <h3>🚀 Быстрые ссылки</h3>
            <a href="security_reports/bandit_report.html" class="btn" target="_blank">Bandit HTML отчет</a>
            <a href="security_reports/comparison_report.md" class="btn" target="_blank">Сравнительный анализ</a>
            <a href="README_WINDOWS.md" class="btn" target="_blank">Инструкция</a>
        </div>
        
        <div class="section">
            <h3>📋 Для дипломной работы</h3>
            <p>1. Используйте скриншоты из папки screenshots/</p>
            <p>2. Приведите примеры уязвимостей из JSON отчетов</p>
            <p>3. Покажите сравнение инструментов Bandit vs OpenGrep</p>
        </div>
    </div>
    
    <script>
        // Динамически добавляем файлы в список
        const securityFiles = [
            'bandit_report.html',
            'bandit_report.json', 
            'comparison_report.md',
            'opengrep_custom.json',
            'opengrep_owasp.json',
            'opengrep_python.json'
        ];
        
        const list = document.getElementById('security-reports');
        securityFiles.forEach(file => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = 'security_reports/' + file;
            a.textContent = file;
            a.target = '_blank';
            li.appendChild(a);
            list.appendChild(li);
        });
    </script>
</body>
</html>
EOF

sed -i "s/TIMESTAMP_PLACEHOLDER/$(date '+%Y-%m-%d %H:%M:%S')/" "$REPORT_DIR/index.html"

# 5. Создаем ZIP архив
echo "🗜️ Создаем ZIP архив..."
zip -r "windows_report_$TIMESTAMP.zip" "$REPORT_DIR"

echo ""
echo "✅ ГОТОВО! Отчеты подготовлены для Windows"
echo "📂 Папка с отчетами: $REPORT_DIR/"
echo "📦 ZIP архив: windows_report_$TIMESTAMP.zip"
echo ""
echo "📋 ЧТО ДАЛЬШЕ:"
echo "1. Скачайте архив 'windows_report_$TIMESTAMP.zip' на Windows"
echo "2. Распакуйте архив в любую папку"
echo "3. Откройте index.html в браузере"
echo "4. Используйте файлы для дипломной работы"
