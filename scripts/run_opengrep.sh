#!/bin/bash

# ============================================
# СКРИПТ ДЛЯ ЗАПУСКА OPENGREP/SEMGREP АНАЛИЗА
# Дипломный проект - Информационная безопасность
# ============================================

echo "╔══════════════════════════════════════════════╗"
echo "║     OPENGREP/SEMGREP СТАТИЧЕСКИЙ АНАЛИЗ      ║"
echo "║     Дипломный проект 2024                    ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Проверяем, установлен ли semgrep
if ! command -v semgrep &> /dev/null; then
    echo "❌ Semgrep не найден. Устанавливаем..."
    pip install semgrep
fi

echo "✅ Semgrep версии: $(semgrep --version)"
echo "📅 Дата анализа: $(date)"
echo "📁 Анализируемая папка: ./src"
echo ""

# Создаем директорию для отчетов
REPORT_DIR="./opengrep_reports"
mkdir -p "$REPORT_DIR"

# Запускаем анализ с разными наборами правил
echo "🔍 Запуск анализа с правилами OpenGrep..."
echo "─────────────────────────────────────────────"

# 1. Анализ с правилами OWASP Top 10
echo "1. OWASP Top 10 анализ..."
semgrep --config "p/owasp-top-ten" ./src --json -o "${REPORT_DIR}/owasp_analysis.json" || true

# 2. Анализ Python кода
echo "2. Python Security анализ..."
semgrep --config "p/python" ./src --json -o "${REPORT_DIR}/python_analysis.json" || true

# 3. Поиск секретов
echo "3. Secrets Detection анализ..."
semgrep --config "p/secrets" ./src --json -o "${REPORT_DIR}/secrets_analysis.json" || true

# 4. Общий аудит безопасности
echo "4. Security Audit анализ..."
semgrep --config "p/security-audit" ./src --json -o "${REPORT_DIR}/security_audit.json" || true

# 5. Сканирование с собственными правилами
echo "5. Custom Rules анализ..."
if [ -f ".semgrep.yml" ]; then
    semgrep --config .semgrep.yml ./src --json -o "${REPORT_DIR}/custom_rules_analysis.json" || true
else
    echo "   ⚠️ Файл .semgrep.yml не найден"
fi

echo ""
echo "✅ Анализ завершен!"
echo ""
echo "📊 ОТЧЕТЫ СОХРАНЕНЫ В:"
echo "   ${REPORT_DIR}/"
echo ""
echo "📋 СОДЕРЖАНИЕ ОТЧЕТОВ:"
ls -la "${REPORT_DIR}/"
echo ""
echo "🎯 Для просмотра результатов:"
echo "   cat ${REPORT_DIR}/owasp_analysis.json | jq '.'"
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Анализ готов для включения в дипломную работу║"
echo "╚══════════════════════════════════════════════╝"
