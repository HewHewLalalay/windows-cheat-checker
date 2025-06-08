# 🛡️ Windows Cheat Checker

![Overlay Screenshot](Overlay.png)

**Windows Cheat Checker** — это консольная утилита на C++, которая анализирует системные настройки безопасности, наличие античитов и установленных обновлений в Windows.

## 🚀 Возможности

- Отображение версии и редакции Windows (включая Home/Pro)
- Проверка:
  - **Control Flow Guard (CFG)**
  - **Core Isolation / Memory Integrity**
  - **Windows Defender**
  - **Firewall**
  - **Driver Blocklist**
- Определение установленных обновлений (через WMI)
- Обнаружение популярных античитов:
  - **Riot Vanguard**
  - **FACEIT**
- Цветной вывод, ASCII-баннер, чистая структура консоли

## 🖥️ Поддержка

- Windows 7, 8.1, 10, 11
- x64

## 🔧 Компиляция

Убедитесь, что у вас установлен **MSVC** (Microsoft Visual C++) и выполните:

```bash
cl /EHsc /std:c++17 /MT ConsoleApplication1.cpp ^
    advapi32.lib ole32.lib wbemuuid.lib oleaut32.lib shell32.lib psapi.lib legacy_stdio_definitions.lib
