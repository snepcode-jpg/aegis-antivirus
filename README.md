<div align="center">

# 🛡️ AEGIS Antivirus

**Десктопный антивирус на Python и PySide6 с современным анимированным интерфейсом, эвристическим анализом и фоновой защитой в системном трее.**

![Python](https://img.shields.io/badge/Python-3.10+-22D3EE?style=for-the-badge&logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/PySide6-Qt6-8B5CF6?style=for-the-badge&logo=qt&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-34D399?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-F43F5E?style=for-the-badge)

<br>

<img src="assets/preview.png" alt="AEGIS Antivirus Preview" width="850">

</div>

---

## ✨ Возможности

* **Три режима сканирования + проверка файла** — быстрая, полная, выборочная проверка папок и мгновенный анализ отдельного файла.
* **Защита в реальном времени** — мониторинг новых файлов в папках `Загрузки` и `Рабочий стол` прямо из системного трея с нативными уведомлениями.
* **Сигнатурный анализ (SHA-256)** — проверка файлов по локальной базе сигнатур (`~/.aegis_av/signatures.json`) и поддержка тест-файлов (EICAR / Aegis Test).
* **Эвристический движок** — выявление двойных расширений, замаскированных `.exe`, высокой энтропии (упакованных/зашифрованных файлов), опасных API внедрения кода и подозрительных скриптов.
* **Карантин** — безопасная изоляция угроз с возможностью восстановления или окончательного удаления, плюс режим **Автокарантина**.
* **Мониторинг системы** — отображение нагрузки CPU (с графиком за 60 секунд), RAM и диска в реальном времени.
* **Журнал событий** — история последних 300 действий и график активности проверок.

---

## 🚀 Установка и запуск

1. Клонируйте репозиторий:
```bash
git clone [https://github.com/USERNAME/aegis-antivirus.git](https://github.com/USERNAME/aegis-antivirus.git)
cd aegis-antivirus
