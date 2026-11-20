#!/usr/bin/env python3
"""

============================================

  ______   __                       _
 | __ ) \ / /  ___ _ __   ___ _ __ | |_   _ ____
 |  _ \\ V /  / __| '_ \ / _ \ '_ \| | | | |_  /
 | |_) || |   \__ \ | | |  __/ |_) | | |_| |/ /
 |____/ |_|   |___/_| |_|\___| .__/|_|\__, /___|
                             |_|      |___/

============================================
Telegram - https://t.me/resourcessneplyz


AEGIS Antivirus — антивирус с анимированным интерфейсом (Python + PySide6).

Возможности:
- Быстрая / полная / выборочная проверка и проверка отдельного файла
- Детект по базе SHA-256 сигнатур (~/.aegis_av/signatures.json) и тест-файлам (EICAR)
- Эвристика: двойные расширения, замаскированные .exe, упакованные файлы,
  опасные API внедрения кода, подозрительные скрипты
- Карантин с восстановлением и удалением
- Защита в реальном времени для папок Загрузки и Рабочий стол + работа в трее с уведомлениями
- Журнал событий

Запуск:  pip install PySide6   ->   python aegis_antivirus.py
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import sys
import tempfile
import time
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from PySide6.QtCore import (Qt, QThread, Signal, QTimer, QPropertyAnimation,
                            QVariantAnimation, QEasingCurve, QPointF, QRectF, QPoint)
from PySide6.QtGui import (QPainter, QColor, QLinearGradient, QRadialGradient,
                           QConicalGradient, QPen, QBrush, QFont, QPainterPath,
                           QIcon, QPixmap, QAction)
from PySide6.QtWidgets import (QApplication, QWidget, QFrame, QLabel, QPushButton,
                               QVBoxLayout, QHBoxLayout, QStackedWidget, QScrollArea,
                               QFileDialog, QGraphicsOpacityEffect,
                               QGraphicsDropShadowEffect, QSizeGrip, QSizePolicy,
                               QButtonGroup, QListWidget, QListWidgetItem,
                               QSystemTrayIcon, QMenu)

# ───────────────────────────── Константы ─────────────────────────────
DATA = Path.home() / ".aegis_av"
QDIR = DATA / "quarantine"
STATE = DATA / "state.json"
SIGS = DATA / "signatures.json"
for _d in (DATA, QDIR):
    _d.mkdir(parents=True, exist_ok=True)

# Тест-строки собираются в рантайме, чтобы сам исходник не считался угрозой
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + b"$H+H*")
TEST_MARK = b"AEGIS-ANTIVIRUS" + b"-TEST-THREAT-FILE"

HASH_LIMIT = 64 * 1024 * 1024
SIDEBAR_W = 236
COL = {"safe": "#34D399", "scanning": "#22D3EE", "danger": "#F43F5E"}
LEVELS = {"critical": ("#F43F5E", "Критическая"),
          "high": ("#FB923C", "Высокая"),
          "medium": ("#FBBF24", "Средняя")}


def mix(a, b, t):
    a, b = QColor(a), QColor(b)
    return QColor(int(a.red() + (b.red() - a.red()) * t),
                  int(a.green() + (b.green() - a.green()) * t),
                  int(a.blue() + (b.blue() - a.blue()) * t),
                  int(a.alpha() + (b.alpha() - a.alpha()) * t))


def fmt_size(n):
    for u in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or u == "ГБ":
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


# ───────────────────────────── Хранилище ─────────────────────────────
class Store:
    def __init__(self):
        self.data = {"files": 0, "threats": 0, "last": "", "realtime": True,
                     "log": [], "quarantine": [], "heuristics": True,
                     "autoq": False, "history": []}
        try:
            self.data.update(json.loads(STATE.read_text("utf-8")))
        except Exception:
            pass

    def save(self):
        try:
            STATE.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), "utf-8")
        except Exception:
            pass

    def log(self, text, level="info"):
        self.data["log"].insert(0, {"t": datetime.now().strftime("%d.%m %H:%M:%S"),
                                    "text": text, "level": level})
        del self.data["log"][300:]
        self.save()


# ───────────────────────────── Движок ─────────────────────────────
class Engine:
    EXE_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".sys"}
    SCRIPT_EXT = {".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf"}
    DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
               ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".zip", ".rtf"}
    SKIP_DIRS = {"$recycle.bin", "system volume information", "windows",
                 "node_modules", ".git", "__pycache__", ".aegis_av"}
    SCRIPT_PATTERNS = [
        (b"-encodedcommand", "PowerShell: закодированная команда"),
        (b"frombase64string", "декодирование Base64"),
        (b"downloadstring", "загрузка кода из сети"),
        (b"invoke-expression", "динамическое выполнение кода"),
        (b"certutil -urlcache", "загрузка файла через certutil"),
        (b"vssadmin delete shadows", "удаление теневых копий (шифровальщик)"),
        (b"-executionpolicy bypass", "обход политики PowerShell"),
    ]
    INJECT_APIS = [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
                   b"SetWindowsHookEx", b"NtUnmapViewOfSection"]

    def __init__(self):
        self.heuristics = True
        self.sigs = self.load_sigs()

    def load_sigs(self):
        try:
            d = json.loads(SIGS.read_text("utf-8"))
            return {k.lower(): v for k, v in d.get("sha256", {}).items()}
        except Exception:
            try:
                SIGS.write_text(json.dumps({"sha256": {"<sha256-хэш>": "Название.Угрозы"}},
                                           ensure_ascii=False, indent=1), "utf-8")
            except Exception:
                pass
            return {}

    def skip_dir(self, name):
        return name.lower() in self.SKIP_DIRS

    def analyze(self, path):
        try:
            if os.path.islink(path):
                return None
            size = os.path.getsize(path)
            if size == 0:
                return None
            name = os.path.basename(path)
            low = name.lower()
            ext = os.path.splitext(low)[1]
            digest = None
            with open(path, "rb") as f:
                head = f.read(1024 * 1024)
                if size <= HASH_LIMIT:
                    h = hashlib.sha256(head)
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        h.update(chunk)
                    digest = h.hexdigest()
        except (OSError, PermissionError):
            return None

        def res(level, threat, reason):
            return {"path": path, "name": name, "level": level, "threat": threat,
                    "reason": reason, "size": size, "sha256": digest}

        if digest and digest in self.sigs:
            return res("critical", self.sigs[digest] or "Malware.Known", "хэш найден в базе сигнатур")
        if size < 4096 and TEST_MARK in head:
            return res("critical", "Aegis.Test.Threat", "тестовый файл Aegis (безвредный)")
        if size < 4096 and EICAR in head:
            return res("critical", "EICAR-Test-File", "стандартный тест-файл EICAR")

        if not self.heuristics:
            return None
        score, why = 0, []
        is_pe = head[:2] == b"MZ"
        is_elf = head[:4] == b"\x7fELF"
        parts = low.split(".")
        if (len(parts) >= 3 and "." + parts[-2] in self.DOC_EXT
                and "." + parts[-1] in (self.EXE_EXT | self.SCRIPT_EXT)):
            score += 60
            why.append("двойное расширение")
        if (is_pe or is_elf) and ext in self.DOC_EXT:
            score += 70
            why.append("исполняемый файл замаскирован под документ/медиа")
        if is_pe or ext in self.EXE_EXT:
            ent = entropy(head[:262144])
            if ent > 7.5 and size < 30 * 1024 * 1024:
                score += 35
                why.append(f"файл упакован/зашифрован (энтропия {ent:.1f})")
            if sum(1 for a in self.INJECT_APIS if a in head) >= 3:
                score += 40
                why.append("API внедрения кода в чужие процессы")
        if ext in self.SCRIPT_EXT:
            text = head.lower()
            for pat, label in self.SCRIPT_PATTERNS:
                if pat in text:
                    score += 30
                    why.append(label)
        if score >= 60:
            return res("high" if score >= 80 else "medium",
                       "Heur.Suspicious.Generic", "; ".join(why))
        return None


class ScanWorker(QThread):
    counting = Signal(int)
    progress = Signal(int, int, str)
    found = Signal(dict)
    scan_done = Signal(dict)

    def __init__(self, engine, roots):
        super().__init__()
        self.engine, self.roots, self._stop = engine, roots, False

    def stop(self):
        self._stop = True

    def run(self):
        t0 = time.monotonic()
        files, last = [], 0.0
        for root in self.roots:
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                if self._stop:
                    break
                dirnames[:] = [d for d in dirnames if not self.engine.skip_dir(d)]
                files.extend(os.path.join(dirpath, fn) for fn in filenames)
                now = time.monotonic()
                if now - last > 0.08:
                    self.counting.emit(len(files))
                    last = now
        total, threats, scanned = len(files), 0, 0
        last = 0.0
        for i, p in enumerate(files, 1):
            if self._stop:
                break
            scanned = i
            r = self.engine.analyze(p)
            if r:
                threats += 1
                self.found.emit(r)
            now = time.monotonic()
            if now - last > 0.05 or i == total:
                self.progress.emit(i, total, p)
                last = now
        self.scan_done.emit({"scanned": scanned, "total": total, "threats": threats,
                             "stopped": self._stop, "time": time.monotonic() - t0})


class Quarantine:
    def __init__(self, store):
        self.store = store

    @property
    def items(self):
        return self.store.data["quarantine"]

    def add(self, t):
        qid = uuid.uuid4().hex
        try:
            shutil.move(t["path"], QDIR / f"{qid}.quar")
        except Exception as e:
            return False, str(e)
        self.items.append({"id": qid, "orig": t["path"], "name": t["name"],
                           "threat": t["threat"], "level": t["level"], "size": t["size"],
                           "date": datetime.now().strftime("%d.%m.%Y %H:%M")})
        self.store.save()
        return True, ""

    def _find(self, qid):
        return next((i for i in self.items if i["id"] == qid), None)

    def restore(self, qid):
        it = self._find(qid)
        if not it:
            return False, "не найдено"
        dest = Path(it["orig"])
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest = dest.with_name(dest.stem + "_restored" + dest.suffix)
            shutil.move(QDIR / f"{qid}.quar", dest)
        except Exception as e:
            return False, str(e)
        self.items.remove(it)
        self.store.save()
        return True, str(dest)

    def delete(self, qid):
        it = self._find(qid)
        if not it:
            return False
        try:
            os.remove(QDIR / f"{qid}.quar")
        except OSError:
            pass
        self.items.remove(it)
        self.store.save()
        return True


# ───────────────────────────── Виджеты ─────────────────────────────
def _drop(w):
    w.hide()
    w.setParent(None)
    w.deleteLater()


def fade_in(w, ms=260):
    eff = QGraphicsOpacityEffect(w)
    w.setGraphicsEffect(eff)
    a = QPropertyAnimation(eff, b"opacity", w)
    a.setDuration(ms)
    a.setStartValue(0.0)
    a.setEndValue(1.0)
    a.setEasingCurve(QEasingCurve.OutCubic)
    a.finished.connect(lambda: w.setGraphicsEffect(None))
    a.start(QPropertyAnimation.DeleteWhenStopped)


def shield_path(cx, cy, s):
    p = QPainterPath()
    p.moveTo(cx, cy - s)
    p.cubicTo(cx + s * .35, cy - s * .8, cx + s * .7, cy - s * .75, cx + s * .85, cy - s * .7)
    p.cubicTo(cx + s * .85, cy + s * .1, cx + s * .55, cy + s * .65, cx, cy + s)
    p.cubicTo(cx - s * .55, cy + s * .65, cx - s * .85, cy + s * .1, cx - s * .85, cy - s * .7)
    p.cubicTo(cx - s * .7, cy - s * .75, cx - s * .35, cy - s * .8, cx, cy - s)
    return p


def make_tray_icon(state="safe") -> QIcon:
    """Рисует иконку щита AEGIS для системного трея."""
    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    g = QLinearGradient(0, 6, 0, 58)
    if state == "danger":
        g.setColorAt(0, QColor("#FB7185"))
        g.setColorAt(1, QColor("#F43F5E"))
    elif state == "scanning":
        g.setColorAt(0, QColor("#22D3EE"))
        g.setColorAt(1, QColor("#3B82F6"))
    else:
        g.setColorAt(0, QColor("#22D3EE"))
        g.setColorAt(1, QColor("#8B5CF6"))
    p.setPen(Qt.NoPen)
    p.setBrush(g)
    p.drawPath(shield_path(32, 32, 26))

    pen = QPen(QColor("white"), 5.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    if state == "danger":
        p.drawLine(QPointF(32, 18), QPointF(32, 34))
        p.setPen(Qt.NoPen)
        p.setBrush(QColor("white"))
        p.drawEllipse(QPointF(32, 44), 3.2, 3.2)
    else:
        p.drawPolyline([QPointF(21, 33), QPointF(29, 41), QPointF(44, 24)])
    p.end()
    return QIcon(pm)


class ElidedLabel(QLabel):
    def __init__(self, text="", mode=Qt.ElideMiddle):
        super().__init__()
        self._full, self._mode = text, mode
        self.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.setMinimumWidth(10)
        self.setFull(text)

    def setFull(self, t):
        self._full = t
        self.setToolTip(t)
        self._apply()

    def _apply(self):
        QLabel.setText(self, self.fontMetrics().elidedText(
            self._full, self._mode, max(10, self.width() - 2)))

    def resizeEvent(self, e):
        self._apply()
        super().resizeEvent(e)


class GlowButton(QPushButton):
    def __init__(self, text, ghost=False, c1="#22D3EE", c2="#8B5CF6", glow=True):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(46)
        self.setMinimumWidth(int(self.fontMetrics().horizontalAdvance(text) * 1.1) + 36)
        if ghost:
            self.setStyleSheet(
                "QPushButton{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.13);"
                "color:#E5E7EB;border-radius:14px;padding:0 16px;font-weight:600;font-size:13px;}"
                "QPushButton:hover{background:rgba(255,255,255,0.13);}"
                "QPushButton:disabled{color:#6B7280;background:rgba(255,255,255,0.03);}")
        else:
            self.setStyleSheet(
                f"QPushButton{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {c1},stop:1 {c2});"
                "border:none;color:#06101C;border-radius:14px;padding:0 18px;font-weight:700;font-size:14px;}"
                "QPushButton:disabled{background:rgba(255,255,255,0.06);color:#6B7280;}")
        self.fx = None
        if glow and not ghost:
            self.fx = QGraphicsDropShadowEffect(self)
            self.fx.setBlurRadius(14)
            self.fx.setOffset(0, 4)
            col = QColor(c1)
            col.setAlpha(150)
            self.fx.setColor(col)
            self.setGraphicsEffect(self.fx)
            self.anim = QPropertyAnimation(self.fx, b"blurRadius", self)
            self.anim.setDuration(200)

    def _glow(self, v):
        if self.fx:
            self.anim.stop()
            self.anim.setStartValue(self.fx.blurRadius())
            self.anim.setEndValue(v)
            self.anim.start()

    def enterEvent(self, e):
        self._glow(38)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._glow(14)
        super().leaveEvent(e)


class Switch(QWidget):
    toggled = Signal(bool)

    def __init__(self, checked=True):
        super().__init__()
        self.setFixedSize(54, 30)
        self.setCursor(Qt.PointingHandCursor)
        self._on, self._pos = checked, 1.0 if checked else 0.0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(240)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._set)

    def _set(self, v):
        self._pos = float(v)
        self.update()

    def setChecked(self, on, emit=False):
        self._on = on
        self.anim.stop()
        self.anim.setStartValue(self._pos)
        self.anim.setEndValue(1.0 if on else 0.0)
        self.anim.start()
        if emit:
            self.toggled.emit(on)

    def mousePressEvent(self, e):
        self.setChecked(not self._on, True)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(mix(QColor(255, 255, 255, 40), QColor("#22D3EE"), self._pos))
        p.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 15, 15)
        p.setBrush(QColor("white"))
        p.drawEllipse(QPointF(15 + self._pos * 24, 15), 11, 11)


class ShieldHero(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(300, 300)
        self.state, self.t, self.pop = "safe", 0.0, 1.0
        self.c_from = self.c_to = QColor(COL["safe"])
        self.color = QColor(COL["safe"])
        self.col_anim = QVariantAnimation(self)
        self.col_anim.setDuration(600)
        self.col_anim.setStartValue(0.0)
        self.col_anim.setEndValue(1.0)
        self.col_anim.valueChanged.connect(
            lambda v: setattr(self, "color", mix(self.c_from, self.c_to, float(v))))
        self.pop_anim = QVariantAnimation(self)
        self.pop_anim.setDuration(700)
        self.pop_anim.setStartValue(0.0)
        self.pop_anim.setEndValue(1.0)
        self.pop_anim.setEasingCurve(QEasingCurve.OutBack)
        self.pop_anim.valueChanged.connect(lambda v: setattr(self, "pop", float(v)))
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(16)

    def set_state(self, s):
        if s == self.state:
            return
        self.state = s
        self.c_from, self.c_to = QColor(self.color), QColor(COL[s])
        self.col_anim.stop()
        self.col_anim.start()
        self.pop_anim.stop()
        self.pop_anim.start()

    def tick(self):
        self.t += 0.016
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h, t = self.width(), self.height(), self.t
        c = QPointF(w / 2, h / 2)
        R = min(w, h) / 2 - 6
        col = self.color
        p.setPen(Qt.NoPen)
        g = QRadialGradient(c, R)
        g.setColorAt(0, QColor(col.red(), col.green(), col.blue(), 70 + int(25 * math.sin(t * 2))))
        g.setColorAt(1, QColor(col.red(), col.green(), col.blue(), 0))
        p.setBrush(g)
        p.drawEllipse(c, R, R)
        for i in range(3):
            ph = (t * 0.4 + i / 3) % 1.0
            r = R * 0.45 + R * 0.55 * ph
            p.setPen(QPen(QColor(col.red(), col.green(), col.blue(), int(120 * (1 - ph))), 2))
            p.setBrush(Qt.NoBrush)
            p.drawEllipse(c, r, r)
        if self.state == "scanning":
            cg = QConicalGradient(c, -((t * 220) % 360))
            cg.setColorAt(0, QColor(col.red(), col.green(), col.blue(), 170))
            cg.setColorAt(0.28, QColor(col.red(), col.green(), col.blue(), 0))
            cg.setColorAt(1, QColor(col.red(), col.green(), col.blue(), 0))
            p.setPen(Qt.NoPen)
            p.setBrush(cg)
            p.drawEllipse(c, R * 0.92, R * 0.92)
        dg = QRadialGradient(c, R * 0.62)
        dg.setColorAt(0, QColor(18, 24, 44, 245))
        dg.setColorAt(1, QColor(10, 14, 28, 245))
        p.setBrush(dg)
        p.setPen(QPen(QColor(col.red(), col.green(), col.blue(), 120), 1.5))
        p.drawEllipse(c, R * 0.62, R * 0.62)
        s = R * 0.38 * (0.85 + 0.15 * self.pop)
        cx, cy = c.x(), c.y() + math.sin(t * 2) * 3
        sg = QLinearGradient(cx, cy - s, cx, cy + s)
        sg.setColorAt(0, col.lighter(135))
        sg.setColorAt(1, col.darker(130))
        p.setPen(Qt.NoPen)
        p.setBrush(sg)
        p.drawPath(shield_path(cx, cy, s))
        pen = QPen(QColor(255, 255, 255, 245), s * 0.15)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        if self.state == "safe":
            path = QPainterPath()
            path.moveTo(cx - s * .38, cy + s * .02)
            path.lineTo(cx - s * .1, cy + s * .3)
            path.lineTo(cx + s * .4, cy - s * .28)
            p.setPen(pen)
            p.setBrush(Qt.NoBrush)
            p.drawPath(path)
        elif self.state == "scanning":
            p.setPen(Qt.NoPen)
            for k in range(3):
                a = 0.3 + 0.7 * max(0.0, math.sin(t * 5 - k * 0.9))
                p.setBrush(QColor(255, 255, 255, int(255 * a)))
                p.drawEllipse(QPointF(cx + (k - 1) * s * .38, cy), s * .09, s * .09)
        else:
            p.setPen(pen)
            p.drawLine(QPointF(cx, cy - s * .38), QPointF(cx, cy + s * .12))
            p.setPen(Qt.NoPen)
            p.setBrush(QColor("white"))
            p.drawEllipse(QPointF(cx, cy + s * .4), s * .09, s * .09)


class ProgressRing(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(270, 270)
        self.target = self.val = 0.0
        self.t, self.busy, self.sub = 0.0, False, "Готов к проверке"
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(16)

    def set_progress(self, v):
        self.target = max(0.0, min(1.0, v))

    def tick(self):
        self.t += 0.016
        self.val += (self.target - self.val) * 0.12
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        R = min(w, h) / 2 - 22
        c = QPointF(w / 2, h / 2)
        rect = QRectF(c.x() - R, c.y() - R, 2 * R, 2 * R)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(255, 255, 255, 20), 14))
        p.drawEllipse(c, R, R)
        if self.busy:
            p.setPen(QPen(QColor(34, 211, 238, 90), 2))
            p.drawArc(rect.adjusted(-14, -14, 14, 14), int(-self.t * 140 * 16), 90 * 16)
            p.drawArc(rect.adjusted(-14, -14, 14, 14), int(-self.t * 140 * 16) + 180 * 16, 40 * 16)
        if self.val > 0.002:
            cg = QConicalGradient(c, 90)
            cg.setColorAt(0.0, QColor("#8B5CF6"))
            cg.setColorAt(1.0, QColor("#22D3EE"))
            pen = QPen(QBrush(cg), 14)
            pen.setCapStyle(Qt.RoundCap)
            p.setPen(pen)
            p.drawArc(rect, 90 * 16, -int(360 * 16 * self.val))
            ang = math.radians(90 - 360 * self.val)
            dot = QPointF(c.x() + R * math.cos(ang), c.y() - R * math.sin(ang))
            gl = QRadialGradient(dot, 18)
            gl.setColorAt(0, QColor(255, 255, 255, 200))
            gl.setColorAt(1, QColor(255, 255, 255, 0))
            p.setPen(Qt.NoPen)
            p.setBrush(gl)
            p.drawEllipse(dot, 18, 18)
        p.setPen(QColor("white"))
        f = QFont(self.font())
        f.setPixelSize(50)
        f.setBold(True)
        p.setFont(f)
        p.drawText(QRectF(0, c.y() - 46, w, 70), Qt.AlignCenter, f"{int(self.val * 100)}%")
        f.setPixelSize(13)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QColor("#9CA3AF"))
        p.drawText(QRectF(0, c.y() + 22, w, 26), Qt.AlignCenter, self.sub)


class StatCard(QFrame):
    def __init__(self, title, color):
        super().__init__()
        self.setObjectName("card")
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 18, 22, 18)
        v.setSpacing(4)
        self.value = QLabel("0")
        self.value.setStyleSheet(f"font-size:30px;font-weight:700;color:{color};")
        cap = QLabel(title)
        cap.setStyleSheet("font-size:12px;color:#9CA3AF;")
        v.addWidget(self.value)
        v.addWidget(cap)
        self.cur = 0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(900)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(
            lambda x: self.value.setText(f"{int(x):,}".replace(",", " ")))

    def set_number(self, n):
        self.anim.stop()
        self.anim.setStartValue(self.cur)
        self.anim.setEndValue(int(n))
        self.cur = int(n)
        self.anim.start()

    def set_text(self, s):
        self.value.setText(s)


class Card(QFrame):
    def __init__(self, title=None, sub=None, pad=(22, 18, 22, 18)):
        super().__init__()
        self.setObjectName("panel")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(*pad)
        self.lay.setSpacing(10)
        self.head = QHBoxLayout()
        if title:
            box = QVBoxLayout()
            box.setSpacing(0)
            t = QLabel(title)
            t.setStyleSheet("font-size:15px;font-weight:700;color:white;")
            box.addWidget(t)
            if sub:
                s = QLabel(sub)
                s.setStyleSheet("font-size:11px;color:#6B7280;")
                box.addWidget(s)
            self.head.addLayout(box)
            self.head.addStretch()
            self.lay.addLayout(self.head)


class Meter(QWidget):
    def __init__(self, name, c1, c2):
        super().__init__()
        self.setFixedHeight(44)
        self.name, self.c1, self.c2 = name, QColor(c1), QColor(c2)
        self.val, self.text = 0.0, "—"
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(700)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._s)

    def _s(self, v):
        self.val = float(v)
        self.update()

    def set_value(self, pct, text):
        self.text = text
        self.anim.stop()
        if pct is None:
            self.val = 0.0
            self.update()
            return
        self.anim.setStartValue(self.val)
        self.anim.setEndValue(max(0.0, min(100.0, float(pct))))
        self.anim.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width()
        f = QFont(self.font())
        f.setPixelSize(12)
        p.setFont(f)
        p.setPen(QColor("#D1D5DB"))
        p.drawText(QRectF(0, 0, w, 18), Qt.AlignLeft | Qt.AlignVCenter, self.name)
        p.setPen(QColor("#9CA3AF"))
        p.drawText(QRectF(0, 0, w, 18), Qt.AlignRight | Qt.AlignVCenter, self.text)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(255, 255, 255, 22))
        p.drawRoundedRect(QRectF(0, 26, w, 10), 5, 5)
        if self.val > 0.3:
            g = QLinearGradient(0, 0, w, 0)
            g.setColorAt(0, self.c1)
            g.setColorAt(1, self.c2)
            p.setBrush(g)
            p.drawRoundedRect(QRectF(0, 26, max(10.0, w * self.val / 100.0), 10), 5, 5)


class Sparkline(QWidget):
    def __init__(self, color="#22D3EE", n=60):
        super().__init__()
        self.setMinimumHeight(80)
        self.n, self.color = n, QColor(color)
        self.data = [0.0] * n

    def push(self, v):
        self.data.append(float(v))
        del self.data[0]
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        p.setPen(QPen(QColor(255, 255, 255, 16), 1))
        for k in range(1, 4):
            p.drawLine(0, int(h * k / 4), w, int(h * k / 4))
        pts = [QPointF(i * w / (self.n - 1), h - 3 - (v / 100.0) * (h - 8))
               for i, v in enumerate(self.data)]
        path = QPainterPath(pts[0])
        for a, b in zip(pts, pts[1:]):
            path.quadTo(a, QPointF((a.x() + b.x()) / 2, (a.y() + b.y()) / 2))
        path.lineTo(pts[-1])
        area = QPainterPath(path)
        area.lineTo(w, h)
        area.lineTo(0, h)
        area.closeSubpath()
        c = self.color
        g = QLinearGradient(0, 0, 0, h)
        g.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 100))
        g.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 0))
        p.fillPath(area, g)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(c, 2))
        p.drawPath(path)


class BarChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumHeight(120)
        self.items, self.prog = [], 1.0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(800)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._s)

    def _s(self, v):
        self.prog = float(v)
        self.update()

    def set_items(self, items):
        self.items = list(items)
        self.anim.stop()
        self.anim.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        f = QFont(self.font())
        f.setPixelSize(11)
        p.setFont(f)
        if not self.items:
            p.setPen(QColor("#6B7280"))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignCenter, "Проверок пока не было\nЗапустите первую проверку")
            return
        n, top, bottom = len(self.items), 16, 22
        avail = h - top - bottom
        mx = max(1, max(i["files"] for i in self.items))
        slot = w / n
        bw = min(34.0, slot * 0.55)
        for k, it in enumerate(self.items):
            x = slot * k + (slot - bw) / 2
            bh = max(5.0, avail * it["files"] / mx * self.prog)
            rect = QRectF(x, top + avail - bh, bw, bh)
            g = QLinearGradient(0, rect.top(), 0, rect.bottom())
            if it["threats"]:
                g.setColorAt(0, QColor("#FB7185"))
                g.setColorAt(1, QColor("#F43F5E"))
            else:
                g.setColorAt(0, QColor("#22D3EE"))
                g.setColorAt(1, QColor("#8B5CF6"))
            p.setPen(Qt.NoPen)
            p.setBrush(g)
            p.drawRoundedRect(rect, 7, 7)
            p.setPen(QColor("#9CA3AF"))
            p.drawText(QRectF(slot * k, h - bottom + 4, slot, 16), Qt.AlignCenter, it["t"])
            if it["threats"]:
                p.setPen(QColor("#FB7185"))
                p.drawText(QRectF(slot * k, rect.top() - 16, slot, 14), Qt.AlignCenter, str(it["threats"]))


class ModeCard(QPushButton):
    def __init__(self, icon, title, desc):
        super().__init__()
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(80)
        self.setStyleSheet(
            "QPushButton{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:18px;}"
            "QPushButton:hover{background:rgba(255,255,255,0.09);}"
            "QPushButton:checked{border:1px solid #22D3EE;background:rgba(34,211,238,0.12);}")
        h = QHBoxLayout(self)
        h.setContentsMargins(20, 12, 20, 12)
        h.setSpacing(16)
        ic = QLabel(icon)
        ic.setStyleSheet("font-size:26px;color:#22D3EE;")
        ic.setFixedWidth(34)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("font-size:14px;font-weight:700;color:white;")
        d = QLabel(desc)
        d.setStyleSheet("font-size:11px;color:#9CA3AF;")
        d.setWordWrap(True)
        col.addWidget(t)
        col.addWidget(d)
        h.addWidget(ic)
        h.addLayout(col, 1)
        for w in (ic, t, d):
            w.setAttribute(Qt.WA_TransparentForMouseEvents)


class ItemRow(QFrame):
    def __init__(self, color, title, sub, detail, buttons):
        super().__init__()
        self.setObjectName("row")
        h = QHBoxLayout(self)
        h.setContentsMargins(18, 12, 14, 12)
        h.setSpacing(14)
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{color};font-size:16px;")
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title)
        t.setStyleSheet("font-weight:700;font-size:14px;color:white;")
        s = ElidedLabel(sub)
        s.setStyleSheet("color:#9CA3AF;font-size:12px;")
        d = ElidedLabel(detail, Qt.ElideRight)
        d.setStyleSheet("color:#6B7280;font-size:11px;")
        for w in (t, s, d):
            col.addWidget(w)
        h.addWidget(dot)
        h.addLayout(col, 1)
        self.btn_box = QHBoxLayout()
        self.btn_box.setSpacing(8)
        for txt, cb, primary in buttons:
            b = GlowButton(txt, ghost=not primary, glow=False)
            b.setMinimumHeight(36)
            b.setMinimumWidth(110)
            b.clicked.connect(cb)
            self.btn_box.addWidget(b)
        h.addLayout(self.btn_box)

    def set_done(self, text, color="#34D399"):
        while self.btn_box.count():
            it = self.btn_box.takeAt(0)
            if it.widget():
                _drop(it.widget())
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color:{color};font-weight:600;font-size:13px;")
        self.btn_box.addWidget(lbl)


class Toast(QFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("toast")
        h = QHBoxLayout(self)
        h.setContentsMargins(18, 14, 22, 14)
        h.setSpacing(12)
        self.dot = QLabel("●")
        self.lbl = QLabel()
        self.lbl.setStyleSheet("color:white;font-size:13px;font-weight:600;")
        h.addWidget(self.dot)
        h.addWidget(self.lbl)
        self.anim = QPropertyAnimation(self, b"pos", self)
        self.anim.finished.connect(lambda: self.hide() if self._leaving else None)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self._out)
        self._leaving = False
        self.hide()

    def show_msg(self, text, level="info"):
        color = {"info": "#22D3EE", "ok": "#34D399", "warn": "#FBBF24", "danger": "#F43F5E"}[level]
        self.dot.setStyleSheet(f"color:{color};font-size:16px;")
        self.lbl.setText(text)
        self.adjustSize()
        pw, ph = self.parent().width(), self.parent().height()
        end = QPoint(pw - self.width() - 28, ph - self.height() - 28)
        self._leaving = False
        self.raise_()
        self.show()
        self.anim.stop()
        self.anim.setDuration(380)
        self.anim.setEasingCurve(QEasingCurve.OutBack)
        self.anim.setStartValue(QPoint(pw + 10, end.y()))
        self.anim.setEndValue(end)
        self.anim.start()
        self.timer.start(3800)

    def _out(self):
        self._leaving = True
        self.anim.stop()
        self.anim.setDuration(300)
        self.anim.setEasingCurve(QEasingCurve.InCubic)
        self.anim.setStartValue(self.pos())
        self.anim.setEndValue(QPoint(self.parent().width() + 10, self.y()))
        self.anim.start()


class LogoWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(70)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        g = QLinearGradient(0, 14, 0, 54)
        g.setColorAt(0, QColor("#22D3EE"))
        g.setColorAt(1, QColor("#8B5CF6"))
        p.setPen(Qt.NoPen)
        p.setBrush(g)
        p.drawPath(shield_path(40, 35, 19))
        p.setPen(QPen(QColor("white"), 3.4, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.drawPolyline([QPointF(32, 36), QPointF(38, 42), QPointF(49, 29)])
        f = QFont(self.font())
        f.setPixelSize(21)
        f.setBold(True)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 3)
        p.setFont(f)
        p.setPen(QColor("white"))
        p.drawText(QPointF(70, 36), "AEGIS")
        f.setPixelSize(10)
        f.setBold(False)
        f.setLetterSpacing(QFont.AbsoluteSpacing, 3.5)
        p.setFont(f)
        p.setPen(QColor("#22D3EE"))
        p.drawText(QPointF(71, 52), "ANTIVIRUS")


class FadeStack(QStackedWidget):
    def go(self, i):
        if i == self.currentIndex():
            return
        self.setCurrentIndex(i)
        fade_in(self.currentWidget(), 300)


class TitleBar(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setFixedHeight(52)
        h = QHBoxLayout(self)
        h.setContentsMargins(20, 10, 16, 0)
        h.addStretch()
        for txt, cb, hov, tip in (
            ("—", win.showMinimized, "rgba(255,255,255,0.14)", "Свернуть"),
            ("✕", win.close, "#F43F5E", "Свернуть в трей"),
        ):
            b = QPushButton(txt)
            b.setToolTip(tip)
            b.setFixedSize(34, 34)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(
                "QPushButton{background:rgba(255,255,255,0.05);border:none;"
                f"border-radius:17px;color:#D1D5DB;font-size:13px;}}QPushButton:hover{{background:{hov};color:white;}}")
            b.clicked.connect(cb)
            h.addWidget(b)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton and self.win.windowHandle():
            self.win.windowHandle().startSystemMove()


def make_scroll():
    sc = QScrollArea()
    sc.setWidgetResizable(True)
    sc.setFrameShape(QFrame.NoFrame)
    inner = QWidget()
    inner.setObjectName("scrollInner")
    lay = QVBoxLayout(inner)
    lay.setContentsMargins(0, 0, 6, 0)
    lay.setSpacing(10)
    lay.addStretch()
    sc.setWidget(inner)
    return sc, lay


QSS = """
* { font-family: 'Segoe UI','Inter','SF Pro Display','Noto Sans',sans-serif; }
QLabel { color:#E5E7EB; background:transparent; }
QFrame#card { background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.09); border-radius:20px; }
QFrame#card:hover { background:rgba(255,255,255,0.085); border:1px solid rgba(34,211,238,0.40); }
QFrame#panel { background:rgba(255,255,255,0.045); border:1px solid rgba(255,255,255,0.09); border-radius:22px; }
QFrame#sideCard { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); border-radius:16px; }
QFrame#row { background:rgba(255,255,255,0.045); border:1px solid rgba(255,255,255,0.08); border-radius:16px; }
QFrame#row:hover { background:rgba(255,255,255,0.075); }
QFrame#toast { background:rgba(17,24,46,0.97); border:1px solid rgba(255,255,255,0.16); border-radius:16px; }
QScrollArea { background:transparent; border:none; }
QScrollArea > QWidget > QWidget { background:transparent; }
QWidget#scrollInner { background:transparent; }
QScrollBar:vertical { background:transparent; width:8px; margin:0; }
QScrollBar::handle:vertical { background:rgba(255,255,255,0.18); border-radius:4px; min-height:30px; }
QScrollBar::handle:vertical:hover { background:rgba(255,255,255,0.32); }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background:transparent; }
QListWidget { background:transparent; border:none; outline:none; }
QListWidget::item { padding:9px 6px; border-bottom:1px solid rgba(255,255,255,0.06); }
"""


# ───────────────────────────── Главное окно ─────────────────────────────
class MainWindow(QWidget):
    NAV = [("◉   Защита", 0), ("⟳   Проверка", 1), ("▣   Карантин", 2), ("≣   Журнал", 3)]
    ORBS = [("#8B5CF6", .15, .2, .55, .5), ("#22D3EE", .85, .15, .45, .4),
            ("#EC4899", .7, .95, .5, .35), ("#3B82F6", .1, .9, .4, .45)]

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle("AEGIS Antivirus")
        self.setWindowIcon(make_tray_icon("safe"))
        self.resize(1260, 830)
        self.setMinimumSize(1100, 740)
        self.setStyleSheet(QSS)

        self.store = Store()
        self.engine = Engine()
        self.quar = Quarantine(self.store)
        self.engine.heuristics = self.store.data.get("heuristics", True)
        self.worker = None
        self.scanning = False
        self.pending = {}
        self.rows = {}
        self.mode = "quick"
        self.bg_t = 0.0
        self.scan_t0 = 0.0
        self.seen = set()
        self._force_quit = False
        self._tray_hint_shown = False

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self.build_sidebar())
        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(TitleBar(self))
        self.stack = FadeStack()
        for page in (self.build_dashboard(), self.build_scan(),
                     self.build_quarantine(), self.build_log()):
            self.stack.addWidget(page)
        right.addWidget(self.stack, 1)
        root.addLayout(right, 1)

        self.grip = QSizeGrip(self)
        self.grip.resize(16, 16)
        self.toast_w = Toast(self)
        self.setup_tray()

        self.bg_timer = QTimer(self)
        self.bg_timer.timeout.connect(self._bg_tick)
        self.bg_timer.start(40)
        self.clock = QTimer(self)
        self.clock.timeout.connect(self._clock_tick)
        self.rt_timer = QTimer(self)
        self.rt_timer.timeout.connect(self.rt_tick)
        self.rt_timer.start(3000)
        self.seen = self.snapshot()
        if psutil:
            psutil.cpu_percent(None)
        self.sys_timer = QTimer(self)
        self.sys_timer.timeout.connect(self.sys_tick)
        self.sys_timer.start(1000)
        self.sys_tick()

        self.refresh_stats()
        self.refresh_q()
        self.refresh_log()
        self.refresh_state()

    # ── системный трей ──
    def setup_tray(self):
        self.tray = QSystemTrayIcon(make_tray_icon("safe"), self)
        self.tray.setToolTip("AEGIS Antivirus — защита активна")

        menu = QMenu()
        menu.setStyleSheet(
            "QMenu{background:#0F1530;color:#E5E7EB;border:1px solid rgba(255,255,255,0.14);"
            "border-radius:10px;padding:6px;}"
            "QMenu::item{padding:7px 20px;border-radius:6px;}"
            "QMenu::item:selected{background:rgba(34,211,238,0.22);color:white;}"
            "QMenu::separator{height:1px;background:rgba(255,255,255,0.09);margin:5px 8px;}")

        act_open = QAction("Открыть AEGIS", self)
        act_open.triggered.connect(self.restore_from_tray)
        act_scan = QAction("Быстрая проверка", self)
        act_scan.triggered.connect(self.tray_quick_scan)
        self.act_rt = QAction("Защита в реальном времени", self)
        self.act_rt.setCheckable(True)
        self.act_rt.setChecked(self.store.data.get("realtime", True))
        self.act_rt.triggered.connect(lambda checked: self.sw.setChecked(checked, True))
        act_quit = QAction("Выход", self)
        act_quit.triggered.connect(self.quit_app)

        menu.addAction(act_open)
        menu.addAction(act_scan)
        menu.addAction(self.act_rt)
        menu.addSeparator()
        menu.addAction(act_quit)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.messageClicked.connect(self.on_tray_message_clicked)
        self.tray.show()

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            if self.isVisible() and not self.isMinimized():
                self.hide_to_tray()
            else:
                self.restore_from_tray()

    def on_tray_message_clicked(self):
        self.restore_from_tray()
        if self.pending:
            self.go(1)

    def restore_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def hide_to_tray(self, silent=False):
        self.hide()
        if not silent and not self._tray_hint_shown and self.tray.isVisible():
            self._tray_hint_shown = True
            self.tray.showMessage(
                "AEGIS Antivirus",
                "Антивирус продолжает защиту в фоновом режиме в системном трее.",
                QSystemTrayIcon.Information,
                3500,
            )

    def tray_quick_scan(self):
        self.restore_from_tray()
        self.set_mode("quick")
        self.start_scan()

    def notify_tray(self, title, body, level="info"):
        if not self.tray.isVisible():
            return
        icon = {
            "danger": QSystemTrayIcon.Critical,
            "warn": QSystemTrayIcon.Warning,
        }.get(level, QSystemTrayIcon.Information)
        self.tray.showMessage(title, body, icon, 6000)

    def quit_app(self):
        self._force_quit = True
        self.tray.hide()
        self.close()
        QApplication.quit()

    # ── фон ──
    def _bg_tick(self):
        self.bg_t += 0.04
        self.update()

    def hideEvent(self, e):
        if hasattr(self, "bg_timer"):
            self.bg_timer.stop()
        super().hideEvent(e)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 22, 22)
        p.setClipPath(path)
        bg = QLinearGradient(0, 0, w, h)
        bg.setColorAt(0, QColor("#080C18"))
        bg.setColorAt(1, QColor("#0F1530"))
        p.fillPath(path, bg)
        p.setPen(Qt.NoPen)
        for i, (col, fx, fy, r, sp) in enumerate(self.ORBS):
            x = w * (fx + 0.12 * math.sin(self.bg_t * sp + i))
            y = h * (fy + 0.12 * math.cos(self.bg_t * sp * 0.8 + i * 2))
            rad = max(w, h) * r
            g = QRadialGradient(QPointF(x, y), rad)
            c0 = QColor(col)
            c0.setAlpha(75)
            c1 = QColor(col)
            c1.setAlpha(0)
            g.setColorAt(0, c0)
            g.setColorAt(1, c1)
            p.setBrush(g)
            p.drawEllipse(QPointF(x, y), rad, rad)
        p.setBrush(QColor(255, 255, 255, 9))
        p.drawRect(0, 0, SIDEBAR_W, h)
        p.setPen(QColor(255, 255, 255, 18))
        p.drawLine(SIDEBAR_W, 0, SIDEBAR_W, h)
        p.setClipping(False)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(255, 255, 255, 32), 1))
        p.drawPath(path)

    def resizeEvent(self, e):
        self.grip.move(self.width() - 22, self.height() - 22)
        self.grip.raise_()
        super().resizeEvent(e)

    # ── сайдбар ──
    def _sb_kv(self, lay, key, val="—"):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        a = QLabel(key)
        a.setStyleSheet("color:#9CA3AF;font-size:11px;")
        b = QLabel(val)
        b.setStyleSheet("color:white;font-size:11px;font-weight:600;")
        h.addWidget(a)
        h.addStretch()
        h.addWidget(b)
        lay.addWidget(w)
        return b

    def build_sidebar(self):
        sb = QWidget()
        sb.setFixedWidth(SIDEBAR_W)
        v = QVBoxLayout(sb)
        v.setContentsMargins(18, 22, 18, 20)
        v.setSpacing(14)
        v.addWidget(LogoWidget())

        self.nav_box = QWidget()
        nv = QVBoxLayout(self.nav_box)
        nv.setContentsMargins(0, 0, 0, 0)
        nv.setSpacing(6)
        self.indicator = QFrame(self.nav_box)
        self.indicator.setStyleSheet(
            "background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 rgba(34,211,238,0.24),stop:1 rgba(139,92,246,0.24));"
            "border:1px solid rgba(139,92,246,0.45);border-radius:14px;")
        self.ind_anim = QPropertyAnimation(self.indicator, b"geometry", self)
        self.ind_anim.setDuration(340)
        self.ind_anim.setEasingCurve(QEasingCurve.OutCubic)
        self.group = QButtonGroup(self)
        self.nav_btns = []
        for text, idx in self.NAV:
            b = QPushButton(text)
            b.setCheckable(True)
            b.setMinimumHeight(46)
            b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet("QPushButton{background:transparent;border:none;text-align:left;padding-left:18px;"
                            "color:#9CA3AF;font-size:14px;font-weight:600;}"
                            "QPushButton:hover{color:white;}QPushButton:checked{color:white;}")
            self.group.addButton(b, idx)
            self.nav_btns.append(b)
            nv.addWidget(b)
            b.clicked.connect(lambda _=False, i=idx: self.go(i))
        self.nav_btns[0].setChecked(True)
        self.indicator.lower()
        v.addWidget(self.nav_box)

        v.addStretch(1)

        # Карточка фонового щита (заполняет пустую область)
        guard = QFrame()
        guard.setObjectName("sideCard")
        gl = QVBoxLayout(guard)
        gl.setContentsMargins(14, 14, 14, 14)
        gl.setSpacing(8)

        gh = QHBoxLayout()
        gt = QLabel("Фоновый щит")
        gt.setStyleSheet("color:white;font-size:13px;font-weight:700;")
        self.sb_badge = QLabel("В трее")
        self.sb_badge.setStyleSheet(
            "background:rgba(52,211,153,0.16);color:#34D399;border-radius:8px;"
            "padding:2px 8px;font-size:10px;font-weight:700;")
        gh.addWidget(gt)
        gh.addStretch()
        gh.addWidget(self.sb_badge)
        gl.addLayout(gh)

        gsub = QLabel("Загрузки • Рабочий стол")
        gsub.setStyleSheet("color:#6B7280;font-size:11px;")
        gl.addWidget(gsub)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background:rgba(255,255,255,0.07);")
        gl.addWidget(sep)

        self.sb_watched = self._sb_kv(gl, "Под защитой", "0 файлов")
        self.sb_heur = self._sb_kv(gl, "Эвристика", "вкл")
        self.sb_autoq = self._sb_kv(gl, "Автокарантин", "выкл")
        self.sb_quar = self._sb_kv(gl, "В карантине", "0")
        v.addWidget(guard)

        # Быстрые действия в сайдбаре
        sb_btn_style = (
            "QPushButton{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.10);"
            "color:#E5E7EB;border-radius:12px;padding:0 12px;font-size:12px;font-weight:600;text-align:left;}"
            "QPushButton:hover{background:rgba(34,211,238,0.14);border:1px solid rgba(34,211,238,0.4);color:white;}"
        )
        btn_file = QPushButton("⌖   Проверить файл")
        btn_file.setMinimumHeight(38)
        btn_file.setCursor(Qt.PointingHandCursor)
        btn_file.setStyleSheet(sb_btn_style)
        btn_file.clicked.connect(self.scan_single_file)

        btn_tray = QPushButton("▾   Свернуть в трей")
        btn_tray.setMinimumHeight(38)
        btn_tray.setCursor(Qt.PointingHandCursor)
        btn_tray.setStyleSheet(sb_btn_style)
        btn_tray.clicked.connect(lambda: self.hide_to_tray(silent=False))

        v.addWidget(btn_file)
        v.addWidget(btn_tray)
        v.addStretch(1)

        self.sb_status = QLabel()
        self.sb_status.setStyleSheet("color:#9CA3AF;font-size:12px;")
        ver = QLabel("AEGIS v1.0  •  сигнатур: 0")
        ver.setStyleSheet("color:#6B7280;font-size:11px;")
        self.ver_lbl = ver
        v.addWidget(self.sb_status)
        v.addWidget(ver)
        return sb

    def showEvent(self, e):
        super().showEvent(e)
        if hasattr(self, "bg_timer") and not self.bg_timer.isActive():
            self.bg_timer.start(40)
        QTimer.singleShot(60, lambda: self.indicator.setGeometry(self.nav_btns[self.stack.currentIndex()].geometry()))
        self.ver_lbl.setText(f"AEGIS v1.0  •  сигнатур: {len(self.engine.sigs)}")

    def go(self, i):
        self.nav_btns[i].setChecked(True)
        self.ind_anim.stop()
        self.ind_anim.setStartValue(self.indicator.geometry())
        self.ind_anim.setEndValue(self.nav_btns[i].geometry())
        self.ind_anim.start()
        self.stack.go(i)

    # ── страница: защита ──
    def _sep(self):
        s = QFrame()
        s.setFixedHeight(1)
        s.setStyleSheet("background:rgba(255,255,255,0.07);")
        return s

    def _module(self, title, desc, widget):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 0, 2)
        col = QVBoxLayout()
        col.setSpacing(1)
        a = QLabel(title)
        a.setStyleSheet("font-size:13px;font-weight:600;color:white;")
        b = QLabel(desc)
        b.setStyleSheet("font-size:11px;color:#9CA3AF;")
        col.addWidget(a)
        col.addWidget(b)
        h.addLayout(col, 1)
        h.addWidget(widget)
        return w, b

    def build_dashboard(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 0, 28, 24)
        v.setSpacing(16)

        row1 = QHBoxLayout()
        row1.setSpacing(16)
        hero_card = Card(pad=(26, 14, 26, 14))
        hc = QHBoxLayout()
        hc.setSpacing(26)
        self.hero = ShieldHero()
        self.hero.setMinimumSize(230, 230)
        hc.addWidget(self.hero, 5)
        r = QVBoxLayout()
        r.setSpacing(10)
        r.addStretch()
        self.h_title = QLabel()
        self.h_title.setWordWrap(True)
        self.h_sub = QLabel()
        self.h_sub.setWordWrap(True)
        self.h_sub.setStyleSheet("font-size:14px;color:#9CA3AF;")
        self.h_chip = QLabel()
        self.h_chip.setStyleSheet("background:rgba(255,255,255,0.07);border-radius:11px;padding:5px 12px;"
                                  "color:#9CA3AF;font-size:11px;")
        r.addWidget(self.h_title)
        r.addWidget(self.h_sub)
        r.addWidget(self.h_chip, 0, Qt.AlignLeft)
        r.addSpacing(6)
        b1 = GlowButton("Быстрая проверка")
        b2 = GlowButton("Полная проверка", ghost=True)
        b1.clicked.connect(lambda: (self.set_mode("quick"), self.start_scan()))
        b2.clicked.connect(lambda: (self.set_mode("full"), self.start_scan()))
        for b in (b1, b2):
            b.setMinimumHeight(42)
        r.addWidget(b1)
        r.addWidget(b2)
        r.addStretch()
        hc.addLayout(r, 6)
        hero_card.lay.addLayout(hc)
        row1.addWidget(hero_card, 1)

        sys_card = Card("Состояние системы", "данные обновляются каждую секунду")
        sys_card.setFixedWidth(370)
        self.m_cpu = Meter("Процессор", "#22D3EE", "#3B82F6")
        self.m_ram = Meter("Память", "#8B5CF6", "#EC4899")
        self.m_disk = Meter("Диск", "#34D399", "#22D3EE")
        for m in (self.m_cpu, self.m_ram, self.m_disk):
            sys_card.lay.addWidget(m)
        cap = QLabel("Нагрузка CPU за последние 60 секунд")
        cap.setStyleSheet("font-size:11px;color:#6B7280;")
        sys_card.lay.addWidget(cap)
        self.spark = Sparkline()
        sys_card.lay.addWidget(self.spark, 1)
        row1.addWidget(sys_card)
        v.addLayout(row1, 3)

        cards = QHBoxLayout()
        cards.setSpacing(16)
        self.c_files = StatCard("Проверено файлов", "#22D3EE")
        self.c_threats = StatCard("Угроз найдено", "#F43F5E")
        self.c_quar = StatCard("В карантине", "#FBBF24")
        self.c_last = StatCard("Последняя проверка", "#34D399")
        for c in (self.c_files, self.c_threats, self.c_quar, self.c_last):
            cards.addWidget(c)
        v.addLayout(cards)

        row3 = QHBoxLayout()
        row3.setSpacing(16)
        mod = Card("Модули защиты", "включайте и отключайте компоненты")
        self.sw = Switch(self.store.data.get("realtime", True))
        self.sw.toggled.connect(self.on_realtime)
        self.sw_heur = Switch(self.store.data.get("heuristics", True))
        self.sw_heur.toggled.connect(self.on_heur)
        self.sw_autoq = Switch(self.store.data.get("autoq", False))
        self.sw_autoq.toggled.connect(self.on_autoq)
        pill = QLabel("Активна")
        pill.setStyleSheet("background:rgba(52,211,153,0.16);color:#34D399;border-radius:11px;"
                           "padding:4px 12px;font-size:11px;font-weight:700;")
        rows = [self._module("Защита в реальном времени", "Новые файлы в Загрузках и на рабочем столе", self.sw),
                self._module("Эвристический анализ", "Поиск подозрительных файлов без сигнатур", self.sw_heur),
                self._module("Автокарантин", "Сразу изолировать найденные угрозы", self.sw_autoq),
                self._module("База сигнатур", "", pill)]
        self.sig_desc = rows[3][1]
        for i, (w, _) in enumerate(rows):
            if i:
                mod.lay.addWidget(self._sep())
            mod.lay.addWidget(w)
        mod.lay.addStretch()
        ev = Card("Последние события", "журнал активности")
        self.ev_lay = QVBoxLayout()
        self.ev_lay.setSpacing(8)
        ev.lay.addLayout(self.ev_lay)
        ev.lay.addStretch()
        act = Card("Активность проверок", "файлы и угрозы за последние 7 проверок")
        self.chart = BarChart()
        act.lay.addWidget(self.chart, 1)
        row3.addWidget(mod, 4)
        row3.addWidget(ev, 4)
        row3.addWidget(act, 4)
        v.addLayout(row3, 2)
        return page

    # ── страница: проверка ──
    def build_scan(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 0, 28, 24)
        v.setSpacing(16)
        mr = QHBoxLayout()
        mr.setSpacing(14)
        self.mode_btns = {}
        for key, icon, title, desc in (("quick", "⚡", "Быстрая проверка", "Загрузки, рабочий стол, документы, Temp"),
                                       ("full", "◎", "Полная проверка", "Вся домашняя папка пользователя"),
                                       ("custom", "▤", "Выборочная проверка", "Выберите нужную папку")):
            b = ModeCard(icon, title, desc)
            b.clicked.connect(lambda _=False, k=key: self.set_mode(k))
            self.mode_btns[key] = b
            mr.addWidget(b)
        self.mode_btns["quick"].setChecked(True)
        v.addLayout(mr)

        mid_card = Card(pad=(26, 16, 26, 16))
        mid = QHBoxLayout()
        mid.setSpacing(26)
        self.ring = ProgressRing()
        self.ring.setMinimumSize(240, 240)
        mid.addWidget(self.ring, 0)
        pr = QVBoxLayout()
        pr.setSpacing(10)
        pr.addStretch()
        self.s_status = QLabel("Готов к проверке")
        self.s_status.setStyleSheet("font-size:24px;font-weight:700;color:white;")
        self.s_file = ElidedLabel("—")
        self.s_file.setStyleSheet("color:#9CA3AF;font-size:12px;")
        pr.addWidget(self.s_status)
        pr.addWidget(self.s_file)
        ms = QHBoxLayout()
        ms.setSpacing(34)
        self.m_files, self.m_threats, self.m_time = (self._mini("Файлов", "0"),
                                                      self._mini("Угроз", "0"),
                                                      self._mini("Время", "0:00"))
        for m in (self.m_files, self.m_threats, self.m_time):
            ms.addWidget(m[0])
        ms.addStretch()
        pr.addLayout(ms)
        pr.addSpacing(8)
        br = QHBoxLayout()
        br.setSpacing(10)
        self.btn_start = GlowButton("Начать проверку")
        self.btn_stop = GlowButton("Остановить", ghost=True)
        self.btn_stop.setEnabled(False)
        self.btn_test = GlowButton("Создать тест-угрозу", ghost=True)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_test.clicked.connect(self.make_test)
        for b in (self.btn_start, self.btn_stop):
            br.addWidget(b)
        pr.addLayout(br)
        pr.addStretch()
        mid.addLayout(pr, 1)
        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setStyleSheet("background:rgba(255,255,255,0.09);")
        mid.addWidget(sep)
        eng = QVBoxLayout()
        eng.setSpacing(12)
        et = QLabel("Движок проверки")
        et.setStyleSheet("font-size:15px;font-weight:700;color:white;")
        eng.addWidget(et)
        self.e_sigs = self._kv(eng, "Сигнатур в базе")
        self.e_heur = self._kv(eng, "Эвристика")
        self._kv(eng, "Хэш файлов до", "64 МБ")
        self._kv(eng, "Алгоритм хэша", "SHA-256")
        self.e_last = self._kv(eng, "Последняя проверка")
        eng.addStretch()
        eng.addWidget(self.btn_test)
        wrap = QWidget()
        wrap.setFixedWidth(250)
        wrap.setLayout(eng)
        mid.addWidget(wrap)
        mid_card.lay.addLayout(mid)
        v.addWidget(mid_card)

        tc = Card("Найденные угрозы", "результаты проверок и защиты в реальном времени")
        self.btn_all = GlowButton("Всё в карантин", ghost=True)
        self.btn_all.setMinimumHeight(36)
        self.btn_all.clicked.connect(self.quarantine_all)
        tc.head.addWidget(self.btn_all)
        sc, self.threat_lay = make_scroll()
        self.t_empty = QLabel("Угроз не обнаружено")
        self.t_empty.setAlignment(Qt.AlignCenter)
        self.t_empty.setStyleSheet("color:#6B7280;font-size:13px;padding:24px;")
        self.threat_lay.insertWidget(0, self.t_empty)
        tc.lay.addWidget(sc, 1)
        v.addWidget(tc, 1)
        return page

    def _kv(self, lay, key, val="—"):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        a = QLabel(key)
        a.setStyleSheet("color:#9CA3AF;font-size:12px;")
        b = QLabel(val)
        b.setStyleSheet("color:white;font-size:12px;font-weight:600;")
        h.addWidget(a)
        h.addStretch()
        h.addWidget(b)
        lay.addWidget(w)
        return b

    def _mini(self, cap, val):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(0)
        a = QLabel(val)
        a.setStyleSheet("font-size:22px;font-weight:700;color:white;")
        b = QLabel(cap)
        b.setStyleSheet("font-size:11px;color:#9CA3AF;")
        l.addWidget(a)
        l.addWidget(b)
        return w, a

    def _tips_card(self, title, tips):
        c = Card(title, "краткая справка")
        c.setFixedWidth(330)
        for icon, head, text in tips:
            row = QHBoxLayout()
            row.setSpacing(12)
            ic = QLabel(icon)
            ic.setStyleSheet("font-size:20px;color:#22D3EE;")
            ic.setFixedWidth(28)
            ic.setAlignment(Qt.AlignTop)
            col = QVBoxLayout()
            col.setSpacing(2)
            a = QLabel(head)
            a.setStyleSheet("font-size:13px;font-weight:600;color:white;")
            b = QLabel(text)
            b.setWordWrap(True)
            b.setStyleSheet("font-size:11px;color:#9CA3AF;")
            col.addWidget(a)
            col.addWidget(b)
            row.addWidget(ic)
            row.addLayout(col, 1)
            c.lay.addLayout(row)
        c.lay.addStretch()
        return c

    # ── страница: карантин ──
    def build_quarantine(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 0, 28, 24)
        v.setSpacing(16)
        row = QHBoxLayout()
        row.setSpacing(16)
        self.q_c1 = StatCard("Файлов в карантине", "#FBBF24")
        self.q_c2 = StatCard("Критических угроз", "#F43F5E")
        self.q_c3 = StatCard("Занято места", "#22D3EE")
        for c in (self.q_c1, self.q_c2, self.q_c3):
            row.addWidget(c)
        v.addLayout(row)
        card = Card("Изолированные файлы", "не могут запускаться и вредить системе")
        sc, self.q_lay = make_scroll()
        card.lay.addWidget(sc, 1)
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(card, 1)
        body.addWidget(self._tips_card("О карантине", [
            ("▣", "Безопасное хранение", "Файлы переименованы и перенесены в ~/.aegis_av/quarantine — запустить их нельзя."),
            ("↺", "Восстановление", "Ложное срабатывание? Верните файл на прежнее место одной кнопкой."),
            ("✕", "Удаление", "Окончательно стирает файл с диска. Отменить это действие нельзя."),
            ("⚙", "Автокарантин", "Включите его на вкладке «Защита», чтобы угрозы изолировались сразу.")]))
        v.addLayout(body, 1)
        return page

    # ── страница: журнал ──
    def build_log(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 0, 28, 24)
        v.setSpacing(16)
        row = QHBoxLayout()
        row.setSpacing(16)
        self.l_c1 = StatCard("Всего событий", "#22D3EE")
        self.l_c2 = StatCard("Угроз обнаружено", "#F43F5E")
        self.l_c3 = StatCard("Успешных действий", "#34D399")
        for c in (self.l_c1, self.l_c2, self.l_c3):
            row.addWidget(c)
        v.addLayout(row)
        card = Card("История событий", "последние 300 записей")
        self.log_list = QListWidget()
        card.lay.addWidget(self.log_list, 1)
        body = QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(card, 1)
        body.addWidget(self._tips_card("О журнале", [
            ("◉", "Что записывается", "Запуски проверок, найденные угрозы, действия с карантином и смена настроек."),
            ("●", "Цвета записей", "Красный — угроза, зелёный — успешное действие, жёлтый — предупреждение."),
            ("≣", "Хранение", "Журнал хранит последние 300 событий в файле ~/.aegis_av/state.json.")]))
        v.addLayout(body, 1)
        return page

    # ── состояние ──
    def refresh_state(self):
        if self.scanning:
            s, title, sub = "scanning", "Идёт проверка…", "Aegis анализирует файлы. Это может занять некоторое время."
        elif self.pending:
            s = "danger"
            title = f"Обнаружено угроз: {len(self.pending)}"
            sub = "Откройте вкладку «Проверка» и отправьте угрозы в карантин."
        else:
            s, title, sub = "safe", "Устройство защищено", "Угроз не обнаружено. Защита работает в штатном режиме."
        self.hero.set_state(s)
        self.h_title.setText(title)
        self.h_title.setStyleSheet(f"font-size:28px;font-weight:700;color:{COL[s]};")
        self.h_sub.setText(sub)
        rt = self.store.data.get("realtime", True)
        autoq = self.store.data.get("autoq", False)
        self.h_chip.setText(f"Сигнатур: {len(self.engine.sigs)}   •   Эвристика: {'вкл' if self.engine.heuristics else 'выкл'}")
        self.e_sigs.setText(str(len(self.engine.sigs)))
        self.e_heur.setText("включена" if self.engine.heuristics else "выключена")
        self.sig_desc.setText(f"{len(self.engine.sigs)} сигнатур  •  пополняется вручную")
        self.sb_status.setText("● Защита активна" if rt else "● Защита в реальном времени выкл.")
        self.sb_status.setStyleSheet(f"color:{'#34D399' if rt else '#FBBF24'};font-size:12px;font-weight:600;")

        # Обновление карточки фонового щита в сайдбаре
        self.sb_watched.setText(f"{len(self.seen)} файлов")
        self.sb_heur.setText("вкл" if self.engine.heuristics else "выкл")
        self.sb_heur.setStyleSheet(f"color:{'#34D399' if self.engine.heuristics else '#9CA3AF'};font-size:11px;font-weight:600;")
        self.sb_autoq.setText("вкл" if autoq else "выкл")
        self.sb_autoq.setStyleSheet(f"color:{'#22D3EE' if autoq else '#9CA3AF'};font-size:11px;font-weight:600;")
        self.sb_quar.setText(str(len(self.quar.items)))
        if rt:
            self.sb_badge.setText("В трее")
            self.sb_badge.setStyleSheet(
                "background:rgba(52,211,153,0.16);color:#34D399;border-radius:8px;"
                "padding:2px 8px;font-size:10px;font-weight:700;")
        else:
            self.sb_badge.setText("Пауза")
            self.sb_badge.setStyleSheet(
                "background:rgba(251,191,36,0.16);color:#FBBF24;border-radius:8px;"
                "padding:2px 8px;font-size:10px;font-weight:700;")

        # Обновление иконки и подсказки в трее
        if hasattr(self, "tray"):
            self.tray.setIcon(make_tray_icon(s))
            self.tray.setToolTip(f"AEGIS Antivirus — {title}")
            self.act_rt.setChecked(rt)

    def refresh_stats(self):
        d = self.store.data
        self.c_files.set_number(d["files"])
        self.c_threats.set_number(d["threats"])
        self.c_quar.set_number(len(self.quar.items))
        self.c_last.set_text(d["last"] or "—")
        self.c_last.value.setStyleSheet("font-size:20px;font-weight:700;color:#34D399;")
        self.e_last.setText(d["last"] or "—")
        self.chart.set_items(d.get("history", []))
        self.sb_quar.setText(str(len(self.quar.items)))

    def log(self, text, level="info"):
        self.store.log(text, level)
        self.refresh_log()

    def refresh_events(self):
        while self.ev_lay.count():
            it = self.ev_lay.takeAt(0)
            if it.widget():
                _drop(it.widget())
        colors = {"info": "#D1D5DB", "ok": "#34D399", "warn": "#FBBF24", "danger": "#F43F5E"}
        log = self.store.data["log"]
        if not log:
            e = QLabel("Событий пока нет")
            e.setStyleSheet("color:#6B7280;font-size:12px;")
            self.ev_lay.addWidget(e)
        for e in log[:7]:
            lbl = ElidedLabel(f"{e['t']}   {e['text']}", Qt.ElideRight)
            lbl.setStyleSheet(f"color:{colors.get(e['level'], '#D1D5DB')};font-size:12px;")
            self.ev_lay.addWidget(lbl)
        self.l_c1.set_number(len(log))
        self.l_c2.set_number(sum(1 for e in log if e["level"] == "danger"))
        self.l_c3.set_number(sum(1 for e in log if e["level"] == "ok"))

    def refresh_log(self):
        self.log_list.clear()
        self.refresh_events()
        colors = {"info": "#D1D5DB", "ok": "#34D399", "warn": "#FBBF24", "danger": "#F43F5E"}
        for e in self.store.data["log"]:
            it = QListWidgetItem(f"{e['t']}    {e['text']}")
            it.setForeground(QColor(colors.get(e["level"], "#D1D5DB")))
            self.log_list.addItem(it)

    def toast(self, text, level="info"):
        if self.isVisible():
            self.toast_w.show_msg(text, level)

    # ── проверка ──
    def set_mode(self, m):
        self.mode = m
        for k, b in self.mode_btns.items():
            b.setChecked(k == m)

    def scan_single_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите файл для проверки", str(Path.home()))
        if not path:
            return
        res = self.engine.analyze(path)
        self.store.data["files"] += 1
        self.store.data["last"] = datetime.now().strftime("%d.%m %H:%M")
        if res:
            self.store.data["threats"] += 1
            self.store.save()
            self.go(1)
            self.register_threat(res, realtime=True)
        else:
            self.store.save()
            self.log(f"Файл проверен — угроз нет: {os.path.basename(path)}", "ok")
            self.toast(f"Файл чист: {os.path.basename(path)}", "ok")
        self.refresh_stats()
        self.refresh_state()

    def scan_roots(self, mode):
        home = Path.home()
        if mode == "quick":
            c = [home / "Downloads", home / "Desktop", home / "Documents", Path(tempfile.gettempdir())]
            if os.environ.get("APPDATA"):
                c.append(Path(os.environ["APPDATA"]))
            return [str(x) for x in c if x.exists()]
        if mode == "full":
            return [str(home)]
        d = QFileDialog.getExistingDirectory(self, "Выберите папку для проверки", str(home))
        return [d] if d else []

    def start_scan(self):
        if self.scanning:
            self.toast("Проверка уже выполняется", "warn")
            return
        roots = self.scan_roots(self.mode)
        if not roots:
            return
        if self.worker:
            self.worker.wait()
        self.scanning = True
        self.worker = ScanWorker(self.engine, roots)
        self.worker.counting.connect(self.on_counting)
        self.worker.progress.connect(self.on_progress)
        self.worker.found.connect(self.register_threat)
        self.worker.scan_done.connect(self.on_done)
        self.ring.busy = True
        self.ring.set_progress(0)
        self.ring.val = 0
        self.ring.sub = "Подготовка…"
        self.s_status.setText("Идёт проверка…")
        self.m_files[1].setText("0")
        self.m_threats[1].setText("0")
        self.scan_found = 0
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.scan_t0 = time.monotonic()
        self.clock.start(1000)
        self.go(1)
        self.refresh_state()
        self.log(f"Запущена проверка ({ {'quick': 'быстрая', 'full': 'полная', 'custom': 'выборочная'}[self.mode] })")
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.scanning:
            self.worker.stop()
            self.btn_stop.setEnabled(False)

    def _clock_tick(self):
        s = int(time.monotonic() - self.scan_t0)
        self.m_time[1].setText(f"{s // 60}:{s % 60:02d}")

    def on_counting(self, n):
        self.ring.sub = f"Подготовка… найдено {n}"

    def on_progress(self, i, total, path):
        self.ring.set_progress(i / max(1, total))
        self.ring.sub = "Проверка файлов"
        self.s_file.setFull(path)
        self.m_files[1].setText(f"{i} / {total}")

    def on_done(self, st):
        self.scanning = False
        self.clock.stop()
        self._clock_tick()
        self.ring.busy = False
        if not st["stopped"]:
            self.ring.set_progress(1.0)
        self.ring.sub = "Остановлено" if st["stopped"] else "Завершено"
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.s_file.setFull("—")
        d = self.store.data
        d["files"] += st["scanned"]
        d["threats"] += st["threats"]
        d["last"] = datetime.now().strftime("%d.%m %H:%M")
        if not st["stopped"]:
            d.setdefault("history", []).append({"t": datetime.now().strftime("%d.%m"),
                                                 "files": st["scanned"], "threats": st["threats"]})
            del d["history"][:-7]
        self.store.save()
        if st["stopped"]:
            self.s_status.setText("Проверка остановлена")
            self.toast("Проверка остановлена", "warn")
        elif st["threats"]:
            self.s_status.setText(f"Найдено угроз: {st['threats']}")
            self.toast(f"Найдено угроз: {st['threats']}", "danger")
            if not self.isVisible():
                self.notify_tray(
                    "AEGIS: Проверка завершена",
                    f"Обнаружено угроз: {st['threats']}. Нажмите, чтобы открыть список.",
                    "danger",
                )
        else:
            self.s_status.setText("Угроз не найдено")
            self.toast("Проверка завершена — угроз нет", "ok")
        self.log(f"Проверка завершена: файлов {st['scanned']}, угроз {st['threats']}, "
                 f"{st['time']:.1f} с", "danger" if st["threats"] else "ok")
        self.refresh_stats()
        self.refresh_state()

    # ── угрозы ──
    def register_threat(self, t, realtime=False):
        if t["path"] in self.pending:
            return
        self.pending[t["path"]] = t
        color, lvl = LEVELS[t["level"]]
        row = ItemRow(color, f"{t['threat']}  •  {lvl}", t["path"],
                      f"{t['reason']}  •  {fmt_size(t['size'])}",
                      [("В карантин", lambda _=False, tt=t: self.quarantine_threat(tt), True),
                       ("Игнорировать", lambda _=False, tt=t: self.ignore_threat(tt), False)])
        self.rows[t["path"]] = row
        self.t_empty.hide()
        self.threat_lay.insertWidget(self.threat_lay.count() - 1, row)
        fade_in(row)
        self.m_threats[1].setText(str(len(self.pending)))
        self.log(f"Обнаружено: {t['threat']} — {t['path']}", "danger")
        self.refresh_state()

        autoq = self.store.data.get("autoq", False)
        if realtime:
            self.toast(f"Угроза: {t['name']}", "danger")
            action_note = "Файл автоматически перемещён в карантин." if autoq else "Нажмите, чтобы изолировать файл."
            self.notify_tray(
                f"AEGIS: Подозрительный файл ({lvl})",
                f"{t['name']} — {t['threat']}\nПричина: {t['reason']}\n{action_note}",
                "danger",
            )
        if autoq:
            self.quarantine_threat(t)

    def quarantine_threat(self, t):
        ok, msg = self.quar.add(t)
        row = self.rows.get(t["path"])
        if ok:
            self.pending.pop(t["path"], None)
            if row:
                row.set_done("✓ В карантине")
            self.log(f"В карантин: {t['path']}", "ok")
            self.toast("Файл перемещён в карантин", "ok")
            self.refresh_q()
            self.refresh_stats()
            self.refresh_state()
        else:
            self.toast(f"Не удалось: {msg[:60]}", "danger")

    def ignore_threat(self, t):
        self.pending.pop(t["path"], None)
        row = self.rows.get(t["path"])
        if row:
            row.set_done("Игнорируется", "#9CA3AF")
        self.log(f"Игнорируется: {t['path']}", "warn")
        self.refresh_state()

    def quarantine_all(self):
        for t in list(self.pending.values()):
            self.quarantine_threat(t)

    # ── карантин ──
    def refresh_q(self):
        its = self.quar.items
        self.q_c1.set_number(len(its))
        self.q_c2.set_number(sum(1 for i in its if i["level"] == "critical"))
        self.q_c3.set_text(fmt_size(sum(i["size"] for i in its)))
        self.q_c3.value.setStyleSheet("font-size:30px;font-weight:700;color:#22D3EE;")
        while self.q_lay.count() > 1:
            it = self.q_lay.takeAt(0)
            if it.widget():
                _drop(it.widget())
        if not self.quar.items:
            e = QLabel("Карантин пуст")
            e.setAlignment(Qt.AlignCenter)
            e.setStyleSheet("color:#6B7280;font-size:14px;padding:40px;")
            self.q_lay.insertWidget(0, e)
            return
        for it in reversed(self.quar.items):
            color = LEVELS.get(it["level"], LEVELS["medium"])[0]
            row = ItemRow(color, f"{it['threat']}", it["orig"],
                          f"{it['date']}  •  {fmt_size(it['size'])}",
                          [("Восстановить", lambda _=False, i=it["id"]: self.q_restore(i), False),
                           ("Удалить", lambda _=False, i=it["id"]: self.q_delete(i), True)])
            self.q_lay.insertWidget(self.q_lay.count() - 1, row)
            fade_in(row)

    def q_restore(self, qid):
        ok, msg = self.quar.restore(qid)
        if ok:
            self.log(f"Восстановлено из карантина: {msg}", "warn")
            self.toast("Файл восстановлен", "warn")
        else:
            self.toast(f"Ошибка: {msg[:60]}", "danger")
        self.refresh_q()
        self.refresh_stats()

    def q_delete(self, qid):
        self.quar.delete(qid)
        self.log("Файл удалён из карантина", "ok")
        self.toast("Файл удалён навсегда", "ok")
        self.refresh_q()
        self.refresh_stats()

    # ── защита в реальном времени ──
    def watch_dirs(self):
        return [Path.home() / "Downloads", Path.home() / "Desktop"]

    def snapshot(self):
        s = set()
        for d in self.watch_dirs():
            try:
                with os.scandir(d) as it:
                    for e in it:
                        if e.is_file(follow_symlinks=False):
                            s.add(e.path)
            except OSError:
                pass
        return s

    def on_realtime(self, on):
        self.store.data["realtime"] = on
        self.store.save()
        if on:
            self.seen = self.snapshot()
        self.log("Защита в реальном времени " + ("включена" if on else "выключена"), "info")
        self.toast("Защита в реальном времени " + ("включена" if on else "выключена"), "ok" if on else "warn")
        self.refresh_state()

    def on_heur(self, on):
        self.engine.heuristics = on
        self.store.data["heuristics"] = on
        self.store.save()
        self.log("Эвристический анализ " + ("включён" if on else "выключен"), "info")
        self.toast("Эвристика " + ("включена" if on else "выключена"), "ok" if on else "warn")
        self.refresh_state()

    def on_autoq(self, on):
        self.store.data["autoq"] = on
        self.store.save()
        self.log("Автокарантин " + ("включён" if on else "выключен"), "info")
        self.toast("Автокарантин " + ("включён" if on else "выключен"), "ok" if on else "warn")
        self.refresh_state()

    def sys_tick(self):
        if not self.isVisible():
            return
        cpu = ram = None
        ram_text = "нужен psutil"
        if psutil:
            cpu = psutil.cpu_percent(None)
            vm = psutil.virtual_memory()
            ram = vm.percent
            ram_text = f"{fmt_size(vm.used)} из {fmt_size(vm.total)}"
        elif hasattr(os, "getloadavg"):
            try:
                cpu = min(100.0, os.getloadavg()[0] / (os.cpu_count() or 1) * 100)
            except OSError:
                pass
        self.m_cpu.set_value(cpu, f"{cpu:.0f}%" if cpu is not None else "нужен psutil")
        self.m_ram.set_value(ram, ram_text)
        self.spark.push(cpu or 0)
        try:
            du = shutil.disk_usage(Path.home().anchor or "/")
            self.m_disk.set_value(du.used / du.total * 100, f"{fmt_size(du.used)} из {fmt_size(du.total)}")
        except OSError:
            self.m_disk.set_value(None, "—")

    def rt_tick(self):
        if not self.store.data.get("realtime", True) or self.scanning:
            return
        now = time.time()
        changed = False
        for d in self.watch_dirs():
            try:
                with os.scandir(d) as it:
                    for e in it:
                        if not e.is_file(follow_symlinks=False) or e.path in self.seen:
                            continue
                        st = e.stat()
                        if now - st.st_mtime < 2:
                            continue
                        self.seen.add(e.path)
                        changed = True
                        if st.st_size > 50 * 1024 * 1024:
                            continue
                        t = self.engine.analyze(e.path)
                        if t:
                            self.store.data["threats"] += 1
                            self.store.save()
                            self.register_threat(t, realtime=True)
                            self.refresh_stats()
            except OSError:
                pass
        if changed:
            self.sb_watched.setText(f"{len(self.seen)} файлов")

    def make_test(self):
        d = Path.home() / "Downloads"
        d.mkdir(exist_ok=True)
        f = d / f"aegis_test_threat_{int(time.time()) % 10000}.txt"
        f.write_bytes(TEST_MARK + "\nБезвредный файл для проверки работы антивируса.\n".encode("utf-8"))
        self.toast("Тест-файл создан в «Загрузки»", "info")
        self.log(f"Создан тестовый файл: {f}", "info")

    def closeEvent(self, e):
        if not self._force_quit and self.tray.isVisible():
            e.ignore()
            self.hide_to_tray(silent=False)
            return
        if self.worker and self.scanning:
            self.worker.stop()
            self.worker.wait(3000)
        self.store.save()
        super().closeEvent(e)


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setFont(QFont("Segoe UI", 10))
    w = MainWindow()
    w.show()
    geo = w.screen().availableGeometry()
    w.move(geo.center().x() - w.width() // 2, geo.center().y() - w.height() // 2)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
