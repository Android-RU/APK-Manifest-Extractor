#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manifest.py — инструмент для извлечения и анализа AndroidManifest.xml из APK/AAB/директории
"""

import argparse
import json
import logging
import sys
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from xml.etree import ElementTree as ET

# androguard используется для декодирования бинарного AXML
try:
    from androguard.core.bytecodes.axml import AXMLPrinter
except ImportError:
    print("Ошибка: требуется пакет 'androguard' (pip install androguard)", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------

def detect_source(path: Path) -> str:
    """Определяем тип источника: APK, AAB или DIR"""
    if path.is_dir():
        return "DIR"
    elif path.suffix.lower() == ".apk":
        return "APK"
    elif path.suffix.lower() == ".aab":
        return "AAB"
    else:
        raise ValueError(f"Неизвестный формат источника: {path}")


def read_manifest_bytes(path: Path) -> bytes:
    """Читает AndroidManifest.xml из APK/AAB/директории"""
    st = detect_source(path)
    if st == "DIR":
        manifest = path / "AndroidManifest.xml"
        if not manifest.exists():
            raise FileNotFoundError(f"Не найден AndroidManifest.xml в {path}")
        return manifest.read_bytes()

    with zipfile.ZipFile(path, "r") as zf:
        if st == "APK":
            # В APK манифест обычно в корне
            name = "AndroidManifest.xml"
            if name not in zf.namelist():
                raise FileNotFoundError(f"Файл {name} не найден в {path}")
            return zf.read(name)
        elif st == "AAB":
            # В AAB манифест обычно по пути base/manifest/AndroidManifest.xml
            candidates = ["base/manifest/AndroidManifest.xml"]
            # запасной вариант — вдруг другой модуль
            candidates.extend(p for p in zf.namelist() if p.endswith("/manifest/AndroidManifest.xml"))
            for cand in candidates:
                if cand in zf.namelist():
                    return zf.read(cand)
            raise FileNotFoundError(f"Манифест не найден в {path}")
    raise RuntimeError("Не удалось прочитать манифест")


def parse_axml(raw_bytes: bytes) -> ET.Element:
    """Декодирует бинарный AXML и возвращает ElementTree root"""
    axml = AXMLPrinter(raw_bytes)
    xml_str = axml.get_xml().decode("utf-8", errors="replace")
    return ET.fromstring(xml_str)


def get_attr(elem: ET.Element, name: str, default=None):
    """Извлекает атрибут android:name → корректно с namespace"""
    for k, v in elem.attrib.items():
        if k.endswith(name):
            return v
    return default


def extract_manifest_data(root: ET.Element) -> Dict[str, Any]:
    """Основная логика парсинга AndroidManifest.xml"""
    data: Dict[str, Any] = {}

    # --------------------------
    # Метаданные пакета
    # --------------------------
    data["packageName"] = root.attrib.get("package")
    data["versionCode"] = get_attr(root, "versionCode")
    data["versionName"] = get_attr(root, "versionName")

    # SDK info
    sdk_node = root.find("uses-sdk")
    data["sdk"] = {
        "min": int(get_attr(sdk_node, "minSdkVersion", 0)) if sdk_node is not None else None,
        "target": int(get_attr(sdk_node, "targetSdkVersion", 0)) if sdk_node is not None else None,
        "max": int(get_attr(sdk_node, "maxSdkVersion", 0)) if sdk_node is not None else None,
    }

    # --------------------------
    # Приложение
    # --------------------------
    app = root.find("application")
    if app is not None:
        data["application"] = {
            "label": get_attr(app, "label"),
            "icon": get_attr(app, "icon"),
            "debuggable": get_attr(app, "debuggable") == "true",
            "allowBackup": get_attr(app, "allowBackup") != "false",
            "usesCleartextTraffic": get_attr(app, "usesCleartextTraffic") == "true",
            "networkSecurityConfig": get_attr(app, "networkSecurityConfig"),
        }
    else:
        data["application"] = {}

    # --------------------------
    # Разрешения
    # --------------------------
    permissions = []
    for p in root.findall("uses-permission"):
        permissions.append({
            "name": get_attr(p, "name"),
            "maxSdkVersion": get_attr(p, "maxSdkVersion"),
        })
    data["permissions"] = permissions

    # --------------------------
    # Компоненты приложения
    # --------------------------
    def parse_component_list(tag: str) -> List[Dict[str, Any]]:
        out = []
        if app is None:
            return out
        for comp in app.findall(tag):
            info = {
                "name": get_attr(comp, "name"),
                "exported": (get_attr(comp, "exported") == "true"),
            }
            # intent-filters
            filters = []
            for f in comp.findall("intent-filter"):
                actions = [get_attr(a, "name") for a in f.findall("action") if get_attr(a, "name")]
                cats = [get_attr(c, "name") for c in f.findall("category") if get_attr(c, "name")]
                datas = [get_attr(d, "scheme") for d in f.findall("data") if get_attr(d, "scheme")]
                filters.append({"actions": actions, "categories": cats, "data": datas})
            if filters:
                info["intentFilters"] = filters
            out.append(info)
        return out

    data["activities"] = parse_component_list("activity")
    data["services"] = parse_component_list("service")
    data["receivers"] = parse_component_list("receiver")

    # Providers — немного другие атрибуты
    providers = []
    if app is not None:
        for pr in app.findall("provider"):
            providers.append({
                "name": get_attr(pr, "name"),
                "exported": get_attr(pr, "exported") == "true",
                "authorities": get_attr(pr, "authorities"),
                "grantUriPermissions": get_attr(pr, "grantUriPermissions") == "true",
                "readPermission": get_attr(pr, "readPermission"),
                "writePermission": get_attr(pr, "writePermission"),
            })
    data["providers"] = providers

    # --------------------------
    # uses-feature
    # --------------------------
    features = []
    for f in root.findall("uses-feature"):
        features.append({
            "name": get_attr(f, "name"),
            "required": get_attr(f, "required", "true") == "true",
            "glEsVersion": get_attr(f, "glEsVersion"),
        })
    data["features"] = features

    # --------------------------
    # queries (Android 11+)
    # --------------------------
    queries = root.find("queries")
    if queries is not None:
        pkgs = [get_attr(p, "name") for p in queries.findall("package")]
        intents = []
        for q in queries.findall("intent"):
            act = [get_attr(a, "name") for a in q.findall("action") if get_attr(a, "name")]
            cat = [get_attr(c, "name") for c in q.findall("category") if get_attr(c, "name")]
            dat = [get_attr(d, "scheme") for d in q.findall("data") if get_attr(d, "scheme")]
            intents.append({"actions": act, "categories": cat, "data": dat})
        data["queries"] = {"packages": pkgs, "intents": intents}
    else:
        data["queries"] = {}

    return data


# ---------------------------------------------------------
# Форматирование вывода
# ---------------------------------------------------------

def render_text(data: Dict[str, Any]) -> str:
    """Формирует человеко-читаемый отчёт"""
    lines = []
    lines.append(f"Package: {data.get('packageName')}")
    lines.append(f"Version: {data.get('versionName')} ({data.get('versionCode')})")
    sdk = data.get("sdk", {})
    lines.append(f"SDK: min={sdk.get('min')} target={sdk.get('target')}")

    app = data.get("application", {})
    lines.append(f"App: label={app.get('label')} icon={app.get('icon')} "
                 f"debuggable={app.get('debuggable')} allowBackup={app.get('allowBackup')}")

    if data.get("permissions"):
        lines.append(f"\nPermissions ({len(data['permissions'])}):")
        for p in data["permissions"]:
            lines.append(f"  - {p['name']}")

    if data.get("activities"):
        lines.append(f"\nActivities ({len(data['activities'])}):")
        for a in data["activities"]:
            lines.append(f"  - {a['name']} exported={a['exported']}")
            if "intentFilters" in a:
                for f in a["intentFilters"]:
                    for act in f.get("actions", []):
                        lines.append(f"      * action={act}")
                    for cat in f.get("categories", []):
                        lines.append(f"      * category={cat}")

    if data.get("providers"):
        lines.append(f"\nProviders ({len(data['providers'])}):")
        for pr in data["providers"]:
            lines.append(f"  - {pr['name']} authorities={pr['authorities']} exported={pr['exported']}")

    return "\n".join(lines)


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Извлечение и анализ AndroidManifest.xml из APK/AAB/директории"
    )
    parser.add_argument("source", nargs="+", help="путь(и) к APK/AAB/директории")
    parser.add_argument("-j", "--json", action="store_true", help="вывод в JSON")
    parser.add_argument("-o", "--output", help="файл для записи JSON")
    parser.add_argument("--pretty", action="store_true", help="форматированный JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="подробный вывод логов")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.ERROR,
        format="[%(levelname)s] %(message)s",
    )

    results = []
    for src in args.source:
        path = Path(src)
        try:
            logging.info(f"Анализ {path}")
            raw = read_manifest_bytes(path)
            root = parse_axml(raw)
            data = extract_manifest_data(root)
            data["source"] = str(path)
            results.append(data)
        except Exception as e:
            logging.error(f"{path}: {e}")

    if args.json:
        indent = 2 if args.pretty else None
        text = json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=indent)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            print(text)
    else:
        for res in results:
            print("=" * 60)
            print(render_text(res))
            print()

    if not results:
        sys.exit(1)


if __name__ == "__main__":
    main()