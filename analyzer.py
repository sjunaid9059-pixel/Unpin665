import hashlib
from pathlib import Path

from androguard.core.apk import APK


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_apk(path: Path) -> dict:
    # Androguard parses APK structures; this tool never installs or executes the APK.
    apk = APK(str(path))
    if not apk.is_valid_APK():
        raise ValueError("Invalid APK")

    permissions = sorted(set(apk.get_permissions() or []))
    return {
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "package": apk.get_package() or "Unknown",
        "app_name": apk.get_app_name() or "Unknown",
        "version_name": apk.get_androidversion_name() or "Unknown",
        "version_code": apk.get_androidversion_code() or "Unknown",
        "min_sdk": apk.get_min_sdk_version() or "Unknown",
        "target_sdk": apk.get_target_sdk_version() or "Unknown",
        "main_activity": apk.get_main_activity() or "Not declared",
        "permissions": permissions,
    }


def format_report(data: dict) -> str:
    size_mb = data["size"] / (1024 * 1024)
    lines = [
        "🛡️ SJ HACKER — APK SCAN REPORT",
        "",
        f"📦 File: {data['filename']}",
        f"📏 Size: {size_mb:.2f} MB",
        f"🔐 SHA-256: {data['sha256']}",
        "",
        "📱 APP METADATA",
        f"Name: {data['app_name']}",
        f"Package: {data['package']}",
        f"Version: {data['version_name']} (code: {data['version_code']})",
        f"Min SDK: {data['min_sdk']}",
        f"Target SDK: {data['target_sdk']}",
        f"Main activity: {data['main_activity']}",
        "",
        f"🔑 DECLARED PERMISSIONS ({len(data['permissions'])})",
    ]
    if data["permissions"]:
        lines.extend(f"• {p}" for p in data["permissions"])
    else:
        lines.append("No permissions declared / none detected.")

    lines += [
        "",
        "ℹ️ Note: permissions are declarations, not proof that the app "
        "actually uses them. This report is static metadata only; it is "
        "not a malware verdict or a security guarantee.",
    ]
    return "\n".join(lines)
