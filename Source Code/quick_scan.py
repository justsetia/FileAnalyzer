import os
import hashlib
import string


# ==============================
# FILE SIGNATURES
# ==============================
SIGNATURES = {
    "JPEG": b"\xFF\xD8\xFF",
    "PNG": b"\x89\x50\x4E\x47",
    "PDF": b"%PDF",
    "EXE": b"MZ",
    "ZIP": b"\x50\x4B\x03\x04",
    "GIF": b"GIF8",
    "ELF": b"\x7FELF",
}

EOF_MARKERS = {
    "JPEG": b"\xFF\xD9",
    "PNG": b"\x49\x45\x4E\x44\xAE\x42\x60\x82",
}

EXTENSION_MAP = {
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "png": "PNG",
    "pdf": "PDF",
    "exe": "EXE",
    "dll": "EXE",
    "zip": "ZIP",
    "rar": "ZIP",
    "gif": "GIF",
    "elf": "ELF",
    "txt": "TXT"
}


# ==============================
# UTILITY FUNCTIONS
# ==============================
def calculate_hashes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def is_text_file(data):
    printable = set(bytes(string.printable, "ascii"))
    return all(byte in printable or byte in b"\n\r\t" for byte in data[:512])


# ==============================
# MAIN SCAN FUNCTION
# ==============================
def scan(path, log):

    log("🔎 Starting Quick Scan")
    log("=" * 60)

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        log(f"❌ Error reading file: {e}")
        return

    if not data:
        log("❌ File is empty.")
        return

    size = len(data)
    log(f"📦 File Size: {size} bytes")

    md5, sha256 = calculate_hashes(data)
    log(f"🔑 MD5: {md5}")
    log(f"🔐 SHA256: {sha256}")
    log("-" * 60)

    header = data[:8]
    detected = "Unknown"
    sig_length = 0

    for name, sig in SIGNATURES.items():
        if header.startswith(sig):
            detected = name
            sig_length = len(sig)
            break

    # Text detection
    if detected == "Unknown" and is_text_file(data):
        detected = "TXT"

    log(f"📄 Detected Type: {detected}")

    # Extension check
    ext = os.path.splitext(path)[1].lower().replace(".", "")
    expected_type = EXTENSION_MAP.get(ext, "Unknown")

    if expected_type != detected:
        log(f"⚠️ Extension mismatch: .{ext} → Expected {expected_type}, Found {detected}")

        if detected == "EXE":
            log("🚨 CRITICAL: Executable disguised as another file!")
    else:
        log("✅ Extension matches file header.")

    log("-" * 60)

    # ==============================
    # OVERLAY DETECTION
    # ==============================

    # IMAGE TYPES
    if detected in EOF_MARKERS:
        marker = EOF_MARKERS[detected]
        eof_index = data.rfind(marker)

        if eof_index != -1:
            true_end = eof_index + len(marker)

            if len(data) > true_end:
                overlay = data[true_end:]
                log(f"⚠️ Overlay detected: {len(overlay)} extra bytes")

                if overlay.startswith(b"MZ"):
                    log("🚨 Hidden EXE in image overlay!")

                if b"%PDF" in overlay:
                    log("⚠️ Embedded PDF inside image!")

                if b"PK\x03\x04" in overlay:
                    log("⚠️ Embedded ZIP inside image!")

            else:
                log("✅ No overlay detected.")
        else:
            log("❓ EOF marker missing.")

    # PDF
    elif detected == "PDF":
        eof_marker = b"%%EOF"
        eof_index = data.rfind(eof_marker)

        if eof_index != -1:
            true_end = eof_index + len(eof_marker)

            if len(data) > true_end:
                overlay = data[true_end:]
                log(f"⚠️ PDF overlay detected: {len(overlay)} bytes")

                if overlay.startswith(b"MZ"):
                    log("🚨 Hidden EXE inside PDF!")

                if b"PK\x03\x04" in overlay:
                    log("⚠️ ZIP archive hidden in PDF!")

            else:
                log("✅ No PDF overlay.")
        else:
            log("❓ No %%EOF marker found.")

    # ZIP
    elif detected == "ZIP":
        eocd = b"\x50\x4B\x05\x06"
        index = data.rfind(eocd)

        if index != -1 and len(data) >= index + 22:
            comment_len = int.from_bytes(data[index+20:index+22], "little")
            true_end = index + 22 + comment_len

            if len(data) > true_end:
                overlay = data[true_end:]
                log(f"⚠️ ZIP overlay detected: {len(overlay)} bytes")

                if overlay.startswith(b"MZ"):
                    log("🚨 Hidden EXE after ZIP!")

                if b"%PDF" in overlay:
                    log("⚠️ Hidden PDF after ZIP!")

            else:
                log("✅ No ZIP overlay.")
        else:
            log("❓ EOCD record not found.")

    # ELF
    elif detected == "ELF":
        if b"MZ" in data:
            log("⚠️ Possible embedded EXE inside ELF file.")
        else:
            log("✅ No suspicious embedded signatures in ELF.")

    # TXT
    elif detected == "TXT":
        log("✅ Plain text file detected.")

    else:
        log("ℹ️ No deep structural checks available.")

    log("=" * 60)
    log("✅ Quick Scan Completed.")

    # Send highlight info to GUI
    if detected in SIGNATURES:
        return {
            "format": detected,
            "offset": 0,
            "length": sig_length
        }

    return None
