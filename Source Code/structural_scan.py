
import struct

isExe = False


def find_all_exe_headers(data):
    found_executables = False
    search_pos = 0

    while True:
        # Find the next 'MZ' header
        mz_pos = data.find(b"MZ", search_pos)

        # If no more 'MZ' found, exit the loop
        if mz_pos == -1:
            break

        # --- Inline Validation Logic ---
        # 1. Ensure we don't read past the file end when checking the PE pointer
        if mz_pos + 0x40 <= len(data):
            try:
                # 2. Extract e_lfanew (pointer to PE header at offset + 0x3C)
                pe_pointer = int.from_bytes(data[mz_pos + 0x3C: mz_pos + 0x40], 'little')

                # 3. Check if the PE signature ('PE\0\0') exists at that location
                pe_signature_pos = mz_pos + pe_pointer
                if pe_signature_pos + 4 <= len(data):
                    if data[pe_signature_pos: pe_signature_pos + 4] == b"PE\0\0":
                        found_executables = True
            except Exception:
                pass  # If any parsing error occurs, skip this 'MZ'

        # Continue searching from the next byte
        search_pos = mz_pos + 1

    return found_executables


def text_output(data, type):
    bytes = []
    global isExe
    isExe = False

    if type == "EXE":

        # MZ header
        bytes += [0, 2]

        # e_lfanew pointer
        bytes += [60, 64]

        try:
            pe_offset = int.from_bytes(data[60:64], "little")

            # PE signature
            bytes += [pe_offset, pe_offset + 4]

            # COFF header
            coff_start = pe_offset + 4
            bytes += [coff_start, coff_start + 20]

            # Read values from COFF header
            num_sections = int.from_bytes(data[coff_start + 2:coff_start + 4], "little")
            size_optional_header = int.from_bytes(data[coff_start + 16:coff_start + 18], "little")

            # Optional header
            optional_start = coff_start + 20
            optional_end = optional_start + size_optional_header
            bytes += [optional_start, optional_end]

            # Section table
            section_table = optional_end

            for i in range(num_sections):
                sec_start = section_table + i * 40
                sec_end = sec_start + 40

                if sec_end <= len(data):
                    bytes += [sec_start, sec_end]

        except:
            pass

    elif type == "PDF":
        # 1️⃣ PDF header: %PDF-...
        # Typically starts at 0 and at least 4 bytes
        if data.startswith(b"%PDF"):
            # You can extend to e.g. first line, but minimally:
            bytes += [0, 4]  # "%PDF"

        # 2️⃣ XREF table (optional but important)
        xref_pos = data.find(b"xref")
        if xref_pos != -1:
            # highlight 'xref' keyword (4 bytes)
            bytes += [xref_pos, xref_pos + 4]

        # 3️⃣ trailer (optional but important)
        trailer_pos = data.find(b"trailer")
        if trailer_pos != -1:
            # 'trailer' is 7 bytes
            bytes += [trailer_pos, trailer_pos + 7]

        # 4️⃣ EOF marker (required)
        # Use rfind to get the last occurrence
        eof_pos = data.rfind(b"%%EOF")
        if eof_pos != -1:
            # '%%EOF' is 5 bytes
            bytes += [eof_pos, eof_pos + 5]
        isExe = find_all_exe_headers(data)
    elif type == "ZIP":

        # 1️⃣ Local File Header (required)
        # Signature "PK 03 04" at start
        if data.startswith(b"PK\x03\x04"):
            bytes += [0, 4]

        # 2️⃣ EOCD (End of Central Directory) (required)
        eocd_sig = b"PK\x05\x06"
        search_area = data[-65536:]
        pos = search_area.rfind(eocd_sig)

        if pos != -1:
            # Convert search-area-relative position to actual file offset
            real_pos = len(data) - len(search_area) + pos
            bytes += [real_pos, real_pos + 4]

        # 3️⃣ Central Directory Headers (optional, repeated)
        # Signature "PK 01 02"
        cd_sig = b"PK\x01\x02"

        search_cd = 0
        while True:
            cd_pos = data.find(cd_sig, search_cd)
            if cd_pos == -1:
                break

            # Central Directory Header is 46 bytes (fixed portion)
            bytes += [cd_pos, cd_pos + 46]

            # Move search forward
            search_cd = cd_pos + 1
        isExe = find_all_exe_headers(data)
    elif type == "PNG":

        # PNG signature
        bytes += [0, 8]

        # IHDR chunk
        ihdr_pos = data.find(b"IHDR")
        if ihdr_pos != -1:
            bytes += [ihdr_pos, ihdr_pos + 4]

            chunk_start = max(0, ihdr_pos - 4)
            chunk_end = ihdr_pos + 4 + 13 + 4
            bytes += [chunk_start, chunk_end]

        # IDAT chunks
        search = 0
        while True:
            idat_pos = data.find(b"IDAT", search)
            if idat_pos == -1:
                break

            chunk_start = max(0, idat_pos - 4)
            bytes += [chunk_start, idat_pos + 4]

            search = idat_pos + 1

        # IEND chunk
        iend_pos = data.rfind(b"IEND")
        if iend_pos != -1:
            bytes += [iend_pos, iend_pos + 4]

            chunk_start = max(0, iend_pos - 4)
            chunk_end = iend_pos + 8
            bytes += [chunk_start, chunk_end]
        isExe = find_all_exe_headers(data)

    elif type == "JPEG":

        # 1️⃣ SOI (Start Of Image) - required
        if data.startswith(b"\xFF\xD8"):
            bytes += [0, 2]

        # 2️⃣ DQT (Quantization Table) - optional
        search = 0
        while True:
            pos = data.find(b"\xFF\xDB", search)
            if pos == -1:
                break

            bytes += [pos, pos + 2]
            search = pos + 1

        # 3️⃣ SOF markers (image size info)
        # common ones: FFC0, FFC2
        sof_markers = [b"\xFF\xC0", b"\xFF\xC2"]

        for marker in sof_markers:
            pos = data.find(marker)
            if pos != -1:
                bytes += [pos, pos + 2]

        # 4️⃣ SOS (Start of Scan)
        sos_pos = data.find(b"\xFF\xDA")
        if sos_pos != -1:
            bytes += [sos_pos, sos_pos + 2]

        # 5️⃣ EOI (End Of Image) - required
        if data.endswith(b"\xFF\xD9"):
            bytes += [len(data) - 2, len(data)]
        isExe = find_all_exe_headers(data)
    elif type == "GIF":

        # 1️⃣ Header (GIF87a / GIF89a)
        bytes += [0, 6]

        # 2️⃣ Logical Screen Descriptor (7 bytes)
        bytes += [6, 13]

        # 3️⃣ Global Color Table (optional)
        packed = data[10] if len(data) > 10 else 0
        gct_flag = (packed >> 7) & 1
        gct_size = packed & 0b111

        if gct_flag:
            size = 3 * (2 ** (gct_size + 1))
            gct_start = 13
            gct_end = gct_start + size
            bytes += [gct_start, gct_end]

        # 4️⃣ Image Descriptor(s)
        search = 0
        while True:
            pos = data.find(b"\x2C", search)  # image separator
            if pos == -1:
                break

            bytes += [pos, pos + 10]  # descriptor block
            search = pos + 1

        # 5️⃣ Trailer (end of GIF)
        if data.endswith(b"\x3B"):
            bytes += [len(data) - 1, len(data)]
        isExe = find_all_exe_headers(data)

    elif type == "TXT":

        # highlight entire text file
        bytes += [0, len(data)]

        # highlight newline characters
        search = 0
        while True:
            pos = data.find(b"\n", search)
            if pos == -1:
                break

            bytes += [pos, pos + 1]
            search = pos + 1
        isExe = find_all_exe_headers(data)

    # Convert ranges into a set of highlighted byte positions
    # Convert ranges to a set of byte indexes

    highlight = set()
    for i in range(0, len(bytes), 2):
        start = bytes[i]
        end = bytes[i + 1]
        for b in range(start, min(end, len(data))):
            highlight.add(b)

    html = []
    html.append("""
    <html>
    <head>
    <style>
        body { font-family: monospace; background:#111; color:#ddd; }
        .offset { color:#6cf; margin-right:10px; }
        .byte { padding:2px; }
        .hl { background:#ffcc00; color:#000; }
        .ascii { margin-left:20px; color:#aaa; }
    </style>
    </head>
    <body>
    <h3>Hex View</h3>
    <pre>
    """)

    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]

        # offset
        line = f'<span class="offset">{i:08X}</span> '

        ascii_part = ""

        for j, b in enumerate(chunk):
            pos = i + j
            hex_byte = f"{b:02X}"

            if pos in highlight:
                line += f'<span class="byte hl">{hex_byte}</span> '
            else:
                line += f'<span class="byte">{hex_byte}</span> '

            if 32 <= b <= 126:
                ascii_part += chr(b)
            else:
                ascii_part += "."

        line += f'<span class="ascii"> {ascii_part}</span>'
        html.append(line + "\n")

    html.append("""
    </pre>
    </body>
    </html>
    """)

    with open("byte_output.html", "w") as f:
        f.write("".join(html))

    print("Saved highlighted hex view to byte_output.html")


def scan(path, log):
    log("🧩 Starting Structural Parsing")
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

    header = data[:8]

    # --- PE (EXE) ---
    if header.startswith(b"MZ"):
        log("📦 PE Executable Detected")

        try:
            # DOS header pointer to PE header
            pe_offset = struct.unpack("<I", data[60:64])[0]
            log(f"🔎 PE Header Offset: {pe_offset}")

            # Check PE signature
            if data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                log("✅ Valid PE signature found.")
            else:
                log("⚠️ Invalid PE signature.")
                return

            # ---- COFF HEADER ----
            coff_offset = pe_offset + 4
            machine = struct.unpack("<H", data[coff_offset:coff_offset + 2])[0]
            num_sections = struct.unpack("<H", data[coff_offset + 2:coff_offset + 4])[0]
            size_optional = struct.unpack("<H", data[coff_offset + 16:coff_offset + 18])[0]

            log(f"⚙️ Machine Type: {hex(machine)}")
            log(f"📂 Number of Sections: {num_sections}")
            log(f"📦 Optional Header Size: {size_optional}")

            # ---- OPTIONAL HEADER ----
            optional_offset = coff_offset + 20
            magic = struct.unpack("<H", data[optional_offset:optional_offset + 2])[0]

            if magic == 0x10B:
                log("✅ PE32 (32-bit) Optional Header detected")
            elif magic == 0x20B:
                log("✅ PE32+ (64-bit) Optional Header detected")
            else:
                log("⚠️ Unknown Optional Header format")

            # Entry point
            entry_point = struct.unpack("<I", data[optional_offset + 16:optional_offset + 20])[0]
            log(f"🚀 Entry Point RVA: {hex(entry_point)}")

            # ---- SECTION TABLE ----
            section_table = optional_offset + size_optional
            log(f"📑 Section Table Offset: {section_table}")

            for i in range(num_sections):
                sec = section_table + (i * 40)

                name = data[sec:sec + 8].rstrip(b"\x00").decode(errors="ignore")
                virtual_size = struct.unpack("<I", data[sec + 8:sec + 12])[0]
                virtual_addr = struct.unpack("<I", data[sec + 12:sec + 16])[0]
                raw_size = struct.unpack("<I", data[sec + 16:sec + 20])[0]
                raw_ptr = struct.unpack("<I", data[sec + 20:sec + 24])[0]

                log(f"📁 Section {i + 1}: {name}")
                log(f" hex(virtual_addr)  Size: {virtual_size}")
                log(f"   Raw Offset: {raw_ptr}  Raw Size: {raw_size}")

            text_output(data, "EXE")

        except Exception as e:
            log(f"❌ PE parsing failed: {e}")



    # --- PDF ---
    elif header.startswith(b"%PDF"):
        log("📄 PDF Structure Detected")

        if b"xref" in data:
            log("✅ XREF table found.")
        else:
            log("⚠️ XREF table missing.")

        if b"trailer" in data:
            log("✅ Trailer found.")
        else:
            log("⚠️ Trailer missing.")

        if data.rstrip().endswith(b"%%EOF"):
            log("✅ EOF marker found.")
        else:
            log("⚠️ EOF marker missing.")
        text_output(data, "PDF")

    # --- ZIP ---
    elif header.startswith(b"PK\x03\x04"):
        log("📦 ZIP Structure Detected")

        # EOCD signature
        eocd_sig = b"\x50\x4B\x05\x06"

        # ZIP spec: EOCD must be within last 64KB
        search_area = data[-65536:]

        pos = search_area.rfind(eocd_sig)

        if pos != -1:
            log("✅ EOCD record found near end of file.")
        else:
            log("⚠️ EOCD record missing or not near file end.")
        text_output(data, "ZIP")

    # --- PNG ---
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        log("🖼 PNG Structure Detected")

        # IHDR must appear very early
        if data[8:64].find(b"IHDR") != -1:
            # IHDR gives the information of size
            # bit depth, color, compression mode
            log("✅ IHDR chunk found in expected location.")
        else:
            log("⚠️ IHDR chunk missing or misplaced.")

        # IEND must be near the end
        if data.rstrip().endswith(b"IEND\xae\x42\x60\x82"):
            log("✅ IEND chunk found at end of file.")
        else:
            pos = data.rfind(b"IEND")
            if pos != -1:
                log("⚠️ IEND found but not at end (possible overlay).")
            else:
                log("⚠️ IEND chunk missing.")
        text_output(data, "PNG")


    # --- ✅ ADDED: JPEG ---
    elif header.startswith(b"\xFF\xD8"):
        log("🖼 JPEG Structure Detected")
        if data.endswith(b"\xFF\xD9"):
            log("✅ Valid EOI (End of Image) marker found.")
        else:
            log("⚠️ Missing EOI marker. File might be truncated or have an overlay.")

        if b"\xFF\xDB" in data:  # Define Quantization Table
            log("✅ DQT (Quantization Table) found.")
        text_output(data, "JPEG")

    # --- ✅ ADDED: GIF ---
    elif header.startswith(b"GIF8"):
        version = data[3:6].decode(errors='ignore')
        log(f"🖼 GIF Structure Detected (Version: {version})")
        if data.endswith(b"\x3B"):
            log("✅ Valid GIF Trailer (0x3B) found.")
        else:
            log("⚠️ Missing GIF Trailer. File may be corrupt.")
        text_output(data, "GIF")

    # --- ✅ ADDED: TXT (Plain Text) ---
    elif all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:512]):
        log("📝 Plain Text Structure Detected")
        try:
            data.decode('utf-8')
            log("✅ Valid UTF-8 encoding verified.")
            text_output(data, "TXT")
        except UnicodeDecodeError:
            log("⚠️ Encoding Alert: Contains non-UTF-8 sequences (Possible hidden binary data).")

    else:
        log("ℹ️ Structural parsing not implemented for this type.")

    log("=" * 60)
    log("✅ Structural Parsing Completed.")
    if isExe:
        log("⚠️ SECURITY ALERT: Embedded EXE/PE structure detected!", error=True)
