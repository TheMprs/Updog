import email
from email import policy
import zipfile
import io
import py7zr
import rarfile

# tests conducted on attachment.py:
# 1. test for dangerous file types (exe, scr, js, etc.)
# 2. test for password-protected archives (zip, rar, 7z)
# 3. test for MIME type mismatches (e.g. .pdf file with application/zip MIME)

# Risk scores by file type
RISKY_MIME_SCORES = {
    # Direct execution
    ".exe": 1.0, ".scr": 1.0, ".msi": 1.0, ".bat": 1.0, ".cmd": 1.0, ".hta": 1.0,
    # Weaponized/high risk
    ".lnk": 0.9, ".jar": 0.85, ".ps1": 0.8, ".vbs": 0.7, ".js": 0.6,
    # Disk images & archives
    ".iso": 0.7, ".dmg": 0.7, ".7z": 0.7, ".tar": 0.7, ".gz": 0.7,
    # Macro-enabled
    ".docm": 0.6, ".xlsm": 0.6, ".pptm": 0.6,
    # Embedded scripts/phishing pages
    ".svg": 0.5, ".html": 0.5, ".htm": 0.5,
    # Generic archives
    ".zip": 0.4, ".rar": 0.4,
    # Common but can be weaponized
    ".pdf": 0.3,
}

# Expected MIME types for file extensions (used to detect extension spoofing)
EXPECTED_MIMES_BY_EXT = {
    ".pdf": {"application/pdf"},
    ".zip": {"application/zip"},
    ".rar": {"application/x-rar-compressed", "application/x-rar"},
    ".7z": {"application/x-7z-compressed"},
    ".exe": {"application/x-msdownload", "application/x-msdos-program", "application/x-executable"},
    ".jar": {"application/java-archive"},
    ".ps1": {"application/x-powershell"},
    ".vbs": {"application/x-vbscript", "text/vbscript"},
    ".js": {"application/javascript", "text/javascript"},
}

# Dangerous MIME types that indicate execution capability
EXECUTABLE_MIMES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-elf",
    "application/x-java-applet",
}

def extract_attachments(email_raw):
    """
    Extract attachments from email message.
    Returns list of attachment dicts: [{"filename": str, "mime_type": str, "content": bytes}, ...]
    """
    attachments = []

    try:
        msg = email.message_from_string(email_raw, policy=policy.default)

        for part in msg.iter_attachments():
            filename = part.get_filename()
            mime_type = part.get_content_type()
            content = part.get_payload(decode=True)

            if filename and content:
                attachments.append({
                    "filename": filename,
                    "mime_type": mime_type,
                    "content": content
                })
    except Exception:
        pass  # If parsing fails, return empty list

    return attachments

def check_risky_mime_types(attachments):
    """
    Check if any attachments have dangerous MIME types or extensions.
    Returns risk_score: 0.0 (safe) to 1.0 (highly risky)
    """
    if not attachments:
        return 0.0

    max_score = 0.0
    risky_count = 0

    for attachment in attachments:
        filename = attachment["filename"].lower()
        mime_type = attachment["mime_type"].lower()

        # Get file extension
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1]

        # Check for executable MIME type with innocent extension (evasion attempt)
        if mime_type in EXECUTABLE_MIMES and ext not in [".exe", ".scr", ".msi", ".bat", ".cmd", ".hta", ".jar", ".ps1"]:
            return 1.0  # Clear evasion attempt

        # Check extension-based risk
        file_score = RISKY_MIME_SCORES.get(ext, 0.0)

        # if we found a risky file, score it based on type and count how many we found
        if file_score > 0.0:
            risky_count += 1
            max_score = max(max_score, file_score)

    # Apply count multiplier only for high-risk files (>= 0.6) or when already scored high
    if risky_count > 1 and max_score >= 0.6:
        multiplier = min(0.2, risky_count * 0.05)  # Conservative multiplier for high-risk
        max_score = min(1.0, max_score + multiplier)

    return max_score

def check_encrypted_archives(attachments):
    """
    Check if any archive files are password-protected (used to bypass scanners).
    Returns archive_score: 0.0 (no protected archives) to 1.0 (protected archive found)
    """
    if not attachments:
        return 0.0

    max_score = 0.0

    for attachment in attachments:
        filename = attachment["filename"].lower()
        content = attachment["content"]

        # Check if it's a ZIP file
        if filename.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    # Check if any file in the archive is encrypted
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:  # Check encryption flag
                            max_score = max(max_score, 0.7)
            except Exception:
                # If we can't read the ZIP, it's corrupted or malformed (could be intentional)
                max_score = max(max_score, 0.3)

        elif filename.endswith(".rar"):
            try:
                rf = rarfile.RarFile(io.BytesIO(content))
                # Check if archive requires a password
                if rf.needs_password():
                    max_score = max(max_score, 0.7)
            except rarfile.BadRarFile:
                # Corrupted or invalid RAR file
                max_score = max(max_score, 0.3)
            except rarfile.PasswordRequired:
                # Archive is encrypted (caught during instantiation if headers are encrypted)
                max_score = max(max_score, 0.7)
            except Exception:
                # Any other error suggests the file is problematic
                max_score = max(max_score, 0.3)

        elif filename.endswith(".7z"):
            try:
                with py7zr.SevenZipFile(io.BytesIO(content), 'r') as archive:
                    # Check if archive has password set
                    if archive.password_protected:
                        max_score = max(max_score, 0.7)
            except Exception:
                # Any other error suggests the file is problematic
                max_score = max(max_score, 0.3)

    return max_score

def check_mime_extension_mismatch(attachments):
    """
    Check if MIME type matches the file extension.
    Mismatches suggest file type spoofing (e.g., .pdf file with application/zip MIME).
    Returns mismatch_score: 0.0 (no mismatch) to 1.0 (severe mismatch)
    """
    if not attachments:
        return 0.0

    max_mismatch_score = 0.0

    for attachment in attachments:
        filename = attachment["filename"].lower()
        mime_type = attachment["mime_type"].lower()

        # Get file extension
        ext = ""
        if "." in filename:
            ext = "." + filename.rsplit(".", 1)[-1]

        # Check if extension has expected MIME types defined
        if ext not in EXPECTED_MIMES_BY_EXT:
            continue  # No MIME expectations for this extension

        expected_mimes = EXPECTED_MIMES_BY_EXT[ext]

        # Check if actual MIME matches any expected MIME for this extension
        if mime_type not in expected_mimes:
            # MIME doesn't match extension
            ext_score = RISKY_MIME_SCORES.get(ext, 0.0)

            # Score mismatch severity: penalize safe extension with dangerous MIME
            if mime_type in EXECUTABLE_MIMES:
                # Safe extension (.pdf) with executable MIME = clear spoofing
                mismatch_score = 0.9
            elif mime_type in ["application/zip", "application/x-rar-compressed", "application/x-rar"]:
                # Safe extension with archive MIME = likely trojan wrapper
                mismatch_score = 0.8
            else:
                # Other mismatches are suspicious but not as severe
                mismatch_score = 0.5

            max_mismatch_score = max(max_mismatch_score, mismatch_score)

    return max_mismatch_score

def analyze_attachments(email_raw):
    """
    Analyze email attachments for malicious indicators.

    Args:
        email_raw: Full email string (headers + body)

    Returns:
        attachment_score: 0.0 (safe) to 1.0 (malicious)
    """
    # Parse email to extract attachments
    attachments = extract_attachments(email_raw)

    if not attachments:
        return 0.0, {"risky_extension": False, "encrypted_archive": False, "mime_mismatch": False, "risky_files": [], "total_attachments": 0}

    # Run all checks and take maximum score
    mime_score = check_risky_mime_types(attachments)
    zip_score = check_encrypted_archives(attachments)
    mismatch_score = check_mime_extension_mismatch(attachments)

    attachment_score = max(mime_score, zip_score, mismatch_score)

    risky_files = [
        a["filename"] for a in attachments
        if RISKY_MIME_SCORES.get("." + a["filename"].lower().rsplit(".", 1)[-1], 0.0) > 0
        and "." in a["filename"]
    ]

    return attachment_score, {
        "risky_extension": mime_score > 0,
        "encrypted_archive": zip_score > 0,
        "mime_mismatch": mismatch_score > 0,
        "risky_files": risky_files,
        "total_attachments": len(attachments),
    }

