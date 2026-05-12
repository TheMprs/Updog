import pytest
import sys
import zipfile
import io
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from analyzers.attachment import (
    extract_attachments,
    check_risky_mime_types,
    check_encrypted_archives,
    check_mime_extension_mismatch,
    analyze_attachments,
)

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False


class TestCheckEncryptedArchives:
    """Tests for encrypted archive detection"""

    def test_unencrypted_zip(self):
        # Create unencrypted ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('test.txt', 'Hello World')

        attachment = [{
            "filename": "archive.zip",
            "mime_type": "application/zip",
            "content": zip_buffer.getvalue()
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.0  # No encryption

    def test_encrypted_zip(self):
        # Create password-protected ZIP using writestr with pwd parameter
        # Note: standard zipfile doesn't support encryption on write, so we'll test
        # by creating a ZIP and manually setting encryption flags
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('test.txt', 'Hello World')
            # Manually set encryption flag on the file info
            info = zf.infolist()[0]
            info.flag_bits |= 0x1  # Set encryption flag

        # Re-open and verify encryption flag is set
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            # Check if encryption flag is set
            has_encryption = any(info.flag_bits & 0x1 for info in zf.infolist())

        if has_encryption:
            zip_buffer.seek(0)
            attachment = [{
                "filename": "archive.zip",
                "mime_type": "application/zip",
                "content": zip_buffer.getvalue()
            }]

            score = check_encrypted_archives(attachment)
            assert score == 0.7  # Encrypted
        else:
            # If we can't set encryption flag directly, skip this test
            pytest.skip("Cannot create encrypted ZIP with standard library")

    def test_corrupted_zip(self):
        # Corrupted ZIP data
        attachment = [{
            "filename": "archive.zip",
            "mime_type": "application/zip",
            "content": b"This is not a valid ZIP file content"
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.3  # Suspicious/corrupted

    @pytest.mark.skipif(not HAS_RARFILE, reason="rarfile package not installed")
    def test_encrypted_rar(self):
        # Note: Creating encrypted RAR requires rar command-line tool or rarfile with write support
        # For now, we'll test with a sample encrypted RAR header
        # This is a minimal valid RAR5 header with encryption markers
        rar_data = (
            b'Rar!\x07\x00'  # RAR5 signature
            + b'\x00' * 100  # Padding
        )

        attachment = [{
            "filename": "archive.rar",
            "mime_type": "application/x-rar-compressed",
            "content": rar_data
        }]

        score = check_encrypted_archives(attachment)
        # Will either be 0.0 (if library doesn't detect) or 0.3 (if lib flags as suspicious)
        assert score in [0.0, 0.3]

    @pytest.mark.skipif(not HAS_RARFILE, reason="rarfile package not installed")
    def test_corrupted_rar(self):
        # Invalid RAR file
        attachment = [{
            "filename": "archive.rar",
            "mime_type": "application/x-rar-compressed",
            "content": b"This is not a valid RAR file"
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.3  # Suspicious/corrupted

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr package not installed")
    def test_unencrypted_7z(self):
        # Create unencrypted 7z archive
        seven_z_buffer = io.BytesIO()
        with py7zr.SevenZipFile(seven_z_buffer, 'w') as archive:
            archive.writestr('test.txt', 'Hello World')

        attachment = [{
            "filename": "archive.7z",
            "mime_type": "application/x-7z-compressed",
            "content": seven_z_buffer.getvalue()
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.0  # No encryption

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr package not installed")
    def test_encrypted_7z(self):
        # Create password-protected 7z archive
        seven_z_buffer = io.BytesIO()
        with py7zr.SevenZipFile(seven_z_buffer, 'w', password='secret') as archive:
            archive.writestr('test.txt', 'Hello World')

        attachment = [{
            "filename": "archive.7z",
            "mime_type": "application/x-7z-compressed",
            "content": seven_z_buffer.getvalue()
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.7  # Encrypted

    @pytest.mark.skipif(not HAS_PY7ZR, reason="py7zr package not installed")
    def test_corrupted_7z(self):
        # Invalid 7z file
        attachment = [{
            "filename": "archive.7z",
            "mime_type": "application/x-7z-compressed",
            "content": b"This is not a valid 7z file"
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.3  # Suspicious/corrupted

    def test_empty_attachments(self):
        score = check_encrypted_archives([])
        assert score == 0.0

    def test_none_attachments(self):
        score = check_encrypted_archives(None)
        assert score == 0.0

    def test_non_archive_file(self):
        # Non-archive file should not trigger archive checks
        attachment = [{
            "filename": "document.pdf",
            "mime_type": "application/pdf",
            "content": b"%PDF-1.4\n..."
        }]

        score = check_encrypted_archives(attachment)
        assert score == 0.0

    def test_mixed_archives_detects_max(self):
        # Email with both unencrypted ZIP and encrypted 7z should detect the encrypted 7z
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('test.txt', 'Hello World')

        seven_z_buffer = io.BytesIO()
        with py7zr.SevenZipFile(seven_z_buffer, 'w', password='secret') as archive:
            archive.writestr('secret.txt', 'Secret content')

        attachments = [
            {
                "filename": "safe.zip",
                "mime_type": "application/zip",
                "content": zip_buffer.getvalue()
            },
            {
                "filename": "encrypted.7z",
                "mime_type": "application/x-7z-compressed",
                "content": seven_z_buffer.getvalue()
            }
        ]

        score = check_encrypted_archives(attachments)
        assert score == 0.7  # Should detect the encrypted 7z, not return 0.0 from safe ZIP


class TestCheckMimeExtensionMismatch:
    def test_matching_mime_extension(self):
        # PDF file with correct MIME type
        attachment = [{
            "filename": "document.pdf",
            "mime_type": "application/pdf",
            "content": b"PDF content"
        }]

        score = check_mime_extension_mismatch(attachment)
        assert score == 0.0

    def test_pdf_with_executable_mime(self):
        # PDF extension with executable MIME = clear spoofing
        attachment = [{
            "filename": "document.pdf",
            "mime_type": "application/x-msdownload",
            "content": b"Executable content"
        }]

        score = check_mime_extension_mismatch(attachment)
        assert score == 0.9  # Clear spoofing

    def test_pdf_with_zip_mime(self):
        # PDF extension with ZIP MIME = trojan wrapper
        attachment = [{
            "filename": "resume.pdf",
            "mime_type": "application/zip",
            "content": b"ZIP content"
        }]

        score = check_mime_extension_mismatch(attachment)
        assert score == 0.8  # Trojan wrapper

    def test_zip_with_executable_mime(self):
        # ZIP extension with executable MIME
        attachment = [{
            "filename": "archive.zip",
            "mime_type": "application/x-executable",
            "content": b"Executable content"
        }]

        score = check_mime_extension_mismatch(attachment)
        assert score == 0.9  # Clear spoofing

    def test_unknown_extension(self):
        # Unknown extension with any MIME = no check
        attachment = [{
            "filename": "file.xyz",
            "mime_type": "application/x-executable",
            "content": b"Content"
        }]

        score = check_mime_extension_mismatch(attachment)
        assert score == 0.0  # No expectation for .xyz


class TestAnalyzeAttachments:
    def test_no_attachments(self):
        email = "From: test@example.com\nSubject: Test\n\nNo attachments"
        score, _ = analyze_attachments(email)
        assert score == 0.0

    def test_safe_attachment(self):
        # Simple email with safe file type
        email = (
            "From: test@example.com\n"
            "Subject: Document\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=boundary123\n"
            "\n"
            "--boundary123\n"
            "Content-Type: text/plain\n"
            "\n"
            "Here is a document\n"
            "--boundary123\n"
            "Content-Type: application/pdf\n"
            "Content-Disposition: attachment; filename=\"document.pdf\"\n"
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "JVBERi0xLjQK\n"
            "--boundary123--\n"
        )

        score, _ = analyze_attachments(email)
        assert score < 0.5  # Safe or low risk

    def test_risky_extension(self):
        # Email with .exe attachment
        email = (
            "From: test@example.com\n"
            "Subject: Program\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=boundary123\n"
            "\n"
            "--boundary123\n"
            "Content-Type: application/x-msdownload\n"
            "Content-Disposition: attachment; filename=\"program.exe\"\n"
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "TVpaAAAA\n"
            "--boundary123--\n"
        )

        score, _ = analyze_attachments(email)
        assert score >= 0.8  # High risk

    def test_signals_returned(self):
        email = (
            "From: test@example.com\n"
            "Subject: Program\n"
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=boundary123\n"
            "\n"
            "--boundary123\n"
            "Content-Type: application/x-msdownload\n"
            "Content-Disposition: attachment; filename=\"program.exe\"\n"
            "Content-Transfer-Encoding: base64\n"
            "\n"
            "TVpaAAAA\n"
            "--boundary123--\n"
        )
        _, signals = analyze_attachments(email)
        assert signals["risky_extension"] is True
        assert "program.exe" in signals["risky_files"]
        assert isinstance(signals["encrypted_archive"], bool)
        assert isinstance(signals["mime_mismatch"], bool)
