"""
Import .eml files into Gmail inbox via Gmail API.
Usage: python tools/import_emails.py <path-to-eml-folder>

Setup:
  1. Go to Google Cloud Console → APIs & Services → Credentials
  2. Create OAuth 2.0 Client ID (Desktop app)
  3. Download as credentials.json and place next to this script
  4. pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client
"""

import base64
import os
import sys
import glob
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.insert"]
CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "credentials.json")
TOKEN_FILE = os.path.join(os.path.dirname(__file__), "token.json")


def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    return build("gmail", "v1", credentials=creds)


def insert_eml(service, eml_path):
    with open(eml_path, "rb") as f:
        raw = base64.urlsafe_b64encode(f.read()).decode()
    service.users().messages().insert(
        userId="me",
        internalDateSource="dateHeader",
        body={"raw": raw, "labelIds": ["INBOX"]},
    ).execute()


def main():
    if len(sys.argv) != 2:
        print("Usage: python tools/import_emails.py <path-to-eml-folder>")
        sys.exit(1)

    folder = sys.argv[1]
    if not os.path.isdir(folder):
        print(f"Error: {folder} is not a directory")
        sys.exit(1)

    eml_files = glob.glob(os.path.join(folder, "**/*.eml"), recursive=True)
    eml_files += glob.glob(os.path.join(folder, "*.eml"))
    eml_files = list(set(eml_files))

    if not eml_files:
        print(f"No .eml files found in {folder}")
        sys.exit(1)

    print(f"Found {len(eml_files)} .eml files")
    service = get_gmail_service()

    success, failed = 0, 0
    for i, path in enumerate(eml_files, 1):
        try:
            insert_eml(service, path)
            print(f"[{i}/{len(eml_files)}] OK {os.path.basename(path)}")
            success += 1
        except Exception as e:
            print(f"[{i}/{len(eml_files)}] FAIL {os.path.basename(path)} - {e}")
            failed += 1

    print(f"\nDone: {success} inserted, {failed} failed")


if __name__ == "__main__":
    main()
