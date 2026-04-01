#!/usr/bin/env python3
"""
Quick OAuth helper — authenticates and saves token.
Run this first, then run copy_drive_files.py.
"""
from google_auth_oauthlib.flow import InstalledAppFlow

flow = InstalledAppFlow.from_client_secrets_file(
    "oauth-client.json",
    scopes=["https://www.googleapis.com/auth/drive"],
)
creds = flow.run_local_server(port=8090, open_browser=False)

with open("oauth-token.json", "w") as f:
    f.write(creds.to_json())

print("Token saved to oauth-token.json")
print("You can now run: python copy_drive_files.py")
