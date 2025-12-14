#!/usr/bin/env python3
"""Helper script to obtain Gmail OAuth2 access token.

This script guides you through the OAuth2 flow to get an access token
that can be used with the imap_sync_to_gmail.py script.

Prerequisites:
1. Install required packages:
   pip install -r requirements.txt

2. Create OAuth2 credentials at Google Cloud Console:
   - Go to https://console.cloud.google.com/
   - Create a new project or select existing one
   - Enable Gmail API
   - Create OAuth 2.0 credentials (Desktop app)
   - Download the credentials JSON file

Usage:
    python get_gmail_token.py --credentials client_secret.json
"""

import argparse
import json
import sys
from pathlib import Path

try:
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
except ImportError:
    print("Error: Required packages not found.")
    print("Please install them with:")
    print("  pip install google-auth-oauthlib google-auth-httplib2")
    sys.exit(1)


# Gmail IMAP requires the full Gmail scope
SCOPES = ['https://mail.google.com/']


def get_oauth_token(credentials_file: str, token_file: str = 'token.json') -> str:
    """
    Get OAuth2 access token for Gmail.

    Args:
        credentials_file: Path to OAuth2 client credentials JSON file
        token_file: Path to save the token (default: token.json)

    Returns:
        Access token string
    """
    creds = None
    token_path = Path(token_file)

    # Check if we have a previously saved token
    if token_path.exists():
        print(f"Loading existing token from {token_file}")
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    # If there are no (valid) credentials available, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("Refreshing expired token...")
            creds.refresh(Request())
        else:
            print("Starting OAuth2 flow...")
            print("A browser window will open for you to authorize the application.")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
        print(f"Token saved to {token_file}")

    print("\n" + "=" * 60)
    print("SUCCESS! OAuth2 token obtained.")
    print("=" * 60)
    print(f"\nAccess Token: {creds.token}")
    print(f"\nThe token has been saved to {token_file}")
    print(f"\nYou can now use this with imap_sync_to_gmail.py:")
    print(f"\n1. Create a config.json file with your settings:")
    print(f"   {{")
    print(f"     \"source_server\": \"imap.sourceserver.com\",")
    print(f"     \"source_user\": \"user@sourceserver.com\",")
    print(f"     \"source_pass\": \"source_password\",")
    print(f"     \"target_user\": \"your-email@gmail.com\",")
    print(f"     \"target_token_file\": \"{token_file}\"")
    print(f"   }}")
    print(f"\n2. Run the sync script:")
    print(f"   python imap_sync_to_gmail.py --config config.json")
    print(f"\nNote: The token will be automatically refreshed when it expires.")
    print(f"      Refresh credentials are saved in {token_file}.")
    print("=" * 60)

    return creds.token


def main():
    parser = argparse.ArgumentParser(
        description='Obtain Gmail OAuth2 access token for IMAP sync',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Setup Instructions:
1. Go to https://console.cloud.google.com/
2. Create a new project or select an existing one
3. Enable the Gmail API
4. Go to "Credentials" and create OAuth 2.0 Client ID (Desktop app)
5. Download the credentials JSON file
6. Run this script with the downloaded file:
   python get_gmail_token.py --credentials client_secret.json
        """
    )

    parser.add_argument('--credentials', required=True,
                       help='Path to OAuth2 client credentials JSON file from Google Cloud Console')
    parser.add_argument('--token-file', default='token.json',
                       help='Path to save/load the token (default: token.json)')

    args = parser.parse_args()

    # Check if credentials file exists
    if not Path(args.credentials).exists():
        print(f"Error: Credentials file not found: {args.credentials}")
        print("\nPlease download your OAuth2 credentials from:")
        print("https://console.cloud.google.com/apis/credentials")
        sys.exit(1)

    try:
        get_oauth_token(args.credentials, args.token_file)
    except Exception as e:
        print(f"\nError obtaining token: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
