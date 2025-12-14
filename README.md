# IMAP Email Synchronization with Gmail OAuth2

This script synchronizes emails from a source IMAP server to Gmail using OAuth2 authentication.

## Features

- **Real-time sync** using IMAP IDLE notifications (with polling fallback)
- **Gmail OAuth2 authentication** - secure "Login with Google"
- **Persistent state tracking** - remembers synced messages across runs
- **Initial bulk transfer** - sync historical emails (configurable timeframe)
- **Continuous monitoring** - automatically copy new emails as they arrive
- **Comprehensive logging** - track all sync operations
- **Automatic OAuth token refresh** - no manual token renewal needed

## Prerequisites

### Required Python Packages

```bash
pip install -r requirements.txt
```

### Gmail OAuth2 Setup

To use Gmail as the target server, you need to set up OAuth2 credentials:

1. **Go to Google Cloud Console**: https://console.cloud.google.com/

2. **Create or select a project**:
   - Click "Select a project" → "New Project"
   - Give it a name (e.g., "IMAP Sync")
   - Click "Create"

3. **Enable Gmail API**:
   - Go to "APIs & Services" → "Library"
   - Search for "Gmail API"
   - Click on it and click "Enable"

4. **Create OAuth2 Credentials**:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - If prompted, configure the OAuth consent screen:
     - Choose "External" (unless you have a Google Workspace)
     - Fill in app name, user support email, and developer email
     - Click "Save and Continue"
     - Skip scopes section
     - Add your Gmail address as a test user
   - Back in credentials, create OAuth client ID:
     - Application type: "Desktop app"
     - Name: "IMAP Sync Client"
     - Click "Create"
   - Download the JSON file (button appears after creation)
   - Save it as `client_secret.json`

5. **Obtain an Access Token**:
   ```bash
   python get_gmail_token.py --credentials client_secret.json
   ```
   - A browser window will open
   - Log in with your Gmail account
   - Grant the requested permissions
   - The script will display your access token
   - Token is saved in `token.json` for future use

## Usage

### Configuration File Setup

Create a configuration file (e.g., `config.json`) with your server settings:

```json
{
  "source_server": "imap.sourceserver.com",
  "source_user": "user@sourceserver.com",
  "source_pass": "source_password",
  "target_user": "your-email@gmail.com",
  "target_token_file": "token.json"
}
```

A sample configuration file is provided as `config.json.example`.

**Important**: Keep your configuration file secure and never commit it to version control. Add `config.json` to your `.gitignore`.

### Basic Usage

```bash
python imap_sync_to_gmail.py --config config.json
```

The script will:
1. On first run: sync emails from the last 7 days
2. On subsequent runs: resume from where it left off, only syncing new messages
3. Track all synced messages in `sync_state.json` to prevent duplicates

### Enable Debug Logging

```bash
python imap_sync_to_gmail.py --config config.json --debug
```

### Logging Options

Log to a file (with automatic rotation):

```bash
python imap_sync_to_gmail.py --config config.json --log /var/log/imap_sync.log
```

Customize log rotation (500MB max size, keep 10 files):

```bash
python imap_sync_to_gmail.py --config config.json --log /var/log/imap_sync.log --log-max-size 500M --log-max-files 10
```

**Note**: When logging to a file, the script automatically:
- Rotates the log file when it reaches the specified size (default: 10 MB)
- Keeps the specified number of backup log files (default: 5)
- Compresses rotated log files with zstd (if available) or gzip (fallback)
  - With zstd: `imap_sync.log.1.zst`, `imap_sync.log.2.zst`, etc.
  - With gzip: `imap_sync.log.1.gz`, `imap_sync.log.2.gz`, etc.

Log to system log (syslog):

```bash
python imap_sync_to_gmail.py --config config.json --log syslog
```

Log to stderr (useful for systemd services):

```bash
python imap_sync_to_gmail.py --config config.json --log stderr
```

### Force Polling Mode (Disable IDLE)

If you experience issues with IDLE notifications:

```bash
python imap_sync_to_gmail.py --config config.json --no-idle --poll-interval 30
```

## Command-Line Options

### Mandatory Arguments

- `--config`: Path to JSON configuration file

### Configuration File Fields

The JSON configuration file must contain the following fields:

- `source_server`: Source IMAP server address (IP or FQDN)
- `source_user`: Source IMAP server username
- `source_pass`: Source IMAP password
- `target_user`: Target Gmail email address
- `target_token_file`: Path to JSON file containing OAuth2 token (must have a "token" field)

### Optional Command-Line Arguments

- `--state-file`: Path to state file for tracking synced messages (default: `sync_state.json`)
- `--log`: Logging target - `stdout`, `stderr`, `syslog`, or a file path (default: `stdout`)
- `--log-max-size`: Maximum log file size before rotation (e.g., `100K`, `10M`, `1G`) (default: `10M`)
- `--log-max-files`: Maximum number of rotated log files to keep (default: `5`)
- `--debug`: Enable debug logging for detailed output
- `--poll-interval N`: Seconds between polls if IDLE not supported (default: 60)
- `--no-idle`: Disable IDLE and force polling mode

## State Management

The script maintains a state file (`sync_state.json`) that tracks:
- **Synced message IDs**: Prevents duplicate copies of the same message
- **Last source UID**: Tracks the highest UID processed from source server
- **Last sync timestamp**: Records when the last sync occurred

This state allows the script to:
- Resume from where it left off if interrupted
- Avoid re-copying messages that were already synced
- Work efficiently even when restarted multiple times

**Important**: Keep the state file with your configuration. If deleted, the script will start fresh and may create duplicates for messages that were previously synced.

## How It Works

1. **Initial Sync**:
   - On first run: syncs emails from the last 7 days
   - On subsequent runs: resumes from the last sync timestamp
   - Connects to source server and Gmail (imap.gmail.com)
   - Retrieves emails from source INBOX since the start date
   - Checks state file to skip already-synced messages
   - Copies missing emails to Gmail
   - Updates state file after each batch (every 10 messages)

2. **Continuous Monitoring**:
   - **With IDLE** (preferred): Listens for real-time notifications from source server
   - **Without IDLE** (fallback): Polls source server at regular intervals
   - When new emails arrive, immediately copies them to target
   - Updates state file with each new message

3. **Duplicate Prevention**:
   - Uses Message-ID headers to uniquely identify emails
   - Maintains a set of all synced Message-IDs in the state file
   - Skips emails that have been previously synced
   - Also checks target server to avoid duplicates from manual copies

## Token Management

### Automatic Token Refresh

The script automatically handles OAuth token refresh when tokens expire. The token file (`token.json`) must contain:
- `token`: Current access token
- `refresh_token`: Used to obtain new access tokens
- `client_id`: OAuth client ID
- `client_secret`: OAuth client secret

These fields are automatically saved by `get_gmail_token.py`. When authentication fails due to an expired token, the script will:
1. Automatically request a new access token using the refresh token
2. Update the token file with the new access token
3. Retry the connection with the refreshed token

This means the script can run indefinitely without manual token renewal.

### Manual Token Refresh

If needed, you can manually refresh the token using:
```bash
python get_gmail_token.py --credentials client_secret.json
```

### Security Notes

- Keep `client_secret.json` and `token.json` secure
- Don't commit these files to version control
- Access tokens grant full access to your Gmail account
- Revoke access at: https://myaccount.google.com/permissions

## Troubleshooting

### "Authentication failed" error

- Verify your OAuth2 token is valid and not expired
- Re-run `get_gmail_token.py` to obtain a fresh token
- Ensure Gmail API is enabled in Google Cloud Console

### "IDLE not supported" message

- Some IMAP servers don't support IDLE
- The script automatically falls back to polling mode
- Adjust `--poll-interval` as needed for your use case

### Connection drops/timeouts

- The script automatically attempts to reconnect
- IDLE connections refresh every 29 minutes to prevent timeouts
- Check network stability and firewall rules

### Emails not syncing

- Enable `--debug` mode to see detailed operation logs
- Verify the source server has new emails in INBOX
- Check that Message-IDs are present in email headers

## Example Workflow

```bash
# 1. Set up OAuth2 credentials
python get_gmail_token.py --credentials client_secret.json

# 2. Create configuration file
cat > config.json << EOF
{
  "source_server": "imap.oldserver.com",
  "source_user": "myuser@oldserver.com",
  "source_pass": "mypassword",
  "target_user": "mynewaccount@gmail.com",
  "target_token_file": "token.json"
}
EOF

# 3. Secure the config file
chmod 600 config.json

# 4. Start the sync (in a screen/tmux session for long-running sync)
python imap_sync_to_gmail.py --config config.json --debug

# 5. Monitor the logs and let it run continuously
```

## License

This project is licensed under the BSD 3-Clause License. See the [LICENSE](LICENSE) file for details.
