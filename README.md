# IMAP Email Synchronization with Gmail

This script is a one-way synchronization: new emails that appear at
the source IMAP server are uploaded to Gmail (via IMAP).

Effectively: this script forwards emails received at one mail server
to a Gmail inbox using IMAP as the transport mechanism.

## Why does this project exist?

I created this project because I own a domain and run an email server
on that domain.  Several of my family members receive email at this
domain, but prefer to use the Gmail client to access their email.

Google has many rules, policies, and anti-spam measures in place that
make forwarding email from a small, independent email server to Gmail
difficult.  For example, if you just blindly forward all mail sent to
joe@example.com to joe@gmail.com, that will likely include forwarding
a bunch of spam.  Google will eventually intepret that the SMTP server
at example.com is a spammer, and start penalizing that domain
accordingly.

For years, Gmail offered a feature that periodically POPed mail from
an external mail account and pulled it into a Gmail account.  Even
though this could introduce significant delays in getting mails
delivered to the Gmail account (because Gmail might poll POP for new
messages as little as once an hour), my family members all used this
service: it was reliable and didn't run afoul of any of Googles rules
/ policies / anti-spam measures / etc.

As of January 2026, however, [this POP-to-Gmail feature is being
retired](https://support.google.com/mail/answer/16604719).  I
therefore need a different mechanism for my family members to a) keep
receiving email at my domain but b) have the mail magically show up in
their Gmail inbox.

Hence: this project.  The intent is that this Python script will login
as family member X to my IMAP server, and also login to family
member's X Gmail account via IMAP.  In general, when a new email
arrives at my mail server, IMAP will send an asynchronous notification
which will prompt this Python script to download the message and then
upload it (via IMAP) to family member X's Gmail inbox.

## Features

- **Real-time sync** using IMAP IDLE notifications (with polling fallback)
- **Gmail OAuth2 authentication** - secure "Login with Google"
- **Persistent state tracking** - remembers synced messages across
  runs
- **Initial bulk transfer** - sync historical emails (configurable
  timeframe)
- **Continuous monitoring** - automatically copy new emails as they
  arrive
- **Comprehensive logging** - track all sync operations
- **Automatic OAuth token refresh** - no manual token renewal needed
- **Docker support** - containerized deployment with automated builds

## Prerequisites

### Docker (Recommended)

The easiest way to run this project is with Docker. No Python
setup required!

Pre-built images are automatically published to GitHub Container
Registry:
- On every push to `main` branch → `latest` and `edge` tags
- On every tagged release → version-specific tags (e.g., `v1.0.0`)

Pull the image:
```bash
docker pull ghcr.io/jsquyres/imap-to-gmail-sync:latest
```

See the [Docker Usage](#docker-recommended) section below for
complete instructions.

### Building Docker Image Locally

To build the Docker image yourself:

```bash
# Build the image
docker build -t imap-to-gmail-sync:local .

# Test it
docker run --rm imap-to-gmail-sync:local \
  python imap_sync_to_gmail.py --help
```

### Native Python Installation

If you prefer not to use Docker:

#### Required Python Packages

```bash
pip install -r requirements.txt
```

#### Gmail OAuth2 Setup

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

5. **Publish Your OAuth App** (Important for Long-Running
   Operation):
   - Go to "APIs & Services" → "OAuth consent screen" → "Audience"
   - Click **"PUBLISH APP"** button
   - Confirm the dialog
   - **Why this matters**: Apps in "Testing" status have refresh
     tokens that expire after 7 days (or sometimes even within N
     number of refreshes), requiring manual re-authentication.
     Published apps have refresh tokens that remain valid
     indefinitely (until manually revoked), allowing truly
     unattended operation.
   - **Note**: For personal/family use with under 100 users, you
     don't need Google's verification. Your app will show a "Google
     hasn't verified this app" warning during login - this is normal
     and safe for personal apps. Just click "Continue" to proceed.

6. **Obtain an Access Token**:
   ```bash
   python get_gmail_token.py --credentials client_secret.json
   ```
   - A browser window will open
   - Log in with your Gmail account
   - Grant the requested permissions
   - The script will display your access token
   - Token is saved in `token.json` for future use
   - **Important**: Generate tokens AFTER publishing your app to get
     non-expiring refresh tokens

## Usage

### Docker (Recommended)

The easiest way to run this project is using Docker. Pre-built
images are available from GitHub Container Registry.

#### Pull the Docker image

```bash
# Pull the latest version
docker pull ghcr.io/jsquyres/imap-to-gmail-sync:latest

# Or pull a specific version
docker pull ghcr.io/jsquyres/imap-to-gmail-sync:v1.0.0
```

#### Generate OAuth Token

First, obtain your Gmail OAuth token:

```bash
# Create a directory for your configuration files
mkdir -p ~/imap-sync-data

# Copy your client_secret.json to the data directory
cp client_secret.json ~/imap-sync-data/

# Generate the OAuth token
docker run --rm -it \
  -v ~/imap-sync-data:/data \
  ghcr.io/jsquyres/imap-to-gmail-sync:latest \
  python get_gmail_token.py \
    --credentials /data/client_secret.json \
    --token /data/token.json
```

#### Create Configuration File

Create a configuration file at `~/imap-sync-data/config.json`:

```json
{
  "source_server": "imap.sourceserver.com",
  "source_user": "user@sourceserver.com",
  "source_pass": "source_password",
  "target_user": "your-email@gmail.com",
  "target_token_file": "/data/token.json"
}
```

#### Run the Sync

```bash
# Run the sync in the foreground (for testing)
docker run --rm -it \
  -v ~/imap-sync-data:/data \
  ghcr.io/jsquyres/imap-to-gmail-sync:latest \
  python imap_sync_to_gmail.py \
    --config /data/config.json \
    --log /data/sync.log

# Run the sync in the background (detached)
docker run -d \
  --name imap-sync \
  --restart unless-stopped \
  -v ~/imap-sync-data:/data \
  ghcr.io/jsquyres/imap-to-gmail-sync:latest \
  python imap_sync_to_gmail.py \
    --config /data/config.json \
    --log /data/sync.log
```

#### Managing the Container

```bash
# View logs
docker logs imap-sync

# Follow logs in real-time
docker logs -f imap-sync

# Stop the sync
docker stop imap-sync

# Start it again
docker start imap-sync

# Remove the container
docker rm imap-sync
```

### Native Python Installation

If you prefer not to use Docker, you can run the scripts directly
with Python.

#### Configuration File Setup

Create a configuration file (e.g., `config.json`) with your server
settings:

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

#### Basic Usage

```bash
python imap_sync_to_gmail.py --config config.json
```

The script will:
1. On first run: sync emails from the last 7 days
2. On subsequent runs: resume from where it left off, only syncing
   new messages
3. Track the last 31 days worth of synced messages in
   `sync_state.json` to prevent duplicates

#### Enable Debug Logging

```bash
python imap_sync_to_gmail.py --config config.json --debug
```

#### Logging Options

Log to a file (with automatic rotation):

```bash
python imap_sync_to_gmail.py \
  --config config.json \
  --log /var/log/imap_sync.log
```

Customize log rotation (500MB max size, keep 10 files):

```bash
python imap_sync_to_gmail.py \
  --config config.json \
  --log /var/log/imap_sync.log \
  --log-max-size 500M \
  --log-max-files 10
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
python imap_sync_to_gmail.py \
  --config config.json \
  --no-idle \
  --poll-interval 30
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
- `target_token_file`: Path to JSON file containing OAuth2 token
  (must have a "token" field)

### Optional Command-Line Arguments

- `--state-file`: Path to state file for tracking synced messages
  (default: `sync_state.json`)
- `--log`: Logging target - `stdout`, `stderr`, `syslog`, or a file
  path (default: `stdout`)
- `--log-max-size`: Maximum log file size before rotation (e.g.,
  `100K`, `10M`, `1G`) (default: `10M`)
- `--log-max-files`: Maximum number of rotated log files to keep
  (default: `5`)
- `--debug`: Enable debug logging for detailed output
- `--poll-interval N`: Seconds between polls if IDLE not supported
  (default: 60)
- `--no-idle`: Disable IDLE and force polling mode

## Running as a Systemd Service (Linux)

For production deployments on Linux, you can configure the sync script
to run automatically at boot using user-level systemd services. This
approach supports running multiple instances simultaneously, each with
its own configuration, log files, and state tracking.

### Prerequisites

- Linux system with systemd (most modern distributions)
- Python 3.8 or later installed
- OAuth token and configuration files already set up (see above)

### Single Instance Setup

#### 1. Create the Systemd Service File

Create `~/.config/systemd/user/imap-sync.service`:

```ini
[Unit]
Description=IMAP to Gmail Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/imap-to-gmail-sync
ExecStart=/usr/bin/python3 %h/imap-to-gmail-sync/imap_sync_to_gmail.py \
    --config %h/imap-to-gmail-sync/config.json \
    --state-file %h/imap-to-gmail-sync/sync_state.json \
    --log stderr
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
```

**Notes**:
- `%h` expands to your home directory
- Adjust paths to match your installation location
- `--log stderr` sends logs to systemd's journal
- `Restart=always` ensures automatic restart on crashes
- `RestartSec=30` waits 30 seconds before restarting

#### 2. Enable and Start the Service

```bash
# Reload systemd to pick up the new service file
systemctl --user daemon-reload

# Enable the service to start at boot
systemctl --user enable imap-sync.service

# Start the service now
systemctl --user start imap-sync.service

# Check the service status
systemctl --user status imap-sync.service
```

#### 3. Enable Lingering (Important for Auto-Start)

By default, user systemd services only run while you're logged in.
To enable auto-start at boot (even when not logged in):

```bash
# Enable lingering for your user account
sudo loginctl enable-linger $USER
```

#### 4. Managing the Service

```bash
# View logs (last 100 lines)
journalctl --user -u imap-sync.service -n 100

# Follow logs in real-time
journalctl --user -u imap-sync.service -f

# Restart the service
systemctl --user restart imap-sync.service

# Stop the service
systemctl --user stop imap-sync.service

# Disable auto-start at boot
systemctl --user disable imap-sync.service
```

### Multiple Instance Setup (Template Service)

To run multiple sync instances (e.g., for different family members),
use a systemd template service.

#### 1. Create the Template Service File

Create `~/.config/systemd/user/imap-sync@.service`:

```ini
[Unit]
Description=IMAP to Gmail Sync for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%h/imap-to-gmail-sync
ExecStart=/usr/bin/python3 %h/imap-to-gmail-sync/imap_sync_to_gmail.py \
    --config %h/imap-to-gmail-sync/%i-config.json \
    --state-file %h/imap-to-gmail-sync/%i-sync_state.json \
    --log stderr
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
```

**Key Points**:
- `%i` is replaced with the instance name (e.g., `alice`, `bob`)
- Each instance uses its own config and state files

#### 2. Set Up Configuration Files

For each user, create separate files with the instance name prefix:

```bash
# Alice's configuration
~/imap-to-gmail-sync/alice-config.json
~/imap-to-gmail-sync/alice-token.json

# Bob's configuration
~/imap-to-gmail-sync/bob-config.json
~/imap-to-gmail-sync/bob-token.json

# And so on...
```

Example `alice-config.json`:
```json
{
  "source_server": "imap.example.com",
  "source_user": "alice@example.com",
  "source_pass": "alice_password",
  "target_user": "alice@gmail.com",
  "target_token_file": "/home/youruser/imap-to-gmail-sync/alice-token.json"
}
```

#### 3. Enable and Start Multiple Instances

```bash
# Reload systemd
systemctl --user daemon-reload

# Enable lingering (only needed once)
sudo loginctl enable-linger $USER

# Enable and start instances for Alice and Bob
systemctl --user enable imap-sync@alice.service
systemctl --user enable imap-sync@bob.service
systemctl --user start imap-sync@alice.service
systemctl --user start imap-sync@bob.service

# Check status of all instances
systemctl --user status 'imap-sync@*.service'
```

#### 4. Managing Multiple Instances

```bash
# View logs for a specific instance
journalctl --user -u imap-sync@alice.service -f

# Restart a specific instance
systemctl --user restart imap-sync@bob.service

# Stop all instances
systemctl --user stop 'imap-sync@*.service'

# List all running instances
systemctl --user list-units 'imap-sync@*.service'
```

### Log File Alternative

If you prefer log files instead of systemd journal:

Modify the `ExecStart` line in your service file:

```ini
ExecStart=/usr/bin/python3 %h/imap-to-gmail-sync/imap_sync_to_gmail.py \
    --config %h/imap-to-gmail-sync/%i-config.json \
    --state-file %h/imap-to-gmail-sync/%i-sync_state.json \
    --log %h/imap-to-gmail-sync/%i-sync.log \
    --log-max-size 50M \
    --log-max-files 10
```

This creates separate log files:
- `alice-sync.log`, `alice-sync.log.1.zst`, etc.
- `bob-sync.log`, `bob-sync.log.1.zst`, etc.

### Troubleshooting Systemd Services

#### Service fails to start

```bash
# Check service status and recent logs
systemctl --user status imap-sync.service
journalctl --user -u imap-sync.service -n 50

# Verify paths are correct
# Verify config file is valid JSON
python3 -m json.tool ~/imap-to-gmail-sync/config.json
```

#### Service doesn't auto-start at boot

```bash
# Verify lingering is enabled
loginctl show-user $USER | grep Linger

# If it shows "Linger=no", enable it:
sudo loginctl enable-linger $USER

# Verify service is enabled
systemctl --user is-enabled imap-sync.service
```

#### Python not found

If `/usr/bin/python3` doesn't exist on your system, find the correct
path:

```bash
which python3
```

Then update the `ExecStart` line in your service file to use the
correct path.

## State Management

The script maintains a state file (`sync_state.json`) that tracks:
- **Synced message IDs**: Prevents duplicate copies of the same message
- **Last source UID**: Tracks the highest UID processed from source server
- **Last sync timestamp**: Records when the last sync occurred

This state allows the script to:
- Resume from where it left off if interrupted
- Avoid re-copying messages that were already synced
- Work efficiently even when restarted multiple times

## How It Works

1. **Initial Sync**:
   - On first run: syncs emails from the last 7 days
   - On subsequent runs: resumes from the last sync timestamp
   - Connects to source server and Gmail (imap.gmail.com)
   - Retrieves emails from source INBOX since the start date
     - Note that the IMAP protocol only allows searching for messages
       by date (not a specific timestamp on a date).
     - Hence, when re-starting the script, it is expected that we may
       find messages on the source IMAP server that have already been
       transferred to Gmail.
     - The script therefore tracks message IDs of messages that it
       transferrs to Gmail, enabling duplicate detection and the
       prevention of transferring the same message to Gmail more than
       once.
   - Checks state file to skip already-synced messages
   - Copies missing emails to Gmail
   - Updates state file after each batch (every 10 messages)

2. **Continuous Monitoring**:
   - **With IDLE** (preferred): Listens for real-time notifications
     from source server
   - **Without IDLE** (fallback): Polls source server at regular
     intervals
   - When new emails arrive, immediately copies them to target
   - Updates state file with each new message

3. **Duplicate Prevention**:
   - Uses Message-ID headers to uniquely identify emails
   - Maintains a set of all synced Message-IDs in the state file
   - Skips emails that have been previously synced
   - Also checks target server to avoid duplicates from manual copies

## Token Management

### Automatic Token Refresh

The script automatically handles OAuth token refresh when tokens
expire. The token file (`token.json`) must contain:
- `token`: Current access token
- `refresh_token`: Used to obtain new access tokens
- `client_id`: OAuth client ID
- `client_secret`: OAuth client secret

These fields are automatically saved by `get_gmail_token.py`. When
authentication fails due to an expired token, the script will:
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

This project is licensed under the BSD 3-Clause License. See the
[LICENSE](LICENSE) file for details.
