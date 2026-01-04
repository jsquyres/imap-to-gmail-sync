#!/usr/bin/env python3
"""
IMAP Email Synchronization Script

Synchronizes emails from a source IMAP server to a target IMAP server,
with support for initial bulk transfer and continuous monitoring.
"""

import argparse
import imaplib
import email
import logging
import time
import select
import json
import requests
import os
from datetime import datetime, timedelta, timezone
from typing import Set, Optional
import sys


# Logger will be configured in main() based on CLI arguments
logger = logging.getLogger(__name__)


class ActivityTrackingHandler(logging.Handler):
    """Handler that tracks whether any logging has occurred.

    This allows us to help limit the amount of logging output during idle periods.
    Specifically: be able to tell if we have emitted something since the last time
    we checked.  If nothing has occurred, no need to emit again."""

    def __init__(self):
        super().__init__()
        self.activity_occurred = False

    def emit(self, record):
        """Called for every log record - mark activity as occurred."""
        self.activity_occurred = True

    def check_and_reset(self) -> bool:
        """Check if activity occurred and reset the flag."""
        occurred = self.activity_occurred
        self.activity_occurred = False
        return occurred


class IMAPSync:
    """Handles IMAP email synchronization between two servers."""

    def __init__(self, src_server: str, src_user: str, src_pass: str,
                 tgt_user: str, tgt_oauth_token: str,
                 state_file: str = 'sync_state.json'):
        """
        Initialize IMAP synchronization.

        Args:
            src_server: Source IMAP server address
            src_user: Source IMAP username
            src_pass: Source IMAP password
            tgt_user: Target Gmail email address
            tgt_oauth_token: Target OAuth2 access token for Gmail
            state_file: Path to state file for tracking synced messages
        """
        self.src_server = src_server
        self.src_user = src_user
        self.src_pass = src_pass
        self.tgt_server = 'imap.gmail.com'
        self.tgt_user = tgt_user
        self.tgt_oauth_token = tgt_oauth_token
        self.state_file = state_file

        self.src_conn: Optional[imaplib.IMAP4_SSL] = None
        self.tgt_conn: Optional[imaplib.IMAP4_SSL] = None
        self.idle_supported: bool = False

        # Load or initialize state
        self.state = self.load_state()

        logger.debug(f"Loaded state: {len(self.state.get('synced_message_ids', {}))} previously synced messages")

    def load_state(self) -> dict:
        """Load synchronization state from file.

        Returns:
            Dictionary containing sync state
        """
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    # Handle both old format (set/list) and new format (dict with timestamps)
                    if 'synced_message_ids' in state:
                        if isinstance(state['synced_message_ids'], list):
                            # Old format: convert list to dict with None timestamps
                            state['synced_message_ids'] = {msg_id: None for msg_id in state['synced_message_ids']}
                        # New format is already a dict
                    logger.info(f"Loaded state from {self.state_file}")

                    # Prune messages older than 31 days
                    state = self.prune_old_messages(state)
                    return state
            except Exception as e:
                logger.warning(f"Could not load state file: {e}. Starting fresh.")

        # Initialize new state
        return {
            'synced_message_ids': {},
            'last_source_uid': 0,
            'last_sync': None
        }

    def prune_old_messages(self, state: dict) -> dict:
        """Prune messages with timestamps older than 31 days from state.

        Args:
            state: State dictionary to prune

        Returns:
            Pruned state dictionary
        """
        if 'synced_message_ids' not in state or not isinstance(state['synced_message_ids'], dict):
            return state

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=31)
        original_count = len(state['synced_message_ids'])

        # Filter out messages older than 31 days
        state['synced_message_ids'] = {
            msg_id: timestamp
            for msg_id, timestamp in state['synced_message_ids'].items()
            if timestamp is None or datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc) > cutoff_date
        }

        pruned_count = original_count - len(state['synced_message_ids'])
        if pruned_count > 0:
            logger.info(f"Pruned {pruned_count} messages older than 31 days from state")

        return state

    def save_state(self):
        """Save synchronization state to file."""
        try:
            # Prune old messages before saving
            self.state = self.prune_old_messages(self.state)

            # Save state (synced_message_ids is already a dict)
            state_to_save = self.state.copy()
            state_to_save['last_sync'] = datetime.now(timezone.utc).isoformat()

            with open(self.state_file, 'w') as f:
                json.dump(state_to_save, f, indent=2)
            logger.debug(f"Saved state to {self.state_file}")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def connect_target(self, log_prefix: str = "Connecting") -> bool:
        """
        Connect to the target IMAP server (Gmail) using OAuth2.

        Args:
            log_prefix: Prefix for log messages (e.g., "Connecting" or "Reconnecting")

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Connect to target server (Gmail) using OAuth2
            logger.info(f"{log_prefix} to target IMAP server (Gmail): {self.tgt_server}")
            self.tgt_conn = imaplib.IMAP4_SSL(self.tgt_server)

            # Authenticate with OAuth2
            logger.debug("Authenticating to Gmail using OAuth2...")
            auth_string = self.generate_oauth2_string(self.tgt_user, self.tgt_oauth_token)
            try:
                self.tgt_conn.authenticate('XOAUTH2', lambda x: auth_string.encode())
                logger.info(f"Successfully authenticated to Gmail as {self.tgt_user}")
            except imaplib.IMAP4.error as auth_error:
                # Check if it's an authentication error that might be due to expired token
                error_str = str(auth_error)
                if 'AUTHENTICATIONFAILED' in error_str or 'Invalid credentials' in error_str:
                    logger.warning("Authentication failed - token may be expired, attempting refresh...")
                    if hasattr(self, 'token_file') and hasattr(self, 'token_data'):
                        new_token = self.refresh_oauth_token(self.token_file, self.token_data)
                        if new_token:
                            # Retry authentication with new token
                            self.tgt_oauth_token = new_token
                            auth_string = self.generate_oauth2_string(self.tgt_user, self.tgt_oauth_token)
                            self.tgt_conn.authenticate('XOAUTH2', lambda x: auth_string.encode())
                            logger.info(f"Successfully authenticated to Gmail with refreshed token as {self.tgt_user}")
                        else:
                            # Token refresh failed - this is a fatal error
                            logger.error("Cannot continue without valid authentication")
                            logger.error("Please generate a new token and restart the sync")
                            raise auth_error
                    else:
                        logger.error("Token refresh not available (missing token_file or token_data)")
                        raise auth_error
                else:
                    raise auth_error

            return True

        except Exception as e:
            logger.error(f"Failed to connect to target server: {e}")
            return False

    def connect_source(self) -> bool:
        """
        Connect to the source IMAP server.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Connect to source server
            logger.info(f"Connecting to source IMAP server: {self.src_server}")
            self.src_conn = imaplib.IMAP4_SSL(self.src_server)
            self.src_conn.login(self.src_user, self.src_pass)
            logger.info(f"Successfully authenticated to source server as {self.src_user}")

            # Check if server supports IDLE
            self.check_idle_support()

            return True

        except imaplib.IMAP4.error as e:
            logger.error(f"IMAP authentication error on source server: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection error on source server: {e}")
            return False

    def connect(self) -> bool:
        """
        Establish encrypted IMAP connections to both servers.

        Returns:
            True if both connections successful, False otherwise
        """
        # Connect to source server using helper method
        if not self.connect_source():
            return False

        # Connect to target server using helper method
        if not self.connect_target("Connecting"):
            return False

        return True

    def reconnect_target(self) -> bool:
        """
        Reconnect to the target IMAP server (Gmail).

        Returns:
            True if reconnection successful, False otherwise
        """
        # Close existing connection if any
        if self.tgt_conn:
            try:
                self.tgt_conn.logout()
            except:
                pass

        # Use the common connect_target method
        return self.connect_target("Reconnecting")

    def with_target_retry(self, operation, *args, max_attempts: int = 3, **kwargs):
        """
        Execute an operation on the target IMAP connection with automatic retry and reconnection.

        Args:
            operation: Callable to execute
            *args: Positional arguments for the operation
            max_attempts: Maximum number of retry attempts (default: 3)
            **kwargs: Keyword arguments for the operation

        Returns:
            Result of the operation

        Raises:
            Exception: If all retry attempts fail
        """
        for attempt in range(1, max_attempts + 1):
            try:
                return operation(*args, **kwargs)
            except Exception as e:
                logger.error(f"Target IMAP error on attempt {attempt}/{max_attempts}: {e}")

                if attempt < max_attempts:
                    logger.info(f"Attempting to reconnect to target server (attempt {attempt}/{max_attempts})...")

                    # Close and reconnect
                    if self.reconnect_target():
                        logger.info("Reconnection successful, retrying operation...")
                        continue
                    else:
                        logger.error("Reconnection failed")
                        time.sleep(2)  # Brief delay before retry
                        continue
                else:
                    logger.error(f"Operation failed after {max_attempts} attempts")
                    raise

    def generate_oauth2_string(self, user: str, token: str) -> str:
        """
        Generate OAuth2 authentication string for Gmail IMAP.

        Args:
            user: Gmail email address
            token: OAuth2 access token

        Returns:
            OAuth2 authentication string (not base64 encoded)
        """
        auth_string = f'user={user}\x01auth=Bearer {token}\x01\x01'
        return auth_string

    def refresh_oauth_token(self, token_file: str, token_data: dict) -> Optional[str]:
        """
        Refresh an expired OAuth2 token using the refresh token.

        Args:
            token_file: Path to token file to update
            token_data: Current token data containing refresh_token

        Returns:
            New access token if successful, None otherwise
        """
        if 'refresh_token' not in token_data:
            logger.error("No refresh_token available in token file")
            return None

        if 'client_id' not in token_data or 'client_secret' not in token_data:
            logger.error("Token file missing client_id or client_secret for refresh")
            return None

        logger.info("Attempting to refresh OAuth token...")

        try:
            # Prepare token refresh request
            token_url = 'https://oauth2.googleapis.com/token'
            data = {
                'client_id': token_data['client_id'],
                'client_secret': token_data['client_secret'],
                'refresh_token': token_data['refresh_token'],
                'grant_type': 'refresh_token'
            }

            response = requests.post(token_url, data=data)
            response.raise_for_status()

            new_token_data = response.json()

            # Update token in the data
            token_data['token'] = new_token_data['access_token']
            if 'expires_in' in new_token_data:
                token_data['expiry'] = (datetime.now(timezone.utc) + timedelta(seconds=new_token_data['expires_in'])).isoformat()

            # Save updated token to file
            with open(token_file, 'w') as f:
                json.dump(token_data, f, indent=2)

            logger.info("Successfully refreshed OAuth token")
            return new_token_data['access_token']

        except requests.exceptions.HTTPError as e:
            # Parse error response for more details
            error_detail = ""
            try:
                error_response = e.response.json()
                error_detail = error_response.get('error', '')
                error_description = error_response.get('error_description', '')

                if error_detail:
                    logger.error(f"Token refresh failed: {error_detail}")
                    if error_description:
                        logger.error(f"Details: {error_description}")
            except:
                pass

            # Provide actionable guidance based on error type
            if e.response.status_code == 400:
                logger.error("="*60)
                logger.error("AUTHENTICATION ERROR: Refresh token is invalid or expired")
                logger.error("="*60)
                logger.error("Your OAuth refresh token is no longer valid. This can happen if:")
                logger.error("  - The token was revoked in Google Account settings")
                logger.error("  - The token expired (refresh tokens can expire)")
                logger.error("  - The OAuth client credentials changed")
                logger.error("")
                logger.error("ACTION REQUIRED: Generate a new OAuth token by running:")
                logger.error(f"  python3 get_gmail_token.py")
                logger.error("")
                logger.error("This will create a new token file that you can use.")
                logger.error("="*60)
            else:
                logger.error(f"Failed to refresh token: {e}")

            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during token refresh: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during token refresh: {e}")
            return None

    def check_idle_support(self):
        """Check if the source server supports IDLE extension."""
        try:
            if hasattr(self.src_conn, 'capability'):
                capability = self.src_conn.capability()
                if capability and capability[0] == 'OK':
                    capabilities = capability[1][0].decode('utf-8').upper()
                    self.idle_supported = 'IDLE' in capabilities
                    if self.idle_supported:
                        logger.info("Source server supports IDLE - using real-time notifications")
                    else:
                        logger.info("Source server does not support IDLE - will use polling")
        except Exception as e:
            logger.warning(f"Could not check IDLE capability: {e}. Will use polling.")
            self.idle_supported = False

    def disconnect(self):
        """Close IMAP connections."""
        try:
            if self.src_conn:
                self.src_conn.logout()
                logger.debug("Disconnected from source server")
        except:
            pass

        try:
            if self.tgt_conn:
                self.tgt_conn.logout()
                logger.debug("Disconnected from target server")
        except:
            pass

    def get_message_ids(self, conn: imaplib.IMAP4_SSL) -> Set[str]:
        """
        Get all Message-IDs from the INBOX.

        Args:
            conn: IMAP connection

        Returns:
            Set of Message-ID strings
        """
        message_ids = set()

        try:
            conn.select('INBOX', readonly=True)
            logger.debug("Fetching all message IDs from server...")
            _, message_numbers = conn.search(None, 'ALL')
            logger.debug(f"Total messages in INBOX: {len(message_numbers[0].split())}")

            msg_count = 0
            for num in message_numbers[0].split():
                try:
                    _, msg_data = conn.fetch(num, '(BODY[HEADER.FIELDS (MESSAGE-ID)])')
                    if msg_data and msg_data[0]:
                        email_message = email.message_from_bytes(msg_data[0][1])
                        msg_id = email_message.get('Message-ID', '').strip()
                        if msg_id:
                            message_ids.add(msg_id)
                            msg_count += 1
                            if msg_count % 100 == 0:
                                logger.debug(f"Processed {msg_count} message IDs...")
                except Exception as e:
                    logger.debug(f"Error fetching message {num}: {e}")

            logger.debug(f"Finished fetching message IDs. Total: {len(message_ids)}")

        except Exception as e:
            logger.error(f"Error getting message IDs: {e}")

        return message_ids

    def get_messages_since(self, conn: imaplib.IMAP4_SSL, since_date: datetime) -> list:
        """
        Get all messages from INBOX since a specific date.

        Args:
            conn: IMAP connection
            since_date: Only fetch messages on or after this date (in UTC)

        Returns:
            List of tuples (message_id, message_data, timestamp_iso)
        """
        messages = []

        try:
            conn.select('INBOX', readonly=True)

            # IMAP SINCE uses server's local date (no timezone), so we need to be conservative.
            # Subtract an extra day to account for timezone differences between UTC and server time.
            # This ensures we don't miss messages due to timezone offset (up to ±24 hours).
            # We'll filter out duplicates using our state tracking.
            conservative_date = since_date - timedelta(days=1)

            # Format date for IMAP SINCE command (DD-MMM-YYYY)
            # Note: IMAP SINCE compares dates only (no time component) in server's local timezone
            date_str = conservative_date.strftime('%d-%b-%Y')
            logger.debug(f"Searching for messages since {date_str} (server local date, adjusted from {since_date.date()} UTC for timezone safety)")

            _, message_numbers = conn.search(None, f'SINCE {date_str}')

            if not message_numbers[0]:
                logger.info("No messages found since specified date")
                return messages

            msg_nums = message_numbers[0].split()
            logger.info(f"Found {len(msg_nums)} messages since {date_str} (may include some older than {since_date.date()} UTC due to timezone adjustment)")

            for num in msg_nums:
                try:
                    # Fetch the entire message including headers and body
                    _, msg_data = conn.fetch(num, '(RFC822)')
                    if msg_data and msg_data[0]:
                        raw_email = msg_data[0][1]
                        email_message = email.message_from_bytes(raw_email)
                        msg_id = email_message.get('Message-ID', '').strip()

                        if msg_id:
                            # Extract Date header and convert to ISO format
                            msg_timestamp = self.extract_message_timestamp(email_message)

                            # Filter out messages that are actually before our UTC cutoff
                            # This handles the timezone safety margin we added above
                            msg_datetime = datetime.fromisoformat(msg_timestamp)
                            if msg_datetime < since_date:
                                logger.debug(f"Skipping message {msg_id} (date: {msg_timestamp}) - older than requested cutoff {since_date.isoformat()} (caught by timezone-safe query margin)")
                                continue

                            messages.append((msg_id, raw_email, msg_timestamp))
                            logger.debug(f"Fetched message: {msg_id} (date: {msg_timestamp})")
                        else:
                            logger.warning(f"Message {num} has no Message-ID")

                except Exception as e:
                    logger.error(f"Error fetching message {num}: {e}")

        except Exception as e:
            logger.error(f"Error searching for messages: {e}")

        return messages

    def extract_message_timestamp(self, email_message) -> str:
        """Extract and normalize message timestamp from Date header.

        Args:
            email_message: Parsed email message object

        Returns:
            ISO format timestamp string in UTC, or current UTC time if Date header is missing/invalid
        """
        try:
            date_header = email_message.get('Date', '')
            if date_header:
                # Parse the date using email.utils (returns timezone-aware datetime)
                from email.utils import parsedate_to_datetime
                msg_date = parsedate_to_datetime(date_header)
                # Convert to UTC and return ISO format
                msg_date_utc = msg_date.astimezone(timezone.utc)
                return msg_date_utc.isoformat()
        except Exception as e:
            logger.debug(f"Could not parse Date header: {e}")

        # Fallback to current UTC time if Date header is missing or invalid
        return datetime.now(timezone.utc).isoformat()

    def copy_message(self, message_data: bytes) -> bool:
        """
        Copy a message to the target server's INBOX.
        Implements retry logic with connection recovery for transient failures.

        Args:
            message_data: Raw email message data

        Returns:
            True if successful, False otherwise
        """
        try:
            def _copy():
                self.tgt_conn.select('INBOX')
                # Use APPEND to add the message directly
                self.tgt_conn.append('INBOX', '', imaplib.Time2Internaldate(time.time()), message_data)

            self.with_target_retry(_copy, max_attempts=5)
            return True

        except Exception as e:
            logger.error(f"Failed to copy message after all retry attempts: {e}")
            return False

    def check_message_exists(self, conn: imaplib.IMAP4_SSL, msg_id: str) -> bool:
        """Check if a message with given Message-ID exists on the server.

        Args:
            conn: IMAP connection
            msg_id: Message-ID to search for

        Returns:
            True if message exists, False otherwise
        """
        # If this is the target connection, use retry logic (because
        # Gmail may expire our token and require a refresh)
        if conn is self.tgt_conn:
            try:
                def _check():
                    conn.select('INBOX', readonly=True)
                    _, result = conn.search(None, f'HEADER Message-ID "{msg_id}"')
                    return len(result[0]) > 0
                return self.with_target_retry(_check)
            except Exception as e:
                logger.error(f"Error checking if message exists on target after retries: {e}")
                return False
        else:
            # Source connection: do it without retry logic
            try:
                conn.select('INBOX', readonly=True)
                _, result = conn.search(None, f'HEADER Message-ID "{msg_id}"')
                return len(result[0]) > 0
            except Exception as e:
                logger.debug(f"Error checking if message exists: {e}")
                return False

    def initial_sync(self):
        """Perform initial bulk synchronization."""
        logger.info("=" * 60)
        logger.info("Starting initial synchronization")
        logger.info("=" * 60)

        # Determine time range for initial sync
        if self.state['last_sync']:
            # Resume from last sync
            try:
                last_sync_time = datetime.fromisoformat(self.state['last_sync'])
                # Ensure timezone awareness (treat as UTC if naive)
                if last_sync_time.tzinfo is None:
                    last_sync_time = last_sync_time.replace(tzinfo=timezone.utc)
                logger.info(f"Resuming from last sync at {last_sync_time}")
                first_transfer = last_sync_time
            except:
                first_transfer = datetime.now(timezone.utc) - timedelta(days=7)
                logger.info("Could not parse last sync time, defaulting to 7 days ago")
        else:
            # First run - sync last 7 days
            first_transfer = datetime.now(timezone.utc) - timedelta(days=7)
            logger.info("First run: syncing emails from last 7 days")

        # Get messages from source since first_transfer timestamp
        logger.info("Fetching messages from source server...")
        source_messages = self.get_messages_since(self.src_conn, first_transfer)
        logger.info(f"Source server has {len(source_messages)} messages since {first_transfer}")

        # Copy messages that haven't been synced before
        copied_count = 0
        skipped_count = 0
        synced_message_ids = self.state['synced_message_ids']

        for msg_id, msg_data, msg_timestamp in source_messages:
            # Skip if already synced in previous runs
            if msg_id in synced_message_ids:
                logger.debug(f"Message synced previously: {msg_id}")
                skipped_count += 1
                continue

            # Check if this specific message exists on target
            if not self.check_message_exists(self.tgt_conn, msg_id):
                logger.info(f"Copying message: {msg_id}")
                if self.copy_message(msg_data):
                    copied_count += 1
                    synced_message_ids[msg_id] = msg_timestamp
                    # Save state periodically (every 10 messages)
                    if copied_count % 10 == 0:
                        self.save_state()
                else:
                    logger.error(f"Failed to copy message: {msg_id}")
            else:
                logger.debug(f"Message already exists on target: {msg_id}")
                synced_message_ids[msg_id] = msg_timestamp  # Mark as synced even if it existed
                skipped_count += 1

        # Save final state
        self.save_state()

        logger.info("=" * 60)
        logger.info(f"Initial sync complete: {copied_count} copied, {skipped_count} skipped")
        logger.info("=" * 60)

    def process_new_messages(self, last_uid: int) -> int:
        """
        Process and copy any new messages found on the source server.

        Args:
            last_uid: Last known UID from source server

        Returns:
            Updated last UID
        """
        try:
            self.src_conn.select('INBOX', readonly=True)

            # Get the current highest UID
            _, response = self.src_conn.uid('SEARCH', None, 'ALL')
            if not response[0]:
                logger.debug("No messages in source inbox")
                return last_uid

            uids = response[0].split()
            if not uids:
                return last_uid

            current_max_uid = int(uids[-1])

            # If no new messages, return
            if current_max_uid <= last_uid:
                logger.debug("No new messages found")
                return last_uid

            # Fetch only messages with UID greater than last_uid
            logger.debug(f"Checking for messages with UID > {last_uid}")
            _, new_msgs = self.src_conn.uid('SEARCH', None, f'UID {last_uid+1}:*')

            if not new_msgs[0]:
                logger.debug("No new messages to process")
                return current_max_uid

            new_uids = new_msgs[0].split()
            logger.info(f"Found {len(new_uids)} new message(s) to process")

            synced_message_ids = self.state['synced_message_ids']
            copied_in_batch = 0

            # Process each new message
            for uid in new_uids:
                try:
                    # Convert UID to string for logging (handle both bytes and int)
                    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                    logger.debug(f"Fetching message UID: {uid_str}")
                    _, msg_data = self.src_conn.uid('FETCH', uid, '(RFC822)')
                    if msg_data and msg_data[0]:
                        raw_email = msg_data[0][1]
                        email_message = email.message_from_bytes(raw_email)
                        msg_id = email_message.get('Message-ID', '').strip()

                        if msg_id:
                            # Skip if already synced
                            if msg_id in synced_message_ids:
                                logger.debug(f"Message already synced: {msg_id}")
                                continue

                            # Extract message timestamp
                            msg_timestamp = self.extract_message_timestamp(email_message)

                            # Extract subject for logging
                            # Note: sometimes the subjects have newlines in them, likely from
                            # STMP header wrapping.  Clean them up for logging.
                            subject = email_message.get('Subject', '(no subject)')[:100].replace('\n', ' ').replace('\r', ' '   )

                            # Check if already exists on target before copying
                            if not self.check_message_exists(self.tgt_conn, msg_id):
                                logger.info(f"Copying new message: {msg_id}: {subject}")
                                if self.copy_message(raw_email):
                                    logger.info(f"Successfully copied: {msg_id}: {subject}")
                                    synced_message_ids[msg_id] = msg_timestamp
                                    copied_in_batch += 1
                                else:
                                    logger.error(f"Failed to copy: {msg_id}")
                            else:
                                logger.debug(f"Message already exists on target: {msg_id}")
                                synced_message_ids[msg_id] = msg_timestamp
                        else:
                            logger.warning(f"Message UID {uid_str} has no Message-ID")
                except Exception as e:
                    logger.error(f"Error processing message UID {uid_str}: {e}")

            # Update state with new UIDs
            self.state['last_source_uid'] = current_max_uid
            if copied_in_batch > 0:
                self.save_state()

            logger.debug("Finished processing new messages")
            return current_max_uid

        except Exception as e:
            logger.error(f"Error processing new messages: {e}")
            return last_uid

    def idle_monitor(self, timeout: int = 14 * 60):
        """
        Monitor for new emails using IMAP IDLE for real-time notifications.

        Args:
            timeout: IDLE timeout in seconds (default: 14 minutes, max is typically 30)
        """
        logger.info("=" * 60)
        logger.info("Entering IDLE monitoring mode (real-time notifications)")
        logger.info(f"IDLE timeout: {timeout // 60} minutes")
        logger.info("=" * 60)

        # Get the current highest UID to track from
        self.src_conn.select('INBOX', readonly=True)
        _, response = self.src_conn.uid('SEARCH', None, 'ALL')
        last_uid = 0
        if response[0]:
            uids = response[0].split()
            if uids:
                last_uid = int(uids[-1])
        logger.info(f"Starting IDLE monitoring from UID: {last_uid}")

        # Set up activity tracking handler to monitor logging activity
        activity_handler = ActivityTrackingHandler()
        logger.addHandler(activity_handler)

        try:
            while True:
                try:
                    # Select INBOX for monitoring
                    self.src_conn.select('INBOX')

                    # Enter IDLE mode
                    logger.debug("Entering IDLE mode, waiting for notifications...")
                    tag = self.src_conn._new_tag().decode()
                    self.src_conn.send(f"{tag} IDLE\r\n".encode())

                    # Wait for continuation response
                    response = self.src_conn.readline()
                    if b'+ idling' not in response.lower() and b'+ waiting' not in response.lower():
                        logger.error(f"Unexpected IDLE response: {response}")
                        break

                    # Only emit this message if something else has been logged since last time
                    if activity_handler.check_and_reset():
                        logger.info("IDLE mode active - waiting for new messages...")

                    # Wait for notifications with timeout
                    start_time = time.time()
                    while True:
                        # Check if there's data available to read (with 1 second timeout)
                        readable, _, _ = select.select([self.src_conn.socket()], [], [], 1.0)

                        if readable:
                            # Read the notification
                            response = self.src_conn.readline()
                            logger.debug(f"Received IDLE notification: {response}")

                            # Check if it's a notification about new messages
                            if b'EXISTS' in response or b'RECENT' in response:
                                logger.info("New message notification received!")

                                # Exit IDLE mode to process messages
                                self.src_conn.send(b"DONE\r\n")
                                self.src_conn.readline()  # Read the tagged response

                                # Process new messages
                                last_uid = self.process_new_messages(last_uid)

                                # Break to re-enter IDLE
                                break

                        # Check if we've exceeded the timeout
                        if time.time() - start_time > timeout:
                            logger.debug("IDLE timeout reached, refreshing connection...")
                            # Exit IDLE mode
                            self.src_conn.send(b"DONE\r\n")
                            self.src_conn.readline()  # Read the tagged response
                            break

                except Exception as e:
                    logger.error(f"Error in IDLE loop: {e}")
                    logger.info("Attempting to reconnect...")
                    if not self.connect():
                        logger.error("Reconnection failed, exiting")
                        break
                    # Get updated message list after reconnect
                    known_message_ids = self.get_message_ids(self.src_conn)

        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal, shutting down...")
            try:
                self.src_conn.send(b"DONE\r\n")
            except:
                pass
        finally:
            # Remove the activity tracking handler
            logger.removeHandler(activity_handler)

    def poll_monitor(self, poll_interval: int = 60):
        """
        Monitor for new emails using polling (fallback when IDLE is not supported).

        Args:
            poll_interval: Seconds to wait between checks
        """
        logger.info("=" * 60)
        logger.info("Entering polling monitoring mode")
        logger.info(f"Polling interval: {poll_interval} seconds")
        logger.info("=" * 60)

        # Get the current highest UID to track from
        self.src_conn.select('INBOX', readonly=True)
        _, response = self.src_conn.uid('SEARCH', None, 'ALL')
        last_uid = 0
        if response[0]:
            uids = response[0].split()
            if uids:
                last_uid = int(uids[-1])
        logger.info(f"Starting polling from UID: {last_uid}")

        try:
            while True:
                time.sleep(poll_interval)

                logger.debug("Checking for new messages...")

                try:
                    last_uid = self.process_new_messages(last_uid)

                except Exception as e:
                    logger.error(f"Error in polling loop: {e}")
                    logger.info("Attempting to reconnect...")
                    if not self.connect():
                        logger.error("Reconnection failed, exiting")
                        break
                    # Get updated UID after reconnect
                    self.src_conn.select('INBOX', readonly=True)
                    _, response = self.src_conn.uid('SEARCH', None, 'ALL')
                    if response[0]:
                        uids = response[0].split()
                        if uids:
                            last_uid = int(uids[-1])

        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal, shutting down...")

    def monitor_loop(self, poll_interval: int = 60):
        """
        Monitor for new emails using IDLE if supported, otherwise poll.

        Args:
            poll_interval: Seconds between polls if IDLE is not supported
        """
        if self.idle_supported:
            self.idle_monitor()
        else:
            self.poll_monitor(poll_interval)

    def run(self):
        """Main execution flow."""
        if not self.connect():
            logger.error("Failed to establish connections. Exiting.")
            return 1

        try:
            # Perform initial sync
            self.initial_sync()

            # Enter monitoring mode
            self.monitor_loop()

        except KeyboardInterrupt:
            logger.info("\nShutdown requested")
            # Save state before exit
            self.save_state()
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return 1
        finally:
            self.disconnect()

        return 0

def configure_logging(log_target: str, debug: bool, max_bytes: int = 10*1024*1024, backup_count: int = 5):
    """Configure logging based on destination and debug level.

    Args:
        log_target: Logging target ('stdout', 'stderr', 'syslog', or a file path)
        debug: Enable debug logging level
        max_bytes: Maximum size of log file before rotation (default: 10MB)
        backup_count: Number of backup log files to keep (default: 5)
    """
    log_level = logging.DEBUG if debug else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # Remove any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configure handler based on target
    if log_target == 'stdout':
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        root_logger.addHandler(handler)
    elif log_target == 'stderr':
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
        root_logger.addHandler(handler)
    elif log_target == 'syslog':
        try:
            # Try to connect to system log
            if sys.platform == 'darwin' or sys.platform.startswith('linux'):
                # macOS and Linux
                from logging.handlers import SysLogHandler
                if sys.platform == 'darwin':
                    syslog_address = '/var/run/syslog'
                else:
                    syslog_address = '/dev/log'
                handler = SysLogHandler(address=syslog_address)
                # Syslog format (no timestamp needed, syslog adds it)
                handler.setFormatter(logging.Formatter('imap_sync_to_gmail: %(levelname)s - %(message)s'))
                root_logger.addHandler(handler)
            else:
                # Windows or other - fallback to stderr
                print("Warning: syslog not available on this platform, using stderr", file=sys.stderr)
                handler = logging.StreamHandler(sys.stderr)
                handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
                root_logger.addHandler(handler)
        except Exception as e:
            print(f"Warning: Could not configure syslog: {e}, using stderr", file=sys.stderr)
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
            root_logger.addHandler(handler)
    else:
        # Treat as a file path - use rotating file handler with compression
        try:
            from logging.handlers import RotatingFileHandler
            import shutil

            # Check if zstd is available, fall back to gzip
            try:
                import zstandard as zstd
                use_zstd = True
                compression_ext = '.zst'
            except ImportError:
                import gzip
                use_zstd = False
                compression_ext = '.gz'

            # Rotator function to compress old log files
            def rotator(source, dest):
                """Compress rotated log files with zstd (preferred) or gzip (fallback)."""
                if use_zstd:
                    # Use zstd compression
                    with open(source, 'rb') as f_in:
                        with open(f'{dest}{compression_ext}', 'wb') as f_out:
                            cctx = zstd.ZstdCompressor(level=3)
                            with cctx.stream_writer(f_out) as compressor:
                                shutil.copyfileobj(f_in, compressor)
                else:
                    # Fall back to gzip compression
                    with open(source, 'rb') as f_in:
                        with gzip.open(f'{dest}{compression_ext}', 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                os.remove(source)

            # Use RotatingFileHandler with configurable parameters
            handler = RotatingFileHandler(
                log_target,
                mode='a',
                maxBytes=max_bytes,
                backupCount=backup_count
            )
            handler.rotator = rotator
            handler.setFormatter(logging.Formatter(log_format, datefmt=date_format))
            root_logger.addHandler(handler)

            if use_zstd:
                logger.debug("Using zstd compression for log rotation")
            else:
                logger.debug("Using gzip compression for log rotation (zstd not available)")
        except Exception as e:
            print(f"Error: Could not open log file {log_target}: {e}", file=sys.stderr)
            sys.exit(1)

    root_logger.setLevel(log_level)
    logger.setLevel(log_level)

    if debug:
        logger.debug(f"Debug logging enabled, output to {log_target}")

def main():
    """Parse arguments and run the sync."""
    parser = argparse.ArgumentParser(
        description='Synchronize emails from IMAP server to Gmail using OAuth2',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Mandatory arguments
    parser.add_argument('--config', required=True,
                       help='Path to JSON configuration file')

    # Optional arguments
    parser.add_argument('--state-file', default='sync_state.json',
                       help='Path to state file for tracking synced messages (default: sync_state.json)')
    parser.add_argument('--log', default='stdout',
                       help='Logging target: stdout, stderr, syslog, or a file path (default: stdout)')
    parser.add_argument('--log-max-size', default='10M',
                       help='Maximum log file size before rotation, e.g., 100K, 10M, 1G (default: 10M)')
    parser.add_argument('--log-max-files', type=int, default=5,
                       help='Maximum number of rotated log files to keep (default: 5)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--poll-interval', type=int, default=60,
                       help='Seconds between polls if IDLE is not supported (default: 60)')
    parser.add_argument('--no-idle', action='store_true',
                       help='Disable IDLE and force polling mode')

    args = parser.parse_args()

    # Parse log file size
    def parse_size(size_str: str) -> int:
        """Parse size string like '10M', '100K', '1G' to bytes."""
        size_str = size_str.strip().upper()
        if size_str.endswith('K'):
            return int(size_str[:-1]) * 1024
        elif size_str.endswith('M'):
            return int(size_str[:-1]) * 1024 * 1024
        elif size_str.endswith('G'):
            return int(size_str[:-1]) * 1024 * 1024 * 1024
        else:
            # Assume bytes if no suffix
            return int(size_str)

    try:
        max_log_bytes = parse_size(args.log_max_size)
    except ValueError:
        print(f"Error: Invalid log size format '{args.log_max_size}'. Use format like 100K, 10M, or 1G", file=sys.stderr)
        return 1

    # Configure logging based on arguments
    configure_logging(args.log, args.debug, max_log_bytes, args.log_max_files)

    # Load configuration from file
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {args.config}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error reading configuration file: {e}")
        return 1

    # Validate required configuration fields
    required_fields = ['source_server', 'source_user', 'source_pass', 'target_user', 'target_token_file']
    missing_fields = [field for field in required_fields if field not in config]
    if missing_fields:
        logger.error(f"Missing required fields in configuration: {', '.join(missing_fields)}")
        return 1

    # Load OAuth token from file
    try:
        token_file_path = config['target_token_file']
        with open(token_file_path, 'r') as f:
            token_data = json.load(f)
        if 'token' not in token_data:
            logger.error(f"Token file {token_file_path} does not contain 'token' field")
            return 1
        oauth_token = token_data['token']
    except FileNotFoundError:
        logger.error(f"Token file not found: {config['target_token_file']}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in token file: {e}")
        return 1
    except Exception as e:
        logger.error(f"Error reading token file: {e}")
        return 1

    # Create and run sync
    sync = IMAPSync(
        src_server=config['source_server'],
        src_user=config['source_user'],
        src_pass=config['source_pass'],
        tgt_user=config['target_user'],
        tgt_oauth_token=oauth_token,
        state_file=args.state_file
    )

    # Store token file info for potential refresh
    sync.token_file = token_file_path
    sync.token_data = token_data

    # Override IDLE support if user requested no-idle
    if args.no_idle:
        logger.info("IDLE disabled by user, forcing polling mode")
        sync.idle_supported = False

    return sync.run()

if __name__ == '__main__':
    sys.exit(main())
