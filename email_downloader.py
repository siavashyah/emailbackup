import imaplib
import email
from email.header import decode_header
import os
import re
import json
import configparser
import logging
from pathlib import Path
from datetime import datetime
from database import EmailDatabase

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Email Configuration
IMAP_SERVER = config.get('EMAIL', 'imap_server')
IMAP_PORT = config.getint('EMAIL', 'imap_port')
USE_SSL = config.getboolean('EMAIL', 'use_ssl')
EMAIL_ACCOUNT = config.get('EMAIL', 'email_account')
PASSWORD = config.get('EMAIL', 'password')

# Download folder
DOWNLOAD_FOLDER = config.get('DOWNLOAD', 'download_folder')

# Database
DB_FILE = config.get('DATABASE', 'database_file')

# Security Configuration
MAX_EMAIL_SIZE_MB = config.getfloat('SECURITY', 'max_email_size_mb', fallback=100.0)
MAX_ATTACHMENT_SIZE_MB = config.getfloat('SECURITY', 'max_attachment_size_mb', fallback=100.0)
BLOCK_EXECUTABLE_FILES = config.getboolean('SECURITY', 'block_executable_files', fallback=True)
SKIP_SUSPICIOUS_EMAILS = config.getboolean('SECURITY', 'skip_suspicious_emails', fallback=True)

# Blacklist senders (comma-separated in config)
BLACKLIST_SENDERS = [s.strip() for s in config.get('SECURITY', 'blacklist_senders', fallback='').split(',') if s.strip()]

# Executable file extensions to block
EXECUTABLE_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.msi', '.vbs', 
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.app', '.deb', '.rpm',
    '.jar', '.apk', '.dmg', '.pkg', '.run', '.bin','.tbz'
]

# Suspicious patterns in email
SUSPICIOUS_PATTERNS = [
    'urgent', 'verify account', 'suspended', 'click here immediately',
    'congratulations', 'you won', 'claim your prize', 'act now'
]

# Logging
if config.getboolean('LOGGING', 'enable_logging'):
    logging.basicConfig(
        filename=config.get('LOGGING', 'log_file'),
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def create_download_folder():
    """Create download folder if it doesn't exist"""
    Path(DOWNLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

def decode_str(s):
    """Decode encoded strings from email headers"""
    if s is None:
        return ""
    
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')
    
    decoded_parts = decode_header(s)
    decoded_string = ""
    
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            if encoding:
                try:
                    decoded_string += part.decode(encoding)
                except:
                    decoded_string += part.decode('utf-8', errors='ignore')
            else:
                decoded_string += part.decode('utf-8', errors='ignore')
        else:
            decoded_string += str(part)
    
    return decoded_string

def clean_filename(filename):
    """Clean filename from invalid characters"""
    filename = filename.replace('\r', '').replace('\n', '').replace('\t', ' ')
    
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    filename = filename.strip(' .')
    
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext
    
    if not filename:
        filename = "unnamed_file"
    
    return filename

def is_sender_blacklisted(from_addr):
    """Check if sender is in blacklist"""
    if not from_addr:
        return False
    
    from_addr_lower = from_addr.lower()
    for blocked in BLACKLIST_SENDERS:
        if blocked.lower() in from_addr_lower:
            return True
    return False

def is_executable_file(filename):
    """Check if file is executable based on extension"""
    if not filename:
        return False
    
    filename_lower = filename.lower()
    for ext in EXECUTABLE_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True
    return False

def check_suspicious_content(subject, body_text):
    """Check if email contains suspicious patterns"""
    content = (subject + " " + body_text).lower()
    suspicious_found = []
    
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern in content:
            suspicious_found.append(pattern)
    
    return suspicious_found

def get_email_size_kb(mail, email_id):
    """Get email size before full download"""
    try:
        status, data = mail.fetch(email_id, '(RFC822.SIZE)')
        if status == 'OK':
            size_match = re.search(r'RFC822.SIZE (\d+)', data[0].decode('utf-8', errors='ignore'))
            if size_match:
                size_bytes = int(size_match.group(1))
                return round(size_bytes / 1024, 2)
    except Exception as e:
        logging.error(f"Error getting email size: {e}")
    return 0

def is_email_safe(mail, email_id, index):
    """Comprehensive security check before downloading"""
    reasons = []
    
    # 1. Check email size
    size_kb = get_email_size_kb(mail, email_id)
    max_size_kb = MAX_EMAIL_SIZE_MB * 1024
    
    if size_kb > max_size_kb:
        reasons.append(f"Size too large ({size_kb} KB > {max_size_kb} KB)")
    
    # 2. Fetch headers only for quick check
    try:
        status, header_data = mail.fetch(email_id, '(BODY[HEADER.FIELDS (FROM SUBJECT)])')
        if status == 'OK':
            header_msg = email.message_from_bytes(header_data[0][1])
            from_addr = decode_str(header_msg.get('From', ''))
            subject = decode_str(header_msg.get('Subject', ''))
            
            # Check blacklist
            if is_sender_blacklisted(from_addr):
                reasons.append(f"Sender in blacklist: {from_addr}")
            
            # Check suspicious patterns in subject
            if SKIP_SUSPICIOUS_EMAILS:
                suspicious = check_suspicious_content(subject, "")
                if suspicious:
                    reasons.append(f"Suspicious patterns: {', '.join(suspicious)}")
    except Exception as e:
        logging.error(f"Error checking email safety: {e}")
        reasons.append(f"Error reading email headers")
    
    return len(reasons) == 0, reasons, size_kb

def extract_links(text):
    """Extract URLs from text"""
    if not text:
        return []
    
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))

def identify_link_type(url):
    """Identify the type of cloud storage link"""
    url_lower = url.lower()
    
    if 'drive.google.com' in url_lower or 'docs.google.com' in url_lower:
        return 'google_drive'
    elif 'dropbox.com' in url_lower:
        return 'dropbox'
    elif 'onedrive' in url_lower or 'sharepoint' in url_lower:
        return 'onedrive'
    elif 'box.com' in url_lower:
        return 'box'
    else:
        return 'other'

def is_attachment_link(part):
    """Check if attachment is actually a link/URL file"""
    filename = part.get_filename()
    if not filename:
        return False
    
    content_type = part.get_content_type()
    
    # Known file extensions that are actual files, not links
    file_extensions = [
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pdf', '.txt', '.zip', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp',
        '.mp3', '.mp4', '.avi', '.mov',
        '.exe', '.msi', '.apk'
    ]
    
    filename_lower = filename.lower()
    for ext in file_extensions:
        if filename_lower.endswith(ext):
            return False
    
    # Check if filename contains URL
    if re.search(r'https?://', filename):
        return True
    
    # Check content type
    known_file_types = [
        'application/msword',
        'application/vnd.openxmlformats',
        'application/pdf',
        'application/zip',
        'image/',
        'video/',
        'audio/'
    ]
    
    for file_type in known_file_types:
        if content_type.startswith(file_type):
            return False
    
    # Check content
    try:
        content = part.get_payload(decode=True)
        if content and isinstance(content, bytes):
            if len(content) > 10240:  # If larger than 10KB, likely a real file
                return False
            
            content_str = content.decode('utf-8', errors='ignore')
            urls = re.findall(r'https?://[^\s]+', content_str)
            if urls:
                total_url_length = sum(len(url) for url in urls)
                if total_url_length > len(content_str) * 0.5:
                    return True
    except:
        pass
    
    return False

def process_attachments(msg, email_folder):
    """Process email attachments - OPTIMIZED: Direct download without ZIP"""
    attachment_files = []
    attachment_links = []
    blocked_files = []
    processed_parts = set()  # Track processed parts to avoid duplicates
    
    max_attachment_bytes = MAX_ATTACHMENT_SIZE_MB * 1024 * 1024
    
    for part in msg.walk():
        # Skip multipart containers
        if part.get_content_maintype() == 'multipart':
            continue
        
        # Skip if no Content-Disposition (not an attachment)
        if part.get('Content-Disposition') is None:
            continue
        
        filename = part.get_filename()
        if not filename:
            continue
            
        filename = decode_str(filename)
        
        # Create unique identifier to prevent duplicate processing
        part_id = f"{filename}_{part.get_content_type()}_{len(part.get_payload(decode=False))}"
        if part_id in processed_parts:
            print(f"  ⚠️  Skipping duplicate: {filename}")
            continue
        processed_parts.add(part_id)
        
        # Security check: Block executable files
        if BLOCK_EXECUTABLE_FILES and is_executable_file(filename):
            blocked_files.append(filename)
            print(f"  🚫 BLOCKED executable file: {filename}")
            logging.warning(f"Blocked executable file: {filename}")
            continue
        
        # Check if this is a link attachment
        if is_attachment_link(part):
            try:
                content = part.get_payload(decode=True)
                if content:
                    content_str = content.decode('utf-8', errors='ignore')
                    urls = extract_links(content_str)
                    for url in urls:
                        attachment_links.append({
                            'url': url,
                            'filename': clean_filename(filename),
                            'type': identify_link_type(url)
                        })
                    print(f"  🔗 Link attachment found: {filename}")
            except Exception as e:
                logging.error(f"Error extracting link from attachment: {e}")
        else:
            # Regular file attachment - DIRECT DOWNLOAD WITHOUT ZIP
            try:
                content = part.get_payload(decode=True)
                
                if not content:
                    print(f"  ⚠️  Empty content: {filename}")
                    continue
                
                # Check attachment size
                file_size_mb = len(content) / 1024 / 1024
                if len(content) > max_attachment_bytes:
                    blocked_files.append(f"{filename} (size: {file_size_mb:.2f} MB)")
                    print(f"  🚫 BLOCKED large file: {filename} ({file_size_mb:.2f} MB)")
                    logging.warning(f"Blocked large file: {filename}")
                    continue
                
                # Clean filename and save directly
                clean_name = clean_filename(filename)
                filepath = os.path.join(email_folder, clean_name)
                
                # Prevent overwriting if file exists
                counter = 1
                base_name, ext = os.path.splitext(clean_name)
                while os.path.exists(filepath):
                    clean_name = f"{base_name}_{counter}{ext}"
                    filepath = os.path.join(email_folder, clean_name)
                    counter += 1
                
                # Write file ONCE
                with open(filepath, 'wb') as f:
                    f.write(content)
                
                attachment_files.append(clean_name)
                print(f"  📎 Attachment saved: {clean_name} ({file_size_mb:.2f} MB)")
                
            except Exception as e:
                logging.error(f"Error saving attachment {filename}: {e}")
                print(f"  ❌ Error saving {filename}: {e}")
    
    if blocked_files:
        print(f"  ⚠️  Total blocked files: {len(blocked_files)}")
    
    return attachment_files, attachment_links, blocked_files

def log_suspicious_email(subject, from_addr, reasons, size_kb, index):
    """Log suspicious email to a text file"""
    log_file = os.path.join(DOWNLOAD_FOLDER, "suspicious_emails.txt")
    
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"Email #{index} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Subject: {subject}\n")
            f.write(f"From: {from_addr}\n")
            f.write(f"Size: {size_kb} KB\n")
            f.write(f"Reasons:\n")
            for reason in reasons:
                f.write(f"  - {reason}\n")
            f.write(f"{'='*70}\n")
    except Exception as e:
        logging.error(f"Error logging suspicious email: {e}")

def download_email(email_id, mail, index, db):
    """Download a specific email - OPTIMIZED: Only save attachments to disk"""
    
    # Check if email already exists in database
    email_id_str = email_id.decode('utf-8')
    if db.email_exists(email_id_str):
        print(f"\n⏭  Email #{index} already exists in database - skipping")
        return False, 'exists'
    
    # Security check before downloading
    is_safe, reasons, size_kb = is_email_safe(mail, email_id, index)
    
    if not is_safe:
        # Fetch basic info for logging
        try:
            status, header_data = mail.fetch(email_id, '(BODY[HEADER.FIELDS (FROM SUBJECT)])')
            if status == 'OK':
                header_msg = email.message_from_bytes(header_data[0][1])
                from_addr = decode_str(header_msg.get('From', ''))
                subject = decode_str(header_msg.get('Subject', ''))
        except:
            from_addr = "Unknown"
            subject = "Unknown"
        
        print(f"\n🚫 Email #{index} SKIPPED (suspicious)")
        print(f"   Subject: {subject[:60]}...")
        print(f"   From: {from_addr}")
        print(f"   Reasons: {', '.join(reasons)}")
        
        log_suspicious_email(subject, from_addr, reasons, size_kb, index)
        logging.info(f"Skipped suspicious email #{index}: {reasons}")
        return False, 'skipped'
    
    # Fetch email ONCE
    try:
        status, data = mail.fetch(email_id, '(RFC822)')
    except Exception as e:
        print(f"✗ Error fetching email {index}: {e}")
        logging.error(f"Error fetching email {index}: {e}")
        return False, 'error'
    
    if status != 'OK' or not data or not data[0]:
        print(f"✗ Invalid response for email {index}")
        return False, 'error'
    
    # Parse email ONCE
    try:
        msg = email.message_from_bytes(data[0][1])
    except Exception as e:
        print(f"✗ Error parsing email {index}: {e}")
        logging.error(f"Error parsing email {index}: {e}")
        return False, 'error'
    
    # Extract email information
    subject = decode_str(msg.get('Subject', 'No Subject'))
    from_addr = decode_str(msg.get('From', ''))
    to_addr = decode_str(msg.get('To', ''))
    cc_addr = decode_str(msg.get('Cc', ''))
    date = msg.get('Date', '')
    
    print(f"\n{'='*70}")
    print(f"Email #{index}")
    print(f"Subject: {subject}")
    print(f"From: {from_addr}")
    print(f"Date: {date}")
    print(f"Size: {size_kb} KB")
    print(f"{'='*70}")
    
    # Create folder for this email (only if it has attachments)
    folder_name = f"email_{index}_{clean_filename(subject[:50])}"
    email_folder = os.path.join(DOWNLOAD_FOLDER, folder_name)
    
    # Extract email body (for database only, NOT saved to files)
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not body_text:
                try:
                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
            elif content_type == "text/html" and not body_html:
                try:
                    body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    pass
    else:
        try:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                payload_str = payload.decode('utf-8', errors='ignore')
                if content_type == "text/plain":
                    body_text = payload_str
                elif content_type == "text/html":
                    body_html = payload_str
        except:
            body_text = str(msg.get_payload())
    
    print(f"  ✓ Email body extracted")
    
    # Extract links from body
    body_links = extract_links(body_text) + extract_links(body_html)
    
    # Create folder only if needed (for attachments)
    Path(email_folder).mkdir(parents=True, exist_ok=True)
    
    # Process attachments (ONLY DOWNLOAD ATTACHMENTS - NO ZIP, NO EXTRA FILES)
    attachment_files, attachment_links, blocked_files = process_attachments(msg, email_folder)
    
    # If no attachments, remove the empty folder
    if not attachment_files and not attachment_links:
        try:
            os.rmdir(email_folder)
            email_folder = ""  # No folder created
        except:
            pass
    
    # Determine attachment type
    has_files = len(attachment_files) > 0
    has_links = len(attachment_links) > 0
    
    if has_files and has_links:
        attachment_type = 'both'
    elif has_files:
        attachment_type = 'file'
    elif has_links:
        attachment_type = 'link'
    else:
        attachment_type = 'none'
    
    # Prepare links data
    links_data = {
        'attachment_links': attachment_links,
        'body_links': body_links,
        'blocked_files': blocked_files
    }
    
    # Display summary
    total_attachments = len(attachment_files) + len(attachment_links)
    if total_attachments > 0:
        print(f"  📊 Attachments summary:")
        if attachment_files:
            print(f"     - Files: {len(attachment_files)} (saved directly)")
        if attachment_links:
            print(f"     - Links: {len(attachment_links)}")
    else:
        print(f"  ℹ  No attachments")
    
    # Prepare data for database
    email_data = {
        'email_id': email_id_str,
        'subject': subject,
        'from_address': from_addr,
        'to_address': to_addr,
        'cc_address': cc_addr,
        'date': date,
        'body_text': body_text[:5000],
        'body_html': body_html[:10000] if body_html else '',
        'has_attachments': 1 if (has_files or has_links) else 0,
        'attachment_type': attachment_type,
        'attachment_count': total_attachments,
        'attachment_zip_path': '',  # No ZIP anymore
        'links': links_data,
        'folder_path': os.path.relpath(email_folder) if email_folder else '',
        'size_kb': size_kb
    }
    
    # Insert into database
    try:
        db_id = db.insert_email(email_data)
        if db_id:
            print(f"  ✓ Saved to database (ID: {db_id})")
            logging.info(f"Email downloaded: {subject} (DB ID: {db_id})")
    except Exception as e:
        print(f"  ❌ Database error: {e}")
        logging.error(f"Database error for email {index}: {e}")
    
    if email_folder:
        print(f"  ✓ Email saved in folder: {email_folder}")
    else:
        print(f"  ✓ Email saved to database (no attachments)")
    
    return True, 'success'

def test_connection(server, port):
    """Test IMAP server connection"""
    import socket
    print(f"Testing connection to {server}:{port}...")
    try:
        socket.create_connection((server, port), timeout=10)
        print("✓ Server is reachable")
        return True
    except socket.gaierror:
        print(f"✗ ERROR: Cannot resolve hostname '{server}'")
        return False
    except socket.timeout:
        print(f"✗ ERROR: Connection timeout")
        return False
    except Exception as e:
        print(f"✗ ERROR: {e}")
        return False

def main():
    """Main function"""
    create_download_folder()
    
    print("="*70)
    print("SECURE EMAIL DOWNLOADER - OPTIMIZED VERSION")
    print("="*70)
    print(f"\nConfiguration:")
    print(f"  Server: {IMAP_SERVER}")
    print(f"  Port: {IMAP_PORT}")
    print(f"  SSL: {USE_SSL}")
    print(f"  Email: {EMAIL_ACCOUNT}")
    print(f"  Database: {DB_FILE}")
    print(f"  Download Folder: {DOWNLOAD_FOLDER}")
    print(f"\nSecurity Settings:")
    print(f"  Max Email Size: {MAX_EMAIL_SIZE_MB} MB")
    print(f"  Max Attachment Size: {MAX_ATTACHMENT_SIZE_MB} MB")
    print(f"  Block Executables: {BLOCK_EXECUTABLE_FILES}")
    print(f"  Blacklisted Senders: {len(BLACKLIST_SENDERS)}")
    if BLACKLIST_SENDERS:
        for sender in BLACKLIST_SENDERS:
            print(f"    - {sender}")
    print(f"\n💡 OPTIMIZATIONS:")
    print(f"  - No ZIP compression (direct file save)")
    print(f"  - No extra text files (data in database only)")
    print(f"  - Duplicate detection enabled")
    print(f"  - Memory optimized for large emails")
    print()
    
    # Initialize database
    db = EmailDatabase(DB_FILE)
    
    # Test connection
    if not test_connection(IMAP_SERVER, IMAP_PORT):
        print("\n" + "="*70)
        print("CONNECTION FAILED")
        print("="*70)
        return
    
    print("\nConnecting to email server...")
    
    try:
        # Connect to IMAP server
        if USE_SSL:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        else:
            mail = imaplib.IMAP4(IMAP_SERVER, IMAP_PORT)
        mail.login(EMAIL_ACCOUNT, PASSWORD)
        print("✓ Connected successfully!\n")
        
        # Select inbox
        mail.select('INBOX')
        
        # Search for emails
        status, messages = mail.search(None, 'ALL')
        
        if status != 'OK':
            print("Error searching emails")
            return
        
        email_ids = messages[0].split()
        total_emails = len(email_ids)
        
        print(f"Total emails found: {total_emails}\n")
        
        # Ask how many emails to download
        try:
            count = int(input(f"How many emails do you want to download? (max {total_emails}): "))
            count = min(count, total_emails)
        except:
            count = min(10, total_emails)
            print(f"Downloading {count} emails by default...")
        
        # Download latest emails
        downloaded = 0
        skipped = 0
        blocked = 0
        
        for i, email_id in enumerate(reversed(email_ids[-count:])):
            result, status_code = download_email(email_id, mail, i + 1, db)
            
            if status_code == 'success':
                downloaded += 1
            elif status_code == 'exists':
                skipped += 1
            elif status_code == 'skipped':
                blocked += 1
        
        print(f"\n{'='*70}")
        print(f"DOWNLOAD COMPLETE!")
        print(f"{'='*70}")
        print(f"✓ Downloaded: {downloaded} email(s)")
        if skipped > 0:
            print(f"⏭  Already in DB: {skipped} email(s)")
        if blocked > 0:
            print(f"🚫 Blocked/Skipped: {blocked} suspicious email(s)")
            print(f"   📄 Check 'suspicious_emails.txt' for details")
        print(f"📁 Location: {os.path.abspath(DOWNLOAD_FOLDER)}")
        print(f"💾 Database: {os.path.abspath(DB_FILE)}")
        
        # Show database statistics
        print(f"\n{'='*70}")
        print(f"DATABASE STATISTICS")
        print(f"{'='*70}")
        stats = db.get_statistics()
        print(f"Total emails in database: {stats['total_emails']}")
        print(f"Emails with attachments: {stats['emails_with_attachments']}")
        print(f"Emails with links: {stats['emails_with_links']}")
        print(f"Total attachments: {stats['total_attachments']}")
        print(f"Total size: {stats['total_size_mb']} MB")
        print(f"{'='*70}")
        
        # Close database
        db.close()
        
        # Disconnect
        mail.close()
        mail.logout()
        
        print("\n✓ All done!")
        
    except imaplib.IMAP4.error as e:
        print(f"\nIMAP Error: {e}")
        logging.error(f"IMAP Error: {e}")
    except Exception as e:
        print(f"\nError: {e}")
        logging.error(f"Error: {e}")
    finally:
        if db:
            db.close()

if __name__ == "__main__":
    main()