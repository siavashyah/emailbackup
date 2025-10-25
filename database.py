import sqlite3
import json
from datetime import datetime
from pathlib import Path

class EmailDatabase:
    """Manage SQLite database for emails"""
    
    def __init__(self, db_file='emails.db'):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.init_database()
    
    def init_database(self):
        """Initialize database and create tables"""
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()
        
        # Create emails table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE,
                subject TEXT,
                from_address TEXT,
                to_address TEXT,
                cc_address TEXT,
                date TEXT,
                body_text TEXT,
                body_html TEXT,
                has_attachments INTEGER DEFAULT 0,
                attachment_type TEXT DEFAULT 'none',
                attachment_count INTEGER DEFAULT 0,
                attachment_zip_path TEXT,
                links TEXT,
                folder_path TEXT,
                download_date TEXT,
                size_kb INTEGER
            )
        ''')
        
        # Create indexes for faster search
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_subject ON emails(subject)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_from ON emails(from_address)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_date ON emails(date)')
        self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_has_attachments ON emails(has_attachments)')
        
        # Create FTS5 virtual table for full-text search
        self.cursor.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS emails_fts USING fts5(
                subject, body_text, from_address, to_address,
                content=emails,
                content_rowid=id
            )
        ''')
        
        # Create triggers to keep FTS table in sync
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS emails_ai AFTER INSERT ON emails BEGIN
                INSERT INTO emails_fts(rowid, subject, body_text, from_address, to_address)
                VALUES (new.id, new.subject, new.body_text, new.from_address, new.to_address);
            END
        ''')
        
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS emails_ad AFTER DELETE ON emails BEGIN
                INSERT INTO emails_fts(emails_fts, rowid, subject, body_text, from_address, to_address)
                VALUES('delete', old.id, old.subject, old.body_text, old.from_address, old.to_address);
            END
        ''')
        
        self.cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS emails_au AFTER UPDATE ON emails BEGIN
                INSERT INTO emails_fts(emails_fts, rowid, subject, body_text, from_address, to_address)
                VALUES('delete', old.id, old.subject, old.body_text, old.from_address, old.to_address);
                INSERT INTO emails_fts(rowid, subject, body_text, from_address, to_address)
                VALUES (new.id, new.subject, new.body_text, new.from_address, new.to_address);
            END
        ''')
        
        self.conn.commit()
        print(f"✓ Database initialized: {self.db_file}")
    
    def email_exists(self, email_id):
        """Check if email already exists in database"""
        self.cursor.execute('SELECT id FROM emails WHERE email_id = ?', (email_id,))
        return self.cursor.fetchone() is not None
    
    def insert_email(self, email_data):
        """Insert email into database"""
        try:
            # Convert links to JSON string
            links_json = json.dumps(email_data.get('links', {}), ensure_ascii=False)
            
            self.cursor.execute('''
                INSERT INTO emails (
                    email_id, subject, from_address, to_address, cc_address,
                    date, body_text, body_html, has_attachments, attachment_type,
                    attachment_count, attachment_zip_path, links, folder_path,
                    download_date, size_kb
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_data['email_id'],
                email_data['subject'],
                email_data['from_address'],
                email_data.get('to_address', ''),
                email_data.get('cc_address', ''),
                email_data['date'],
                email_data['body_text'],
                email_data.get('body_html', ''),
                email_data['has_attachments'],
                email_data['attachment_type'],
                email_data['attachment_count'],
                email_data.get('attachment_zip_path', ''),
                links_json,
                email_data['folder_path'],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                email_data.get('size_kb', 0)
            ))
            
            self.conn.commit()
            return self.cursor.lastrowid
        
        except sqlite3.IntegrityError:
            print(f"  ⚠ Email already exists in database: {email_data['subject'][:50]}")
            return None
        except Exception as e:
            print(f"  ✗ Database error: {e}")
            return None
    
    def search_emails(self, query=None, field='all', limit=100):
        """Search emails in database"""
        if query is None:
            # Return all emails
            self.cursor.execute('SELECT * FROM emails ORDER BY date DESC LIMIT ?', (limit,))
        elif field == 'all':
            # Full-text search
            self.cursor.execute('''
                SELECT emails.* FROM emails
                JOIN emails_fts ON emails.id = emails_fts.rowid
                WHERE emails_fts MATCH ?
                ORDER BY emails.date DESC
                LIMIT ?
            ''', (query, limit))
        elif field == 'subject':
            self.cursor.execute(
                'SELECT * FROM emails WHERE subject LIKE ? ORDER BY date DESC LIMIT ?',
                (f'%{query}%', limit)
            )
        elif field == 'from':
            self.cursor.execute(
                'SELECT * FROM emails WHERE from_address LIKE ? ORDER BY date DESC LIMIT ?',
                (f'%{query}%', limit)
            )
        elif field == 'date':
            self.cursor.execute(
                'SELECT * FROM emails WHERE date LIKE ? ORDER BY date DESC LIMIT ?',
                (f'%{query}%', limit)
            )
        
        return self.cursor.fetchall()
    
    def get_statistics(self):
        """Get database statistics"""
        stats = {}
        
        # Total emails
        self.cursor.execute('SELECT COUNT(*) FROM emails')
        stats['total_emails'] = self.cursor.fetchone()[0]
        
        # Emails with attachments
        self.cursor.execute('SELECT COUNT(*) FROM emails WHERE has_attachments = 1')
        stats['emails_with_attachments'] = self.cursor.fetchone()[0]
        
        # Emails with links
        self.cursor.execute("SELECT COUNT(*) FROM emails WHERE attachment_type IN ('link', 'both')")
        stats['emails_with_links'] = self.cursor.fetchone()[0]
        
        # Total size
        self.cursor.execute('SELECT SUM(size_kb) FROM emails')
        total_kb = self.cursor.fetchone()[0] or 0
        stats['total_size_mb'] = round(total_kb / 1024, 2)
        
        # Total attachments
        self.cursor.execute('SELECT SUM(attachment_count) FROM emails')
        stats['total_attachments'] = self.cursor.fetchone()[0] or 0
        
        return stats
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()