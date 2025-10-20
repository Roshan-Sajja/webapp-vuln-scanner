import sqlite3
import os
from typing import Iterable, Tuple, Any, Optional, Dict, List


DB_PATH = os.getenv("DB_PATH", "scanner.db")

SCHEMA = """ 
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    status_code INTEGER,
    content_type TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    page_id INTEGER NOT NULL,
    vuln_type TEXT NOT NULL, 
    payload TEXT, 
    evidence TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(page_id) REFERENCES pages(id) ON DELETE CASCADE
);
"""
def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)



#update and insert page record
def upsert_page(url: str, status_code: Optional[int] = None, content_type: Optional[str] = None) -> int:
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO pages(url, status_code, content_type) VALUES (?, ?, ?)",
            (url, status_code, content_type)
        )
        cursor.execute(
            "UPDATE pages SET status_code = COALESCE(?, status_code), "
            "content_type = COALESCE(?, content_type) WHERE url = ?",
            (status_code, content_type, url)
        )
        conn.commit()
        cursor.execute("SELECT id FROM pages WHERE url = ?", (url,))
        row = cursor.fetchone()
        return int(row[0])
    

#insert finding record
def insert_finding(page_id: int, vuln_type: str, payload: Optional[str], evidence: Optional[str]) -> int:
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO findings(page_id, vuln_type, payload, evidence) VALUES (?, ?, ?, ?)",
            (page_id, vuln_type, payload, evidence)
        )
        conn.commit()
        return int(cursor.lastrowid)

#insert findings in bulk
def insert_findings(page_id: int, rows: Iterable[Tuple[str, Optional[str], Optional[str]]]) -> None:
    with get_conn() as conn:
        conn.executemany(
            "INSERT INTO findings(page_id, vuln_type, payload, evidence) VALUES (?, ?, ?, ?)",
            ((page_id, vuln_type, payload, evidence) for (vuln_type, payload, evidence) in rows)
        )
        conn.commit()


def get_pages() -> List[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM pages ORDER BY scanned_at DESC")
        return [dict(r) for r in cur.fetchall()]

def get_page_by_url(url: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute("SELECT * FROM pages WHERE url = ?", (url,))
        row = cur.fetchone()
        return dict(row) if row else None

def get_findings_for_page(page_id: int) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT vuln_type, payload, evidence, created_at FROM findings WHERE page_id = ? ORDER BY id DESC",
            (page_id,)
        )
        return [dict(r) for r in cur.fetchall()]
    
def get_findings_for_scan(job_id: str, target_url: str) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        curr = conn.execute("""
            SELECT 
                p.id as page_id,
                p.url,
                p.status_code,
                f.vuln_type,
                f.payload,
                f.evidence,
                f.created_at
            FROM findings f
            JOIN pages p ON f.page_id = p.id
            WHERE p.url LIKE ?
            ORDER BY p.url, f.created_at DESC
        """, (f"{target_url}%",))
        
        rows = curr.fetchall()

        findings_by_url = {}

        for row in rows:
            url = row['url']

            if url not in findings_by_url:
                findings_by_url[url] = {
                    'url': url,
                    'status_code': row['status_code'],
                    'findings': []
                }

            findings_by_url[url]['findings'].append({
                'type': row['vuln_type'],
                'payload': row['payload'],
                'evidence': row['evidence'],
                'timestamp': row['created_at']
            })

        return list(findings_by_url.values())


def clear_all() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM pages")
        conn.commit()