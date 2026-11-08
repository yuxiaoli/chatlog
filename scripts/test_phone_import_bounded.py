"""Bounded phone transactions retain all records; only unpublished staging may opt in."""
import tempfile
import io
import json
import unittest
import subprocess
import sys
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import duckdb
import export_wechat_history as exporter

class RecordingConnection:
    def __init__(self,conn): self.conn=conn;self.commits=0;self.checkpoints=0
    def execute(self,sql,*args):
        if sql=='COMMIT': self.commits+=1
        if sql=='CHECKPOINT':self.checkpoints+=1
        return self.conn.execute(sql,*args)
    def __getattr__(self,name):return getattr(self.conn,name)

def segment(index):
    messages=[]
    for ordinal in range(6):
        messages.append(SimpleNamespace(ordinal=ordinal,record_offset=ordinal*2048,record_length=2048,
            sender_id='sender',recipient_id='peer',message_type=1,create_time=1700000000,
            server_id=index*100+ordinal,msg_sequence=ordinal,sequence=ordinal,
            content='synthetic',raw_record=bytes([index])*2048))
    return SimpleNamespace(index_rowid=index,talker_id=1,user_name='peer',segment_id=str(index),
        start_time=1700000000,end_time=1700000000,source_file='BAK_1_TEXT',source_offset=index*16384,
        encrypted_length=16384,plaintext_length=16380,padding_length=4,root_value=bytes([index])*16380,
        ciphertext_sha256='a'*64,plaintext_sha256='b'*64,messages=messages)

class BoundedPhoneTests(unittest.TestCase):
    def fixture(self,tmp):
        index=Path(tmp)/'Backup.db';index.write_bytes(b'fixture')
        database=SimpleNamespace(stage_status='ok',mode='decrypted_phone_backup_index',staged_path=index,
            source_path=str(index),database_id='db',account=SimpleNamespace(account_id='owner'),auxiliary_sha256='')
        conn=duckdb.connect(str(Path(tmp)/'stage.duckdb'));self.addCleanup(conn.close)
        exporter.create_catalog(conn)
        return RecordingConnection(conn),database

    def test_multiple_byte_and_row_batches_preserve_exact_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            with patch.object(exporter,'catalog_backup_archive_files'),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=iter([segment(i) for i in range(1,5)])),patch.object(exporter,'BACKUP_MESSAGE_BATCH_SIZE',2):
                count=exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096)
            self.assertEqual(count,24)
            self.assertGreaterEqual(conn.commits,5)
            self.assertEqual(conn.checkpoints,4)
            self.assertEqual(conn.execute('SELECT count(*),count(DISTINCT source_message_key),sum(octet_length(raw_record)) FROM chatlog.backup_message_records').fetchone(),(24,24,24*2048))
            self.assertEqual(conn.execute('SELECT count(*),sum(octet_length(root_value)) FROM chatlog.backup_text_segments').fetchone(),(4,4*16380))
            conn.close()

    def test_late_failure_is_fatal_even_after_staging_chunks_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            def failing():
                yield segment(1)
                yield segment(2)
                raise exporter.BackupArchiveError('synthetic late failure')
            with patch.object(exporter,'catalog_backup_archive_files'),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=failing()):
                with self.assertRaisesRegex(exporter.ExportError,'synthetic late failure'):
                    exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096)
            self.assertEqual(conn.checkpoints,2)
            self.assertEqual(conn.execute('SELECT count(*) FROM chatlog.backup_message_records').fetchone()[0],12)
            conn.close()

    def test_json_progress_counts_and_timings_contain_no_message_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            output=io.StringIO()
            def catalog(duck,database,root):
                duck.execute("INSERT INTO chatlog.backup_archive_files VALUES ('archive','owner','db','text','BAK_1_TEXT','fixture',65536,0,4,65536,0)")
            with patch.object(exporter,'catalog_backup_archive_files',side_effect=catalog),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=iter([segment(i) for i in range(1,5)])),patch('sys.stderr',output):
                exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096)
            events=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(events[-1]['processed_segments'],4)
            self.assertEqual(events[-1]['total_segments'],4)
            self.assertEqual(events[-1]['records'],24)
            self.assertTrue(any(e.get('checkpoint_seconds',-1)>=0 for e in events))
            self.assertTrue(any(e.get('commit_seconds',-1)>=0 for e in events))
            self.assertNotIn('synthetic',output.getvalue())
            self.assertNotIn('sender',output.getvalue())
            conn.close()

    def test_chunked_mode_rejects_partial_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            with self.assertRaisesRegex(ValueError,'forbids partial'):
                exporter.import_phone_backup_messages(conn,[db],bytes(32),True,staging_commit_bytes=4096)
            conn.close()


    def test_deferred_checkpoints_keep_small_commits_and_exact_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            with patch.object(exporter,'catalog_backup_archive_files'),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=iter([segment(i) for i in range(1,5)])):
                count=exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096,staging_checkpoint_bytes=1_000_000)
            self.assertEqual(count,24)
            self.assertEqual(conn.commits,5)
            self.assertEqual(conn.checkpoints,1)
            actual=conn.execute('SELECT raw_record FROM chatlog.backup_message_records ORDER BY source_message_key').fetchall()
            self.assertEqual([hashlib.sha256(r[0]).digest() for r in actual],[hashlib.sha256(bytes([i])*2048).digest() for i in range(1,5) for _ in range(6)])
            conn.close()

    def test_checkpoint_budget_requires_bounded_transactions(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            for commit,checkpoint in ((0,100),(200,100),(100,-1),(100,True)):
                with self.assertRaises(ValueError):
                    exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=commit,staging_checkpoint_bytes=checkpoint)
            conn.close()

    def test_deferred_checkpoint_failure_is_fatal_after_durable_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn,db=self.fixture(tmp)
            original=conn.execute
            def execute(sql,*args):
                if sql=='CHECKPOINT':raise duckdb.Error('synthetic checkpoint failure')
                return original(sql,*args)
            with patch.object(conn,'execute',side_effect=execute),patch.object(exporter,'catalog_backup_archive_files'),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=iter([segment(1),segment(2)])):
                with self.assertRaisesRegex(exporter.ExportError,'synthetic checkpoint failure'):
                    exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096,staging_checkpoint_bytes=1_000_000)
            self.assertEqual(conn.execute('SELECT count(*) FROM chatlog.backup_message_records').fetchone()[0],12)
            conn.close()

    def test_crash_recovers_committed_segment_and_discards_uncommitted_segment(self):
        with tempfile.TemporaryDirectory() as tmp:
            child = r"""
import os,sys
from unittest.mock import patch
from test_phone_import_bounded import BoundedPhoneTests,segment,exporter
conn,db=BoundedPhoneTests().fixture(sys.argv[1])
original=conn.execute
commits=0
def execute(sql,*args):
    global commits
    if sql=='COMMIT':
        commits+=1
        if commits==2:os._exit(17)
    return original(sql,*args)
with patch.object(conn,'execute',side_effect=execute),patch.object(exporter,'catalog_backup_archive_files'),patch.object(exporter,'phone_backup_auxiliary_sha256',return_value='stable'),patch.object(exporter,'iter_backup_segments',return_value=iter([segment(1),segment(2)])):
    exporter.import_phone_backup_messages(conn,[db],bytes(32),False,staging_commit_bytes=4096,staging_checkpoint_bytes=1_000_000)
"""
            result=subprocess.run([sys.executable,'-c',child,tmp],cwd=Path(__file__).parent,capture_output=True,timeout=30)
            self.assertEqual(result.returncode,17,result.stderr)
            with duckdb.connect(str(Path(tmp)/'stage.duckdb')) as conn:
                self.assertEqual(conn.execute('SELECT index_rowid,message_count FROM chatlog.backup_text_segments').fetchall(),[(1,6)])
                rows=conn.execute('SELECT message_ordinal,raw_record FROM chatlog.backup_message_records ORDER BY message_ordinal').fetchall()
                self.assertEqual(rows,[(i,bytes([1])*2048) for i in range(6)])

if __name__=='__main__':unittest.main()
