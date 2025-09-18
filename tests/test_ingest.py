import pytest 
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.ingest import parse_email_file, get_email_body
from pathlib import Path 

def test_parse_email_file(tmp_path):
    dummuy_file=tmp_path/"test_email.eml"
    dummuy_file.write_text("From:me@gmail.com \n"
                          "To:you@gmail.com \n"  
                          "Subject:test email \n\n"
                          "Test is done")
    
    msg=parse_email_file(str(dummuy_file))
    body=get_email_body(msg)
    assert msg is not None
    assert msg["From"]=="me@gmail.com "
    assert msg["To"]=="you@gmail.com "
    assert msg["Subject"]=="test email "
    assert "Test is done" in body


