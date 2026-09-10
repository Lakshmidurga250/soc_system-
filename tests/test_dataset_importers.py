"""Unit Tests for Public Cybersecurity Dataset Importers."""
from backend.app.parsers.dataset_importers import dataset_importer

SAMPLE_CICIDS2017_CSV = """Source IP,Destination IP,Source Port,Destination Port,Protocol,Timestamp,Label,Flow Duration
192.168.10.50,172.16.0.1,49152,80,6,2026-09-10 12:00:00,BENIGN,12000
192.168.10.50,172.16.0.1,49153,22,6,2026-09-10 12:00:01,SSH-Patator,54000
192.168.10.50,172.16.0.1,49154,80,6,2026-09-10 12:00:02,DoS Slowloris,34000
192.168.10.50,172.16.0.1,49155,80,6,2026-09-10 12:00:03,Web Attack – SQL Injection,89000
"""

SAMPLE_UNSW_NB15_CSV = """srcip,dstip,sport,dsport,proto,attack_cat,label,dur,sbytes,dbytes
10.40.85.1,149.171.126.1,1024,443,tcp,Normal,0,0.12,120,450
10.40.85.1,149.171.126.1,1025,80,tcp,Backdoor,1,0.45,1500,24000
10.40.85.1,149.171.126.1,1026,21,tcp,Reconnaissance,1,0.08,400,600
"""

def test_parse_cicids2017_csv():
    events = dataset_importer.parse_cicids2017_csv(SAMPLE_CICIDS2017_CSV)
    assert len(events) == 4
    assert events[0]["category"] == "Normal"
    assert events[1]["category"] == "Brute Force"
    assert events[2]["category"] == "DoS"
    assert events[3]["category"] == "Web Attack"
    assert events[3]["severity"] == "CRITICAL"

def test_parse_unsw_nb15_csv():
    events = dataset_importer.parse_unsw_nb15_csv(SAMPLE_UNSW_NB15_CSV)
    assert len(events) == 3
    assert events[0]["category"] == "Normal"
    assert events[1]["category"] == "Malware"
    assert events[2]["category"] == "Network Scan"
