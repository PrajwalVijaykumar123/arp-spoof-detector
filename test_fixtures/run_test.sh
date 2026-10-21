#!/bin/sh
# Generates a realistic JSONL ARP capture (normal traffic, then a real
# gateway-spoofing attack pattern matching what arpspoof/Ettercap
# actually produce) and runs the real arpwatch.py --replay against it -
# the full real detection pipeline, no mocked detector calls.
set -e
cd "$(dirname "$0")/.."

echo "== Generating attack capture =="
python3 test_fixtures/make_capture.py /tmp/asd_attack.jsonl
cat /tmp/asd_attack.jsonl

echo
echo "== Replaying attack capture with --gateway-ip set =="
set +e
python3 arpwatch.py --replay /tmp/asd_attack.jsonl --gateway-ip 192.168.1.1 --json /tmp/asd_report.json > /tmp/asd_out.txt 2>&1
EXIT_ATTACK=$?
set -e
cat /tmp/asd_out.txt

grep -q "CRITICAL" /tmp/asd_out.txt && echo "PASS: CRITICAL finding raised" || { echo "FAIL"; exit 1; }
grep -q "gateway_rebind" /tmp/asd_out.txt && echo "PASS: correctly classified as gateway_rebind" || { echo "FAIL"; exit 1; }
grep -q "aa:aa:aa:aa:aa:01" /tmp/asd_out.txt && grep -q "ff:ff:ff:ff:ff:99" /tmp/asd_out.txt && echo "PASS: both old and new MAC named in the finding" || { echo "FAIL"; exit 1; }
[ "$EXIT_ATTACK" = "1" ] && echo "PASS: exit code 1 when a HIGH+ finding occurred" || { echo "FAIL: expected exit 1, got $EXIT_ATTACK"; exit 1; }

python3 -c "
import json
report = json.load(open('/tmp/asd_report.json'))
assert len(report) == 1, f'expected exactly 1 finding, got {len(report)}'
assert report[0]['severity'] == 'CRITICAL'
assert report[0]['kind'] == 'gateway_rebind'
print('PASS: JSON report has exactly one correctly-classified CRITICAL finding')
"

echo
echo "== Replaying the same capture WITHOUT --gateway-ip set =="
echo "   (the rebind is on an IP the tool doesn't know is the gateway - still flagged, but as HIGH not CRITICAL)"
set +e
python3 arpwatch.py --replay /tmp/asd_attack.jsonl > /tmp/asd_out_nogw.txt 2>&1
EXIT_NOGW=$?
set -e
cat /tmp/asd_out_nogw.txt
grep -q "HIGH" /tmp/asd_out_nogw.txt && grep -q "ip_mac_rebind" /tmp/asd_out_nogw.txt && echo "PASS: without --gateway-ip, same rebind is still caught, correctly downgraded to HIGH" || { echo "FAIL"; exit 1; }

echo
echo "== Pure benign traffic: expect zero findings, exit 0 =="
python3 -c "
import json
events = [
    (0.0, 'request', '192.168.1.1', 'aa:aa:aa:aa:aa:01'),
    (0.1, 'reply', '192.168.1.1', 'aa:aa:aa:aa:aa:01'),
    (1.0, 'request', '192.168.1.50', 'bb:bb:bb:bb:bb:50'),
    (1.1, 'reply', '192.168.1.50', 'bb:bb:bb:bb:bb:50'),
]
with open('/tmp/asd_clean.jsonl', 'w') as f:
    for ts, op, ip, mac in events:
        f.write(json.dumps({'ts': ts, 'op': op, 'src_ip': ip, 'src_mac': mac}) + chr(10))
"
set +e
python3 arpwatch.py --replay /tmp/asd_clean.jsonl --gateway-ip 192.168.1.1 > /tmp/asd_clean_out.txt 2>&1
EXIT_CLEAN=$?
set -e
cat /tmp/asd_clean_out.txt
grep -q "0 finding(s)" /tmp/asd_clean_out.txt && echo "PASS: benign traffic produces zero findings" || { echo "FAIL"; exit 1; }
[ "$EXIT_CLEAN" = "0" ] && echo "PASS: exit code 0 on benign traffic" || { echo "FAIL: expected exit 0, got $EXIT_CLEAN"; exit 1; }

rm -f /tmp/asd_attack.jsonl /tmp/asd_report.json /tmp/asd_out.txt /tmp/asd_out_nogw.txt /tmp/asd_clean.jsonl /tmp/asd_clean_out.txt
echo
echo "All tests passed."
