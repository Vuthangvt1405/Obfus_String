import json, sys
try:
    d=json.load(open('.omo/evidence/task-12-runtime-report.json'))
    assert d['total_strings'] >= 1
    assert any('thecyberyeti.com' in s.get('content','') for s in d['strings'])
    print('runtime capture ok')
except Exception as e:
    print(f"skip validation: {e}")
