#!/bin/bash
# Quick engagement state checker
TOKEN=$(node -e "const jwt = require('jsonwebtoken'); console.log(jwt.sign({username:'test-operator',role:'admin',loginTime:Date.now(),authType:'caldera',sessionId:'t-'+Date.now()}, process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024', {expiresIn:'2h'}))")
ENG_ID=${1:-1950002}
curl -s --max-time 10 -b "caldera_session=$TOKEN" "http://localhost:3000/api/trpc/engagementOps.getState?input=%7B%22json%22%3A%7B%22engagementId%22%3A${ENG_ID}%7D%7D" > /tmp/state_check.json
python3 -c "
import json, sys
try:
    d=json.load(open('/tmp/state_check.json'))
    s=d.get('result',{}).get('data',{}).get('json')
    if not s:
        print(f'No state found: {json.dumps(d)[:200]}')
        sys.exit(1)
    print(f'Phase: {s[\"phase\"]} | Running: {s[\"isRunning\"]} | Progress: {s.get(\"progress\",0)}%')
    print(f'Assets: {len(s.get(\"assets\",[]))} | Vulns: {s.get(\"stats\",{}).get(\"vulnsFound\",0)} | Exploits: {s.get(\"stats\",{}).get(\"exploitsAttempted\",0)}/{s.get(\"stats\",{}).get(\"exploitsSucceeded\",0)}')
    print(f'Action: {s.get(\"currentAction\",\"none\")[:120]}')
    print(f'--- Last 5 logs ---')
    for l in s.get('log',[])[-5:]:
        print(f'  [{l[\"phase\"]}] {l[\"type\"]}: {(l.get(\"title\") or \"\")[:100]}')
    # Check for errors
    errors = [l for l in s.get('log',[]) if l.get('type') == 'error']
    if errors:
        print(f'\\n--- ERRORS ({len(errors)}) ---')
        for e in errors[-3:]:
            print(f'  {e.get(\"title\",\"\")[:80]}')
            print(f'    {e.get(\"detail\",\"\")[:200]}')
except Exception as ex:
    print(f'Parse error: {ex}')
"
