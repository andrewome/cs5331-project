import os
import json
import base64

out = []
for rule in os.listdir('rules'):
    with open(f'rules/{rule}', 'r') as f:
        out.append(f.read())

# Output into js file
out = json.dumps(out).encode()
out = base64.b64encode(out).decode()
out = f'const yaraRules = JSON.parse(atob("{out}"));'
with open('rules.js', 'w') as f:
    f.write(out)
 