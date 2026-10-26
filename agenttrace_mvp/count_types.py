import json
import collections
import sys

c = collections.Counter()
first_call = None
for line in open(sys.argv[1], encoding="utf-8"):
    o = json.loads(line)
    p = o.get("payload", {})
    t = p.get("type") if isinstance(p, dict) else None
    c[(o.get("type"), t)] += 1
    if first_call is None and t and "call" in t and "output" not in t:
        first_call = line[:500]

for k, v in c.most_common():
    print(v, k)
print("\nFIRST CALL:\n", first_call)
