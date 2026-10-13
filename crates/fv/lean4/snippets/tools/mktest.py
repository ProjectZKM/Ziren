"""mktest.py SPLIT_FILE SNIPPET OUT: a chip file with the snippet in place of its theorem."""
import re, sys
L = open(sys.argv[1]).read().split('\n')
t = next(i for i, l in enumerate(L) if l.startswith('theorem deterministic'))
ow = next(l for l in L[t:] if l.strip().startswith('obtain ⟨x')).strip()
oc = next(l for l in L[t:] if re.match(r'\s*obtain ⟨+c0', l)).strip()
head = L[:t]
if any(l.startswith('/-! Conjuncts as definitions') for l in head):
    head = head[:next(i for i, l in enumerate(head) if l.startswith('/-! Conjuncts as definitions'))] + ['', '/--', '-/']
while not head[-1].startswith('/--'):
    head.pop()
head.pop()
h = '\n'.join(head).replace('import ZirenDet.GadgetProofs', 'import ZirenDet.GadgetProofs\nimport ZirenDet.DivRem')
owp = re.sub(r'\bx(\d+)', r'y\1', ow).replace(':= w', ":= w'")
ocp = re.sub(r'\bc(\d+g?)\b', r'd\1', oc).replace(':= hw', ":= hw'")
sn = open(sys.argv[2]).read().replace("%OPEN_W'%", owp).replace("%OPEN_HW'%", ocp).replace('%OPEN_W%', ow).replace('%OPEN_HW%', oc)
ns = [l.split()[1] for l in L if l.startswith('namespace ')]
ns = [n for n in ns if any(l.startswith(f'end {n}') for l in L)]
keep = [n for n in ns if L.index(f'namespace {n}') < t and L.index(f'end {n}') > t]
open(sys.argv[3], 'w').write(h + '\n' + sn + '\n' + '\n'.join(f'end {n}' for n in reversed(keep)) + '\n')
