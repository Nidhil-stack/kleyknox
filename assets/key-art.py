import base64, hashlib
mask = open('assets/key-mask.txt').read().rstrip('\n').split('\n')
# A deterministic base64 stream, so the drawing is the same on every build.
stream, block = '', b'KleyKnox'
while len(stream) < 2000:
    block = hashlib.sha256(block).digest()
    stream += base64.b64encode(block).decode().rstrip('=')
it = iter(stream)
out = []
for row in mask:
    line = ''
    for c in row:
        if c == ' ': line += ' '; continue
        ch = next(it)
        line += ch.upper() if c == 'X' else ch.lower()   # lit face upper case, shaded face lower
    out.append(line)
# Like the last line of an armored block: padding at the end.
out[-1] = out[-1][:-2] + '=='
print('\n'.join(out))
