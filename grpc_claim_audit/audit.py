"""Offline claim matching and module-local evidence detection."""
import ast
import fnmatch
import os
import re
from pathlib import Path

GRPC = ('grpc api', 'grpc apis', 'grpc endpoint', 'grpc endpoints',
        'grpc server', 'grpc service', 'grpc interface', 'grpc support',
        'grpc enabled', 'grpc powered', 'grpc based', 'supports grpc',
        'support for grpc', 'uses grpc', 'using grpc', 'over grpc',
        'via grpc', 'with grpc')
NOGRPC = ('no grpc api support', 'no grpc support', 'does not support grpc',
          'does not use grpc', 'grpc not supported', 'without grpc',
          'no grpc api', 'no grpc')


def normalize(text):
    return ' '.join(text.lower().replace("n't", ' not').replace('-', ' ').split())


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in
                      sorted(phrases, key=len, reverse=True)) + r')\b')


def claims(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fence:
            if re.match(r'^\s{0,3}' + re.escape(fence[0]) + '{' + str(fence[1]) + r',}\s*$', line):
                fence = None
            lines.append('')
        elif match:
            fence = (match[1][0], len(match[1]))
            lines.append('')
        else:
            lines.append(line)
    positive = negative = False
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        text = normalize(paragraph)
        negative = negative or bool(pattern(NOGRPC).search(text))
        text = pattern(NOGRPC).sub(' ', text)
        positive = positive or bool(pattern(GRPC).search(text))
    return positive, negative


def evidence(source):
    tree = ast.parse(source)
    imports = {}
    local = {n.name for n in ast.walk(tree) if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imports[alias.asname or alias.name] = (node.module or '') + '.' + alias.name

    def resolve(node):
        if isinstance(node, ast.Name):
            return imports.get(node.id, '')
        if isinstance(node, ast.Attribute):
            base = resolve(node.value)
            return base + '.' + node.attr if base else ''
        return ''

    server = registration = channel = stub = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ''
        resolved = resolve(func)
        if resolved.split('.')[0] == 'grpc':
            server |= name == 'server' or resolved.rsplit('.', 1)[-1] == 'server'
            channel |= resolved.rsplit('.', 1)[-1] in ('insecure_channel', 'secure_channel')
        registration |= name.endswith('_to_server')
        if isinstance(func, ast.Name):
            original = imports.get(func.id, '').rsplit('.', 1)[-1]
            stub |= original.endswith('Stub') and func.id not in local
        elif isinstance(func, ast.Attribute):
            root = func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            stub |= name.endswith('Stub') and isinstance(root, ast.Name) and root.id in imports and root.id not in local
    return (server and registration) or (channel and stub)


def audit(root, ignores=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir() or not os.access(str(root), os.R_OK | os.X_OK):
        raise ValueError('root must be a readable directory')
    positive = negative = prod = test = False
    locations = []
    errors = []
    for directory, dirs, files in os.walk(str(root), followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            rel = path.relative_to(root)
            if path.is_symlink() or any(fnmatch.fnmatchcase(rel.as_posix(), g) for g in ignores):
                continue
            parts = rel.parts
            is_doc = rel.as_posix() == 'README.md' or ('docs' in parts[:-1] and path.suffix.lower() == '.md')
            is_test = 'tests' in parts[:-1] or name.startswith('test_') or name.endswith('_test.py')
            excluded = any(p in ('fixtures', 'docs', 'examples') for p in parts[:-1])
            if not is_doc and (path.suffix != '.py' or excluded):
                continue
            try:
                content = path.read_text(encoding='utf-8')
                if is_doc:
                    p, n = claims(content)
                    positive |= p
                    negative |= n
                elif evidence(content):
                    if is_test:
                        test = True
                    else:
                        prod = True
                    locations.append({'path': rel.as_posix(), 'scope': 'test' if is_test else 'production'})
            except (OSError, UnicodeError, SyntaxError) as exc:
                errors.append({'path': rel.as_posix(), 'error': str(exc)})
    findings = []
    if positive and not prod:
        findings.append({'rule': 'documented-grpc-claim-false', 'severity': 'MEDIUM' if test else 'HIGH',
                         'message': 'Documented capability lacks production evidence.'})
    if negative and prod:
        findings.append({'rule': 'documented-no-grpc-claim-false', 'severity': 'HIGH',
                         'message': 'Documented absence contradicts production evidence.'})
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return {'verdict': 'FAIL' if failed else 'PASS', 'findings': findings,
            'evidence': locations, 'errors': errors}
