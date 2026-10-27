import contextlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from grpc_claim_audit.audit import GRPC, NOGRPC, audit, claims, evidence, normalize, pattern
from grpc_claim_audit.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
SERVER = 'import grpc\ns = grpc.server(None)\nadd_GreeterServicer_to_server(None, s)\n'
CLIENT = 'import grpc\nfrom generated import GreeterStub\nc = grpc.insecure_channel("x")\ns = GreeterStub(c)\n'


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=str(ROOT))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def run_cli(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            try:
                code = main([str(self.root)] + list(args))
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue()

    def case(self, claim, source=None, severity=None, rule='documented-grpc-claim-false'):
        self.write('README.md', claim)
        if source is not None:
            self.write('app.py', source)
        code, output = self.run_cli('--json')
        result = json.loads(output)
        expected = [] if severity is None else [rule]
        self.assertEqual([f['rule'] for f in result['findings']], expected)
        if severity:
            self.assertEqual(result['findings'][0]['severity'], severity)
        self.assertEqual(code, 2 if severity == 'HIGH' else 0)
        self.assertEqual(result['verdict'], 'FAIL' if code == 2 else 'PASS')
        return result

    def test_01_server(self):
        self.case('grpc api', SERVER)

    def test_02_alias(self):
        self.case('grpc server', SERVER.replace('import grpc', 'import grpc as g').replace('grpc.server', 'g.server'))

    def test_03_aio(self):
        self.case('grpc service', SERVER.replace('grpc.server', 'grpc.aio.server'))

    def test_04_client(self):
        self.case('uses grpc', CLIENT)

    def test_05_secure(self):
        self.case('grpc endpoint', CLIENT.replace('insecure_channel', 'secure_channel'))

    def test_06_import(self):
        self.case('grpc api', 'import grpc', 'HIGH')

    def test_07_server_half(self):
        self.case('grpc api', 'import grpc\ns=grpc.server(None)', 'HIGH')

    def test_08_registration_half(self):
        self.case('grpc api', 'add_GreeterServicer_to_server(None, None)', 'HIGH')

    def test_09_channel_half(self):
        self.case('grpc api', 'import grpc\nc=grpc.insecure_channel("x")', 'HIGH')

    def test_10_stub_half(self):
        self.case('grpc api', 'from generated import GreeterStub\ns=GreeterStub(None)', 'HIGH')

    def test_11_local_stub(self):
        self.case('grpc api', CLIENT + '\nclass GreeterStub: pass\n', 'HIGH')

    def test_12_rest(self):
        self.case('grpc api', '@app.get("/")\ndef index(): return {"ok": True}', 'HIGH')

    def test_13_socket(self):
        self.case('grpc server', 'import socket\ns=socket.socket()\ns.connect(("x", 1))', 'HIGH')

    def test_14_negative(self):
        self.case('no grpc support', SERVER, 'HIGH', 'documented-no-grpc-claim-false')

    def test_15_no_claim(self):
        self.case('A useful utility.', SERVER)

    def test_16_bare_noun(self):
        self.case('the grpc chapter explains the protocol', 'import grpc')

    def test_17_rest_exclusion(self):
        self.case('rest api', '@app.get("/")\ndef index(): return {}')

    def test_18_graphql_exclusion(self):
        self.case('graphql api', 'schema = Schema(query=Query)')

    def test_19_no_source(self):
        self.case('grpc api', severity='HIGH')
        self.case('no grpc support')

    def test_20_test_only(self):
        self.write('tests/helper.py', SERVER)
        self.case('grpc api', severity='MEDIUM')
        code, output = self.run_cli('--json', '--fail-on', 'MEDIUM')
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['verdict'], 'FAIL')

    def test_21_fence_inline(self):
        self.case('```text\ngrpc api\n```')
        self.case('`grpc api`', severity='HIGH')

    def test_22_negation(self):
        self.assertEqual(claims('does not support grpc'), (False, True))
        self.case('does not support grpc', SERVER, 'HIGH', 'documented-no-grpc-claim-false')

    def test_23_self(self):
        # Temporary fixtures in this test's root would alter the self-audit.
        result = audit(ROOT, ignores=(self.root.name + '/*', '.verification/*', 'build/*', 'dist/*'))
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['verdict'], 'PASS')
        for path in [ROOT / 'README.md'] + list((ROOT / 'docs').rglob('*.md')):
            text = normalize(path.read_text(encoding='utf-8'))
            self.assertIsNone(pattern(GRPC + NOGRPC).search(text), str(path))

    def test_24_cli(self):
        self.write('app.py', SERVER)
        self.assertEqual(self.run_cli('--version'), (0, '0.1.0\n'))
        self.assertEqual(json.loads(self.run_cli('--json')[1])['verdict'], 'PASS')
        self.assertIn('app.py', self.run_cli('--verbose')[1])
        self.write('docs/claim.md', 'no grpc support')
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual(self.run_cli('--ignore', 'docs/*')[0], 0)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main([str(self.root / 'missing')])
        self.assertEqual(exc.exception.code, 1)
        self.assertEqual(self.run_cli('--fail-on', 'INVALID')[0], 1)

    def test_25_env_guard(self):
        self.write('.env', 'MARKER_ONLY')
        self.write('tests/fixtures/.env', 'MARKER_ONLY')
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_26_packaging(self):
        for path in list((ROOT / 'grpc_claim_audit').glob('*.py')) + list((ROOT / 'tests').glob('*.py')) + [ROOT / 'README.md']:
            text = path.read_text(encoding='utf-8')
            self.assertIsNone(re.search(r'\b' + 'py' + r'thon\b', text), str(path))
        project = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('setuptools>=77', project)
        self.assertIn('license = "MIT"', project)
        self.assertIn('requires-' + 'py' + 'thon = ">=3.9"', project)
        manifest = (ROOT / 'MANIFEST.in').read_text()
        self.assertIn('recursive-include tests *.py', manifest)
        self.assertIn('recursive-include tests/fixtures *', manifest)

    def test_27_all_templates(self):
        for phrase in GRPC:
            self.assertEqual(claims(phrase), (True, False), phrase)
        for phrase in NOGRPC:
            self.assertEqual(claims(phrase), (False, True), phrase)

    def test_28_normalization_boundaries(self):
        self.assertEqual(claims("doesn't support grpc"), (False, True))
        self.assertEqual(claims('GRPC-\nAPI'), (True, False))
        self.assertEqual(claims('grpc\n\napi'), (False, False))
        self.assertEqual(claims('xgrpc apix'), (False, False))

    def test_29_module_boundary(self):
        self.write('a.py', 'import grpc\ns=grpc.server(None)')
        self.write('b.py', 'add_X_to_server(None, None)')
        self.case('grpc api', severity='HIGH')

    def test_30_exclusions(self):
        for name in ('fixtures/a.py', 'docs/a.py', 'examples/a.py'):
            self.write(name, SERVER)
        self.case('grpc api', severity='HIGH')

    def test_31_symlink(self):
        self.write('examples/source.py', SERVER)
        (self.root / 'app.py').symlink_to(self.root / 'examples/source.py')
        self.case('grpc api', severity='HIGH')

    def test_32_alias_variants(self):
        for source in (CLIENT.replace('import grpc', 'import grpc as g').replace('grpc.insecure', 'g.aio.insecure'),
                       CLIENT.replace('GreeterStub', 'Renamed').replace('import Renamed', 'import GreeterStub as Renamed'),
                       CLIENT.replace('from generated import GreeterStub', 'import generated as pb').replace('s = GreeterStub', 's = pb.GreeterStub'),
                       SERVER.replace('import grpc', 'from grpc import aio as g').replace('grpc.server', 'g.server')):
            self.assertTrue(evidence(source), source)

    def test_33_non_evidence(self):
        for source in ('grpc.server(None)\nadd_X_to_server(None, None)',
                       '"grpc.server(None)"', 'def grpc_handler(): return "grpc"',
                       'class XServicer(Base): pass', '# grpc.server(None)\n',
                       'import socket as grpc\ns=grpc.server(None)\nadd_X_to_server(None,None)'):
            self.assertFalse(evidence(source), source)

    def test_34_two_families(self):
        self.write('README.md', 'grpc api\n\nno grpc support')
        self.write('app.py', SERVER)
        result = audit(self.root)
        self.assertEqual([f['rule'] for f in result['findings']], ['documented-no-grpc-claim-false'])

    def test_35_test_named_file(self):
        self.write('test_transport.py', SERVER)
        self.case('grpc api', severity='MEDIUM')

    def test_36_fence_variants(self):
        self.assertEqual(claims('~~~md\ngrpc api\n~~~'), (False, False))
        self.assertEqual(claims('````\ngrpc api\n```\ngrpc server'), (False, False))

    def test_37_diagnostics(self):
        self.write('app.py', 'def broken(')
        self.case('grpc api', severity='HIGH')
        self.assertEqual(audit(self.root)['errors'][0]['path'], 'app.py')
