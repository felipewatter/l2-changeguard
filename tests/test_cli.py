import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO
from l2_changeguard import __version__
from l2_changeguard.cli import run

ROOT=Path(__file__).resolve().parents[1]
EXAMPLES=ROOT/'examples'


class CliTest(unittest.TestCase):
    def cmd(self,*args):
        return [*args,'--candidate',str(EXAMPLES/'candidate-risky.json'),'--policy',str(EXAMPLES/'policy.json')]

    def test_cli_audit_block(self):
        with patch('sys.stdout',new_callable=StringIO) as output:
            code=run(self.cmd('audit'))
        self.assertEqual(code,2)
        self.assertEqual(json.loads(output.getvalue())['verdict'],'blocked')

    def test_cli_compare_block(self):
        with patch('sys.stdout',new_callable=StringIO) as output:
            code=run(self.cmd('compare','--baseline',str(EXAMPLES/'baseline.json')))
        self.assertEqual(code,2)
        self.assertEqual(json.loads(output.getvalue())['gate'],'new-findings-only')

    def test_cli_compare_none_threshold_passes(self):
        with patch('sys.stdout',new_callable=StringIO) as output:
            code=run(self.cmd('compare','--baseline',str(EXAMPLES/'baseline.json'),'--fail-on','none'))
        self.assertEqual(code,0)

    def test_cli_audit_clean_passes(self):
        with patch('sys.stdout',new_callable=StringIO):
            code=run(['audit','--candidate',str(EXAMPLES/'baseline.json'),'--policy',str(EXAMPLES/'policy.json')])
        self.assertEqual(code,0)

    def test_output_files(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d)/'report.json'; s=Path(d)/'report.sarif'
            code=run(self.cmd('audit','--output',str(r),'--sarif',str(s)))
            self.assertEqual(code,2)
            self.assertEqual(json.loads(r.read_text())['verdict'],'blocked')
            self.assertEqual(json.loads(s.read_text())['version'],'2.1.0')

    def test_missing_baseline(self):
        with self.assertRaises(SystemExit) as e:
            run(self.cmd('compare'))
        self.assertEqual(e.exception.code,2)

    def test_wrong_baseline_on_audit(self):
        with self.assertRaises(SystemExit):
            run(self.cmd('audit','--baseline',str(EXAMPLES/'baseline.json')))

    def test_invalid_input_code(self):
        with tempfile.TemporaryDirectory() as d:
            invalid=Path(d)/'bad.json';invalid.write_text('{}')
            with patch('sys.stderr',new_callable=StringIO) as errors:
                status=run(['audit','--candidate',str(invalid),'--policy',str(EXAMPLES/'policy.json')])
            self.assertEqual(status,3)
            self.assertIn('input error:',errors.getvalue())

    def test_cli_module_smoke(self):
        code=subprocess.run([sys.executable,'-m','l2_changeguard','--version'],capture_output=True,text=True,check=False)
        self.assertEqual(code.returncode,0)
        self.assertIn(__version__,code.stdout)

    def test_refuse_output_unwritable(self):
        with tempfile.TemporaryDirectory() as d:
            code=run(self.cmd('audit','--output',str(Path(d)/'no-such-directory'/'report.json')))
            self.assertEqual(code,3)


if __name__=='__main__':unittest.main()
