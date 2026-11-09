"""Local verification of distributable ZIP and SHA-256 manifest."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ReleaseTest(unittest.TestCase):
    def produce(self,folder):
        result=subprocess.run([sys.executable,str(ROOT/'scripts/build_release.py'),str(folder)],capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stderr)
        return (folder/'l2-changeguard-v0.1.0-source.zip',folder/'l2-changeguard-v0.1.0-manifest.json',folder/'l2-changeguard-v0.1.0-SHA256SUMS.txt')

    def test_manifest_matches_zip(self):
        with tempfile.TemporaryDirectory() as d:
            archive,manifest,_=self.produce(Path(d))
            m=json.loads(manifest.read_text())
            with zipfile.ZipFile(archive) as z:
                paths=z.namelist()
                self.assertEqual(len(paths),len(m['sha256']))
                for item in paths:
                    self.assertTrue(item.startswith('l2-changeguard-v0.1.0/'))
                    self.assertNotIn('..',item.split('/'))
                    rel=item.split('/',1)[1]
                    self.assertEqual(hashlib.sha256(z.read(item)).hexdigest(),m['sha256'][rel])

    def test_checksums(self):
        with tempfile.TemporaryDirectory() as d:
            archive,manifest,checksums=self.produce(Path(d))
            actual={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (archive,manifest)}
            reported=dict((name,digest) for digest,name in (line.split('  ',1) for line in checksums.read_text().splitlines()))
            self.assertEqual(actual,reported)

    def test_archive_reproducible(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            one=self.produce(Path(a));two=self.produce(Path(b))
            self.assertEqual([hashlib.sha256(x.read_bytes()).hexdigest() for x in one], [hashlib.sha256(x.read_bytes()).hexdigest() for x in two])

    def test_avoid_local_machine_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            archive,*_=self.produce(Path(d))
            with zipfile.ZipFile(archive) as z:
                for file in z.namelist():
                    self.assertNotIn('pycache',file.lower())
                    self.assertNotIn('.egg-info',file)
                    self.assertNotIn('.git/',file)
                    self.assertNotIn('dist/',file)

    def test_docs_included(self):
        with tempfile.TemporaryDirectory() as d:
            archive,*_=self.produce(Path(d))
            with zipfile.ZipFile(archive) as z:
                paths=set(z.namelist())
                for f in ('README.md','LICENSE','SECURITY.md','pyproject.toml','.github/workflows/ci.yml','.github/workflows/release.yml','docs/THREAT_MODEL.md'):
                    self.assertIn('l2-changeguard-v0.1.0/'+f,paths)


if __name__ == '__main__':
    unittest.main()
