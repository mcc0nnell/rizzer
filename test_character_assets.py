"""Rizzer's portrait variants are deterministic, scalable and labeled."""
# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("build_mascot", ROOT / "scripts" / "build_mascot.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
NS = {"svg": "http://www.w3.org/2000/svg"}


class VectorMascotTests(unittest.TestCase):
    def test_five_expressions_are_all_vector_and_have_names(self):
        self.assertEqual(len(module.EXPRESSIONS), 5)
        for pose in module.EXPRESSIONS:
            with self.subTest(pose=pose):
                content = module.build(pose)
                root = ET.fromstring(content)
                self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
                self.assertEqual(root.attrib.get("viewBox"), "0 0 512 512")
                self.assertEqual(root.attrib.get("role"), "img")
                self.assertEqual(root.find("svg:title", NS).text, f"Rizzer — {pose}")
                self.assertIn("two joined polo shirts", root.find("svg:desc", NS).text)
                self.assertEqual(content, (ROOT / "assets" / f"rizzer-{pose}.svg").read_text())
                for banned in ("<image", "<script", "data:image", "javascript:"):
                    self.assertNotIn(banned, content)

    def test_master_is_exact_smug_variant(self):
        self.assertEqual((ROOT / "assets/rizzer.svg").read_bytes(),
                         (ROOT / "assets/rizzer-smug.svg").read_bytes())

    def test_variants_share_geometry_and_differ_in_faces(self):
        poses = [module.build(p) for p in module.EXPRESSIONS]
        self.assertTrue(all(module.BODY in svg for svg in poses))
        self.assertEqual(len(set(poses)), 5)

    def test_invalid_pose_rejected(self):
        with self.assertRaises(ValueError):
            module.build("security-vulnerability-confirmed")


if __name__ == "__main__":
    unittest.main()
