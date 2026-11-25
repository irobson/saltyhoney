import os
import tempfile
import unittest
import zipfile
from pathlib import Path

import cbz


class TestCbz(unittest.TestCase):
    def test_filters_binaries_and_keeps_code_non_destructive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            proj = tmp_dir / "meu_projeto"
            (proj / "src").mkdir(parents=True)
            (proj / "build").mkdir(parents=True)
            (proj / ".git" / "objects").mkdir(parents=True)

            (proj / "src" / "Main.java").write_text("public class Main {}\n", encoding="utf-8")
            (proj / "pom.xml").write_text("<project><name>Ação</name></project>\n", encoding="utf-8")
            (proj / "config.json").write_text('{"ok": true}\n', encoding="utf-8")
            (proj / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"></svg>', encoding="utf-8")
            (proj / "notes_latin1.txt").write_bytes("Atenção versão 1\n".encode("latin-1"))
            (proj / "utf16.ps1").write_bytes("Write-Output 'Olá'".encode("utf-16"))
            (proj / ".gitignore").write_text("*.class\n", encoding="utf-8")

            (proj / "build" / "Main.class").write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d")
            (proj / "foto.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
            (proj / "arquivo_sem_extensao").write_bytes(os.urandom(512))
            (proj / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")
            (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

            out_zip = tmp_dir / "limpo.zip"
            res_path, kept, removed, _ = cbz.clean_and_zip_folder(proj, output_zip=out_zip)

            self.assertEqual(res_path, out_zip)
            self.assertEqual(kept, 7)
            self.assertEqual(removed, 4)

            self.assertTrue((proj / "build" / "Main.class").exists())
            self.assertTrue((proj / "foto.png").exists())

            with zipfile.ZipFile(out_zip, "r") as zf:
                names = set(zf.namelist())
                self.assertEqual(
                    names,
                    {
                        "meu_projeto/src/Main.java",
                        "meu_projeto/pom.xml",
                        "meu_projeto/config.json",
                        "meu_projeto/logo.svg",
                        "meu_projeto/notes_latin1.txt",
                        "meu_projeto/utf16.ps1",
                        "meu_projeto/.gitignore",
                    },
                )

    def test_in_place_deletes_binaries_and_empty_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            proj = tmp_dir / "app"
            (proj / "src").mkdir(parents=True)
            (proj / "bin_only").mkdir(parents=True)

            (proj / "src" / "App.java").write_text("class App {}", encoding="utf-8")
            (proj / "bin_only" / "lib.jar").write_bytes(b"PK\x03\x04\x14\x00")
            (proj / "bin_only" / "raw.bin").write_bytes(b"\x00\x01\x02\x03\xff\xfe")

            rc = cbz.main([str(proj), "--in-place"])
            self.assertEqual(rc, 0)

            self.assertTrue((proj / "src" / "App.java").exists())
            self.assertFalse((proj / "bin_only").exists())

            out_zip = tmp_dir / "app.zip"
            self.assertTrue(out_zip.is_file())
            with zipfile.ZipFile(out_zip, "r") as zf:
                self.assertEqual(zf.namelist(), ["app/src/App.java"])


if __name__ == "__main__":
    unittest.main()
