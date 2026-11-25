import tempfile
import unittest
import zipfile
from pathlib import Path

import zip_crypto


class TestZipCrypto(unittest.TestCase):
    def test_rfc8439_chacha20_vector(self) -> None:
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        nonce = bytes.fromhex("000000000000004a00000000")
        counter = 1
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: "
            b"If I could offer you only one tip for the future, sunscreen would be it."
        )
        expected_ciphertext = bytes.fromhex(
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b357"
            "1639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e"
            "52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42"
            "874d"
        )
        actual = zip_crypto.chacha20_xor(key, counter, nonce, plaintext)
        self.assertEqual(actual, expected_ciphertext)
        self.assertEqual(zip_crypto.chacha20_xor(key, counter, nonce, actual), plaintext)

    def test_zip_roundtrip_and_crlf_resilience(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            original_zip = tmp_dir / "dados.zip"
            with zipfile.ZipFile(original_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("oi.txt", "Olá mundo com acentuação UTF-8! 🚀")
                zf.writestr("binario.bin", bytes(range(256)) * 400)

            original_bytes = original_zip.read_bytes()
            txt_file = tmp_dir / "dados.txt"

            zip_crypto.encrypt_zip_file(original_zip, txt_file, "minha-chave-secreta!")
            txt_content = txt_file.read_text(encoding="utf-8")

            txt_content.encode("ascii")
            self.assertIn(zip_crypto.ARMOR_BEGIN, txt_content)
            self.assertIn(zip_crypto.ARMOR_END, txt_content)

            txt_file.write_text(txt_content.replace("\n", "\r\n") + "\r\n", encoding="utf-8")

            restored_zip = tmp_dir / "restaurado.zip"
            zip_crypto.decrypt_txt_file(txt_file, restored_zip, "minha-chave-secreta!")

            self.assertEqual(restored_zip.read_bytes(), original_bytes)
            with zipfile.ZipFile(restored_zip, "r") as zf:
                self.assertIsNone(zf.testzip())
                self.assertEqual(zf.read("oi.txt").decode("utf-8"), "Olá mundo com acentuação UTF-8! 🚀")

    def test_wrong_key_rejected_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            src_zip = tmp_dir / "secret.zip"
            with zipfile.ZipFile(src_zip, "w") as zf:
                zf.writestr("a.txt", "segredo")

            txt_file = tmp_dir / "secret.txt"
            zip_crypto.encrypt_zip_file(src_zip, txt_file, "chave-correta")

            restored = tmp_dir / "restored.zip"
            with self.assertRaises(zip_crypto.ZipCryptoError):
                zip_crypto.decrypt_txt_file(txt_file, restored, "chave-errada")

            self.assertFalse(restored.exists())

    def test_tampered_txt_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            src_zip = tmp_dir / "doc.zip"
            with zipfile.ZipFile(src_zip, "w") as zf:
                zf.writestr("doc.txt", "conteudo")

            txt_file = tmp_dir / "doc.txt"
            zip_crypto.encrypt_zip_file(src_zip, txt_file, "senha123")

            lines = txt_file.read_text(encoding="utf-8").splitlines()
            mid = len(lines) // 2
            ch = "A" if lines[mid][0] != "A" else "B"
            lines[mid] = ch + lines[mid][1:]
            txt_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(zip_crypto.ZipCryptoError):
                zip_crypto.decrypt_txt_file(txt_file, tmp_dir / "out.zip", "senha123")

    def test_cli_encrypt_and_decrypt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            src_zip = tmp_dir / "cli.zip"
            with zipfile.ZipFile(src_zip, "w") as zf:
                zf.writestr("hello.txt", "world")

            txt_file = tmp_dir / "cli.txt"
            out_zip = tmp_dir / "cli_out.zip"

            rc1 = zip_crypto.main(["encrypt", str(src_zip), "-o", str(txt_file), "-k", "pass123"])
            rc2 = zip_crypto.main(["decrypt", str(txt_file), "-o", str(out_zip), "-k", "pass123"])
            rc_bad = zip_crypto.main(["decrypt", str(txt_file), "-o", str(tmp_dir / "bad.zip"), "-k", "wrong"])

            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            self.assertEqual(rc_bad, 1)
            self.assertEqual(out_zip.read_bytes(), src_zip.read_bytes())


if __name__ == "__main__":
    unittest.main()
