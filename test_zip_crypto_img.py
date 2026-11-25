import os
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

import zip_crypto_img


def _make_minimal_png(width: int = 2, height: int = 2) -> bytes:
    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + b"\xff\x00\x80" * width for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _make_minimal_jpg() -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"


class TestZipCryptoImg(unittest.TestCase):
    def test_large_zip_over_3mb_roundtrip_in_png(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "capa.png"
            img_path.write_bytes(_make_minimal_png(16, 16))

            zip_path = tmp_dir / "grande.zip"
            payload = os.urandom(3 * 1024 * 1024 + 512 * 1024)
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("dados.bin", payload)
                zf.writestr("info.txt", "arquivo grande")

            self.assertGreater(zip_path.stat().st_size, 3 * 1024 * 1024)
            original_zip_bytes = zip_path.read_bytes()

            out_img = tmp_dir / "saida.png"
            zip_crypto_img.hide_zip_in_image(img_path, zip_path, out_img, "chave-forte-123")

            self.assertTrue(out_img.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))
            self.assertGreater(out_img.stat().st_size, 3 * 1024 * 1024)

            restored_zip = tmp_dir / "restaurado.zip"
            zip_crypto_img.extract_zip_from_image(out_img, restored_zip, "chave-forte-123")

            self.assertEqual(restored_zip.read_bytes(), original_zip_bytes)
            with zipfile.ZipFile(restored_zip, "r") as zf:
                self.assertIsNone(zf.testzip())
                self.assertEqual(zf.read("dados.bin"), payload)

    def test_wrong_key_and_tampering_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "foto.jpg"
            img_path.write_bytes(_make_minimal_jpg())

            zip_path = tmp_dir / "segredo.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("a.txt", "conteudo confidencial")

            out_img = tmp_dir / "foto_oculta.jpg"
            zip_crypto_img.hide_zip_in_image(img_path, zip_path, out_img, "senha-certa")

            bad_out = tmp_dir / "falha.zip"
            with self.assertRaises(zip_crypto_img.ZipCryptoImgError):
                zip_crypto_img.extract_zip_from_image(out_img, bad_out, "senha-errada")
            self.assertFalse(bad_out.exists())

            data = bytearray(out_img.read_bytes())
            data[-40] ^= 0xFF
            tampered_img = tmp_dir / "adulterada.jpg"
            tampered_img.write_bytes(bytes(data))

            with self.assertRaises(zip_crypto_img.ZipCryptoImgError):
                zip_crypto_img.extract_zip_from_image(tampered_img, bad_out, "senha-certa")
            self.assertFalse(bad_out.exists())

    def test_plain_image_without_hidden_zip_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "normal.png"
            img_path.write_bytes(_make_minimal_png())

            with self.assertRaises(zip_crypto_img.ZipCryptoImgError):
                zip_crypto_img.extract_zip_from_image(img_path, tmp_dir / "out.zip", "qualquer")

    def test_cli_hide_and_extract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            img_path = tmp_dir / "img.png"
            img_path.write_bytes(_make_minimal_png())

            zip_path = tmp_dir / "src.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("hello.txt", "world")

            out_img = tmp_dir / "hidden.png"
            out_zip = tmp_dir / "restored.zip"

            rc1 = zip_crypto_img.main(["hide", str(img_path), str(zip_path), "-o", str(out_img), "-k", "k123"])
            rc2 = zip_crypto_img.main(["extract", str(out_img), "-o", str(out_zip), "-k", "k123"])
            rc_bad = zip_crypto_img.main(["extract", str(out_img), "-o", str(tmp_dir / "no.zip"), "-k", "bad"])

            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            self.assertEqual(rc_bad, 1)
            self.assertEqual(out_zip.read_bytes(), zip_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
