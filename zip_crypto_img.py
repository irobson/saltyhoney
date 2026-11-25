from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import secrets
import shutil
import struct
import sys
import zipfile
from pathlib import Path
from typing import Optional, Tuple

HEADER_MAGIC = b"ZIMG"
FOOTER_MAGIC = b"ZIMGEND1"
FORMAT_VERSION = 1
DEFAULT_KDF_ITERATIONS = 600_000
MIN_KDF_ITERATIONS = 100_000
MAX_KDF_ITERATIONS = 10_000_000
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32
PERSON = b"zip_crypto_img1\x00"

HEADER_STRUCT = struct.Struct(">4sBI16s16sQ")
FOOTER_STRUCT = struct.Struct(">8sQ")

CHUNK_SIZE = 1024 * 1024
XOR_BATCH_SIZE = 64 * 1024


class ZipCryptoImgError(Exception):
    pass


def _is_supported_image(path: Path) -> bool:
    with path.open("rb") as fh:
        head = fh.read(16)
    if len(head) < 4:
        return False
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if head.startswith(b"\xff\xd8\xff"):
        return True
    if head.startswith((b"GIF87a", b"GIF89a")):
        return True
    if head.startswith(b"BM"):
        return True
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return True
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return True
    if head.startswith(b"\x00\x00\x01\x00"):
        return True
    return False


def _derive_keys(password: str, salt: bytes, iterations: int) -> Tuple[bytes, bytes]:
    if not password:
        raise ZipCryptoImgError("A chave de criptografia não pode ser vazia.")
    material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return material[:32], material[32:]


def _blake2b_keystream(enc_key: bytes, nonce: bytes, start_counter: int, length: int) -> Tuple[bytes, int]:
    blake2b = hashlib.blake2b
    pack = struct.pack
    n_blocks = (length + 63) // 64
    parts = [
        blake2b(
            pack("<Q", start_counter + i),
            key=enc_key,
            salt=nonce,
            person=PERSON,
            digest_size=64,
        ).digest()
        for i in range(n_blocks)
    ]
    return b"".join(parts)[:length], start_counter + n_blocks


def _xor_stream_chunk(data: bytes, enc_key: bytes, nonce: bytes, counter: int) -> Tuple[bytes, int]:
    if not data:
        return b"", counter
    out = bytearray()
    offset = 0
    total = len(data)
    while offset < total:
        end = min(offset + XOR_BATCH_SIZE, total)
        piece = data[offset:end]
        ks, counter = _blake2b_keystream(enc_key, nonce, counter, len(piece))
        xored = int.from_bytes(piece, "little") ^ int.from_bytes(ks, "little")
        out.extend(xored.to_bytes(len(piece), "little"))
        offset = end
    return bytes(out), counter


def hide_zip_in_image(
    image_path: Path,
    zip_path: Path,
    output_path: Optional[Path],
    password: str,
    force: bool = False,
    verify_zip: bool = True,
    verify_image: bool = True,
    iterations: int = DEFAULT_KDF_ITERATIONS,
) -> Path:
    if not image_path.is_file():
        raise ZipCryptoImgError(f"Imagem não encontrada: {image_path}")
    if not zip_path.is_file():
        raise ZipCryptoImgError(f"Arquivo .zip não encontrado: {zip_path}")
    if verify_image and not _is_supported_image(image_path):
        raise ZipCryptoImgError(
            f"O arquivo não parece ser uma imagem válida (PNG/JPG/GIF/BMP/WEBP/TIFF/ICO): {image_path} "
            "(use --no-verify-image para forçar)."
        )
    if verify_zip and not zipfile.is_zipfile(zip_path):
        raise ZipCryptoImgError(
            f"O arquivo não parece ser um .zip válido: {zip_path} "
            "(use --no-verify-zip para forçar)."
        )
    if not (MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS):
        raise ZipCryptoImgError(
            f"Número de iterações inválido ({iterations}). "
            f"Deve estar entre {MIN_KDF_ITERATIONS} e {MAX_KDF_ITERATIONS}."
        )

    out_path = (
        output_path
        if output_path is not None
        else image_path.with_name(f"{image_path.stem}_oculto{image_path.suffix}")
    )

    if out_path.resolve() in (image_path.resolve(), zip_path.resolve()):
        raise ZipCryptoImgError("O arquivo de saída deve ser diferente dos arquivos de entrada.")
    if out_path.exists() and not force:
        raise ZipCryptoImgError(
            f"O arquivo de saída já existe: {out_path} (use --force ou -o para outro nome)."
        )

    payload_len = zip_path.stat().st_size
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(password, salt, iterations)

    header = HEADER_STRUCT.pack(
        HEADER_MAGIC,
        FORMAT_VERSION,
        iterations,
        salt,
        nonce,
        payload_len,
    )
    mac = hmac.new(mac_key, header, hashlib.sha256)

    tmp_path = out_path.with_name(f".{out_path.name}.{secrets.token_hex(6)}.tmp")
    try:
        with tmp_path.open("wb") as dst:
            with image_path.open("rb") as img_src:
                shutil.copyfileobj(img_src, dst, length=CHUNK_SIZE)

            dst.write(header)

            counter = 0
            with zip_path.open("rb") as zip_src:
                while True:
                    chunk = zip_src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    cipher_chunk, counter = _xor_stream_chunk(chunk, enc_key, nonce, counter)
                    mac.update(cipher_chunk)
                    dst.write(cipher_chunk)

            tag = mac.digest()
            dst.write(tag)

            total_blob_len = HEADER_STRUCT.size + payload_len + TAG_SIZE + FOOTER_STRUCT.size
            footer = FOOTER_STRUCT.pack(FOOTER_MAGIC, total_blob_len)
            dst.write(footer)

        tmp_path.replace(out_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    return out_path


def extract_zip_from_image(
    image_path: Path,
    output_zip_path: Optional[Path],
    password: str,
    force: bool = False,
) -> Path:
    if not image_path.is_file():
        raise ZipCryptoImgError(f"Imagem não encontrada: {image_path}")

    out_path = (
        output_zip_path
        if output_zip_path is not None
        else image_path.with_suffix(".zip")
    )

    if out_path.resolve() == image_path.resolve():
        raise ZipCryptoImgError("O arquivo .zip de saída deve ser diferente da imagem de entrada.")
    if out_path.exists() and not force:
        raise ZipCryptoImgError(
            f"O arquivo de saída já existe: {out_path} (use --force ou -o para outro nome)."
        )

    file_size = image_path.stat().st_size
    min_blob_len = HEADER_STRUCT.size + TAG_SIZE + FOOTER_STRUCT.size
    if file_size < min_blob_len:
        raise ZipCryptoImgError("Esta imagem não contém um arquivo criptografado oculto.")

    with image_path.open("rb") as src:
        src.seek(file_size - FOOTER_STRUCT.size)
        footer_bytes = src.read(FOOTER_STRUCT.size)
        footer_magic, total_blob_len = FOOTER_STRUCT.unpack(footer_bytes)

        if footer_magic != FOOTER_MAGIC:
            raise ZipCryptoImgError("Esta imagem não contém um arquivo criptografado oculto.")
        if total_blob_len < min_blob_len or total_blob_len > file_size:
            raise ZipCryptoImgError("Metadados ocultos corrompidos ou inválidos.")

        blob_start = file_size - total_blob_len
        src.seek(blob_start)
        header = src.read(HEADER_STRUCT.size)
        magic, version, iterations, salt, nonce, payload_len = HEADER_STRUCT.unpack(header)

        if magic != HEADER_MAGIC:
            raise ZipCryptoImgError("Cabeçalho oculto inválido.")
        if version != FORMAT_VERSION:
            raise ZipCryptoImgError(f"Versão de formato não suportada: {version}.")
        if not (MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS):
            raise ZipCryptoImgError("Parâmetro KDF inválido no cabeçalho oculto.")
        expected_total = HEADER_STRUCT.size + payload_len + TAG_SIZE + FOOTER_STRUCT.size
        if total_blob_len != expected_total:
            raise ZipCryptoImgError("Tamanho do bloco criptografado inconsistente.")

        enc_key, mac_key = _derive_keys(password, salt, iterations)

        mac = hmac.new(mac_key, header, hashlib.sha256)
        ciphertext_start = blob_start + HEADER_STRUCT.size
        remaining = payload_len
        src.seek(ciphertext_start)
        while remaining > 0:
            to_read = min(CHUNK_SIZE, remaining)
            chunk = src.read(to_read)
            if len(chunk) != to_read:
                raise ZipCryptoImgError("Imagem truncada durante leitura dos dados criptografados.")
            mac.update(chunk)
            remaining -= to_read

        tag = src.read(TAG_SIZE)
        if len(tag) != TAG_SIZE:
            raise ZipCryptoImgError("Tag de autenticação truncada.")

        if not hmac.compare_digest(tag, mac.digest()):
            raise ZipCryptoImgError("Chave de criptografia incorreta ou imagem adulterada.")

        tmp_path = out_path.with_name(f".{out_path.name}.{secrets.token_hex(6)}.tmp")
        try:
            src.seek(ciphertext_start)
            remaining = payload_len
            counter = 0
            with tmp_path.open("wb") as dst:
                while remaining > 0:
                    to_read = min(CHUNK_SIZE, remaining)
                    chunk = src.read(to_read)
                    plain_chunk, counter = _xor_stream_chunk(chunk, enc_key, nonce, counter)
                    dst.write(plain_chunk)
                    remaining -= to_read
            tmp_path.replace(out_path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    return out_path


def _clean_input_path(raw: str) -> Path:
    cleaned = raw.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return Path(cleaned).expanduser()


def _prompt_password(confirm: bool) -> str:
    pw = getpass.getpass("Digite a chave de criptografia: ")
    if not pw:
        raise ZipCryptoImgError("A chave de criptografia não pode ser vazia.")
    if confirm:
        pw2 = getpass.getpass("Confirme a chave de criptografia: ")
        if pw != pw2:
            raise ZipCryptoImgError("As chaves digitadas não coincidem.")
    return pw


def _run_interactive() -> int:
    print("=== Zip Crypto Img (Imagem + .zip -> Imagem com .zip oculto) ===")
    print("1) Esconder .zip criptografado dentro de uma imagem")
    print("2) Extrair/restaurar .zip de uma imagem")
    choice = input("Escolha uma opção (1 ou 2): ").strip()

    if choice == "1":
        img = _clean_input_path(input("Caminho da imagem: "))
        zp = _clean_input_path(input("Caminho do arquivo .zip: "))
        dst_raw = input("Caminho da nova imagem de saída (Enter para padrão): ").strip()
        dst = _clean_input_path(dst_raw) if dst_raw else None
        pw = _prompt_password(confirm=True)
        out = hide_zip_in_image(img, zp, dst, pw)
        print(f"Sucesso! Imagem com .zip criptografado salva em: {out}")
        return 0

    if choice == "2":
        img = _clean_input_path(input("Caminho da imagem com .zip oculto: "))
        dst_raw = input("Caminho do .zip restaurado (Enter para padrão): ").strip()
        dst = _clean_input_path(dst_raw) if dst_raw else None
        pw = _prompt_password(confirm=False)
        out = extract_zip_from_image(img, dst, pw)
        print(f"Sucesso! Arquivo .zip restaurado em: {out}")
        return 0

    print("Opção inválida.", file=sys.stderr)
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Esconde um .zip criptografado dentro de uma imagem e restaura o .zip com a chave.",
    )
    sub = parser.add_subparsers(dest="command")

    p_hide = sub.add_parser(
        "hide",
        aliases=["encrypt", "enc", "e", "h"],
        help="Esconder .zip criptografado dentro de uma imagem",
    )
    p_hide.add_argument("image", type=Path, help="Caminho da imagem de entrada")
    p_hide.add_argument("zip", type=Path, help="Caminho do arquivo .zip de entrada")
    p_hide.add_argument("-o", "--output", type=Path, default=None, help="Caminho da imagem de saída")
    p_hide.add_argument("-k", "--key", default=None, help="Chave de criptografia (omitir para digitar oculto)")
    p_hide.add_argument("-f", "--force", action="store_true", help="Sobrescrever arquivo de saída se existir")
    p_hide.add_argument("--no-verify-zip", action="store_true", help="Não validar assinatura .zip na entrada")
    p_hide.add_argument("--no-verify-image", action="store_true", help="Não validar assinatura da imagem")

    p_ext = sub.add_parser(
        "extract",
        aliases=["decrypt", "dec", "d", "restore", "x"],
        help="Extrair e restaurar .zip de uma imagem",
    )
    p_ext.add_argument("image", type=Path, help="Caminho da imagem com o .zip oculto")
    p_ext.add_argument("-o", "--output", type=Path, default=None, help="Caminho do .zip restaurado")
    p_ext.add_argument("-k", "--key", default=None, help="Chave de criptografia (omitir para digitar oculto)")
    p_ext.add_argument("-f", "--force", action="store_true", help="Sobrescrever arquivo de saída se existir")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command is None:
            return _run_interactive()

        if args.command in ("hide", "encrypt", "enc", "e", "h"):
            pw = args.key if args.key is not None else _prompt_password(confirm=True)
            out = hide_zip_in_image(
                args.image,
                args.zip,
                args.output,
                pw,
                force=args.force,
                verify_zip=not args.no_verify_zip,
                verify_image=not args.no_verify_image,
            )
            print(f"Imagem gerada com .zip oculto em: {out}")
            return 0

        if args.command in ("extract", "decrypt", "dec", "d", "restore", "x"):
            pw = args.key if args.key is not None else _prompt_password(confirm=False)
            out = extract_zip_from_image(args.image, args.output, pw, force=args.force)
            print(f"Arquivo .zip restaurado em: {out}")
            return 0

    except ZipCryptoImgError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperação cancelada.", file=sys.stderr)
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
