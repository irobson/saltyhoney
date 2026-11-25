from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import secrets
import struct
import sys
import zipfile
from pathlib import Path
from typing import Optional, Tuple

MAGIC = b"EZIP"
FORMAT_VERSION = 1
DEFAULT_KDF_ITERATIONS = 600_000
MIN_KDF_ITERATIONS = 100_000
MAX_KDF_ITERATIONS = 10_000_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 32
HEADER_STRUCT = struct.Struct(">4sBI16s12s")

ARMOR_BEGIN = "-----BEGIN ENCRYPTED ZIP-----"
ARMOR_END = "-----END ENCRYPTED ZIP-----"

_CHACHA_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF


class ZipCryptoError(Exception):
    pass


def _rotl32(v: int, c: int) -> int:
    return ((v << c) & _MASK32) | (v >> (32 - c))


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("A chave ChaCha20 deve ter exatamente 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("O nonce ChaCha20 deve ter exatamente 12 bytes.")
    if not (0 <= counter <= _MASK32):
        raise OverflowError("Contador de blocos ChaCha20 excedeu o limite de 32 bits.")

    k = struct.unpack("<8I", key)
    n = struct.unpack("<3I", nonce)
    state = [
        _CHACHA_CONSTANTS[0], _CHACHA_CONSTANTS[1], _CHACHA_CONSTANTS[2], _CHACHA_CONSTANTS[3],
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7],
        counter, n[0], n[1], n[2],
    ]
    x = state.copy()

    for _ in range(10):
        x[0] = (x[0] + x[4]) & _MASK32; x[12] = _rotl32(x[12] ^ x[0], 16)
        x[8] = (x[8] + x[12]) & _MASK32; x[4] = _rotl32(x[4] ^ x[8], 12)
        x[0] = (x[0] + x[4]) & _MASK32; x[12] = _rotl32(x[12] ^ x[0], 8)
        x[8] = (x[8] + x[12]) & _MASK32; x[4] = _rotl32(x[4] ^ x[8], 7)

        x[1] = (x[1] + x[5]) & _MASK32; x[13] = _rotl32(x[13] ^ x[1], 16)
        x[9] = (x[9] + x[13]) & _MASK32; x[5] = _rotl32(x[5] ^ x[9], 12)
        x[1] = (x[1] + x[5]) & _MASK32; x[13] = _rotl32(x[13] ^ x[1], 8)
        x[9] = (x[9] + x[13]) & _MASK32; x[5] = _rotl32(x[5] ^ x[9], 7)

        x[2] = (x[2] + x[6]) & _MASK32; x[14] = _rotl32(x[14] ^ x[2], 16)
        x[10] = (x[10] + x[14]) & _MASK32; x[6] = _rotl32(x[6] ^ x[10], 12)
        x[2] = (x[2] + x[6]) & _MASK32; x[14] = _rotl32(x[14] ^ x[2], 8)
        x[10] = (x[10] + x[14]) & _MASK32; x[6] = _rotl32(x[6] ^ x[10], 7)

        x[3] = (x[3] + x[7]) & _MASK32; x[15] = _rotl32(x[15] ^ x[3], 16)
        x[11] = (x[11] + x[15]) & _MASK32; x[7] = _rotl32(x[7] ^ x[11], 12)
        x[3] = (x[3] + x[7]) & _MASK32; x[15] = _rotl32(x[15] ^ x[3], 8)
        x[11] = (x[11] + x[15]) & _MASK32; x[7] = _rotl32(x[7] ^ x[11], 7)

        x[0] = (x[0] + x[5]) & _MASK32; x[15] = _rotl32(x[15] ^ x[0], 16)
        x[10] = (x[10] + x[15]) & _MASK32; x[5] = _rotl32(x[5] ^ x[10], 12)
        x[0] = (x[0] + x[5]) & _MASK32; x[15] = _rotl32(x[15] ^ x[0], 8)
        x[10] = (x[10] + x[15]) & _MASK32; x[5] = _rotl32(x[5] ^ x[10], 7)

        x[1] = (x[1] + x[6]) & _MASK32; x[12] = _rotl32(x[12] ^ x[1], 16)
        x[11] = (x[11] + x[12]) & _MASK32; x[6] = _rotl32(x[6] ^ x[11], 12)
        x[1] = (x[1] + x[6]) & _MASK32; x[12] = _rotl32(x[12] ^ x[1], 8)
        x[11] = (x[11] + x[12]) & _MASK32; x[6] = _rotl32(x[6] ^ x[11], 7)

        x[2] = (x[2] + x[7]) & _MASK32; x[13] = _rotl32(x[13] ^ x[2], 16)
        x[8] = (x[8] + x[13]) & _MASK32; x[7] = _rotl32(x[7] ^ x[8], 12)
        x[2] = (x[2] + x[7]) & _MASK32; x[13] = _rotl32(x[13] ^ x[2], 8)
        x[8] = (x[8] + x[13]) & _MASK32; x[7] = _rotl32(x[7] ^ x[8], 7)

        x[3] = (x[3] + x[4]) & _MASK32; x[14] = _rotl32(x[14] ^ x[3], 16)
        x[9] = (x[9] + x[14]) & _MASK32; x[4] = _rotl32(x[4] ^ x[9], 12)
        x[3] = (x[3] + x[4]) & _MASK32; x[14] = _rotl32(x[14] ^ x[3], 8)
        x[9] = (x[9] + x[14]) & _MASK32; x[4] = _rotl32(x[4] ^ x[9], 7)

    out = [(x[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    if not data:
        return b""

    output = bytearray()
    chunk_blocks = 1024
    offset = 0
    total = len(data)
    blk_counter = counter

    while offset < total:
        end = min(offset + chunk_blocks * 64, total)
        chunk = data[offset:end]
        needed_blocks = (len(chunk) + 63) // 64
        ks_parts = []
        for _ in range(needed_blocks):
            ks_parts.append(_chacha20_block(key, blk_counter, nonce))
            blk_counter += 1
        keystream = b"".join(ks_parts)[: len(chunk)]
        xored = int.from_bytes(chunk, "little") ^ int.from_bytes(keystream, "little")
        output.extend(xored.to_bytes(len(chunk), "little"))
        offset = end

    return bytes(output)


def _derive_keys(password: str, salt: bytes, iterations: int) -> Tuple[bytes, bytes]:
    if not password:
        raise ZipCryptoError("A chave de criptografia não pode ser vazia.")
    material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return material[:32], material[32:]


def encrypt_bytes(data: bytes, password: str, iterations: int = DEFAULT_KDF_ITERATIONS) -> str:
    if not (MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS):
        raise ZipCryptoError(
            f"Número de iterações inválido ({iterations}). "
            f"Deve estar entre {MIN_KDF_ITERATIONS} e {MAX_KDF_ITERATIONS}."
        )

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = _derive_keys(password, salt, iterations)

    ciphertext = chacha20_xor(enc_key, 1, nonce, data)
    header = HEADER_STRUCT.pack(MAGIC, FORMAT_VERSION, iterations, salt, nonce)
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()

    raw_envelope = header + ciphertext + tag
    b64 = base64.b64encode(raw_envelope).decode("ascii")
    wrapped = "\n".join(b64[i : i + 76] for i in range(0, len(b64), 76))
    return f"{ARMOR_BEGIN}\n{wrapped}\n{ARMOR_END}\n"


def _extract_armored_base64(text: str) -> bytes:
    stripped = text.strip()
    if ARMOR_BEGIN in stripped and ARMOR_END in stripped:
        start = stripped.index(ARMOR_BEGIN) + len(ARMOR_BEGIN)
        end = stripped.index(ARMOR_END, start)
        payload = stripped[start:end]
    else:
        payload = stripped

    cleaned = "".join(payload.split())
    if not cleaned:
        raise ZipCryptoError("O arquivo .txt está vazio ou não contém dados criptografados.")
    try:
        return base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        raise ZipCryptoError("O arquivo .txt não contém um bloco Base64 válido.") from exc


def decrypt_text(text: str, password: str) -> bytes:
    raw = _extract_armored_base64(text)
    min_len = HEADER_STRUCT.size + TAG_SIZE
    if len(raw) < min_len:
        raise ZipCryptoError("Arquivo corrompido ou truncado.")

    header = raw[: HEADER_STRUCT.size]
    ciphertext = raw[HEADER_STRUCT.size : -TAG_SIZE]
    tag = raw[-TAG_SIZE:]

    magic, version, iterations, salt, nonce = HEADER_STRUCT.unpack(header)
    if magic != MAGIC:
        raise ZipCryptoError("Formato inválido: este .txt não foi gerado por este script.")
    if version != FORMAT_VERSION:
        raise ZipCryptoError(f"Versão de formato não suportada: {version}.")
    if not (MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS):
        raise ZipCryptoError("Parâmetro KDF inválido no cabeçalho do arquivo.")

    enc_key, mac_key = _derive_keys(password, salt, iterations)
    expected_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ZipCryptoError("Chave de criptografia incorreta ou arquivo .txt adulterado.")

    return chacha20_xor(enc_key, 1, nonce, ciphertext)


def encrypt_zip_file(
    zip_path: Path,
    txt_path: Optional[Path],
    password: str,
    force: bool = False,
    verify_zip: bool = True,
) -> Path:
    if not zip_path.is_file():
        raise ZipCryptoError(f"Arquivo não encontrado: {zip_path}")

    if verify_zip and not zipfile.is_zipfile(zip_path):
        raise ZipCryptoError(
            f"O arquivo informado não parece ser um .zip válido: {zip_path} "
            "(use --no-verify-zip para forçar)."
        )

    out_path = txt_path if txt_path is not None else zip_path.with_suffix(".txt")
    if out_path.exists() and not force:
        raise ZipCryptoError(
            f"O arquivo de destino já existe: {out_path} (use --force ou -o para outro nome)."
        )

    raw_zip = zip_path.read_bytes()
    armored_text = encrypt_bytes(raw_zip, password)
    with out_path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(armored_text)
    return out_path


def _default_restored_zip_path(txt_path: Path) -> Path:
    if txt_path.name.lower().endswith(".zip.txt"):
        return txt_path.with_name(txt_path.name[:-4])
    return txt_path.with_suffix(".zip")


def decrypt_txt_file(
    txt_path: Path,
    zip_path: Optional[Path],
    password: str,
    force: bool = False,
) -> Path:
    if not txt_path.is_file():
        raise ZipCryptoError(f"Arquivo não encontrado: {txt_path}")

    out_path = zip_path if zip_path is not None else _default_restored_zip_path(txt_path)
    if out_path.exists() and not force:
        raise ZipCryptoError(
            f"O arquivo de destino já existe: {out_path} (use --force ou -o para outro nome)."
        )

    armored_text = txt_path.read_text(encoding="utf-8")
    restored_bytes = decrypt_text(armored_text, password)
    out_path.write_bytes(restored_bytes)
    return out_path


def _clean_input_path(raw: str) -> Path:
    cleaned = raw.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return Path(cleaned).expanduser()


def _prompt_password(confirm: bool) -> str:
    pw = getpass.getpass("Digite a chave de criptografia: ")
    if not pw:
        raise ZipCryptoError("A chave de criptografia não pode ser vazia.")
    if confirm:
        pw2 = getpass.getpass("Confirme a chave de criptografia: ")
        if pw != pw2:
            raise ZipCryptoError("As chaves digitadas não coincidem.")
    return pw


def _run_interactive() -> int:
    print("=== Zip Crypto (.zip <-> .txt criptografado) ===")
    print("1) Criptografar .zip -> .txt")
    print("2) Restaurar .txt -> .zip")
    choice = input("Escolha uma opção (1 ou 2): ").strip()

    if choice == "1":
        src = _clean_input_path(input("Caminho do arquivo .zip: "))
        dst_raw = input("Arquivo .txt de saída (Enter para padrão): ").strip()
        dst = _clean_input_path(dst_raw) if dst_raw else None
        pw = _prompt_password(confirm=True)
        out = encrypt_zip_file(src, dst, pw)
        print(f"Sucesso! Arquivo criptografado salvo em: {out}")
        return 0

    if choice == "2":
        src = _clean_input_path(input("Caminho do arquivo .txt: "))
        dst_raw = input("Arquivo .zip restaurado (Enter para padrão): ").strip()
        dst = _clean_input_path(dst_raw) if dst_raw else None
        pw = _prompt_password(confirm=False)
        out = decrypt_txt_file(src, dst, pw)
        print(f"Sucesso! Arquivo .zip restaurado em: {out}")
        return 0

    print("Opção inválida.", file=sys.stderr)
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Converte .zip para .txt criptografado e restaura para .zip com a chave.",
    )
    sub = parser.add_subparsers(dest="command")

    p_enc = sub.add_parser("encrypt", aliases=["enc", "e"], help="Criptografar .zip para .txt")
    p_enc.add_argument("input", type=Path, help="Caminho do arquivo .zip de entrada")
    p_enc.add_argument("-o", "--output", type=Path, default=None, help="Caminho do .txt de saída")
    p_enc.add_argument("-k", "--key", default=None, help="Chave de criptografia (omitir para digitar oculto)")
    p_enc.add_argument("-f", "--force", action="store_true", help="Sobrescrever arquivo de saída se existir")
    p_enc.add_argument("--no-verify-zip", action="store_true", help="Não validar assinatura .zip na entrada")

    p_dec = sub.add_parser("decrypt", aliases=["dec", "d", "restore"], help="Restaurar .txt para .zip")
    p_dec.add_argument("input", type=Path, help="Caminho do arquivo .txt criptografado")
    p_dec.add_argument("-o", "--output", type=Path, default=None, help="Caminho do .zip restaurado")
    p_dec.add_argument("-k", "--key", default=None, help="Chave de criptografia (omitir para digitar oculto)")
    p_dec.add_argument("-f", "--force", action="store_true", help="Sobrescrever arquivo de saída se existir")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command is None:
            return _run_interactive()

        if args.command in ("encrypt", "enc", "e"):
            pw = args.key if args.key is not None else _prompt_password(confirm=True)
            out = encrypt_zip_file(
                args.input,
                args.output,
                pw,
                force=args.force,
                verify_zip=not args.no_verify_zip,
            )
            print(f"Arquivo .txt criptografado gerado em: {out}")
            return 0

        if args.command in ("decrypt", "dec", "d", "restore"):
            pw = args.key if args.key is not None else _prompt_password(confirm=False)
            out = decrypt_txt_file(args.input, args.output, pw, force=args.force)
            print(f"Arquivo .zip restaurado em: {out}")
            return 0

    except ZipCryptoError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperação cancelada.", file=sys.stderr)
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
