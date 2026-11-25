from __future__ import annotations

import argparse
import os
import sys
import zipfile
from pathlib import Path
from typing import Optional, Tuple

BINARY_EXTENSIONS = frozenset({
    ".class", ".jar", ".war", ".ear", ".aar", ".dex", ".apk", ".ipa",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".a", ".lib",
    ".pyc", ".pyo", ".pyd", ".wasm", ".bin", ".dat", ".out", ".app",
    ".msi", ".deb", ".rpm", ".dmg", ".iso", ".img",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst", ".lz4", ".cab",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".icns",
    ".tif", ".tiff", ".psd", ".ai", ".eps", ".raw", ".heic", ".avif",
    ".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".opus",
    ".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv", ".flv",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".odt", ".ods", ".odp",
    ".db", ".sqlite", ".sqlite3", ".mdb",
    ".parquet", ".avro", ".pickle", ".pkl", ".npy", ".npz", ".h5", ".hdf5",
})

IGNORED_FILENAMES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})

TEXT_CONTROL_BYTES = frozenset({7, 8, 9, 10, 12, 13, 27})

SAMPLE_SIZE = 8192


class CbzError(Exception):
    pass


def _is_valid_utf8_prefix(sample: bytes) -> bool:
    for trim in range(4):
        end = len(sample) - trim
        if end <= 0:
            break
        try:
            sample[:end].decode("utf-8", errors="strict")
            return True
        except UnicodeDecodeError:
            continue
    return False


def is_binary_file(path: Path) -> bool:
    if path.name in IGNORED_FILENAMES:
        return True
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True

    try:
        with path.open("rb") as fh:
            sample = fh.read(SAMPLE_SIZE)
    except OSError as exc:
        raise CbzError(f"Não foi possível ler o arquivo {path}: {exc}") from exc

    if not sample:
        return False

    if sample.startswith(b"\xef\xbb\xbf"):
        return not _is_valid_utf8_prefix(sample[3:])

    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        even_len = len(sample) - (len(sample) % 2)
        try:
            sample[:even_len].decode("utf-16", errors="strict")
            return False
        except UnicodeDecodeError:
            return True

    if b"\x00" in sample:
        return True

    for b in sample:
        if b < 32 and b not in TEXT_CONTROL_BYTES:
            return True
        if b == 127:
            return True

    if _is_valid_utf8_prefix(sample):
        return False

    high_bytes = sum(1 for b in sample if b >= 128)
    return (high_bytes / len(sample)) > 0.30


def _remove_empty_dirs(root: Path) -> int:
    removed = 0
    for current, dirs, files in os.walk(root, topdown=False):
        cur_path = Path(current)
        if cur_path == root:
            continue
        if cur_path.name == ".git" or ".git" in cur_path.parts:
            continue
        try:
            if not any(cur_path.iterdir()):
                cur_path.rmdir()
                removed += 1
        except OSError:
            pass
    return removed


def clean_and_zip_folder(
    folder_path: Path,
    output_zip: Optional[Path] = None,
    in_place: bool = False,
    include_git: bool = False,
    force: bool = False,
) -> Tuple[Path, int, int, int]:
    if not folder_path.exists():
        raise CbzError(f"Pasta não encontrada: {folder_path}")
    if not folder_path.is_dir():
        raise CbzError(f"O caminho informado não é uma pasta: {folder_path}")

    resolved_folder = folder_path.resolve()
    root_name = resolved_folder.name or "archive"
    out_path = (
        output_zip
        if output_zip is not None
        else resolved_folder.parent / f"{root_name}.zip"
    )

    if out_path.exists() and not force:
        raise CbzError(
            f"O arquivo .zip de destino já existe: {out_path} (use --force ou -o para outro nome)."
        )

    out_resolved = out_path.resolve()
    kept_files: list[Path] = []
    binary_files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(resolved_folder):
        if not include_git:
            dirnames[:] = sorted(d for d in dirnames if d != ".git")
        else:
            dirnames[:] = sorted(dirnames)

        cur_dir = Path(dirpath)
        for fname in sorted(filenames):
            fpath = cur_dir / fname
            if fpath.is_symlink():
                continue
            if fpath.resolve() == out_resolved:
                continue
            if is_binary_file(fpath):
                binary_files.append(fpath)
            else:
                kept_files.append(fpath)

    if in_place:
        for bfile in binary_files:
            bfile.unlink()
        _remove_empty_dirs(resolved_folder)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for kfile in kept_files:
            rel = kfile.relative_to(resolved_folder)
            arcname = f"{root_name}/{rel.as_posix()}"
            zf.write(kfile, arcname=arcname)

    total_zip_size = out_path.stat().st_size
    return out_path, len(kept_files), len(binary_files), total_zip_size


def _clean_input_path(raw: str) -> Path:
    cleaned = raw.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return Path(cleaned).expanduser()


def _run_interactive() -> int:
    print("=== CBZ (Limpar binários e compactar pasta em .zip) ===")
    folder = _clean_input_path(input("Caminho da pasta: "))
    out_raw = input("Arquivo .zip de saída (Enter para padrão): ").strip()
    out_zip = _clean_input_path(out_raw) if out_raw else None
    clean_orig = input("Remover os binários também da pasta original? (s/N): ").strip().lower()
    in_place = clean_orig in ("s", "sim", "y", "yes")

    out_path, kept, removed, size_bytes = clean_and_zip_folder(
        folder,
        output_zip=out_zip,
        in_place=in_place,
    )
    print(f"Sucesso! .zip gerado em: {out_path}")
    print(f"Arquivos incluídos (texto/código): {kept} | Binários ignorados/removidos: {removed} | Tamanho: {size_bytes} bytes")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Remove/ignora arquivos binários de uma pasta e compacta apenas texto/código em .zip.",
    )
    parser.add_argument("folder", nargs="?", type=Path, help="Caminho da pasta de entrada")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Caminho do arquivo .zip de saída")
    parser.add_argument(
        "--in-place",
        "--clean",
        action="store_true",
        dest="in_place",
        help="Apagar os arquivos binários da pasta original antes de compactar",
    )
    parser.add_argument("--include-git", action="store_true", help="Incluir arquivos de texto dentro de .git")
    parser.add_argument("-f", "--force", action="store_true", help="Sobrescrever .zip de saída se existir")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.folder is None:
            return _run_interactive()

        out_path, kept, removed, size_bytes = clean_and_zip_folder(
            args.folder,
            output_zip=args.output,
            in_place=args.in_place,
            include_git=args.include_git,
            force=args.force,
        )
        print(f"Arquivo .zip gerado em: {out_path}")
        print(f"Arquivos incluídos: {kept} | Binários filtrados: {removed} | Tamanho: {size_bytes} bytes")
        return 0
    except CbzError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperação cancelada.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
