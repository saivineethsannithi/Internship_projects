#!/usr/bin/env python3
"""
PDF Protection Tool
-------------------
A command-line tool to add password protection to PDF files using PyPDF2/pypdf.

Usage:
    python pdf_protect.py <input_pdf> <output_pdf> <password>
    python pdf_protect.py <input_pdf> <output_pdf> <user_password> --owner-password <owner_password>

Author: Inlighn Tech
"""

import sys
import os
import argparse
from pathlib import Path

try:
    from pypdf import PdfReader, PdfWriter
except ImportError:
    try:
        from PyPDF2 import PdfReader, PdfWriter
    except ImportError:
        print("Error: Neither 'pypdf' nor 'PyPDF2' is installed.")
        print("Install it with: pip install pypdf")
        sys.exit(1)


def validate_input_file(file_path: str) -> Path:
    """Validate that the input file exists and is a PDF."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: '{file_path}'")

    if not path.is_file():
        raise ValueError(f"Path is not a file: '{file_path}'")

    if path.suffix.lower() != ".pdf":
        raise ValueError(f"Input file does not have a .pdf extension: '{file_path}'")

    if path.stat().st_size == 0:
        raise ValueError(f"Input file is empty: '{file_path}'")

    return path


def validate_output_path(file_path: str) -> Path:
    """Validate that the output path is writable."""
    path = Path(file_path)

    if path.suffix.lower() != ".pdf":
        raise ValueError(f"Output file must have a .pdf extension: '{file_path}'")

    # Ensure parent directory exists
    parent = path.parent
    if not parent.exists():
        raise FileNotFoundError(f"Output directory does not exist: '{parent}'")

    if not os.access(parent, os.W_OK):
        raise PermissionError(f"No write permission for directory: '{parent}'")

    return path


def validate_password(password: str) -> None:
    """Validate password strength."""
    if not password:
        raise ValueError("Password cannot be empty.")
    if len(password) < 4:
        raise ValueError("Password must be at least 4 characters long.")


def protect_pdf(
    input_path: str,
    output_path: str,
    user_password: str,
    owner_password: str = None,
) -> dict:
    """
    Encrypt a PDF file with a password.

    Parameters
    ----------
    input_path : str
        Path to the source PDF.
    output_path : str
        Path where the encrypted PDF will be saved.
    user_password : str
        Password required to open and view the PDF.
    owner_password : str, optional
        Password for full owner permissions. Defaults to user_password.

    Returns
    -------
    dict
        A summary of the operation results.
    """
    # Validate inputs
    in_path = validate_input_file(input_path)
    out_path = validate_output_path(output_path)
    validate_password(user_password)

    if owner_password:
        validate_password(owner_password)
    else:
        owner_password = user_password  # Default owner password = user password

    # Read the input PDF
    try:
        reader = PdfReader(str(in_path))
    except Exception as e:
        raise RuntimeError(f"Failed to read PDF file: {e}")

    # Check if already encrypted
    if reader.is_encrypted:
        raise ValueError(
            f"The input PDF is already encrypted: '{input_path}'. "
            "Please decrypt it first before re-encrypting."
        )

    total_pages = len(reader.pages)
    if total_pages == 0:
        raise ValueError(f"The PDF file has no pages: '{input_path}'")

    # Build the writer and copy pages
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    # Copy metadata if available
    if reader.metadata:
        writer.add_metadata(reader.metadata)

    # Apply encryption
    writer.encrypt(user_password=user_password, owner_password=owner_password)

    # Save the encrypted PDF
    try:
        with open(str(out_path), "wb") as output_file:
            writer.write(output_file)
    except IOError as e:
        raise IOError(f"Failed to write output file: {e}")

    return {
        "input_file": str(in_path.resolve()),
        "output_file": str(out_path.resolve()),
        "pages_protected": total_pages,
        "input_size_kb": round(in_path.stat().st_size / 1024, 2),
        "output_size_kb": round(out_path.stat().st_size / 1024, 2),
    }


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="pdf_protect",
        description=(
            "PDF Protection Tool — Add password protection to any PDF file.\n"
            "Encrypts the PDF so it cannot be opened without the correct password."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic usage (user & owner share the same password):
      python pdf_protect.py report.pdf secure_report.pdf MyP@ssw0rd

  Separate user and owner passwords:
      python pdf_protect.py report.pdf secure_report.pdf ViewOnly --owner-password Admin123

  Quiet mode (no output):
      python pdf_protect.py report.pdf secure_report.pdf secret --quiet
        """,
    )

    parser.add_argument("input",  help="Path to the input PDF file.")
    parser.add_argument("output", help="Path for the output (protected) PDF file.")
    parser.add_argument("password", help="Password to protect the PDF.")
    parser.add_argument(
        "--owner-password",
        metavar="OWNER_PWD",
        default=None,
        help=(
            "Owner password granting full permissions (editing, printing, etc.). "
            "Defaults to the same as the user password if not specified."
        ),
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output messages.",
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="%(prog)s 1.0.0",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        result = protect_pdf(
            input_path=args.input,
            output_path=args.output,
            user_password=args.password,
            owner_password=args.owner_password,
        )

        if not args.quiet:
            print("\n✅  PDF successfully protected!\n")
            print(f"   Input  : {result['input_file']}  ({result['input_size_kb']} KB)")
            print(f"   Output : {result['output_file']}  ({result['output_size_kb']} KB)")
            print(f"   Pages  : {result['pages_protected']}")
            print("\n   Open the output file and enter your password to verify.\n")

    except FileNotFoundError as e:
        print(f"\n❌  File Error: {e}\n", file=sys.stderr)
        sys.exit(1)
    except PermissionError as e:
        print(f"\n❌  Permission Error: {e}\n", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\n❌  Validation Error: {e}\n", file=sys.stderr)
        sys.exit(1)
    except (RuntimeError, IOError) as e:
        print(f"\n❌  Processing Error: {e}\n", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌  Unexpected Error: {e}\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
