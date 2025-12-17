import shutil
from pathlib import Path

# Get the project root (parent of backend directory)
backend_dir = Path(__file__).parent
project_root = backend_dir.parent
files_dir = backend_dir / "files"

# Create files directory if it doesn't exist
files_dir.mkdir(exist_ok=True)

# Copy PDF files
id_pdf = project_root / "ID.pdf"
akshaay_pdf = project_root / "AKSHAAY.pdf"

if id_pdf.exists():
    shutil.copy(id_pdf, files_dir / "ID.pdf")
    print(f"✅ Copied ID.pdf to {files_dir / 'ID.pdf'}")
else:
    print(f"❌ ID.pdf not found at {id_pdf}")

if akshaay_pdf.exists():
    shutil.copy(akshaay_pdf, files_dir / "AKSHAAY.pdf")
    print(f"✅ Copied AKSHAAY.pdf to {files_dir / 'AKSHAAY.pdf'}")
else:
    print(f"❌ AKSHAAY.pdf not found at {akshaay_pdf}")

