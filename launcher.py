from pathlib import Path
import subprocess
import sys


def main():
    project_root = Path(__file__).resolve().parent

    if getattr(sys, "frozen", False):
        project_root = Path(sys.executable).resolve().parent

    python_path = project_root / ".venv" / "Scripts" / "python.exe"

    if not python_path.exists():
        input("ERROR: .venv Python not found. Press Enter...")
        raise SystemExit(1)

    subprocess.run(
        [str(python_path), "examples/run_analysis.py"],
        cwd=project_root,
        check=True,
    )

    subprocess.run(
        [str(python_path), "-m", "soc_tool.cli.server"],
        cwd=project_root,
        check=True,
    )


if __name__ == "__main__":
    main()
