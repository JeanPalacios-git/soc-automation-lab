from pathlib import Path
import subprocess
import sys


def pause(message: str) -> None:
    print()
    print("=" * 60)
    print(message)
    print("=" * 60)
    print()
    input("Press Enter to exit...")


def main() -> None:
    project_root = Path(__file__).resolve().parent

    if getattr(sys, "frozen", False):
        project_root = Path(sys.executable).resolve().parent

    python_path = project_root / ".venv" / "Scripts" / "python.exe"
    analysis_script = project_root / "examples" / "run_analysis.py"

    if not python_path.exists():
        pause(
            "[ERROR] Python virtual environment was not found.\n"
            f"Expected: {python_path}"
        )
        return

    if not analysis_script.exists():
        pause(
            "[ERROR] Analysis script was not found.\n"
            f"Expected: {analysis_script}"
        )
        return

    print("=" * 60)
    print(" SOC ANALYST INTERFACE")
    print("=" * 60)
    print()
    print("[*] Connecting to Wazuh Indexer...")
    print("[*] Running SOC analysis...")
    print()

    result = subprocess.run(
        [str(python_path), str(analysis_script)],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        pause(
            "[ERROR] Wazuh Indexer unavailable.\n\n"
            "Unable to complete SOC analysis.\n"
            "Check that the Wazuh VM is running and port 9200 "
            "is reachable."
        )
        return

    if result.stdout:
        print(result.stdout.strip())

    print()
    print("[+] Analysis completed successfully.")
    print("[*] Starting analyst interface...")
    print()

    try:
        subprocess.run(
            [str(python_path), "-m", "soc_tool.cli.server"],
            cwd=project_root,
            check=True,
        )
    except subprocess.CalledProcessError:
        pause("[ERROR] Analyst interface failed to start.")


if __name__ == "__main__":
    main()
