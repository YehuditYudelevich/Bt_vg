
import subprocess
import re
import shutil
from pathlib import Path
from typing import Optional, Tuple, List
from urllib.parse import urlparse
import tempfile


class InputProcessor:
    """
    Process different input types:
    1. Single C file
    2. Local project directory
    3. GitHub repository URL
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.temp_dirs = []  # Track for cleanup

    def process_input(self, input_path: str) -> Tuple[Path, Path]:
        """
        Process input and return (project_path, compile_commands_path)

        Args:
            input_path: Can be:
                - /path/to/file.c
                - /path/to/project
                - https://github.com/user/repo

        Returns:
            (project_path, compile_commands.json path)
        """

        # Check if it's a URL
        if self._is_github_url(input_path):
            return self._process_github_repo(input_path)

        # Check if it's a local path
        path = Path(input_path).resolve()

        if not path.exists():
            raise ValueError(f"Path does not exist: {input_path}")

        # Single file?
        if path.is_file():
            return self._process_single_file(path)

        # Directory (project)?
        if path.is_dir():
            return self._process_project(path)

        raise ValueError(f"Unknown input type: {input_path}")

    def cleanup(self):
        """Clean up temporary directories"""
        for temp_dir in self.temp_dirs:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    # ========================================================================
    # GitHub Repository Processing
    # ========================================================================

    def _is_github_url(self, input_str: str) -> bool:
        """Check if input is a GitHub URL"""

        github_patterns = [
            r'https?://github\.com/[\w\-]+/[\w\-]+',
            r'git@github\.com:[\w\-]+/[\w\-]+\.git',
        ]

        return any(re.match(pattern, input_str) for pattern in github_patterns)

    def _process_github_repo(self, url: str) -> Tuple[Path, Path]:
        """
        Clone GitHub repo and build it

        Steps:
        1. Clone to temp directory
        2. Detect build system
        3. Build with compile_commands.json
        4. Return paths
        """

        self._log("Processing GitHub repository...")
        self._log(f"   URL: {url}")

        # Create persistent directory for downloaded repos
        repo_root = Path("downloaded_repos")
        repo_root.mkdir(exist_ok=True)

        # Clone repository
        repo_dir = self._clone_repo(url, repo_root)

        # Detect and run build system
        compile_commands = self._auto_build(repo_dir)

        return repo_dir, compile_commands

    def _clone_repo(self, url: str, repo_root: Path) -> Path:
        """Clone GitHub repository"""

        self._log("   Cloning repository...")

        # Extract repo name from URL
        repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
        repo_dir = repo_root / repo_name

        # If directory already exists, remove it to clone fresh
        if repo_dir.exists():
            self._log(f"   Directory {repo_dir} already exists, removing...")
            shutil.rmtree(repo_dir)

        try:
            # Clone with depth=1 for speed
            cmd = ['git', 'clone', '--depth=1', url, str(repo_dir)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )

            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr}")

            self._log(f"   Cloned to {repo_dir}")
            return repo_dir

        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out (5 minutes)")
        except FileNotFoundError:
            raise RuntimeError("git not found - please install git")

    # ========================================================================
    # Single File Processing
    # ========================================================================

    def _process_single_file(self, file_path: Path) -> Tuple[Path, Path]:
        """
        Process a single C/C++ file

        Creates a minimal compile_commands.json for it
        """

        self._log(f"Processing single file: {file_path}")

        # Validate it's a C/C++ file
        if file_path.suffix not in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
            raise ValueError(f"Not a C/C++ file: {file_path}")

        # Create compile_commands.json in same directory
        project_dir = file_path.parent
        compile_commands = project_dir / 'compile_commands.json'

        self._create_single_file_compile_commands(file_path, compile_commands)

        self._log(f"    Created {compile_commands}")

        return project_dir, compile_commands

    def _create_single_file_compile_commands(
        self,
        file_path: Path,
        output_path: Path
    ):
        """Create compile_commands.json for a single file"""

        import json

        compile_command = {
            "directory": str(file_path.parent.resolve()),
            "command": f"clang -c {file_path.name} -o {file_path.stem}.o",
            "file": str(file_path.resolve())
        }

        with open(output_path, 'w') as f:
            json.dump([compile_command], f, indent=2)

    # ========================================================================
    # Project Processing
    # ========================================================================

    def _process_project(self, project_path: Path) -> Tuple[Path, Path]:
        """
        Process a project directory

        Steps:
        1. Look for existing compile_commands.json
        2. If not found, detect build system
        3. Generate compile_commands.json
        """

        self._log(f"Processing project: {project_path}")

        # Check for existing compile_commands.json
        existing = project_path / 'compile_commands.json'
        if existing.exists():
            self._log(f"   Found existing {existing}")
            return project_path, existing

        # Not found - try to build it
        self._log("   compile_commands.json not found, attempting to generate...")

        compile_commands = self._auto_build(project_path)

        return project_path, compile_commands

    # ========================================================================
    # Auto Build System Detection & Execution
    # ========================================================================

    def _auto_build(self, project_path: Path) -> Path:
        """
        Automatically detect build system and generate compile_commands.json

        Supports:
        - CMake
        - Makefile
        - Autotools (./configure)
        - Bear (fallback for any build system)
        - Manual (scan for .c files)
        """

        self._log("   Detecting build system...")

        # Try CMake
        if (project_path / 'CMakeLists.txt').exists():
            return self._build_with_cmake(project_path)

        # Try Makefile
        if (project_path / 'Makefile').exists() or (project_path / 'makefile').exists():
            return self._build_with_make(project_path)

        # Try Autotools
        if (project_path / 'configure').exists() or (project_path / 'configure.ac').exists():
            return self._build_with_autotools(project_path)

        # Fallback: scan for C files
        return self._build_manual(project_path)

    def _build_with_cmake(self, project_path: Path) -> Path:
        """Build with CMake"""

        self._log("   Detected CMake")

        build_dir = project_path / 'build'
        build_dir.mkdir(exist_ok=True)

        try:
            # Configure with compile_commands.json generation
            self._log("   Running cmake...")

            result = subprocess.run(
                [
                    'cmake',
                    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                    '-S', str(project_path),
                    '-B', str(build_dir)
                ],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                raise RuntimeError(f"CMake failed: {result.stderr}")

            compile_commands = build_dir / 'compile_commands.json'

            if not compile_commands.exists():
                raise RuntimeError("CMake didn't generate compile_commands.json")

            # Copy to project root for convenience
            shutil.copy(compile_commands, project_path / 'compile_commands.json')

            self._log(f"   Generated {compile_commands}")
            return compile_commands

        except FileNotFoundError:
            raise RuntimeError("cmake not found - please install cmake")
        except subprocess.TimeoutExpired:
            raise RuntimeError("CMake timed out")

    def _build_with_make(self, project_path: Path) -> Path:
        """Build with Make + Bear"""

        self._log("   Detected Makefile")

        # Check if bear is available
        if not shutil.which('bear'):
            self._log("   WARNING: bear not found, trying manual scan...")
            return self._build_manual(project_path)

        try:
            self._log("   Running bear -- make...")

            # Clean first
            subprocess.run(
                ['make', 'clean'],
                cwd=project_path,
                capture_output=True,
                timeout=60
            )

            # Build with bear
            result = subprocess.run(
                ['bear', '--', 'make'],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300
            )

            compile_commands = project_path / 'compile_commands.json'

            if not compile_commands.exists():
                raise RuntimeError("bear didn't generate compile_commands.json")

            self._log(f"   Generated {compile_commands}")
            return compile_commands

        except subprocess.TimeoutExpired:
            raise RuntimeError("make timed out")

    def _build_with_autotools(self, project_path: Path) -> Path:
        """Build with Autotools + Bear"""

        self._log("   Detected Autotools")

        # Check for bear
        if not shutil.which('bear'):
            raise RuntimeError("bear required for autotools - install with: apt-get install bear")

        try:
            # Run configure if needed
            if not (project_path / 'Makefile').exists():
                self._log("   Running ./configure...")

                result = subprocess.run(
                    ['./configure'],
                    cwd=project_path,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                if result.returncode != 0:
                    raise RuntimeError(f"configure failed: {result.stderr}")

            # Build with bear
            self._log("   Running bear -- make...")

            result = subprocess.run(
                ['bear', '--', 'make'],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=300
            )

            compile_commands = project_path / 'compile_commands.json'

            if not compile_commands.exists():
                raise RuntimeError("build failed to generate compile_commands.json")

            self._log(f"   Generated {compile_commands}")
            return compile_commands

        except subprocess.TimeoutExpired:
            raise RuntimeError("build timed out")

    def _build_manual(self, project_path: Path) -> Path:
        """
        Manual fallback: scan for C files and create compile_commands.json
        """

        self._log("   Manual mode: scanning for C/C++ files...")

        # Find all C/C++ files
        c_files = []
        for pattern in ['**/*.c', '**/*.cpp', '**/*.cc', '**/*.cxx']:
            c_files.extend(project_path.glob(pattern))

        # Exclude common non-source directories
        exclude_dirs = {'build', 'test', 'tests', 'examples', 'samples', '.git'}
        c_files = [
            f for f in c_files
            if not any(excluded in f.parts for excluded in exclude_dirs)
        ]

        if not c_files:
            raise RuntimeError("No C/C++ files found in project")

        self._log(f"   Found {len(c_files)} C/C++ files")

        # Create compile_commands.json
        import json

        commands = []
        for c_file in c_files:
            commands.append({
                "directory": str(project_path.resolve()),
                "command": f"clang -c {c_file.name} -o {c_file.stem}.o",
                "file": str(c_file.resolve())
            })

        compile_commands = project_path / 'compile_commands.json'

        with open(compile_commands, 'w') as f:
            json.dump(commands, f, indent=2)

        self._log(f"   Created {compile_commands}")
        return compile_commands

    # ========================================================================
    # Utilities
    # ========================================================================

    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(message)


# ============================================================================
# CLI Integration
# ============================================================================

def smart_scan(input_path: str, **kwargs):
    """
    Smart scan that handles any input type

    Usage:
        smart_scan('/path/to/file.c')
        smart_scan('/path/to/project')
        smart_scan('https://github.com/user/repo')
    """

    processor = InputProcessor()

    try:
        # Process input
        project_path, compile_commands = processor.process_input(input_path)

        print(f"\n{'='*70}")
        print("STARTING VULNERABILITY SCAN")
        print(f"{'='*70}")
        print(f"Project: {project_path}")
        print(f"Compile commands: {compile_commands}")
        print()

        # Run analysis
        from .scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner(**kwargs)
        vulnerabilities, stats = scanner.scan(project_path)

        return vulnerabilities, stats

    finally:
        # Cleanup temp directories
        processor.cleanup()


# ============================================================================
# Example usage
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("""
Usage: python input_processor.py <input>

Examples:
  python input_processor.py file.c
  python input_processor.py ./my_project
  python input_processor.py https://github.com/DaveGamble/cJSON
        """)
        sys.exit(1)

    input_arg = sys.argv[1]

    processor = InputProcessor()

    try:
        project_path, compile_commands = processor.process_input(input_arg)

        print(f"\nSUCCESS")
        print(f"Project path: {project_path}")
        print(f"Compile commands: {compile_commands}")

    except Exception as e:
        print(f"\n ERROR: {e}")
        sys.exit(1)

    finally:
        print("yehudit the queen of the world")
        #processor.cleanup() not for now
