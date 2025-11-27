"""
Clang Static Analyzer wrapper
"""

import subprocess
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass


try:
    from ..models.finding import Finding, Severity  
except ImportError:
    from enum import Enum

    class Severity(Enum):
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"

    class Finding:
        #Stub class for standalone usage
        pass



@dataclass
class ClangFinding:
    #Single issue reported by Clang Static Analyzer.
    file: str
    line: int
    column: int
    checker: str
    message: str
    severity: Severity
    category: str
    issue_context: str
    issue_context_kind: str


class ClangStaticAnalyzer:
    """
    Run Clang Static Analyzer with a curated set of security-oriented checkers.

    Supports:
      - Project-level analysis via scan-build
      - Single-file analysis via clang --analyze
      - Mapping Clang severities to internal Severity enum
      - Filtering to high-confidence findings
    """

    # Security & correctness oriented checkers
    SECURITY_CHECKERS = [
        # insecure APIs
        'security.insecureAPI.strcpy',
        'security.insecureAPI.DeprecatedOrUnsafeBufferHandling',
        'security.insecureAPI.getpw',
        'security.insecureAPI.gets',
        'security.insecureAPI.mkstemp',
        'security.insecureAPI.mktemp',
        'security.insecureAPI.rand',
        'security.insecureAPI.vfork',

        # unix / memory
        'unix.API',
        'unix.Malloc',
        'unix.MallocSizeof',
        'unix.MismatchedDeallocator',
        'unix.cstring.BadSizeArg',
        'unix.cstring.NullArg',

        # core correctness
        'core.CallAndMessage',
        'core.DivideZero',
        'core.NonNullParamChecker',
        'core.NullDereference',
        'core.StackAddressEscape',
        'core.UndefinedBinaryOperatorResult',
        'core.VLASize',
        'core.uninitialized.ArraySubscript',
        'core.uninitialized.Assign',
        'core.uninitialized.Branch',
        'core.uninitialized.UndefReturn',

        # alpha security / bounds
        'alpha.security.ArrayBound',
        'alpha.security.MallocOverflow',
        'alpha.security.ReturnPtrRange',
        'alpha.security.taint.TaintPropagation',
        'alpha.unix.cstring.OutOfBounds',
    ]

    
    HIGH_CONFIDENCE_CHECKERS = {
        'security.insecureAPI.strcpy',
        'security.insecureAPI.gets',
        'core.NullDereference',
        'core.StackAddressEscape',
        'unix.Malloc',
    }

    def __init__(
        self,
        clang_path: str = 'clang',
        scan_build_path: str = 'scan-build',
        default_timeout_project: int = 3600,
        default_timeout_file: int = 300,
    ) -> None:
        """
        Args:
            clang_path: Path to clang binary.
            scan_build_path: Path to scan-build wrapper.
            default_timeout_project: Timeout (seconds) for project analysis.
            default_timeout_file: Timeout (seconds) for single-file analysis.
        """
        self.clang = clang_path
        self.scan_build = scan_build_path
        self.default_timeout_project = default_timeout_project
        self.default_timeout_file = default_timeout_file

    
    # Public API
    
    def analyze_project(
        self,
        project_path: Path,
        compile_commands: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        build_cmd: Optional[List[str]] = None,
    ) -> List[ClangFinding]:
        # Analyze a C/C++ project using scan-build.

        project_path = project_path.resolve()

        if output_dir is None:
            output_dir = project_path / 'clang_analysis'

        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        if build_cmd is None:
            build_cmd = ['make', '-C', str(project_path)]
        else:
           #if provided, make a copy to avoid mutating caller's list
            build_cmd = build_cmd[:]

        # Base scan-build command
        cmd: List[str] = [
            self.scan_build,
            '-o', str(output_dir),
            '--use-analyzer', self.clang,
            '-plist-html',  # generate both HTML and plist reports
            '-analyzer-config', 'stable-report-filename=true',
        ]

        # Enable all security checkers
        for checker in self.SECURITY_CHECKERS:
            cmd.extend(['-enable-checker', checker])

        # Optional compile_commands.json (depends on scan-build version)
        if compile_commands is not None:
           
            cmd.extend(['-compdb', str(compile_commands.resolve())])

        # Attach build command
        cmd.extend(build_cmd)

        print(f"Running Clang Static Analyzer on project: {project_path}")
        print(f"Output dir: {output_dir}")
        print(f"Enabled {len(self.SECURITY_CHECKERS)} security checkers")
        print(f"Build command: {' '.join(build_cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.default_timeout_project,
            )

            if result.returncode != 0:
                print("scan-build returned non-zero exit code")
                if result.stderr:
                    print("---- scan-build stderr ----")
                    print(result.stderr.strip())
                if result.stdout:
                    print("---- scan-build stdout ----")
                    print(result.stdout.strip())

            findings = self._parse_results(output_dir)
            print(f"Clang analysis complete: {len(findings)} findings")
            return findings

        except subprocess.TimeoutExpired:
            print("Clang analysis timed out for project")
            return []
        except FileNotFoundError as e:
            print(f"Failed to run scan-build/clang (file not found): {e}")
            return []
        except Exception as e:
            print(f"Unexpected error running Clang analysis: {e}")
            return []

    def analyze_file(self, c_file: Path, extra_flags: Optional[List[str]] = None) -> List[ClangFinding]:
        # Analyze a single C file using clang --analyze.
        c_file = c_file.resolve()

        cmd: List[str] = [
            self.clang,
            '--analyze',
            '-Xanalyzer', '-analyzer-output=plist',
        ]

        # Enable checkers
        for checker in self.SECURITY_CHECKERS:
            cmd.extend(['-Xanalyzer', f'-analyzer-checker={checker}'])

        if extra_flags:
            cmd.extend(extra_flags)

        cmd.append(str(c_file))

        print(f"Running Clang Static Analyzer on file: {c_file}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.default_timeout_file,
                cwd=str(c_file.parent),
            )

            if result.returncode != 0:
                print(f"clang --analyze returned non-zero exit code for {c_file}")
                if result.stderr:
                    print("---- clang stderr ----")
                    print(result.stderr.strip())

            # By default, clang writes a plist next to the analyzed file
            plist_file = c_file.with_suffix('.plist')

            if plist_file.exists():
                findings = self._parse_plist(plist_file)
        
                try:
                    plist_file.unlink()
                except OSError:
                    
                    pass
                print(f"File analysis complete: {len(findings)} findings")
                return findings

            print("No plist report produced by clang (no findings or error).")
            return []

        except subprocess.TimeoutExpired:
            print(f"Clang analysis timed out for file: {c_file}")
            return []
        except FileNotFoundError as e:
            print(f"Failed to run clang (file not found): {e}")
            return []
        except Exception as e:
            print(f"Unexpected error analyzing {c_file}: {e}")
            return []

    def get_high_confidence_findings(self, findings: List[ClangFinding]) -> List[ClangFinding]:
        # Filter findings to only high-confidence checkers.
        return [
            f for f in findings
            if f.checker in self.HIGH_CONFIDENCE_CHECKERS
        ]

    
    # Internal helpers
   
    def _parse_results(self, output_dir: Path) -> List[ClangFinding]:
        #Parse all plist files under output_dir produced by scan-build.
        findings: List[ClangFinding] = []

        for plist_file in output_dir.rglob('*.plist'):
            findings.extend(self._parse_plist(plist_file))

        return findings

    def _parse_plist(self, plist_file: Path) -> List[ClangFinding]:
        #Parse a single plist file and extract ClangFinding objects.
        import plistlib

        try:
            with open(plist_file, 'rb') as f:
                plist_data = plistlib.load(f)

            files = plist_data.get('files', [])
            diagnostics = plist_data.get('diagnostics', [])

            results: List[ClangFinding] = []

            for diag in diagnostics:
                loc = diag.get('location', {})
                file_idx = loc.get('file')

                if isinstance(file_idx, int) and 0 <= file_idx < len(files):
                    file_path = str(Path(files[file_idx]).resolve())
                else:
                    
                    file_path = str(plist_file)

                line = int(loc.get('line', 0) or 0)
                col = int(loc.get('col', 0) or 0)

                checker = diag.get('check_name', 'unknown')
                message = diag.get('description', '')
                clang_type = diag.get('type', 'warning')

                finding = ClangFinding(
                    file=file_path,
                    line=line,
                    column=col,
                    checker=checker,
                    message=message,
                    severity=self._map_severity(clang_type),
                    category=diag.get('category', ''),
                    issue_context=diag.get('issue_context', ''),
                    issue_context_kind=diag.get('issue_context_kind', ''),
                )

                results.append(finding)

            return results

        except Exception as e:
            print(f"Error parsing plist {plist_file}: {e}")
            return []

    def _map_severity(self, clang_severity: str) -> Severity:
        # Map Clang severity strings to internal Severity enum.
        s = clang_severity.lower().strip()

        mapping = {
            'error': Severity.CRITICAL,
            'warning': Severity.HIGH,
            'note': Severity.MEDIUM,
        }

        return mapping.get(s, Severity.MEDIUM)


# Simple CLI test for single-file usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python clang_analyzer.py <c_file> [extra flags ...]")
        sys.exit(1)

    c_path = Path(sys.argv[1])
    extra = sys.argv[2:] if len(sys.argv) > 2 else None

    analyzer = ClangStaticAnalyzer()
    findings = analyzer.analyze_file(c_path, extra_flags=extra)

    print(f"\n{'=' * 60}")
    print("Clang Static Analyzer Results")
    print(f"{'=' * 60}\n")

    for f in findings:
        print(f"{f.file}:{f.line}:{f.column}")
        print(f"   Checker:  {f.checker}")
        print(f"   Severity: {f.severity.name}")
        print(f"   Message:  {f.message}")
        print()

