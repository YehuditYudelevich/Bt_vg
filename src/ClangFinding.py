"""
Clang Static Analyzer wrapper with export capabilities
"""

import subprocess
import plistlib
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


# Severity enum (ideally import from models, but fallback here)
class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ClangFinding:
    """Single issue reported by Clang Static Analyzer."""
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
      - Export to JSON and SARIF formats
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
    
    VULN_RESEARCHERS_CHECKERS = [
        'alpha.core.BoolAssignment',
        'alpha.core.CastSize',
        'alpha.core.CastToStruct',
        'alpha.core.IdenticalExpr',
        'alpha.core.PointerArithm',
        'alpha.core.DynamicTypeChecker',
        'deadcode.DeadStores',
    ]

    ALL_CHECKERS = SECURITY_CHECKERS + VULN_RESEARCHERS_CHECKERS
            
    HIGH_CONFIDENCE_CHECKERS = {
        'security.insecureAPI.strcpy',
        'security.insecureAPI.gets',
        'core.NullDereference',
        'core.StackAddressEscape',
        'unix.Malloc',
        'alpha.unix.cstring.OutOfBounds',
        'alpha.security.MallocOverflow',
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

    def analyze_project(
        self,
        project_path: Path,
        compile_commands: Optional[Path] = None,
        output_dir: Optional[Path] = None,
        build_cmd: Optional[List[str]] = None,
    ) -> List[ClangFinding]:
        """Analyze a C/C++ project using scan-build."""
        
        project_path = project_path.resolve()

        if output_dir is None:
            output_dir = project_path / 'clang_analysis'

        output_dir = output_dir.resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        if build_cmd is None:
            build_cmd = ['make', '-C', str(project_path)]
        else:
            build_cmd = build_cmd[:]

        # Base scan-build command
        cmd: List[str] = [
            self.scan_build,
            '-o', str(output_dir),
            '--use-analyzer', self.clang,
            '-plist-html',
            '-analyzer-config', 'stable-report-filename=true',
        ]

        # Enable all security checkers
        for checker in self.ALL_CHECKERS:
            cmd.extend(['-enable-checker', checker])

        # Optional compile_commands.json
        if compile_commands is not None:
            cmd.extend(['-compdb', str(compile_commands.resolve())])
        else:
            import os
            os.environ['CCC_CC'] = self.clang
            print("  No compile_commands.json provided; using CCC_CC environment variable")

        cmd.extend(build_cmd)

        print(f" Running Clang Static Analyzer on project: {project_path}")
        print(f"  Output dir: {output_dir}")
        print(f"  Enabled {len(self.ALL_CHECKERS)} checkers")
        print(f"  Build command: {' '.join(build_cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.default_timeout_project,
            )

            if result.returncode != 0:
                print(" scan-build returned non-zero exit code")
                if result.stderr:
                    print("---- stderr ----")
                    print(result.stderr.strip())

            findings = self._parse_results(output_dir)
            print(f" Clang analysis complete: {len(findings)} findings")
            return findings

        except subprocess.TimeoutExpired:
            print(" Clang analysis timed out")
            return []
        except FileNotFoundError as e:
            print(f" scan-build not found: {e}")
            return []
        except Exception as e:
            print(f"Unexpected error: {e}")
            return []

    def analyze_file(
        self, 
        c_file: Path, 
        extra_flags: Optional[List[str]] = None
    ) -> List[ClangFinding]:
        """Analyze a single C file using clang --analyze."""
        
        c_file = c_file.resolve()

        cmd: List[str] = [
            self.clang,
            '--analyze',
            '-Xanalyzer', '-analyzer-output=plist',
        ]

        for checker in self.ALL_CHECKERS:
            cmd.extend(['-Xanalyzer', f'-analyzer-checker={checker}'])

        if extra_flags:
            cmd.extend(extra_flags)

        cmd.append(str(c_file))

        print(f"Analyzing file: {c_file}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.default_timeout_file,
                cwd=str(c_file.parent),
            )

            if result.returncode != 0:
                print(f" clang returned non-zero exit code")
                if result.stderr:
                    print(result.stderr.strip())

            plist_file = c_file.with_suffix('.plist')

            if plist_file.exists():
                findings = self._parse_plist(plist_file)
                try:
                    plist_file.unlink()
                except OSError:
                    pass
                
                print(f" Found {len(findings)} issues")
                return findings

            print(" No issues found")
            return []

        except subprocess.TimeoutExpired:
            print(f"Analysis timed out")
            return []
        except FileNotFoundError as e:
            print(f"clang not found: {e}")
            return []
        except Exception as e:
            print(f"Error: {e}")
            return []

    def get_high_confidence_findings(
        self, 
        findings: List[ClangFinding]
    ) -> List[ClangFinding]:
        """Filter to only high-confidence checkers."""
        return [
            f for f in findings
            if f.checker in self.HIGH_CONFIDENCE_CHECKERS
        ]

    def export_to_json(
        self, 
        findings: List[ClangFinding], 
        output_file: Path
    ) -> None:
        """Export findings to JSON format."""
        
        data = {
            'findings': [asdict(f) for f in findings],
            'metadata': {
                'analyzer': 'Clang Static Analyzer',
                'timestamp': datetime.now().isoformat(),
                'total': len(findings),
                'by_severity': {
                    'critical': sum(1 for f in findings if f.severity == Severity.CRITICAL),
                    'high': sum(1 for f in findings if f.severity == Severity.HIGH),
                    'medium': sum(1 for f in findings if f.severity == Severity.MEDIUM),
                    'low': sum(1 for f in findings if f.severity == Severity.LOW),
                }
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"Results exported to {output_file}")

    def export_to_sarif(
        self, 
        findings: List[ClangFinding], 
        output_file: Path
    ) -> None:
        """Export to SARIF format (GitHub code scanning compatible)."""
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Clang Static Analyzer",
                        "version": "1.0",
                        "informationUri": "https://clang.llvm.org/docs/ClangStaticAnalyzer.html"
                    }
                },
                "results": []
            }]
        }
        
        for f in findings:
            sarif["runs"][0]["results"].append({
                "ruleId": f.checker,
                "level": "error" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "warning",
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.column
                        }
                    }
                }]
            })
        
        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)
        
        print(f"SARIF results exported to {output_file}")

    # Internal helpers
    
    def _parse_results(self, output_dir: Path) -> List[ClangFinding]:
        """Parse all plist files in output directory."""
        findings: List[ClangFinding] = []
        
        for plist_file in output_dir.rglob('*.plist'):
            findings.extend(self._parse_plist(plist_file))
        
        # Deduplicate
        seen = set()
        unique = []
        
        for f in findings:
            key = (f.file, f.line, f.checker)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        return unique

    def _parse_plist(self, plist_file: Path) -> List[ClangFinding]:
        """Parse a single plist file."""
        
        try:
            with open(plist_file, 'rb') as f:
                plist_data = plistlib.load(f)

            if not isinstance(plist_data, dict):
                return []

            files = plist_data.get('files', [])
            diagnostics = plist_data.get('diagnostics', [])

            results: List[ClangFinding] = []

            for diag in diagnostics:
                loc = diag.get('location', {})
                file_idx = loc.get('file')

                if isinstance(file_idx, int) and 0 <= file_idx < len(files):
                    file_path = str(Path(files[file_idx]).resolve())
                else:
                    # Skip invalid entries
                    continue

                line = int(loc.get('line', 0) or 0)
                col = int(loc.get('col', 0) or 0)

                finding = ClangFinding(
                    file=file_path,
                    line=line,
                    column=col,
                    checker=diag.get('check_name', 'unknown'),
                    message=diag.get('description', ''),
                    severity=self._map_severity(diag.get('type', 'warning')),
                    category=diag.get('category', ''),
                    issue_context=diag.get('issue_context', ''),
                    issue_context_kind=diag.get('issue_context_kind', ''),
                )

                results.append(finding)

            return results

        except Exception as e:
            print(f"Error parsing {plist_file}: {e}")
            return []

    def _map_severity(self, clang_severity: str) -> Severity:
        """Map Clang severity to internal Severity enum."""
        s = clang_severity.lower().strip()

        mapping = {
            'error': Severity.CRITICAL,
            'warning': Severity.HIGH,
            'note': Severity.MEDIUM,
        }

        return mapping.get(s, Severity.MEDIUM)


# CLI test
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python clang_analyzer.py <c_file> [extra_flags...]")
        print("\nExample:")
        print("  python clang_analyzer.py vuln.c")
        print("  python clang_analyzer.py vuln.c -I/usr/include")
        sys.exit(1)

    c_path = Path(sys.argv[1])
    extra = sys.argv[2:] if len(sys.argv) > 2 else None

    analyzer = ClangStaticAnalyzer()
    findings = analyzer.analyze_file(c_path, extra_flags=extra)

    print(f"\n{'=' * 70}")
    print(" CLANG STATIC ANALYZER RESULTS")
    print(f"{'=' * 70}\n")

    if not findings:
        print(" No issues found!")
    else:
        for i, f in enumerate(findings, 1):
            print(f"Finding #{i}")
            print(f" Location: {f.file}:{f.line}:{f.column}")
            print(f" Checker:  {f.checker}")
            print(f" Severity: {f.severity.name}")
            print(f"  Message:  {f.message}")
            print()
        
        # Export to JSON
        json_path = c_path.with_suffix('.results.json')
        analyzer.export_to_json(findings, json_path)
        
        # Export to SARIF
        sarif_path = c_path.with_suffix('.sarif.json')
        analyzer.export_to_sarif(findings, sarif_path)