
import subprocess
import re
import json
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime


# ============================================================================
# Data Models
# ============================================================================

class ASANErrorType(Enum):
    """Types of errors detected by ASAN"""
    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"
    USE_AFTER_FREE = "heap-use-after-free"
    USE_AFTER_RETURN = "stack-use-after-return"
    USE_AFTER_SCOPE = "stack-use-after-scope"
    DOUBLE_FREE = "double-free"
    MEMORY_LEAK = "memory-leak"
    STACK_OVERFLOW = "stack-overflow"
    INITIALIZATION_ORDER = "initialization-order-fiasco"
    INVALID_FREE = "invalid-free"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Severity levels for ASAN findings"""
    CRITICAL = "CRITICAL"  # RCE, UAF, Double-free
    HIGH = "HIGH"          # Buffer overflows
    MEDIUM = "MEDIUM"      # Memory leaks
    LOW = "LOW"            # Minor issues


@dataclass
class ASANLocation:
    """Source code location of an ASAN error"""
    file: str
    line: int
    column: int
    function: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.column} in {self.function}"


@dataclass
class ASANStackFrame:
    """Single frame in ASAN stack trace"""
    frame_number: int
    address: str
    function: str
    location: Optional[ASANLocation]

    def __str__(self) -> str:
        loc_str = str(self.location) if self.location else "unknown"
        return f"#{self.frame_number} {self.address} in {self.function} ({loc_str})"


@dataclass
class ASANFinding:
    """
    Single ASAN detection

    Represents a runtime memory error detected by AddressSanitizer,
    including full context needed for analysis and remediation.
    """

    # Error classification
    error_type: ASANErrorType
    severity: Severity

    # Error details
    description: str
    error_address: Optional[str]
    access_size: Optional[int]

    # Location information
    error_location: Optional[ASANLocation]
    allocation_location: Optional[ASANLocation]
    deallocation_location: Optional[ASANLocation]

    # Context
    stack_trace: List[ASANStackFrame]
    shadow_bytes: Optional[str]  # Memory shadow dump

    # Test information
    test_input: str
    executable: str
    timestamp: str

    # Full output for debugging
    raw_output: str

    def __post_init__(self):
        """Convert enums from strings if needed"""
        if isinstance(self.error_type, str):
            try:
                self.error_type = ASANErrorType(self.error_type)
            except ValueError:
                self.error_type = ASANErrorType.UNKNOWN

        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity)
            except ValueError:
                self.severity = Severity.MEDIUM

    @property
    def is_exploitable(self) -> bool:
        """Check if this bug is potentially exploitable"""
        exploitable_types = {
            ASANErrorType.HEAP_BUFFER_OVERFLOW,
            ASANErrorType.STACK_BUFFER_OVERFLOW,
            ASANErrorType.USE_AFTER_FREE,
            ASANErrorType.DOUBLE_FREE,
            ASANErrorType.INVALID_FREE,
        }
        return self.error_type in exploitable_types

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'error_type': self.error_type.value,
            'severity': self.severity.value,
            'description': self.description,
            'error_address': self.error_address,
            'access_size': self.access_size,
            'error_location': asdict(self.error_location) if self.error_location else None,
            'allocation_location': asdict(self.allocation_location) if self.allocation_location else None,
            'deallocation_location': asdict(self.deallocation_location) if self.deallocation_location else None,
            'stack_trace': [str(frame) for frame in self.stack_trace],
            'test_input': self.test_input[:100] if len(self.test_input) > 100 else self.test_input,
            'executable': self.executable,
            'timestamp': self.timestamp,
            'exploitable': self.is_exploitable,
        }


@dataclass
class ASANStats:
    """Statistics from ASAN analysis"""
    total_executables: int
    successful_compilations: int
    failed_compilations: int
    skipped_files: int  # Server/test framework files
    total_tests_run: int
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_severity: Dict[str, int]
    exploitable_count: int
    analysis_time: float


# ============================================================================
# ASAN Analyzer
# ============================================================================

class ASANAnalyzer:
 

    # ASAN detection patterns
    ERROR_PATTERNS = {
        ASANErrorType.HEAP_BUFFER_OVERFLOW: [
            r'heap-buffer-overflow',
            r'WRITE of size \d+ at',
            r'READ of size \d+ at',
        ],
        ASANErrorType.STACK_BUFFER_OVERFLOW: [
            r'stack-buffer-overflow',
            r'Address .* is located in stack of',
        ],
        ASANErrorType.GLOBAL_BUFFER_OVERFLOW: [
            r'global-buffer-overflow',
        ],
        ASANErrorType.USE_AFTER_FREE: [
            r'heap-use-after-free',
            r'use-after-free',
        ],
        ASANErrorType.USE_AFTER_RETURN: [
            r'stack-use-after-return',
        ],
        ASANErrorType.USE_AFTER_SCOPE: [
            r'stack-use-after-scope',
        ],
        ASANErrorType.DOUBLE_FREE: [
            r'attempting double-free',
            r'double-free',
        ],
        ASANErrorType.INVALID_FREE: [
            r'attempting free on address which was not malloc',
            r'invalid-free',
        ],
        ASANErrorType.MEMORY_LEAK: [
            r'detected memory leaks',
            r'LeakSanitizer',
        ],
        ASANErrorType.STACK_OVERFLOW: [
            r'stack-overflow',
        ],
        ASANErrorType.INITIALIZATION_ORDER: [
            r'initialization-order-fiasco',
        ],
    }

    # Severity mapping
    SEVERITY_MAP = {
        ASANErrorType.HEAP_BUFFER_OVERFLOW: Severity.CRITICAL,
        ASANErrorType.USE_AFTER_FREE: Severity.CRITICAL,
        ASANErrorType.DOUBLE_FREE: Severity.CRITICAL,
        ASANErrorType.INVALID_FREE: Severity.CRITICAL,
        ASANErrorType.STACK_BUFFER_OVERFLOW: Severity.HIGH,
        ASANErrorType.GLOBAL_BUFFER_OVERFLOW: Severity.HIGH,
        ASANErrorType.USE_AFTER_RETURN: Severity.HIGH,
        ASANErrorType.USE_AFTER_SCOPE: Severity.HIGH,
        ASANErrorType.STACK_OVERFLOW: Severity.HIGH,
        ASANErrorType.INITIALIZATION_ORDER: Severity.MEDIUM,
        ASANErrorType.MEMORY_LEAK: Severity.MEDIUM,
        ASANErrorType.UNKNOWN: Severity.MEDIUM,
    }

    def __init__(
        self,
        clang_path: str = 'clang',
        clangxx_path: str = 'clang++',
        timeout: int = 30,
        max_test_inputs: int = 20,
        verbose: bool = True,
    ):
        """
        Initialize ASAN Analyzer

        Args:
            clang_path: Path to clang binary
            clangxx_path: Path to clang++ binary
            timeout: Timeout per test execution (seconds)
            max_test_inputs: Maximum number of test inputs per executable
            verbose: Print detailed progress
        """
        self.clang = clang_path
        self.clangxx = clangxx_path
        self.timeout = timeout
        self.max_test_inputs = max_test_inputs
        self.verbose = verbose

        # Verify tools exist
        if not shutil.which(self.clang):
            raise RuntimeError(f"clang not found at '{self.clang}'")
        if not shutil.which(self.clangxx):
            raise RuntimeError(f"clang++ not found at '{self.clangxx}'")

    def analyze_project(
        self,
        project_path: Path,
        compile_commands: Optional[Path] = None,
        test_inputs: Optional[List[str]] = None,
    ) -> Tuple[List[ASANFinding], ASANStats]:
        """
        Perform full ASAN analysis on a project

        Args:
            project_path: Root directory of project
            compile_commands: Path to compile_commands.json
            test_inputs: Custom test inputs (optional)

        Returns:
            Tuple of (findings, statistics)
        """

        start_time = datetime.now()

        # Handle single file input
        single_file_target = None
        if project_path.is_file():
            single_file_target = project_path
            project_path = project_path.parent
            self._log(f"Single file detected: {single_file_target.name}, using directory: {project_path}\n")

        self._log("=" * 70)
        self._log("ASAN RUNTIME ANALYSIS")
        self._log("=" * 70)
        self._log(f"Project: {project_path}\n")

        # Stage 1: Compile with ASAN
        self._log("Stage 1: Compiling with AddressSanitizer...")
        executables, compile_stats = self._compile_with_asan(
            project_path,
            compile_commands,
            single_file_target
        )

        if not executables:
            # Check if files were skipped
            if compile_stats.get('skipped_server', 0) > 0 or compile_stats.get('skipped_framework', 0) > 0:
                self._log("\n    Note: Files were found but skipped:")
                if compile_stats.get('skipped_server', 0) > 0:
                    self._log(f"      • {compile_stats['skipped_server']} server/daemon program(s) (require network testing)")
                if compile_stats.get('skipped_framework', 0) > 0:
                    self._log(f"      • {compile_stats['skipped_framework']} test framework file(s) (require framework build)")
                self._log("     Static analysis stages will still analyze these files\n")
            else:
                self._log("   No executables compiled successfully")
                self._log("   Reason: No main() functions found or compilation errors\n")

            end_time = datetime.now()
            stats = ASANStats(
                total_executables=0,
                successful_compilations=0,
                failed_compilations=compile_stats['failed'],
                skipped_files=compile_stats.get('skipped_server', 0) + compile_stats.get('skipped_framework', 0),
                total_tests_run=0,
                total_findings=0,
                findings_by_type={},
                findings_by_severity={},
                exploitable_count=0,
                analysis_time=(end_time - start_time).total_seconds(),
            )
            return [], stats

        self._log(f"   Successfully compiled {len(executables)} executable(s)\n")

        # Stage 2: Generate test inputs
        if test_inputs is None:
            test_inputs = self._generate_test_inputs()

        self._log(f"Stage 2: Running {len(executables)} executable(s) with {len(test_inputs)} test inputs...")

        # Stage 3: Run and collect findings
        all_findings = []
        total_tests = 0

        for exe_path in executables:
            self._log(f"\n   Testing: {exe_path.name}")
            findings, num_tests = self._run_with_asan(exe_path, test_inputs)
            all_findings.extend(findings)
            total_tests += num_tests

        # Deduplicate findings
        unique_findings = self._deduplicate_findings(all_findings)

        self._log(f"\n   Total tests run: {total_tests}")
        self._log(f"   Unique issues found: {len(unique_findings)}\n")

        # Calculate statistics
        end_time = datetime.now()
        stats = self._calculate_stats(
            unique_findings,
            len(executables),
            compile_stats,
            total_tests,
            (end_time - start_time).total_seconds()
        )

        return unique_findings, stats

    def _compile_with_asan(
        self,
        project_path: Path,
        compile_commands: Optional[Path],
        single_file_target: Optional[Path] = None
    ) -> Tuple[List[Path], Dict]:
        """
        Compile project with ASAN instrumentation

        Returns:
            Tuple of (executable_paths, compile_statistics)
        """

        executables = []
        stats = {'success': 0, 'failed': 0, 'skipped': 0, 'skipped_server': 0, 'skipped_framework': 0}

        # Find source files with main()
        if single_file_target:
            # Only analyze the specific file if provided
            if self._has_main_function(single_file_target, stats):
                source_files = [single_file_target]
            else:
                self._log(f"   File {single_file_target.name} does not contain main() function")
                return [], stats
        else:
            source_files = self._find_source_files_with_main(project_path, stats)

        if not source_files:
            self._log("   No source files with main() function found")
            return [], stats

        self._log(f"   Found {len(source_files)} file(s) with main() function")

        # Create output directory (handle single file case)
        if project_path.is_file():
            asan_dir = project_path.parent / '.asan_builds'
        else:
            asan_dir = project_path / '.asan_builds'
        asan_dir.mkdir(exist_ok=True)

        # Get compilation flags from compile_commands.json
        compile_flags_map = {}
        if compile_commands and compile_commands.exists():
            compile_flags_map = self._parse_compile_commands(compile_commands)

        # Compile each file
        for source_file in source_files:
            self._log(f"\n   Compiling {source_file.name}...")

            # Determine compiler
            is_cpp = source_file.suffix in ['.cpp', '.cc', '.cxx', '.C']
            compiler = self.clangxx if is_cpp else self.clang

            # Get existing flags
            existing_flags = compile_flags_map.get(source_file.resolve(), [])

            # Output executable name
            output_name = source_file.stem + '_asan'
            output_path = asan_dir / output_name
            
            # Find library sources to link (for test files)
            library_sources = []
            if 'test' in source_file.name.lower():
                library_sources = self._find_library_sources(project_path, source_file)
                if library_sources:
                    self._log(f"      Found {len(library_sources)} library file(s) to link")

            # Build command
            cmd = [
                compiler,
                str(source_file),
            ]
            
            # Add library sources
            for lib_src in library_sources:
                cmd.append(str(lib_src))
            
            cmd.extend([
                '-o', str(output_path),

                # ASAN flags
                '-fsanitize=address',
                '-fno-omit-frame-pointer',
                '-g',  # Debug symbols
                '-O1',  # Optimization for better detection

                # Additional useful sanitizers
                '-fsanitize=undefined',  # Catch undefined behavior
                '-fno-sanitize-recover=all',  # Abort on first error
            ])
            
            # Add include directories for headers
            # Add project root and common include directories
            include_dirs = set()
            if project_path.is_file():
                include_dirs.add(str(project_path.parent))
            else:
                include_dirs.add(str(project_path))
                # Add common include directories
                for inc_dir in ['include', 'inc', 'src']:
                    potential_inc = project_path / inc_dir
                    if potential_inc.exists():
                        include_dirs.add(str(potential_inc))
            
            for inc_dir in include_dirs:
                cmd.extend(['-I', inc_dir])

            # Add existing flags (exclude output-related flags)
            for flag in existing_flags:
                if flag not in ['-c', '-o'] and not flag.endswith('.o'):
                    cmd.append(flag)
            
            # Add math library (needed by many C projects)
            cmd.append('-lm')

            # Add C++ standard if needed
            if is_cpp:
                if not any('-std=' in f for f in existing_flags):
                    cmd.append('-std=c++17')

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    cwd=project_path
                )

                if result.returncode == 0 and output_path.exists():
                    # Make executable
                    output_path.chmod(0o755)
                    executables.append(output_path)
                    stats['success'] += 1
                    self._log(f"      ✓ Success: {output_name}")
                else:
                    stats['failed'] += 1
                    self._log(f"      ✗ Failed")
                    if self.verbose and result.stderr:
                        # Show first few lines of error
                        error_lines = result.stderr.split('\n')[:3]
                        for line in error_lines:
                            if line.strip():
                                self._log(f"         {line[:80]}")

            except subprocess.TimeoutExpired:
                stats['failed'] += 1
                self._log(f"      ✗ Compilation timeout")

            except Exception as e:
                stats['failed'] += 1
                self._log(f"      ✗ Error: {e}")

        return executables, stats

    def _run_with_asan(
        self,
        executable: Path,
        test_inputs: List[str]
    ) -> Tuple[List[ASANFinding], int]:
        """
        Run executable with ASAN and collect findings

        Returns:
            Tuple of (findings, num_tests_run)
        """

        findings = []
        tests_run = 0

        # Limit test inputs
        test_inputs = test_inputs[:self.max_test_inputs]

        for i, test_input in enumerate(test_inputs, 1):
            tests_run += 1

            try:
                # Set ASAN options
                env = {
                    'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=0:print_stats=0',
                    'PATH': subprocess.os.environ.get('PATH', ''),
                }

                result = subprocess.run(
                    [str(executable)],
                    input=test_input,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=env
                )

                # Check for ASAN errors
                output = result.stderr + result.stdout

                if self._has_asan_error(output):
                    # Parse error
                    finding = self._parse_asan_output(
                        output,
                        executable,
                        test_input,
                        i
                    )

                    if finding:
                        findings.append(finding)
                        self._log(f"      🔴 Test {i}/{len(test_inputs)}: {finding.error_type.value}")
                elif result.returncode != 0:
                    # Program exited with error - check if it's network-related
                    if 'connect' in output.lower() or 'connection' in output.lower() or 'socket' in output.lower():
                        if i % 5 == 0 or i == len(test_inputs):
                            self._log(f"        Tests {i-4 if i >= 5 else 1}-{i}: Network error (requires server/network setup)")
                    else:
                        if i % 5 == 0 or i == len(test_inputs):
                            self._log(f"        Tests {i-4 if i >= 5 else 1}-{i}: Program exited with error (no memory issues)")
                else:
                    # Program ran successfully
                    if i % 5 == 0 or i == len(test_inputs):
                        self._log(f"      ✓ Tests {i-4 if i >= 5 else 1}-{i}: Clean")

            except subprocess.TimeoutExpired:
                self._log(f"        Test {i}/{len(test_inputs)}: Timeout")

            except Exception as e:
                self._log(f"      ✗ Test {i}/{len(test_inputs)}: {e}")

        return findings, tests_run

    def _parse_asan_output(
        self,
        output: str,
        executable: Path,
        test_input: str,
        test_number: int
    ) -> Optional[ASANFinding]:
     

        # Detect error type
        error_type = self._detect_error_type(output)
        severity = self.SEVERITY_MAP.get(error_type, Severity.MEDIUM)

        # Extract description
        desc_match = re.search(r'ERROR: AddressSanitizer: (.+?)(\n|$)', output)
        description = desc_match.group(1).strip() if desc_match else error_type.value

        # Extract error address
        addr_match = re.search(r'on address (0x[0-9a-f]+)', output)
        error_address = addr_match.group(1) if addr_match else None

        # Extract access size
        size_match = re.search(r'(READ|WRITE) of size (\d+)', output)
        access_size = int(size_match.group(2)) if size_match else None

        # Parse stack trace
        stack_trace = self._parse_stack_trace(output)

        # Extract error location (first frame of stack trace)
        error_location = stack_trace[0].location if stack_trace else None

        # Extract allocation/deallocation locations
        allocation_location = self._extract_allocation_location(output)
        deallocation_location = self._extract_deallocation_location(output)

        # Extract shadow bytes
        shadow_match = re.search(
            r'Shadow bytes around the buggy address:(.*?)(?:=====|$)',
            output,
            re.DOTALL
        )
        shadow_bytes = shadow_match.group(1).strip() if shadow_match else None

        return ASANFinding(
            error_type=error_type,
            severity=severity,
            description=description,
            error_address=error_address,
            access_size=access_size,
            error_location=error_location,
            allocation_location=allocation_location,
            deallocation_location=deallocation_location,
            stack_trace=stack_trace,
            shadow_bytes=shadow_bytes,
            test_input=test_input,
            executable=str(executable),
            timestamp=datetime.now().isoformat(),
            raw_output=output[:5000],  # Limit size
        )

    def _parse_stack_trace(self, output: str) -> List[ASANStackFrame]:
    

        frames = []

        # Match stack frames
        frame_pattern = r'#(\d+)\s+(0x[0-9a-f]+)\s+in\s+(.+?)(?:\s+(.+?):(\d+)(?::(\d+))?)?(?:\s+\(.*?\))?$'

        for line in output.split('\n'):
            match = re.search(frame_pattern, line.strip())
            if match:
                frame_num = int(match.group(1))
                address = match.group(2)
                function = match.group(3).strip()

                location = None
                if match.group(4):  # Has file location
                    file = match.group(4)
                    line_num = int(match.group(5))
                    col_num = int(match.group(6)) if match.group(6) else 0

                    location = ASANLocation(
                        file=file,
                        line=line_num,
                        column=col_num,
                        function=function
                    )

                frame = ASANStackFrame(
                    frame_number=frame_num,
                    address=address,
                    function=function,
                    location=location
                )

                frames.append(frame)

        return frames

    def _extract_allocation_location(self, output: str) -> Optional[ASANLocation]:
        """Extract allocation location from ASAN output"""

        # Look for "allocated by thread" section
        alloc_section = re.search(
            r'allocated by thread.*?#\d+.*?in\s+(.+?)\s+(.+?):(\d+)',
            output,
            re.DOTALL
        )

        if alloc_section:
            return ASANLocation(
                file=alloc_section.group(2),
                line=int(alloc_section.group(3)),
                column=0,
                function=alloc_section.group(1)
            )

        return None

    def _extract_deallocation_location(self, output: str) -> Optional[ASANLocation]:
        """Extract deallocation location (for use-after-free)"""

        # Look for "freed by thread" section
        free_section = re.search(
            r'freed by thread.*?#\d+.*?in\s+(.+?)\s+(.+?):(\d+)',
            output,
            re.DOTALL
        )

        if free_section:
            return ASANLocation(
                file=free_section.group(2),
                line=int(free_section.group(3)),
                column=0,
                function=free_section.group(1)
            )

        return None

    def _detect_error_type(self, output: str) -> ASANErrorType:
        """Detect ASAN error type from output"""

        for error_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, output, re.IGNORECASE):
                    return error_type

        return ASANErrorType.UNKNOWN

    def _has_asan_error(self, output: str) -> bool:
        """Check if output contains ASAN error"""

        markers = [
            'AddressSanitizer',
            'ERROR: ',
            'LeakSanitizer',
        ]

        return any(marker in output for marker in markers)

    def _generate_test_inputs(self) -> List[str]:
     

        inputs = []

        # Empty/minimal
        inputs.extend([
            '',
            '0',
            '1',
            'A',
        ])

        # Small strings
        inputs.extend([
            'test',
            'hello',
            '12345',
            'abcdef',
            
        ])

        # Medium strings
        inputs.extend([
            'A' * 10,
            'B' * 50,
            'C' * 100,
        ])

        # Large strings (overflow triggers)
        inputs.extend([
            'D' * 500,
            'E' * 1000,
            'F' * 5000,
            'G' * 10000,
        ])

        # Numeric values
        inputs.extend([
            '-1',
            '-100',
            '-2147483648',  # INT_MIN
            '2147483647',   # INT_MAX
            '4294967295',   # UINT_MAX
        ])

        # Format strings (can trigger bugs)
        inputs.extend([
            '%s%s%s%s',
            '%x%x%x%x',
            '%n%n%n%n',
        ])

        # Special characters
        inputs.extend([
            '\n' * 10,
            '\x00' * 10,
            '\xff' * 10,
        ])

        return inputs

    def _find_source_files_with_main(self, project_path: Path, stats: Optional[Dict] = None) -> List[Path]:
        """
        Find all C/C++ source files containing main() function

        Uses heuristic: looks for "int main" or "void main" in file
        """
        source_files = []
        if project_path.is_file():
            if self._has_main_function(project_path, stats):
                return [project_path]
            else:
                self._log(f"   File {project_path.name} does not contain main()")
                return []
        

        # Find all C/C++ files
        for pattern in ['**/*.c', '**/*.cpp', '**/*.cc', '**/*.cxx', '**/*.C']:
            for file in project_path.glob(pattern):
                # Skip build artifacts and special directories
                relative = file.relative_to(project_path)
                if len(relative.parts) > 1:  # Has subdirectories
                    exclude_dirs = {
                        '.git', 'build', '.asan_builds',
                        'fuzzing', 'fuzz', 'fuzzer',  # Fuzzing directories
                        'unity', 'cmock',  # Test frameworks (not test files themselves)
                    }
                    # Only exclude if subdirectory (not if tests/ is the direct parent)
                    # This allows analyzing test files while skipping framework code
                    exclude_parts = [part for part in relative.parts[:-1] if part in exclude_dirs]
                    if exclude_parts:
                        continue

                # Check for main function
                if self._has_main_function(file, stats):
                    source_files.append(file)

        return source_files

    def _has_main_function(self, file_path: Path, stats: Optional[Dict] = None) -> bool:
        """Check if file contains main() function"""

        try:
            content = file_path.read_text(errors='ignore')

            # Look for main function patterns
            patterns = [
                r'\bint\s+main\s*\(',
                r'\bvoid\s+main\s*\(',
                r'\bauto\s+main\s*\(',
            ]
            
            has_main = any(re.search(pattern, content) for pattern in patterns)
            
            if not has_main:
                return False
            
            # Exclude files that use test frameworks (can't compile standalone)
            test_framework_markers = [
                '#include "unity',        # Unity test framework
                '#include <unity',
                '#include "gtest',        # Google Test
                '#include <gtest',
                '#include "catch',        # Catch2
                '#include <catch',
                '#include "doctest',      # doctest
                '#include <CUnit',        # CUnit
                'TEST_ASSERT',            # Unity macros
                'ASSERT_EQ',              # GTest macros
                'REQUIRE(',               # Catch2 macros
            ]
            
            # Skip if uses test framework
            if any(marker in content for marker in test_framework_markers):
                self._log(f"    Skipping {file_path.name}: Uses test framework (requires framework build system)")
                if stats:
                    stats['skipped_framework'] += 1
                return False
            
            # Exclude server/daemon programs (run forever, can't test with stdin)
            server_markers = [
                'listen(',               # Network server
                'bind(',                 # Socket binding
                'accept(',               # Accepting connections
                'daemon(',               # Daemonize
                'fork(',                 # Forking (often servers)
                'while(1)',              # Infinite loop
                'while (1)',
                'for(;;)',               # Infinite loop
                'for (;;)',
                'event_base_dispatch',   # libevent
                'uv_run',                # libuv event loop
            ]
            
            # Skip if it's a server program (too many markers = likely a server)
            server_count = sum(1 for marker in server_markers if marker in content)
            if server_count >= 3:  # If 3+ server indicators, skip it
                self._log(f"    Skipping {file_path.name}: Detected as server/daemon (requires network testing)")
                if stats:
                    stats['skipped_server'] += 1
                return False

            return True

        except Exception:
            return False
    
    def _find_library_sources(self, project_path: Path, test_file: Path) -> List[Path]:
        """
        Find library source files that a test file depends on
        
        Strategy:
        1. Look for .c/.cpp files in project root or src/ directory
        2. Exclude other test files
        3. Match by name patterns (e.g., for json_patch_tests.c, find cJSON*.c)
        """
        
        library_sources = []
        
        if project_path.is_file():
            project_root = project_path.parent
        else:
            project_root = project_path
        
        # Common library directories
        search_dirs = [
            project_root,
            project_root / 'src',
            project_root / 'lib',
            project_root / 'source',
        ]
        
        # Find all .c/.cpp files (excluding test files)
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
                
            for pattern in ['*.c', '*.cpp', '*.cc', '*.cxx']:
                for lib_file in search_dir.glob(pattern):
                    # Skip if it's the test file itself
                    if lib_file == test_file:
                        continue
                    
                    # Skip if it has main() (likely another executable)
                    if self._has_main_function(lib_file):
                        continue
                    
                    # Skip test files in library directories
                    if any(test_marker in lib_file.name.lower() 
                           for test_marker in ['test', 'example', 'sample', 'demo']):
                        continue
                    
                    library_sources.append(lib_file)
        
        return library_sources

    def _parse_compile_commands(self, compile_commands: Path) -> Dict[Path, List[str]]:
        """Parse compile_commands.json to extract flags for each file"""

        flags_map = {}

        try:
            with open(compile_commands) as f:
                commands = json.load(f)

            for cmd in commands:
                file_path = Path(cmd['file']).resolve()
                command = cmd.get('command', '')
                directory = Path(cmd.get('directory', ''))

                # Extract flags from command
                flags = []
                tokens = command.split()

                i = 0
                while i < len(tokens):
                    token = tokens[i]

                    # Skip compiler name
                    if token in ['clang', 'clang++', 'gcc', 'g++']:
                        i += 1
                        continue

                    # Skip input/output files
                    if token == '-c' or token == '-o':
                        i += 2  # Skip flag and argument
                        continue

                    # Skip source file
                    if token.endswith(('.c', '.cpp', '.cc', '.cxx')):
                        i += 1
                        continue

                    # Include flags
                    if token.startswith('-I'):
                        if len(token) > 2:
                            # -Ipath
                            inc_path = token[2:]
                            if not Path(inc_path).is_absolute():
                                inc_path = str(directory / inc_path)
                            flags.extend(['-I', inc_path])
                        elif i + 1 < len(tokens):
                            # -I path
                            inc_path = tokens[i + 1]
                            if not Path(inc_path).is_absolute():
                                inc_path = str(directory / inc_path)
                            flags.extend(['-I', inc_path])
                            i += 1

                    # Defines
                    elif token.startswith('-D'):
                        flags.append(token)

                    # Standards
                    elif token.startswith('-std='):
                        flags.append(token)

                    # Other important flags
                    elif token in ['-pthread', '-fPIC', '-Wall', '-Wextra']:
                        flags.append(token)

                    i += 1

                flags_map[file_path] = flags

        except Exception as e:
            self._log(f"   Warning: Could not parse compile_commands.json: {e}")

        return flags_map

    def _deduplicate_findings(self, findings: List[ASANFinding]) -> List[ASANFinding]:
        """
        Deduplicate findings based on error location

        Same error type + same location = duplicate
        """

        seen = set()
        unique = []

        for finding in findings:
            # Create key from error type and location
            if finding.error_location:
                key = (
                    finding.error_type.value,
                    finding.error_location.file,
                    finding.error_location.line,
                )
            else:
                key = (
                    finding.error_type.value,
                    finding.executable,
                    finding.description,
                )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _calculate_stats(
        self,
        findings: List[ASANFinding],
        num_executables: int,
        compile_stats: Dict,
        total_tests: int,
        analysis_time: float
    ) -> ASANStats:
        """Calculate analysis statistics"""

        # Count by type
        by_type = {}
        for finding in findings:
            type_name = finding.error_type.value
            by_type[type_name] = by_type.get(type_name, 0) + 1

        # Count by severity
        by_severity = {}
        for finding in findings:
            sev_name = finding.severity.value
            by_severity[sev_name] = by_severity.get(sev_name, 0) + 1

        # Count exploitable
        exploitable = sum(1 for f in findings if f.is_exploitable)

        return ASANStats(
            total_executables=num_executables + compile_stats['failed'],
            successful_compilations=compile_stats['success'],
            failed_compilations=compile_stats['failed'],
            skipped_files=compile_stats.get('skipped_server', 0) + compile_stats.get('skipped_framework', 0),
            total_tests_run=total_tests,
            total_findings=len(findings),
            findings_by_type=by_type,
            findings_by_severity=by_severity,
            exploitable_count=exploitable,
            analysis_time=analysis_time,
        )

    def _log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(message)

    # ========================================================================
    # Export Methods
    # ========================================================================

    def export_to_json(self, findings: List[ASANFinding], output_file: Path):
        """Export findings to JSON format"""

        data = {
            'findings': [f.to_dict() for f in findings],
            'metadata': {
                'analyzer': 'ASAN Runtime Analyzer',
                'timestamp': datetime.now().isoformat(),
                'total': len(findings),
                'exploitable': sum(1 for f in findings if f.is_exploitable),
            }
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"   Results exported to {output_file}")

    def export_to_sarif(self, findings: List[ASANFinding], output_file: Path):
        """Export to SARIF format (GitHub code scanning compatible)"""

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AddressSanitizer",
                        "version": "1.0",
                        "informationUri": "https://clang.llvm.org/docs/AddressSanitizer.html",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        # Add rules
        seen_types = set()
        for finding in findings:
            if finding.error_type.value not in seen_types:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": finding.error_type.value,
                    "name": finding.error_type.value,
                    "shortDescription": {"text": finding.error_type.value},
                    "fullDescription": {"text": f"AddressSanitizer detected {finding.error_type.value}"},
                    "defaultConfiguration": {
                        "level": "error" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "warning"
                    }
                })
                seen_types.add(finding.error_type.value)

        # Add results
        for finding in findings:
            if finding.error_location:
                sarif["runs"][0]["results"].append({
                    "ruleId": finding.error_type.value,
                    "level": "error" if finding.severity in [Severity.CRITICAL, Severity.HIGH] else "warning",
                    "message": {"text": finding.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.error_location.file},
                            "region": {
                                "startLine": finding.error_location.line,
                                "startColumn": finding.error_location.column
                            }
                        }
                    }]
                })

        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2)

        print(f"   SARIF results exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    """Command-line interface for ASAN analyzer"""

    import sys

    if len(sys.argv) < 2:
        print("""
AddressSanitizer Runtime Analyzer
==================================

Usage: python asan_analyzer.py <project_path> [compile_commands.json]

Examples:
  python asan_analyzer.py ./my_project
  python asan_analyzer.py ./my_project compile_commands.json

This tool:
  1. Compiles your C/C++ code with ASAN instrumentation
  2. Runs executables with various test inputs
  3. Detects memory corruption bugs at runtime
  4. Reports findings with detailed stack traces
        """)
        sys.exit(1)

    project = Path(sys.argv[1]).resolve()
    compile_cmds = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None

    if not project.exists():
        print(f"Error: Project path does not exist: {project}")
        sys.exit(1)

    # Run analysis
    analyzer = ASANAnalyzer(verbose=True)

    try:
        findings, stats = analyzer.analyze_project(project, compile_cmds)

        # Display results
        print(f"\n{'=' * 70}")
        print("ASAN ANALYSIS RESULTS")
        print(f"{'=' * 70}\n")

        print(f"Compilation:")
        print(f"  Total executables: {stats.total_executables}")
        print(f"  Successful: {stats.successful_compilations}")
        print(f"  Failed: {stats.failed_compilations}")

        print(f"\nTesting:")
        print(f"  Total tests run: {stats.total_tests_run}")
        print(f"  Analysis time: {stats.analysis_time:.1f}s")

        print(f"\nFindings:")
        print(f"  Total issues: {stats.total_findings}")
        print(f"  Exploitable: {stats.exploitable_count}")

        if findings:
            print(f"\nBy Severity:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = stats.findings_by_severity.get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")

            print(f"\nBy Type:")
            for error_type, count in sorted(stats.findings_by_type.items()):
                print(f"  {error_type}: {count}")

            print(f"\nDetailed Findings:\n")
            for i, finding in enumerate(findings[:10], 1):  # Show first 10
                print(f"{i}. {finding.error_type.value.upper()} [{finding.severity.value}]")
                if finding.error_location:
                    print(f"   Location: {finding.error_location}")
                print(f"   Description: {finding.description}")
                if finding.is_exploitable:
                    print(f"     Potentially exploitable")
                print()

            if len(findings) > 10:
                print(f"... and {len(findings) - 10} more findings")

            # Export results
            json_output = (project.parent if project.is_file() else project) / 'asan_results.json'
            sarif_output = (project.parent if project.is_file() else project) / 'asan_results.sarif.json'

            print(f"\nExporting results...")
            analyzer.export_to_json(findings, json_output)
            azer.export_to_sarif(findings, sarif_output)

        else:
            print("\n✓ No runtime bugs detected!")

    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        sys.exit(1)

    except Exception as e:
        print(f"\nError during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
