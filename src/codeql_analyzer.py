"""
CodeQL Static Analysis Integration
===================================

Integrates CodeQL CLI for automated security analysis of C/C++ codebases.

Features:
- Automatic database creation from local files, projects, or GitHub repos
- Support for security-extended and security-and-quality query packs
- SARIF output generation
- Git repository cloning and caching
- Comprehensive error handling

Author: Yehudit
Version: 1.0
"""

import subprocess
import re
import shutil
import json
import glob as glob_module
from pathlib import Path
from typing import Optional, Dict, Tuple, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CodeQLResult:
    """Result of CodeQL analysis"""
    success: bool
    sarif_path: Optional[str] = None
    json_path: Optional[str] = None
    db_path: Optional[str] = None
    repo_path: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None
    analysis_time: float = 0.0
    findings_count: int = 0


class CodeQLAnalyzer:
    """
    CodeQL static analysis wrapper
    
    Handles database creation, analysis, and result generation for C/C++ projects.
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize CodeQL analyzer
        
        Args:
            verbose: Enable detailed logging
        """
        self.verbose = verbose
        
    def _log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(message)
    
    def ensure_codeql_available(self) -> Tuple[bool, str]:
        """
        Check if CodeQL CLI is installed and available
        
        Returns:
            Tuple of (is_available, version_or_error)
        """
        try:
            result = subprocess.run(
                ["codeql", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                return True, version
            else:
                return False, f"CodeQL command failed: {result.stderr}"
                
        except FileNotFoundError:
            return False, "CodeQL CLI not found in PATH. Please install from https://github.com/github/codeql-cli-binaries"
        except subprocess.TimeoutExpired:
            return False, "CodeQL version check timed out"
        except Exception as e:
            return False, f"Error checking CodeQL: {str(e)}"
    
    def _find_codeql_workflow_files(self, repo_path: Path) -> List[Path]:
        """
        Find GitHub Actions CodeQL workflow files
        
        Args:
            repo_path: Repository root path
            
        Returns:
            List of workflow files containing CodeQL action
        """
        workflow_files = []
        workflows_dir = repo_path / ".github" / "workflows"
        
        if not workflows_dir.exists():
            return workflow_files
        
        # Search for .yml and .yaml files
        for pattern in ["*.yml", "*.yaml"]:
            for workflow_file in workflows_dir.glob(pattern):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Check if it contains CodeQL action
                        if 'github/codeql-action/init' in content:
                            workflow_files.append(workflow_file)
                            self._log(f"   Found CodeQL workflow: {workflow_file.name}")
                except Exception as e:
                    self._log(f"   Warning: Could not read {workflow_file.name}: {e}")
        
        return workflow_files
    
    def _extract_linux_build_recipes_from_workflow(self, workflow_path: Path) -> List[str]:
        """
        Extract Linux build commands from GitHub Actions workflow
        
        Uses heuristic parsing to find build steps and extract commands.
        Only keeps Linux-compatible commands (filters out Windows-specific blocks).
        
        Args:
            workflow_path: Path to workflow YAML file
            
        Returns:
            List of build command strings (joined with &&)
        """
        recipes = []
        
        try:
            with open(workflow_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Heuristic: Find 'run:' blocks that contain build commands
            # This is a simple line-based parser (not full YAML parsing)
            lines = content.split('\n')
            in_run_block = False
            in_windows_block = False
            current_commands = []
            indent_level = 0
            
            for i, line in enumerate(lines):
                stripped = line.strip()
                
                # Skip Windows-specific sections (heuristic detection)
                if any(marker in line.lower() for marker in [
                    'windows', 'win32', 'msvc', 'cmd.exe', 'powershell',
                    'platform == \'windows\'', 'runner.os == \'windows\'',
                    'matrix.os == \'windows', '.exe'
                ]):
                    in_windows_block = True
                    continue
                
                # Reset Windows block on new step or job
                if stripped.startswith('- name:') or stripped.startswith('jobs:'):
                    in_windows_block = False
                
                if in_windows_block:
                    continue
                
                # Detect run: block start
                if stripped.startswith('run:'):
                    in_run_block = True
                    indent_level = len(line) - len(line.lstrip())
                    
                    # Inline command: run: echo "hello"
                    if len(stripped) > 5:
                        cmd = stripped[4:].strip()
                        if self._is_build_command(cmd):
                            current_commands.append(cmd)
                    continue
                
                # Collect multi-line run block
                if in_run_block:
                    current_indent = len(line) - len(line.lstrip())
                    
                    # End of run block (dedent or new key)
                    if stripped and current_indent <= indent_level and ':' in stripped:
                        if current_commands:
                            # Join commands and add to recipes
                            recipe = ' && '.join(current_commands)
                            # Wrap in bash -c if it contains shell operators
                            if '&&' in recipe or '||' in recipe or ';' in recipe:
                                recipe = f"bash -c '{recipe}'"
                            recipes.append(recipe)
                            current_commands = []
                        in_run_block = False
                    elif stripped and not stripped.startswith('#'):
                        # Remove common YAML multi-line indicators
                        cmd = stripped.lstrip('|-').strip()
                        if cmd and self._is_build_command(cmd):
                            current_commands.append(cmd)
            
            # Add remaining commands
            if current_commands:
                recipe = ' && '.join(current_commands)
                # Wrap in bash -c if it contains shell operators
                if '&&' in recipe or '||' in recipe or ';' in recipe:
                    recipe = f"bash -c '{recipe}'"
                recipes.append(recipe)
            
            self._log(f"   Extracted {len(recipes)} build recipe(s) from workflow")
            for idx, recipe in enumerate(recipes, 1):
                preview = recipe[:80] + '...' if len(recipe) > 80 else recipe
                self._log(f"     Recipe {idx}: {preview}")
            
        except Exception as e:
            self._log(f"   Warning: Failed to parse workflow {workflow_path.name}: {e}")
        
        return recipes
    
    def _is_build_command(self, cmd: str) -> bool:
        """
        Check if command looks like a build command
        
        Args:
            cmd: Command string
            
        Returns:
            True if it looks like a build command
        """
        build_keywords = ['cmake', 'make', 'ninja', 'gcc', 'g++', 'clang', 'configure', 'build', 'autogen']
        cmd_lower = cmd.lower()
        return any(keyword in cmd_lower for keyword in build_keywords)
    
    def _choose_build_recipes(self, recipes: List[str], build_mode: str) -> List[str]:
        """
        Choose build recipes based on build mode
        
        Args:
            recipes: Available build recipes
            build_mode: 'fast' or 'coverage'
            
        Returns:
            Selected recipes
        """
        if not recipes:
            return []
        
        if build_mode == "fast":
            # Use only the first recipe
            return [recipes[0]]
        elif build_mode == "coverage":
            # Use up to 3 recipes for broader coverage
            return recipes[:3]
        else:
            self._log(f"   Warning: Unknown build_mode '{build_mode}', using 'fast'")
            return [recipes[0]]
    
    def _detect_ninja(self) -> bool:
        """
        Check if Ninja build system is available
        
        Returns:
            True if ninja is in PATH
        """
        try:
            result = subprocess.run(
                ["ninja", "--version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def is_git_url(self, s: str) -> bool:
        """
        Detect if string is a Git URL
        
        Args:
            s: String to check
            
        Returns:
            True if it looks like a Git URL
        """
        s = s.strip()
        return (
            s.startswith('http://') or
            s.startswith('https://') or
            s.startswith('git@') or
            s.endswith('.git')
        )
    
    def _extract_repo_name(self, url: str) -> str:
        """
        Extract repository name from Git URL
        
        Args:
            url: Git URL
            
        Returns:
            Repository name
        """
        # Remove .git suffix
        url = url.rstrip('/')
        if url.endswith('.git'):
            url = url[:-4]
        
        # Get last component
        parts = url.split('/')
        return parts[-1]
    
    def _clone_repository(self, url: str, target_dir: Path) -> Tuple[bool, str]:
        """
        Clone Git repository
        
        Args:
            url: Git repository URL
            target_dir: Target directory for clone
            
        Returns:
            Tuple of (success, error_message)
        """
        if target_dir.exists():
            self._log(f"   Repository already exists at {target_dir}, reusing...")
            return True, ""
        
        self._log(f"   Cloning repository from {url}...")
        
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target_dir)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                self._log(f"   ✓ Clone successful")
                return True, ""
            else:
                return False, f"Git clone failed: {result.stderr}"
                
        except FileNotFoundError:
            return False, "Git not found in PATH. Please install Git."
        except subprocess.TimeoutExpired:
            return False, "Git clone timed out (>5 minutes)"
        except Exception as e:
            return False, f"Clone error: {str(e)}"
    
    def _resolve_source(self, source_input: str, work_root: Path) -> Tuple[bool, Optional[Path], str]:
        """
        Resolve source input to a project directory
        
        Args:
            source_input: File path, directory path, or Git URL
            work_root: Working directory for clones
            
        Returns:
            Tuple of (success, repo_path, error_message)
        """
        if self.is_git_url(source_input):
            # Clone repository
            repo_name = self._extract_repo_name(source_input)
            repo_path = work_root / repo_name
            
            success, error = self._clone_repository(source_input, repo_path)
            if not success:
                return False, None, error
            
            return True, repo_path, ""
        else:
            # Local path
            path = Path(source_input).resolve()
            
            if not path.exists():
                return False, None, f"Path does not exist: {path}"
            
            if path.is_file():
                # For single files, create a temporary directory with just that file
                # This ensures CodeQL only analyzes the specified file
                self._log(f"   Single file detected: {path.name}")
                temp_dir = work_root / f"single_file_{path.stem}"
                temp_dir.mkdir(parents=True, exist_ok=True)
                
                # Copy the file to temp directory
                import shutil
                target_file = temp_dir / path.name
                if not target_file.exists():
                    shutil.copy2(path, target_file)
                    self._log(f"   Copied to isolated directory: {temp_dir}")
                
                return True, temp_dir, ""
            elif path.is_dir():
                repo_path = path
            else:
                return False, None, f"Invalid path type: {path}"
            
            return True, repo_path, ""
    
    def _create_database(
        self,
        repo_path: Path,
        db_path: Path,
        language: str = "cpp",
        force_recreate: bool = False,
        compile_commands: Optional[Path] = None,
        build_mode: str = "fast",
        build_command: Optional[str] = None
    ) -> Tuple[bool, str, str]:
        """
        Create CodeQL database
        
        Args:
            repo_path: Source code directory
            db_path: Database output path
            language: CodeQL language (cpp, java, python, etc.)
            force_recreate: Delete and recreate if exists
            compile_commands: Path to compile_commands.json
            build_mode: 'fast' or 'coverage' (used for workflow extraction)
            build_command: Explicit build command (from workflow or fallback)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        if db_path.exists():
            if force_recreate:
                self._log(f"   Removing existing database: {db_path}")
                shutil.rmtree(db_path)
            else:
                # Check if database needs finalization
                self._log(f"   Database already exists, checking if finalized...")
                finalized = self._is_database_finalized(db_path)
                if not finalized:
                    self._log(f"   Database needs finalization, finalizing...")
                    success, stdout, stderr = self._finalize_database(db_path)
                    if not success:
                        self._log(f"   Finalization failed, recreating database...")
                        shutil.rmtree(db_path)
                    else:
                        return True, stdout, stderr
                else:
                    self._log(f"   Database is finalized and ready")
                    return True, "", ""
        
        self._log(f"   Creating CodeQL database for {language}...")
        
        # Build command arguments
        cmd = [
            "codeql", "database", "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={repo_path}"
        ]
        
        # For C/C++, provide a build command
        if language == "cpp":
            if build_command is not None and build_command != "":
                # Use explicitly provided build command (e.g., from workflow)
                self._log(f"   Using provided build command")
                cmd.extend([f"--command={build_command}"])
            elif build_command == "":
                # Empty string means use autobuild
                self._log(f"   Using CodeQL autobuild")
                # Don't add --command, let CodeQL auto-detect
            else:
                # Fallback: detect build system
                has_makefile = (repo_path / "Makefile").exists() or (repo_path / "makefile").exists()
                has_cmake = (repo_path / "CMakeLists.txt").exists()
                
                if has_makefile:
                    self._log(f"   Detected Makefile, using make...")
                    cmd.extend(["--command=make"])
                elif has_cmake:
                    # Improved CMake: out-of-source build with optional Ninja
                    self._log(f"   Detected CMake, using out-of-source build...")
                    
                    # Check for Ninja
                    has_ninja = self._detect_ninja()
                    
                    # Build CMake command
                    # Use common flags to reduce dependency requirements
                    cmake_flags = [
                        "-DBUILD_TESTING=OFF",  # Skip tests
                        "-DBUILD_SHARED_LIBS=OFF",  # Static build may have fewer deps
                    ]
                    cmake_config = f"cmake -S . -B build {' '.join(cmake_flags)}"
                    
                    if has_ninja:
                        self._log(f"   Ninja detected, using Ninja generator")
                        cmake_cmd = f"bash -c '{cmake_config} -G Ninja && cmake --build build'"
                    else:
                        cmake_cmd = f"bash -c '{cmake_config} && cmake --build build'"
                    
                    cmd.extend([f"--command={cmake_cmd}"])
                else:
                    # For simple projects without build system, compile all C/C++ files
                    self._log(f"   No build system detected, compiling C/C++ files directly...")
                    c_files = list(repo_path.glob("*.c")) + list(repo_path.glob("*.cpp"))
                    if c_files:
                        # Create a temporary build script
                        build_script = repo_path / "_codeql_build.sh"
                        with open(build_script, 'w') as f:
                            f.write("#!/bin/bash\n")
                            f.write("set +e\n")  # Don't exit on error
                            for c_file in c_files:
                                # Compile each file, ignore errors (we just want CodeQL to trace it)
                                f.write(f"gcc -c {c_file.name} -o {c_file.stem}.o 2>/dev/null || true\n")
                            f.write("exit 0\n")
                        
                        # Make executable
                        import os
                        os.chmod(build_script, 0o755)
                        
                        cmd.extend([f"--command=bash _codeql_build.sh"])
                    else:
                        self._log(f"   Warning: No C/C++ files found in {repo_path}")
                        cmd.extend(["--command=true"])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes
                cwd=str(repo_path)
            )
            
            if result.returncode == 0:
                self._log(f"   ✓ Database created successfully")
                return True, result.stdout, result.stderr
            else:
                # Check if failure is due to CMake dependency issues
                stderr_lower = result.stderr.lower()
                is_cmake_dep_error = any(indicator in stderr_lower for indicator in [
                    'could not find',
                    'missing:',
                    'not found',
                    'find_package',
                    'dependency'
                ]) and 'cmake' in stderr_lower
                
                if is_cmake_dep_error and build_command:
                    self._log(f"    Build command failed due to missing dependencies")
                    self._log(f"   This is expected for workflow recipes without installed dependencies")
                
                return False, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "", "Database creation timed out (>10 minutes)"
        except Exception as e:
            return False, "", f"Database creation error: {str(e)}"
    
    def _is_database_finalized(self, db_path: Path) -> bool:
        """
        Check if CodeQL database is finalized
        
        Args:
            db_path: Database path
            
        Returns:
            True if finalized, False otherwise
        """
        # Check for finalization marker file
        marker_file = db_path / "codeql-database.yml"
        if not marker_file.exists():
            return False
        
        # Read the yaml file to check status
        try:
            with open(marker_file, 'r') as f:
                content = f.read()
                # If it contains "inProgress: true" it's not finalized
                return "inProgress: true" not in content
        except:
            return False
    
    def _finalize_database(self, db_path: Path) -> Tuple[bool, str, str]:
        """
        Finalize CodeQL database
        
        Args:
            db_path: Database path
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ["codeql", "database", "finalize", str(db_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return True, result.stdout, result.stderr
            else:
                return False, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "", "Database finalization timed out"
        except Exception as e:
            return False, "", f"Finalization error: {str(e)}"
    
    def _analyze_database(
        self,
        db_path: Path,
        sarif_path: Path,
        pack: str = "security-extended"
    ) -> Tuple[bool, str, str]:
        """
        Analyze CodeQL database with query pack
        
        Args:
            db_path: Database path
            sarif_path: Output SARIF file path
            pack: Query pack to use (security-extended, security-and-quality)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        self._log(f"   Analyzing database with '{pack}' pack...")
        
        # Map pack names to CodeQL suite paths
        pack_map = {
            "security-extended": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
            "security-and-quality": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls",
            "all": "codeql/cpp-queries"
        }
        
        pack_query = pack_map.get(pack, pack)
        
        try:
            result = subprocess.run(
                [
                    "codeql", "database", "analyze",
                    str(db_path),
                    pack_query,
                    "--format=sarifv2.1.0",
                    f"--output={sarif_path}"
                ],
                capture_output=True,
                text=True,
                timeout=900,  # 15 minutes
            )
            
            if result.returncode == 0:
                self._log(f"   ✓ Analysis complete")
                return True, result.stdout, result.stderr
            else:
                return False, result.stdout, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "", "Analysis timed out (>15 minutes)"
        except Exception as e:
            return False, "", f"Analysis error: {str(e)}"
    
    def _merge_sarif_files(self, sarif_paths: List[Path], output_path: Path) -> Tuple[bool, str]:
        """
        Merge multiple SARIF files into one
        
        Combines runs from multiple SARIF files with simple deduplication.
        
        Args:
            sarif_paths: List of SARIF file paths to merge
            output_path: Output merged SARIF path
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            merged_sarif = None
            all_results = []
            seen_results = set()  # For deduplication: (ruleId, uri, startLine, message)
            
            for sarif_path in sarif_paths:
                if not sarif_path.exists():
                    continue
                    
                with open(sarif_path, 'r', encoding='utf-8') as f:
                    sarif_data = json.load(f)
                
                # Initialize merged_sarif with first file's structure
                if merged_sarif is None:
                    merged_sarif = {
                        'version': sarif_data.get('version', '2.1.0'),
                        '$schema': sarif_data.get('$schema', 'https://json.schemastore.org/sarif-2.1.0.json'),
                        'runs': []
                    }
                
                # Extract results from each run
                for run in sarif_data.get('runs', []):
                    results = run.get('results', [])
                    
                    # Deduplicate results
                    for result in results:
                        rule_id = result.get('ruleId', '')
                        message = result.get('message', {}).get('text', '')
                        
                        # Get location for deduplication
                        uri = 'unknown'
                        start_line = 0
                        locations = result.get('locations', [])
                        if locations:
                            physical_loc = locations[0].get('physicalLocation', {})
                            uri = physical_loc.get('artifactLocation', {}).get('uri', 'unknown')
                            start_line = physical_loc.get('region', {}).get('startLine', 0)
                        
                        # Create dedup signature
                        signature = (rule_id, uri, start_line, message)
                        
                        if signature not in seen_results:
                            seen_results.add(signature)
                            all_results.append(result)
                    
                    # Keep the run metadata from first file
                    if not merged_sarif['runs']:
                        # Copy the run but with merged results
                        merged_run = dict(run)
                        merged_run['results'] = []
                        merged_sarif['runs'].append(merged_run)
            
            # Add all deduplicated results to the single run
            if merged_sarif and merged_sarif['runs']:
                merged_sarif['runs'][0]['results'] = all_results
            
            # Write merged SARIF
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(merged_sarif, f, indent=2, ensure_ascii=False)
            
            self._log(f"   ✓ Merged {len(sarif_paths)} SARIF files into {output_path.name}")
            self._log(f"   ✓ Total deduplicated results: {len(all_results)}")
            
            return True, ""
            
        except Exception as e:
            error_msg = f"Failed to merge SARIF files: {str(e)}"
            self._log(f"   ✗ {error_msg}")
            return False, error_msg
    
    def _parse_sarif_to_json(self, sarif_path: Path, json_path: Path) -> Tuple[bool, int]:
        """
        Parse SARIF file and convert to simplified JSON format
        
        Args:
            sarif_path: Input SARIF file path
            json_path: Output JSON file path
            
        Returns:
            Tuple of (success, findings_count)
        """
        try:
            # Read SARIF file
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            findings = []
            
            # Extract results from SARIF
            for run in sarif_data.get('runs', []):
                tool_name = run.get('tool', {}).get('driver', {}).get('name', 'CodeQL')
                results = run.get('results', [])
                
                for result in results:
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', 'No description')
                    level = result.get('level', 'warning')  # error, warning, note
                    
                    # Get location
                    locations = result.get('locations', [])
                    if locations:
                        physical_location = locations[0].get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        region = physical_location.get('region', {})
                        
                        file_path = artifact_location.get('uri', 'unknown')
                        start_line = region.get('startLine', 0)
                        start_column = region.get('startColumn', 0)
                        end_line = region.get('endLine', start_line)
                    else:
                        file_path = 'unknown'
                        start_line = 0
                        start_column = 0
                        end_line = 0
                    
                    # Get rule details
                    rule_index = result.get('ruleIndex')
                    rule_info = {}
                    if rule_index is not None:
                        rules = run.get('tool', {}).get('driver', {}).get('rules', [])
                        if rule_index < len(rules):
                            rule = rules[rule_index]
                            rule_info = {
                                'name': rule.get('name', rule_id),
                                'short_description': rule.get('shortDescription', {}).get('text', ''),
                                'help_uri': rule.get('helpUri', ''),
                                'security_severity': rule.get('properties', {}).get('security-severity', 'N/A'),
                                'precision': rule.get('properties', {}).get('precision', 'N/A'),
                                'tags': rule.get('properties', {}).get('tags', [])
                            }
                    
                    finding = {
                        'tool': tool_name,
                        'rule_id': rule_id,
                        'severity': level,
                        'message': message,
                        'file': file_path,
                        'line': start_line,
                        'column': start_column,
                        'end_line': end_line,
                        'rule_info': rule_info
                    }
                    
                    findings.append(finding)
            
            # Write simplified JSON
            output = {
                'tool': 'CodeQL',
                'total_findings': len(findings),
                'findings': findings
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
            
            self._log(f"   ✓ Parsed {len(findings)} findings to JSON")
            return True, len(findings)
            
        except Exception as e:
            self._log(f"   ✗ Failed to parse SARIF: {str(e)}")
            return False, 0
    
    def run_codeql_analysis(
        self,
        source_input: str,
        work_root: Path,
        language: str = "cpp",
        pack: str = "security-extended",
        force_recreate: bool = False,
        build_mode: str = "fast"
    ) -> CodeQLResult:
        """
        Run complete CodeQL analysis pipeline
        
        Args:
            source_input: File path, project path, or GitHub URL
            work_root: Working directory for databases and clones
            language: CodeQL language (cpp, java, python, etc.)
            pack: Query pack (security-extended, security-and-quality, all)
            force_recreate: Force database recreation
            build_mode: 'fast' (single recipe) or 'coverage' (multiple recipes)
            
        Returns:
            CodeQLResult with analysis results
        """
        start_time = datetime.now()
        
        # Ensure work_root exists
        work_root = Path(work_root)
        work_root.mkdir(parents=True, exist_ok=True)
        
        self._log("=" * 70)
        self._log("CODEQL STATIC ANALYSIS")
        self._log("=" * 70)
        self._log(f"Source: {source_input}\n")
        
        # Step 1: Resolve source
        self._log("Step 1: Resolving source...")
        success, repo_path, error = self._resolve_source(source_input, work_root)
        
        if not success:
            return CodeQLResult(
                success=False,
                error=error,
                analysis_time=(datetime.now() - start_time).total_seconds()
            )
        
        # Step 1.5: Extract build recipes from GitHub workflow (if available)
        build_recipes = []
        if language == "cpp":
            self._log(f"\nStep 1.5: Searching for GitHub Actions CodeQL workflows...")
            workflow_files = self._find_codeql_workflow_files(repo_path)
            
            if workflow_files:
                self._log(f"   Found {len(workflow_files)} CodeQL workflow(s)")
                for workflow_file in workflow_files:
                    recipes = self._extract_linux_build_recipes_from_workflow(workflow_file)
                    build_recipes.extend(recipes)
                
                if build_recipes:
                    self._log(f"   Total build recipes extracted: {len(build_recipes)}")
                    selected_recipes = self._choose_build_recipes(build_recipes, build_mode)
                    self._log(f"   Selected {len(selected_recipes)} recipe(s) for build_mode='{build_mode}'")
                    build_recipes = selected_recipes
                else:
                    self._log(f"   No build recipes extracted from workflows")
            else:
                self._log(f"   No CodeQL workflows found, using fallback build detection")
        
        # Step 2: Create database
        repo_name = repo_path.name
        db_path = work_root / f"{repo_name}-codeql-db"
        
        self._log(f"\nStep 2: Creating CodeQL database(s)...")
        
        # Check for compile_commands.json
        compile_commands_path = None
        potential_paths = [
            repo_path / "compile_commands.json",
            repo_path / "build" / "compile_commands.json",
        ]
        for path in potential_paths:
            if path.exists():
                compile_commands_path = path
                break
        
        # Create database(s) based on build mode and available recipes
        db_paths = []
        
        if build_recipes and build_mode == "coverage" and len(build_recipes) > 1:
            # Coverage mode: create multiple databases
            self._log(f"   Coverage mode: creating {len(build_recipes)} database(s)...")
            
            for idx, recipe in enumerate(build_recipes, 1):
                db_path_variant = work_root / f"{repo_name}-codeql-db-{idx}"
                self._log(f"\n   Database {idx}/{len(build_recipes)}:")
                
                success, stdout, stderr = self._create_database(
                    repo_path, db_path_variant, language, force_recreate,
                    compile_commands_path, build_mode, recipe
                )
                
                if success:
                    db_paths.append(db_path_variant)
                else:
                    self._log(f"   Warning: Database {idx} creation failed, skipping")
                    self._log(f"   Error: {stderr}")
            
            if not db_paths:
                error_msg = "All database creations failed in coverage mode"
                return CodeQLResult(
                    success=False,
                    db_path=str(db_path),
                    repo_path=str(repo_path),
                    error=error_msg,
                    analysis_time=(datetime.now() - start_time).total_seconds()
                )
        else:
            # Fast mode or single recipe: create one database
            build_command = build_recipes[0] if build_recipes else None
            
            if build_command:
                self._log(f"   Using workflow recipe for build")
            
            success, stdout, stderr = self._create_database(
                repo_path, db_path, language, force_recreate,
                compile_commands_path, build_mode, build_command
            )
            
            if not success:
                # Check if it's a CMake dependency error
                is_cmake_dep_error = 'cmake' in stderr.lower() and any(
                    indicator in stderr.lower() for indicator in [
                        'could not find', 'missing:', 'not found', 'find_package'
                    ]
                )
                
                # Try fallback without workflow recipe
                if build_command:
                    self._log(f"   Workflow recipe failed, trying fallback build detection...")
                    success, stdout, stderr = self._create_database(
                        repo_path, db_path, language, force_recreate,
                        compile_commands_path, build_mode, None
                    )
                
                # If still failing and it's a CMake project, try autobuild
                if not success and is_cmake_dep_error and (repo_path / "CMakeLists.txt").exists():
                    self._log(f"   CMake dependency issues detected, trying CodeQL autobuild...")
                    # Remove previous failed DB
                    if db_path.exists():
                        shutil.rmtree(db_path)
                    
                    # Try with autobuild (CodeQL's built-in build detection)
                    success, stdout, stderr = self._create_database(
                        repo_path, db_path, language, force_recreate,
                        compile_commands_path, build_mode, ""  # Empty string triggers autobuild
                    )
                
                if not success:
                    error_msg = f"Database creation failed: {stderr}"
                    return CodeQLResult(
                        success=False,
                        db_path=str(db_path),
                        repo_path=str(repo_path),
                        stdout=stdout,
                        stderr=stderr,
                        error=error_msg,
                        analysis_time=(datetime.now() - start_time).total_seconds()
                    )
            
            db_paths = [db_path]
        
        # Step 3: Analyze database(s)
        sarif_path = work_root / f"{repo_name}-codeql-results.sarif"
        json_path = work_root / f"{repo_name}-codeql-results.json"
        
        self._log(f"\nStep 3: Running security analysis...")
        
        sarif_paths = []
        analysis_failed = False
        
        for idx, db_path_item in enumerate(db_paths, 1):
            if len(db_paths) > 1:
                sarif_path_variant = work_root / f"{repo_name}-codeql-results-{idx}.sarif"
                self._log(f"\n   Analyzing database {idx}/{len(db_paths)}...")
            else:
                sarif_path_variant = sarif_path
            
            success, stdout, stderr = self._analyze_database(db_path_item, sarif_path_variant, pack)
            
            # If analysis failed due to unfinalized database, try to finalize
            if not success and "needs to be finalized" in stderr:
                self._log(f"   Database needs finalization, finalizing...")
                fin_success, fin_stdout, fin_stderr = self._finalize_database(db_path_item)
                
                if fin_success:
                    # Retry analysis
                    self._log(f"   Retrying analysis...")
                    success, stdout, stderr = self._analyze_database(db_path_item, sarif_path_variant, pack)
                else:
                    self._log(f"   Warning: Could not finalize database {idx}")
            
            if success:
                sarif_paths.append(sarif_path_variant)
            else:
                self._log(f"   Warning: Analysis of database {idx} failed: {stderr}")
                analysis_failed = True
        
        if not sarif_paths:
            error_msg = "All analyses failed"
            return CodeQLResult(
                success=False,
                db_path=str(db_paths[0]) if db_paths else None,
                repo_path=str(repo_path),
                error=error_msg,
                analysis_time=(datetime.now() - start_time).total_seconds()
            )
        
        # Step 3.5: Merge SARIF files if multiple
        if len(sarif_paths) > 1:
            self._log(f"\nStep 3.5: Merging {len(sarif_paths)} SARIF files...")
            merge_success, merge_error = self._merge_sarif_files(sarif_paths, sarif_path)
            
            if not merge_success:
                error_msg = f"SARIF merging failed: {merge_error}"
                return CodeQLResult(
                    success=False,
                    db_path=str(db_paths[0]),
                    repo_path=str(repo_path),
                    error=error_msg,
                    analysis_time=(datetime.now() - start_time).total_seconds()
                )
        
        end_time = datetime.now()
        
        # Step 4: Parse SARIF to JSON
        self._log(f"\nStep 4: Converting SARIF to JSON...")
        parse_success, findings_count = self._parse_sarif_to_json(sarif_path, json_path)
        
        # Success
        return CodeQLResult(
            success=True,
            sarif_path=str(sarif_path),
            json_path=str(json_path) if parse_success else None,
            db_path=str(db_paths[0]) if db_paths else None,
            repo_path=str(repo_path),
            stdout=stdout,
            stderr=stderr,
            findings_count=findings_count,
            analysis_time=(end_time - start_time).total_seconds()
        )
    
    def run_codeql_for_user_input(
        self,
        user_input: str,
        base_work_dir: Path,
        pack: str = "security-extended",
        build_mode: str = "fast"
    ) -> Optional[CodeQLResult]:
        """
        High-level function for CLI integration
        
        Args:
            user_input: User-provided input (file, directory, or URL)
            base_work_dir: Base working directory
            pack: Query pack to use
            build_mode: 'fast' or 'coverage'
            
        Returns:
            CodeQLResult or None if CodeQL not available
        """
        # Check CodeQL availability
        available, version_or_error = self.ensure_codeql_available()
        
        if not available:
            self._log(f"\n⚠️  CodeQL not available: {version_or_error}")
            self._log("Skipping CodeQL analysis...")
            return None
        
        self._log(f"\nCodeQL CLI detected: {version_or_error}")
        
        try:
            result = self.run_codeql_analysis(
                source_input=user_input,
                work_root=base_work_dir,
                language="cpp",
                pack=pack,
                build_mode=build_mode
            )
            
            if result.success:
                self._log(f"\n{'=' * 70}")
                self._log("CODEQL ANALYSIS COMPLETE")
                self._log(f"{'=' * 70}")
                self._log(f"✓ Total findings: {result.findings_count}")
                self._log(f"✓ SARIF output: {result.sarif_path}")
                if result.json_path:
                    self._log(f"✓ JSON output: {result.json_path}")
                self._log(f"✓ Database: {result.db_path}")
                self._log(f"✓ Analysis time: {result.analysis_time:.2f}s\n")
            else:
                self._log(f"\n{'=' * 70}")
                self._log("CODEQL ANALYSIS FAILED")
                self._log(f"{'=' * 70}")
                self._log(f"✗ Error: {result.error}\n")
                if result.stderr:
                    self._log(f"Details:\n{result.stderr}\n")
            
            return result
            
        except Exception as e:
            self._log(f"\n✗ Unexpected error during CodeQL analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            return CodeQLResult(
                success=False,
                error=f"Unexpected error: {str(e)}"
            )


# ============================================================================
# CLI Entry Point (for standalone testing)
# ============================================================================

def main():
    """Standalone CLI for testing CodeQL integration"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python codeql_analyzer.py <path_or_url>")
        sys.exit(1)
    
    user_input = sys.argv[1]
    work_dir = Path.cwd() / "codeql_work"
    
    analyzer = CodeQLAnalyzer(verbose=True)
    result = analyzer.run_codeql_for_user_input(user_input, work_dir)
    
    if result and result.success:
        print(f"\nSARIF file: {result.sarif_path}")
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
