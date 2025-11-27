"""
The goal of this module is to perform professional-grade taint analysis
"""

import re
import subprocess
import json
from dataclasses import dataclass, field, asdict
from typing import Set, Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Data Models 
class TaintSource(Enum):
    """Types of taint sources"""
    ARGV = ("command_line", 1.0)
    STDIN = ("standard_input", 0.9)
    FILE = ("file_input", 0.7)
    NETWORK = ("network_input", 0.95)
    ENVIRONMENT = ("environment_variable", 0.6)
    UNKNOWN = ("unknown", 0.5)
    
    def __init__(self, description: str, severity: float):
        self.description = description
        self.severity = severity


class TaintSink(Enum):
    """Types of dangerous sinks"""
    BUFFER_COPY = ("buffer_copy", 0.9)
    SYSTEM_CALL = ("system_call", 1.0)
    FORMAT_STRING = ("format_string", 0.8)
    SQL_QUERY = ("sql_query", 0.95)
    FILE_OPERATION = ("file_operation", 0.7)
    
    def __init__(self, description: str, severity: float):
        self.description = description
        self.severity = severity


@dataclass
class TaintedValue:
    """A value that carries taint"""
    variable: str
    function: str
    source: TaintSource
    source_location: Tuple[str, int]
    confidence: float
    propagation_depth: int = 0
    propagation_path: List[str] = field(default_factory=list)
    
    def __hash__(self):
        return hash((self.variable, self.function, self.source))


@dataclass
class TaintFlow:
    """A complete flow from source to sink"""
    source_value: TaintedValue
    sink_function: str
    sink_location: Tuple[str, int]
    sink_type: TaintSink
    call_path: List[str]
    exploitability: float
    validation_present: bool = False
    validation_details: Optional[str] = None
    cwe_id: Optional[str] = None
    
    def __hash__(self):
        return hash((self.sink_function, self.sink_location))



# Main Analyzer 
class LLVMTaintAnalyzer:
    """
    Professional-grade taint analysis 
    """
    
    
    TAINT_SOURCES = {
        # Network I/O (buffer argument)
        'recv': (TaintSource.NETWORK, 1),
        'recvfrom': (TaintSource.NETWORK, 1),
        'recvmsg': (TaintSource.NETWORK, 1),
        'accept': (TaintSource.NETWORK, -1),  # return value
        'read': (TaintSource.FILE, 1),
        
        # Standard I/O (buffer argument)
        'fgets': (TaintSource.FILE, 0),
        'gets': (TaintSource.STDIN, 0),
        'getline': (TaintSource.STDIN, 0),
        'getchar': (TaintSource.STDIN, -1),
        'scanf': (TaintSource.STDIN, -1),
        
        # Environment (return value)
        'getenv': (TaintSource.ENVIRONMENT, -1),
    }
    
    # Dangerous sinks with (sink_type, dangerous_arg_index)
    DANGEROUS_SINKS = {
        'strcpy': (TaintSink.BUFFER_COPY, 1),   # source
        'strcat': (TaintSink.BUFFER_COPY, 1),
        'sprintf': (TaintSink.FORMAT_STRING, 1), # format or first data arg
        'memcpy': (TaintSink.BUFFER_COPY, 1),   # source
        'memmove': (TaintSink.BUFFER_COPY, 1),
        
        'system': (TaintSink.SYSTEM_CALL, 0),
        'popen': (TaintSink.SYSTEM_CALL, 0),
        'execl': (TaintSink.SYSTEM_CALL, 0),
        'execv': (TaintSink.SYSTEM_CALL, 0),
        
        'printf': (TaintSink.FORMAT_STRING, 0),
        'fprintf': (TaintSink.FORMAT_STRING, 1),
    }
    
    SANITIZERS = {
        'strlen', 'strnlen', 'sizeof',
        'strncpy', 'strncat', 'snprintf',
        'validate', 'check', 'sanitize', 'escape',
    }
    
    CWE_MAPPINGS = {
        TaintSink.BUFFER_COPY: 'CWE-120',
        TaintSink.SYSTEM_CALL: 'CWE-78',
        TaintSink.FORMAT_STRING: 'CWE-134',
        TaintSink.SQL_QUERY: 'CWE-89',
    }
    
    def __init__(self, max_workers: int = 4, enable_cache: bool = True):
        self.max_workers = max_workers
        self.enable_cache = enable_cache
        
        # Analysis state
        self.tainted_values: Dict[str, Set[TaintedValue]] = defaultdict(set)
        self.taint_flows: List[TaintFlow] = []
        self.llvm_ir: Dict[str, List[str]] = {}
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_call_graph: Dict[str, Set[str]] = defaultdict(set)
        self.function_params: Dict[str, List[str]] = {}
        
        # Track which variables are argv-derived
        self.argv_tainted: Set[str] = set()
    
   
    # Public API
    def analyze_project(
        self, 
        project_path: Path, 
        compile_commands: Optional[Path] = None,
    ) -> Tuple[List[TaintFlow], dict]:
        
        start_time = datetime.now()
        
        print("Starting LLVM Taint Analysis ")
        print(f"   Project: {project_path}\n")
        
        # Stage 1: Compile to IR
        print("Stage 1: Compiling to LLVM IR...")
        ir_files = self._compile_to_ir_parallel(project_path, compile_commands)
        
        if not ir_files:
            print("No IR files generated")
            return [], {}
        
        print(f"Generated {len(ir_files)} IR files")
        
        # Stage 2: Parse IR
        print("\nStage 2: Parsing LLVM IR...")
        for ir_file in ir_files:
            self._parse_ir_file(ir_file)
        
        print(f"Parsed {len(self.llvm_ir)} functions")
        
        # Stage 3: Build call graph
        print("\nStage 3: Building call graph...")
        self._build_call_graph()
        
        # Stage 4: Mark argv sources
        print("\nStage 4: Marking argv sources...")
        self._mark_argv_sources()
        
        # Stage 5: Mark other taint sources
        print("\nStage 5: Marking taint sources...")
        sources_count = self._mark_taint_sources()
        print(f"Marked {sources_count} taint sources")
        
        # Stage 6: Propagate taint
        print("\nStage 6: Propagating taint...")
        self._propagate_taint_inter_procedural()
        print(f"Tainted {len(self.tainted_values)} variables")
        
        # Stage 7: Find dangerous flows
        print("\nStage 7: Finding dangerous flows...")
        self._find_dangerous_flows()
        print(f"Found {len(self.taint_flows)} taint flows")
        
        # Stage 8: Enrich
        print("\nStage 8: Enriching results...")
        self._enrich_flows()
        
        duration = (datetime.now() - start_time).total_seconds()
        
        stats = {
            'total_functions': len(self.llvm_ir),
            'taint_flows': len(self.taint_flows),
            'high_confidence': len(self.get_high_confidence_flows()),
            'duration_seconds': duration
        }
        
        print(f"\nAnalysis complete in {duration:.2f}s")
        
        return self.taint_flows, stats
    
    def get_high_confidence_flows(self, min_exploitability: float = 0.5) -> List[TaintFlow]:
        """Get high-confidence flows"""
        return [
            f for f in self.taint_flows
            if f.exploitability >= min_exploitability and not f.validation_present
        ]
    

    # IR Compilation
    def _compile_to_ir_parallel(
        self, 
        project_path: Path, 
        compile_commands: Optional[Path]
    ) -> List[Path]:
        """Compile with proper flags from compile_commands.json"""
        
        ir_dir = project_path / 'llvm_ir'
        ir_dir.mkdir(parents=True, exist_ok=True)
        
        if compile_commands is None or not compile_commands.exists():
            print("No compile_commands.json found")
            return []
        
        try:
            with open(compile_commands) as f:
                commands = json.load(f)
        except Exception as e:
            print(f"Failed to read compile_commands.json: {e}")
            return []
        
        # Parse compile commands
        compile_entries = []
        for entry in commands:
            file_path = Path(entry.get('file', ''))
            if file_path.suffix not in ['.c', '.cpp', '.cc', '.cxx']:
                continue
            
            # Extract original flags
            command = entry.get('command', '')
            directory = Path(entry.get('directory', project_path))
            
            # Parse flags from command
            flags = self._extract_compile_flags(command)
            
            compile_entries.append((file_path, directory, flags))
        
        print(f"Found {len(compile_entries)} C/C++ files")
        
        # Compile in parallel
        ir_files = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self._compile_file_to_ir_with_flags,
                    c_file, ir_dir, work_dir, flags
                ): c_file
                for c_file, work_dir, flags in compile_entries
            }
            
            for future in as_completed(futures):
                c_file = futures[future]
                try:
                    ir_file = future.result()
                    if ir_file:
                        ir_files.append(ir_file)
                except Exception as e:
                    print(f"Error compiling {c_file.name}: {e}")  
        
        return ir_files
    
    def _extract_compile_flags(self, command: str) -> List[str]:
        """Extract relevant compile flags from command"""
        
        # Split command into tokens
        tokens = command.split()
        
        flags = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            # Include flags
            if token.startswith('-I'):
                if len(token) > 2:
                    flags.append(token)
                elif i + 1 < len(tokens):
                    flags.append(token)
                    flags.append(tokens[i + 1])
                    i += 1
            
            # Define flags
            elif token.startswith('-D'):
                if len(token) > 2:
                    flags.append(token)
                elif i + 1 < len(tokens):
                    flags.append(token)
                    flags.append(tokens[i + 1])
                    i += 1
            
            # Standard flags
            elif token.startswith('-std='):
                flags.append(token)
            
            # System include paths
            elif token == '-isystem' and i + 1 < len(tokens):
                flags.append(token)
                flags.append(tokens[i + 1])
                i += 1
            
            i += 1
        
        return flags
    
    def _compile_file_to_ir_with_flags(
    self, 
    c_file: Path, 
    ir_dir: Path,
    work_dir: Path,
    extra_flags: List[str]) -> Optional[Path]:
        """Compile single file with original flags"""
    
        ir_file = ir_dir / f"{c_file.stem}.ll"
        
        # Check cache
        if self.enable_cache and ir_file.exists():
            if c_file.exists() and c_file.stat().st_mtime < ir_file.stat().st_mtime:
                return ir_file
        
        cmd = [
            'clang',
            '-S',
            '-emit-llvm',
            '-O0',
            '-g',
            '-Xclang', '-disable-O0-optnone',
        ]
        
        # Add original flags
        cmd.extend(extra_flags)
        
        # Add source and output
        cmd.extend(['-c', str(c_file), '-o', str(ir_file)])
        
        try:
            result = subprocess.run(
                cmd,
                cwd=str(work_dir),
                capture_output=True,
                timeout=60,
                check=False
            )
            
            if result.returncode == 0 and ir_file.exists():
                return ir_file
            else:
                # Debug: print why it failed
                if result.stderr:
                    print(f"  Warning: clang error for {c_file.name}")
                    # Uncomment for full debug:
                    print(result.stderr.decode('utf-8', errors='ignore'))
                
        except subprocess.TimeoutExpired:
            print(f"  Timeout compiling {c_file.name}")
        except Exception as e:
            print(f"  Exception: {e}")
        
        return None
    
    
    # IR Parsing
    def _parse_ir_file(self, ir_file: Path):
        """Parse LLVM IR file"""
        
        try:
            with open(ir_file, 'r', encoding='utf-8', errors='ignore') as f:
                ir_content = f.read()
        except Exception:
            print(f"  Failed to read IR file: {ir_file} \\yehudit")
            return
        
        current_function = None
        
        for line in ir_content.split('\n'):
            line = line.strip()
            
            # Function definition
            match = re.search(r'define\s+[^@]*@(\w+)\s*\(([^)]*)\)', line)
            if match:
                current_function = match.group(1)
                params_str = match.group(2)
                
                # Extract parameter names
                params = re.findall(r'%(\w+)', params_str)
                self.function_params[current_function] = params
                self.llvm_ir[current_function] = []
            
            # Store lines
            if current_function:
                self.llvm_ir[current_function].append(line)
            
            # End of function
            if current_function and line == '}':
                current_function = None
    
   
    # Call Graph
    def _build_call_graph(self):
        """Build call graph"""
        
        for func_name, ir_lines in self.llvm_ir.items():
            for line in ir_lines:
                call_match = re.search(r'call\s+[^@]*@(\w+)\s*\(', line)
                if call_match:
                    callee = call_match.group(1)
                    if not callee.startswith('llvm.'):
                        self.call_graph[func_name].add(callee)
                        self.reverse_call_graph[callee].add(func_name)
    
    
    # Taint Source Marking
    def _mark_argv_sources(self):
        """Mark argv-derived values"""
        
        # Find main function
        if 'main' not in self.llvm_ir:
            return
        
        main_ir = self.llvm_ir['main']
        
        main_params = self.function_params.get('main', [])
        
        if len(main_params) >= 2:
            argv_param = main_params[1]  # argv
            # Mark argv as tainted
            argv_var = f"main::{argv_param}"
            
            tainted = TaintedValue(
                variable=argv_var,
                function='main',
                source=TaintSource.ARGV,
                source_location=('main', 0),
                confidence=1.0,
                propagation_depth=0,
                propagation_path=['main']
            )
            
            self.tainted_values[argv_var].add(tainted)
            self.argv_tainted.add(argv_var)
            
            # Also look for argv[i] accesses (getelementptr)
            for i, line in enumerate(main_ir):
                if 'getelementptr' in line and argv_param in line:
                    # This is accessing argv[i]
                    result_var = self._extract_lhs(line)
                    if result_var:
                        result_full = f"main::{result_var}"
                        
                        tainted_elem = TaintedValue(
                            variable=result_full,
                            function='main',
                            source=TaintSource.ARGV,
                            source_location=('main', i),
                            confidence=1.0,
                            propagation_depth=0,
                            propagation_path=['main']
                        )
                        
                        self.tainted_values[result_full].add(tainted_elem)
    
    def _mark_taint_sources(self) -> int:
        """Mark taint sources - FIXED arg_index implementation"""
        
        count = 0
        
        for func_name, ir_lines in self.llvm_ir.items():
            for i, line in enumerate(ir_lines):
                for source_func, (source_type, arg_index) in self.TAINT_SOURCES.items():
                    if re.search(rf'call\s+[^@]*@{source_func}\s*\(', line):
                        self._add_taint_source(func_name, line, source_type, i, arg_index)
                        count += 1
        
        return count
    
    def _add_taint_source(
        self,
        func: str,
        ir_line: str,
        source_type: TaintSource,
        line_num: int,
        arg_index: int
    ):
        """Add tainted value"""
        
        if arg_index == -1:
            # Taint return value
            match = re.search(r'%(\w+)\s*=.*call', ir_line)
            if match:
                var_name = f"{func}::{match.group(1)}"
                
                tainted = TaintedValue(
                    variable=var_name,
                    function=func,
                    source=source_type,
                    source_location=(func, line_num),
                    confidence=source_type.severity,
                    propagation_depth=0,
                    propagation_path=[func]
                )
                
                self.tainted_values[var_name].add(tainted)
        
        else:
            # Extract arguments from the call
            args = self._extract_call_arguments_improved(ir_line)
            
            if arg_index < len(args):
                arg_var = args[arg_index]
                full_var = f"{func}::{arg_var}"
                
                # The argument variable gets tainted
                tainted = TaintedValue(
                    variable=full_var,
                    function=func,
                    source=source_type,
                    source_location=(func, line_num),
                    confidence=source_type.severity,
                    propagation_depth=0,
                    propagation_path=[func]
                )
                
                self.tainted_values[full_var].add(tainted)
    

    # Argument Extraction
     
    def _extract_call_arguments_improved(self, line: str) -> List[str]:
        """
        Extract arguments from function call -
        
        Looks only inside the call parentheses
        """
        match = re.search(r'call\s+[^@]*@[\w.]+\s*\((.*?)\)', line)
        if not match:
            return []
        
        args_part = match.group(1)
        
        # Extract %variables from arguments
        return re.findall(r'%(\w+)', args_part)
    
  
    # Taint Propagation
    def _propagate_taint_inter_procedural(self):
        """Propagate taint"""
        
        changed = True
        iterations = 0
        max_iterations = 100
        
        while changed and iterations < max_iterations:
            changed = False
            iterations += 1
            
            # Intra-procedural
            for func_name, ir_lines in self.llvm_ir.items():
                if self._propagate_within_function(func_name, ir_lines):
                    changed = True
            
            # Inter-procedural
            if self._propagate_across_functions():
                changed = True
    
    def _propagate_within_function(self, func_name: str, ir_lines: List[str]) -> bool:
        """Propagate taint within a single function (כולל store + getelementptr)"""

        changed = False

        for line in ir_lines:
            
            store_match = re.search(r'store\s+\S+\s+%(\w+),\s+\S+\s+%(\w+)', line)
            if store_match:
                src, dst = store_match.groups()
                full_src = f"{func_name}::{src}"
                full_dst = f"{func_name}::{dst}"

                if full_src in self.tainted_values and full_dst not in self.tainted_values:
                    for taint in self.tainted_values[full_src]:
                        new_taint = TaintedValue(
                            variable=full_dst,
                            function=func_name,
                            source=taint.source,
                            source_location=taint.source_location,
                            confidence=taint.confidence * 0.98,
                            propagation_depth=taint.propagation_depth + 1,
                            propagation_path=taint.propagation_path ,
                        )
                        self.tainted_values[full_dst].add(new_taint)
                        changed = True

                
                continue

            # 2) propagate דרך getelementptr: %dst = getelementptr ..., %base, ...
            gep_match = re.search(r'%(\w+)\s*=\s*getelementptr[^%]*%(\w+)', line)
            if gep_match:
                dst, base = gep_match.groups()
                full_dst = f"{func_name}::{dst}"
                full_base = f"{func_name}::{base}"

                
                if full_base in self.tainted_values and full_dst not in self.tainted_values:
                    for taint in self.tainted_values[full_base]:
                        new_taint = TaintedValue(
                            variable=full_dst,
                            function=func_name,
                            source=taint.source,
                            source_location=taint.source_location,
                            confidence=taint.confidence * 0.98,
                            propagation_depth=taint.propagation_depth + 1,
                            propagation_path=taint.propagation_path + [func_name],
                        )
                        self.tainted_values[full_dst].add(new_taint)
                        changed = True

                
                if full_dst in self.tainted_values and full_base not in self.tainted_values:
                    for taint in self.tainted_values[full_dst]:
                        new_taint = TaintedValue(
                            variable=full_base,
                            function=func_name,
                            source=taint.source,
                            source_location=taint.source_location,
                            confidence=taint.confidence * 0.98,
                            propagation_depth=taint.propagation_depth + 1,
                            propagation_path=taint.propagation_path + [func_name],
                        )
                        self.tainted_values[full_base].add(new_taint)
                        changed = True

                continue

            
            if '=' in line:
                lhs = self._extract_lhs(line)
                if not lhs:
                    continue

                rhs_vars = self._extract_rhs_variables(line)

                for rhs_var in rhs_vars:
                    full_rhs_var = f"{func_name}::{rhs_var}"
                    full_lhs_var = f"{func_name}::{lhs}"

                    if full_rhs_var in self.tainted_values:
                        if full_lhs_var not in self.tainted_values:
                            for taint in self.tainted_values[full_rhs_var]:
                                new_taint = TaintedValue(
                                    variable=full_lhs_var,
                                    function=func_name,
                                    source=taint.source,
                                    source_location=taint.source_location,
                                    confidence=taint.confidence * 0.98,
                                    propagation_depth=taint.propagation_depth + 1,
                                    propagation_path=taint.propagation_path + [func_name],
                                )
                                self.tainted_values[full_lhs_var].add(new_taint)
                                changed = True

        return changed

    
    def _propagate_across_functions(self) -> bool:
        """Propagate across function calls"""
        
        changed = False
        
        for caller, callees in self.call_graph.items():
            caller_lines = self.llvm_ir.get(caller, [])
            
            for line in caller_lines:
                for callee in callees:
                    if re.search(rf'call\s+[^@]*@{callee}\s*\(', line):
                        # Use improved argument extraction
                        args = self._extract_call_arguments_improved(line)
                        
                        for i, arg in enumerate(args):
                            full_arg = f"{caller}::{arg}"
                            
                            if full_arg in self.tainted_values:
                                if callee in self.function_params:
                                    params = self.function_params[callee]
                                    if i < len(params):
                                        param_name = f"{callee}::{params[i]}"
                                        
                                        if param_name not in self.tainted_values:
                                            for taint in self.tainted_values[full_arg]:
                                                new_taint = TaintedValue(
                                                    variable=param_name,
                                                    function=callee,
                                                    source=taint.source,
                                                    source_location=taint.source_location,
                                                    confidence=taint.confidence * 0.95,
                                                    propagation_depth=taint.propagation_depth + 1,
                                                    propagation_path=taint.propagation_path + [callee]
                                                )
                                                self.tainted_values[param_name].add(new_taint)
                                                changed = True
        
        return changed
    
   
    # Dangerous Flow Detection
    
    
    def _find_dangerous_flows(self):
        """Find dangerous flows"""
        
        for func_name, ir_lines in self.llvm_ir.items():
            for i, line in enumerate(ir_lines):
                for sink_func, (sink_type, arg_index) in self.DANGEROUS_SINKS.items():
                    if re.search(rf'call\s+[^@]*@{sink_func}\s*\(', line):
                        # Use improved extraction
                        args = self._extract_call_arguments_improved(line)
                        
                        if arg_index < len(args):
                            arg = args[arg_index]
                            full_arg = f"{func_name}::{arg}"
                            
                            if full_arg in self.tainted_values:
                                for taint in self.tainted_values[full_arg]:
                                    validation_present, validation_details = self._check_validation_improved(
                                        func_name, ir_lines, i, arg
                                    )
                                    
                                    flow = TaintFlow(
                                        source_value=taint,
                                        sink_function=sink_func,
                                        sink_location=(func_name, i),
                                        sink_type=sink_type,
                                        call_path=taint.propagation_path + [func_name],
                                        exploitability=self._calculate_exploitability(taint, sink_func, sink_type),
                                        validation_present=validation_present,
                                        validation_details=validation_details
                                    )
                                    
                                    self.taint_flows.append(flow)
    
    def _calculate_exploitability(self, taint, sink, sink_type):
        score = taint.source.severity * sink_type.severity
        return min(1.0, max(0.0, score))

    
    def _check_validation_improved(
        self,
        func_name: str,
        ir_lines: List[str],
        sink_line: int,
        tainted_var: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Improved validation detection 
        """
        
        context = ir_lines[max(0, sink_line-30):sink_line]
        validations = []
        
        # Create proper pattern for the variable
        var_pattern = rf'%{re.escape(tainted_var)}\b'
        
        for j, line in enumerate(context):
            # Check 1: Comparisons
            if 'icmp' in line and re.search(var_pattern, line):
                if any(cmp in line for cmp in ['ult', 'ule', 'slt', 'sle']):
                    if j + 1 < len(context) and 'br i1' in context[j + 1]:
                        validations.append("bounds_check")
            
            # Check 2: strlen/sizeof
            if re.search(r'call.*@(strlen|strnlen)', line) and re.search(var_pattern, line):
                validations.append("length_check")
            
            # Check 3: Sanitizers
            for sanitizer in self.SANITIZERS:
                if re.search(rf'call.*@{sanitizer}\s*\(', line):
                    if re.search(var_pattern, line):
                        validations.append(f"sanitizer:{sanitizer}")
        
        if validations:
            return True, ", ".join(set(validations))
        else:
            return False, None
    
    
    # Enrichment
    
    def _enrich_flows(self):
        """Add CWE IDs"""
        for flow in self.taint_flows:
            flow.cwe_id = self.CWE_MAPPINGS.get(flow.sink_type, 'CWE-Unknown')
    
   
    # Export
    def export_to_json(self, output_file: Path):
        """Export to JSON"""
        
        data = {
            'metadata': {
                'analyzer': 'LLVM Taint Analyzer (Fixed)',
                'timestamp': datetime.now().isoformat(),
            },
            'flows': [self._flow_to_dict(f) for f in self.taint_flows],
            'high_confidence': [self._flow_to_dict(f) for f in self.get_high_confidence_flows()],
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f" Results exported to {output_file}")
    
    def _flow_to_dict(self, flow: TaintFlow) -> dict:
        """Convert flow to dict"""
        return {
            'source': {
                'type': flow.source_value.source.name,
                'location': f"{flow.source_value.source_location[0]}:{flow.source_value.source_location[1]}",
            },
            'sink': {
                'function': flow.sink_function,
                'type': flow.sink_type.name,
                'location': f"{flow.sink_location[0]}:{flow.sink_location[1]}",
            },
            'exploitability': flow.exploitability,
            'validation': flow.validation_present,
            'cwe': flow.cwe_id,
            'path': flow.call_path,
        }
    


    # Utility Methods
    def _extract_lhs(self, line: str) -> str:
        """Extract left-hand side variable"""
        match = re.search(r'%(\w+)\s*=', line)
        return match.group(1) if match else ""
    
    def _extract_rhs_variables(self, line: str) -> List[str]:
        """Extract right-hand side variables"""
        return re.findall(r'%(\w+)', line)



# Test on real code


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python taint_engine_fixed.py <project_path> [compile_commands.json]")
        print("\nTest with simple vulnerable code:")
        print("  python taint_engine_fixed.py ./test_project")
        sys.exit(1)
    
    project = Path(sys.argv[1])
    project = Path(sys.argv[1]).resolve()
    compile_cmds = Path(sys.argv[2]) if len(sys.argv) > 2 else project / 'compile_commands.json'
    
    if not project.exists():
        print(f" Project not found: {project}")
        sys.exit(1) 
    
    # Run analysis
    analyzer = LLVMTaintAnalyzer(max_workers=4)
    flows, stats = analyzer.analyze_project(project, compile_cmds)
    if not stats:
        print("\n[!] Analysis failed – likely no IR was generated (clang? compile_commands.json?)")
        sys.exit(1)

    
    # Print results
    print(f"\n{'=' * 70}")
    print("RESULTS")
    print(f"{'=' * 70}\n")
    
    print(f"Functions: {stats['total_functions']}")
    print(f"Flows found: {stats['taint_flows']}")
    print(f"High confidence: {stats['high_confidence']}\n")
    
    high_conf = analyzer.get_high_confidence_flows()
    
    if high_conf:
        print(f" Top {min(5, len(high_conf))} vulnerabilities:\n")
        
        for i, flow in enumerate(high_conf[:5], 1):
            print(f"{i}. {flow.source_value.source.name} → {flow.sink_function}")
            print(f"   Location: {flow.sink_location[0]}:{flow.sink_location[1]}")
            print(f"   Path: {' → '.join(flow.call_path)}")
            print(f"   Exploitability: {flow.exploitability:.2f}")
            print(f"   CWE: {flow.cwe_id}")
            print()
    else:
        print("No high-confidence vulnerabilities found")
    
    # Export
    output_file = project / 'taint_analysis.json'
    analyzer.export_to_json(output_file)