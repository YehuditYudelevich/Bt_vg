"""
Result Merger for Vulnerability Scanner
========================================

Merges results from multiple analysis engines (CodeQL, Clang, LLVM Taint, ASAN)
into a single unified JSON report, eliminating duplicates and providing comprehensive
vulnerability information.

Author: Yehudit
Version: 1.0
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class UnifiedFinding:
    """Unified vulnerability finding from any tool"""
    id: str  # Unique identifier
    tool: str  # Source tool (CodeQL, Clang, LLVM, ASAN)
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    message: str
    file: str
    line: int
    column: int
    cwe: Optional[str] = None
    exploitability: Optional[str] = None
    confidence: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None


class ResultMerger:
    """
    Merges vulnerability findings from multiple analysis tools
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        
    def _log(self, message: str):
        """Print log message if verbose"""
        if self.verbose:
            print(message)
    
    def _normalize_severity(self, severity: str, tool: str) -> str:
        """
        Normalize severity levels from different tools to standard levels
        
        Args:
            severity: Original severity string
            tool: Tool name
            
        Returns:
            Normalized severity (CRITICAL, HIGH, MEDIUM, LOW)
        """
        severity = severity.upper()
        
        # CodeQL levels: error, warning, note
        if tool == "CodeQL":
            if severity in ["ERROR"]:
                return "HIGH"
            elif severity in ["WARNING"]:
                return "MEDIUM"
            elif severity in ["NOTE"]:
                return "LOW"
        
        # Clang levels: CRITICAL, HIGH, MEDIUM, LOW
        elif tool == "Clang":
            return severity
        
        # ASAN levels: CRITICAL, HIGH, MEDIUM, LOW
        elif tool == "ASAN":
            return severity
        
        # LLVM Taint levels: CRITICAL, HIGH, MEDIUM, LOW
        elif tool == "LLVM":
            return severity
        
        # Default mapping
        if severity in ["CRITICAL", "ERROR"]:
            return "CRITICAL"
        elif severity in ["HIGH", "WARNING"]:
            return "HIGH"
        elif severity in ["MEDIUM", "INFO"]:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _create_finding_signature(self, file: str, line: int, rule_id: str) -> str:
        """
        Create a unique signature for a finding to detect duplicates
        
        Args:
            file: File path
            line: Line number
            rule_id: Rule/checker ID
            
        Returns:
            Unique signature string
        """
        # Normalize file path (remove directory variations)
        file_normalized = Path(file).name if file else "unknown"
        # For same location, ignore rule_id to catch duplicates from different tools
        return f"{file_normalized}:{line}"
    
    def _parse_codeql_results(self, json_path: Path) -> List[UnifiedFinding]:
        """Parse CodeQL JSON results"""
        findings = []
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for finding in data.get('findings', []):
                rule_info = finding.get('rule_info', {})
                cwe = None
                tags = rule_info.get('tags', [])
                for tag in tags:
                    if 'cwe' in tag.lower():
                        cwe = tag.split('/')[-1].upper()
                        break
                
                unified = UnifiedFinding(
                    id=f"codeql_{len(findings)}",
                    tool="CodeQL",
                    rule_id=finding.get('rule_id', 'unknown'),
                    severity=self._normalize_severity(finding.get('severity', 'warning'), "CodeQL"),
                    message=finding.get('message', ''),
                    file=finding.get('file', 'unknown'),
                    line=finding.get('line', 0),
                    column=finding.get('column', 0),
                    cwe=cwe,
                    confidence=rule_info.get('precision', 'medium'),
                    additional_info={
                        'security_severity': rule_info.get('security_severity', 'N/A'),
                        'help_uri': rule_info.get('help_uri', ''),
                        'tags': tags
                    }
                )
                findings.append(unified)
            
            self._log(f"  ✓ Parsed {len(findings)} CodeQL findings")
            
        except FileNotFoundError:
            self._log(f"  ⊘ CodeQL results not found: {json_path}")
        except Exception as e:
            self._log(f"  ✗ Error parsing CodeQL results: {str(e)}")
        
        return findings
    
    def _parse_clang_results(self, json_path: Path) -> List[UnifiedFinding]:
        """Parse Clang Static Analyzer JSON results"""
        findings = []
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle both formats: array or object with 'findings' key
            clang_findings = data.get('findings', []) if isinstance(data, dict) else data
            
            for finding in clang_findings:
                # Extract severity - handle both "MEDIUM" and "Severity.MEDIUM" formats
                severity = finding.get('severity', 'MEDIUM')
                if isinstance(severity, str) and '.' in severity:
                    severity = severity.split('.')[-1]
                
                unified = UnifiedFinding(
                    id=f"clang_{len(findings)}",
                    tool="Clang",
                    rule_id=finding.get('checker', 'unknown'),
                    severity=severity,
                    message=finding.get('message', ''),
                    file=finding.get('file', 'unknown'),
                    line=finding.get('line', 0),
                    column=finding.get('column', 0),
                    cwe=finding.get('cwe'),
                    exploitability=str(finding.get('exploitability', 'N/A')),
                    confidence='high' if finding.get('high_confidence', False) else 'medium',
                    additional_info={
                        'category': finding.get('category', ''),
                        'description': finding.get('description', ''),
                        'issue_context': finding.get('issue_context', '')
                    }
                )
                findings.append(unified)
            
            self._log(f"  ✓ Parsed {len(findings)} Clang findings")
            
        except FileNotFoundError:
            self._log(f"  ⊘ Clang results not found: {json_path}")
        except Exception as e:
            self._log(f"  ✗ Error parsing Clang results: {str(e)}")
        
        return findings
    
    def _parse_llvm_results(self, json_path: Path) -> List[UnifiedFinding]:
        """Parse LLVM Taint Analysis JSON results"""
        findings = []
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            taint_flows = data.get('taint_flows', [])
            
            for flow in taint_flows:
                # Extract location from sink
                sink_location = flow.get('sink_location', '')
                file_path = 'unknown'
                line = 0
                
                if ':' in sink_location:
                    parts = sink_location.split(':')
                    if len(parts) >= 2:
                        file_path = parts[0]
                        try:
                            line = int(parts[1])
                        except ValueError:
                            pass
                
                unified = UnifiedFinding(
                    id=f"llvm_{len(findings)}",
                    tool="LLVM",
                    rule_id=f"{flow.get('source_type', 'unknown')}-to-{flow.get('sink_type', 'unknown')}",
                    severity=flow.get('severity', 'MEDIUM'),
                    message=f"Taint flow from {flow.get('source_type', 'unknown')} to {flow.get('sink_type', 'unknown')}",
                    file=file_path,
                    line=line,
                    column=0,
                    cwe=flow.get('cwe'),
                    confidence=flow.get('confidence', 'medium'),
                    additional_info={
                        'source_location': flow.get('source_location', ''),
                        'sink_location': flow.get('sink_location', ''),
                        'path_length': flow.get('path_length', 0)
                    }
                )
                findings.append(unified)
            
            self._log(f"  ✓ Parsed {len(findings)} LLVM Taint findings")
            
        except FileNotFoundError:
            self._log(f"  ⊘ LLVM results not found: {json_path}")
        except Exception as e:
            self._log(f"  ✗ Error parsing LLVM results: {str(e)}")
        
        return findings
    
    def _parse_asan_results(self, json_path: Path) -> List[UnifiedFinding]:
        """Parse ASAN Runtime Analysis JSON results"""
        findings = []
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle case where data might be None or empty
            if not data:
                self._log(f"  ⊘ ASAN results file is empty: {json_path}")
                return findings
            
            asan_findings = data.get('findings', [])
            if not asan_findings:
                self._log(f"  ⊘ No ASAN findings in results")
                return findings
            
            for finding in asan_findings:
                if not finding:  # Skip None entries
                    continue
                    
                error_location = finding.get('error_location') or {}
                
                unified = UnifiedFinding(
                    id=f"asan_{len(findings)}",
                    tool="ASAN",
                    rule_id=finding.get('error_type', 'unknown'),
                    severity=finding.get('severity', 'HIGH'),
                    message=finding.get('description', 'ASAN runtime error'),
                    file=error_location.get('file', 'unknown') if error_location else 'unknown',
                    line=error_location.get('line', 0) if error_location else 0,
                    column=0,
                    cwe=finding.get('cwe'),
                    exploitability=str(finding.get('is_exploitable', False)),
                    confidence='high',  # ASAN has very high confidence
                    additional_info={
                        'executable': finding.get('executable', ''),
                        'crash_state': finding.get('crash_state', []),
                        'allocation_location': finding.get('allocation_location', {})
                    }
                )
                findings.append(unified)
            
            self._log(f"  ✓ Parsed {len(findings)} ASAN findings")
            
        except FileNotFoundError:
            self._log(f"  ⊘ ASAN results not found: {json_path}")
        except json.JSONDecodeError as e:
            self._log(f"  ✗ Error parsing ASAN JSON: {str(e)}")
        except Exception as e:
            self._log(f"  ✗ Error parsing ASAN results: {str(e)}")
        
        return findings
    
    def _deduplicate_findings(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """
        Remove duplicate findings based on file and line number
        Multiple tools reporting the same issue at the same location will be merged
        
        Args:
            findings: List of findings
            
        Returns:
            Deduplicated list of findings
        """
        seen_signatures: Dict[str, UnifiedFinding] = {}
        
        for finding in findings:
            signature = self._create_finding_signature(
                finding.file,
                finding.line,
                finding.rule_id
            )
            
            # Check if we've seen this exact location
            if signature in seen_signatures:
                existing = seen_signatures[signature]
                
                # Keep the higher severity finding
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                existing_severity = severity_order.get(existing.severity, 0)
                new_severity = severity_order.get(finding.severity, 0)
                
                if new_severity > existing_severity:
                    # Replace with higher severity finding, but preserve tool info
                    finding.tool = f"{existing.tool}+{finding.tool}"
                    seen_signatures[signature] = finding
                elif new_severity == existing_severity:
                    # Merge tools and rule IDs if same severity
                    if finding.tool not in existing.tool:
                        existing.tool = f"{existing.tool}+{finding.tool}"
                    # Merge rule IDs
                    if finding.rule_id not in existing.rule_id:
                        existing.rule_id = f"{existing.rule_id} | {finding.rule_id}"
                else:
                    # Lower severity - just add tool name to existing
                    if finding.tool not in existing.tool:
                        existing.tool = f"{existing.tool}+{finding.tool}"
            else:
                seen_signatures[signature] = finding
        
        deduplicated = list(seen_signatures.values())
        
        duplicates_removed = len(findings) - len(deduplicated)
        if duplicates_removed > 0:
            self._log(f"  ✓ Removed {duplicates_removed} duplicate findings")
        
        return deduplicated
    
    def merge_results(
        self,
        project_path: Path,
        output_path: Optional[Path] = None,
        codeql_result: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Merge all available analysis results into unified report
        
        Args:
            project_path: Project directory or parent directory containing results
            output_path: Optional output path for merged JSON
            codeql_result: Optional specific CodeQL JSON file path
            
        Returns:
            Merged results dictionary
        """
        self._log("\n" + "=" * 70)
        self._log("MERGING ANALYSIS RESULTS")
        self._log("=" * 70 + "\n")
        
        all_findings = []
        
        # Determine result file locations
        if project_path.is_file():
            result_dir = project_path.parent
        else:
            result_dir = project_path
        
        # Parse CodeQL results (use specific file if provided)
        self._log("Parsing CodeQL results...")
        if codeql_result:
            # Use the specific CodeQL result file provided
            codeql_file = Path(codeql_result)
            if codeql_file.exists():
                findings = self._parse_codeql_results(codeql_file)
                all_findings.extend(findings)
        else:
            # Fall back to searching codeql_work directory (old behavior)
            codeql_work = Path.cwd() / "codeql_work"
            codeql_files = list(codeql_work.glob("*-codeql-results.json"))
            if not codeql_files:
                self._log(f"  ⊘ No CodeQL results found in {codeql_work}")
            for codeql_file in codeql_files:
                findings = self._parse_codeql_results(codeql_file)
                all_findings.extend(findings)
        
        # Parse Clang results
        self._log("\nParsing Clang Static Analyzer results...")
        clang_json = result_dir / "clang_results.json"
        clang_findings = self._parse_clang_results(clang_json)
        all_findings.extend(clang_findings)
        
        # Parse LLVM Taint results
        self._log("\nParsing LLVM Taint Analysis results...")
        llvm_json = result_dir / "taint_results.json"
        llvm_findings = self._parse_llvm_results(llvm_json)
        all_findings.extend(llvm_findings)
        
        # Parse ASAN results
        self._log("\nParsing ASAN Runtime Analysis results...")
        asan_json = result_dir / "asan_results.json"
        asan_findings = self._parse_asan_results(asan_json)
        all_findings.extend(asan_findings)
        
        # Deduplicate
        self._log(f"\nDeduplicating findings...")
        self._log(f"  Total findings before deduplication: {len(all_findings)}")
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        # Sort by severity and file
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        deduplicated_findings.sort(
            key=lambda x: (severity_order.get(x.severity, 99), x.file, x.line)
        )
        
        # Create summary statistics
        summary = {
            "total_findings": len(deduplicated_findings),
            "by_severity": {
                "CRITICAL": len([f for f in deduplicated_findings if f.severity == "CRITICAL"]),
                "HIGH": len([f for f in deduplicated_findings if f.severity == "HIGH"]),
                "MEDIUM": len([f for f in deduplicated_findings if f.severity == "MEDIUM"]),
                "LOW": len([f for f in deduplicated_findings if f.severity == "LOW"])
            },
            "by_tool": {},
            "exploitable_count": len([f for f in deduplicated_findings if f.exploitability == "True"]),
            "unique_files": len(set(f.file for f in deduplicated_findings)),
            "unique_cwes": len(set(f.cwe for f in deduplicated_findings if f.cwe))
        }
        
        # Count by tool
        for finding in deduplicated_findings:
            tools = finding.tool.split('+')
            for tool in tools:
                summary["by_tool"][tool] = summary["by_tool"].get(tool, 0) + 1
        
        # Create final report
        merged_report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "project_path": str(project_path),
                "analysis_tools": list(summary["by_tool"].keys())
            },
            "summary": summary,
            "findings": [asdict(f) for f in deduplicated_findings]
        }
        
        # Save to file
        if output_path is None:
            output_path = result_dir / "merged_results.json"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(merged_report, f, indent=2, ensure_ascii=False)
        
        # Print summary
        self._log(f"\n{'=' * 70}")
        self._log("MERGE COMPLETE")
        self._log(f"{'=' * 70}")
        self._log(f"✓ Total findings: {summary['total_findings']}")
        self._log(f"✓ Unique files affected: {summary['unique_files']}")
        self._log(f"\nBy Severity:")
        for severity, count in summary['by_severity'].items():
            if count > 0:
                self._log(f"  {severity}: {count}")
        self._log(f"\nBy Tool:")
        for tool, count in summary['by_tool'].items():
            self._log(f"  {tool}: {count}")
        if summary['exploitable_count'] > 0:
            self._log(f"\n⚠️  Exploitable findings: {summary['exploitable_count']}")
        self._log(f"\n✓ Merged report saved to: {output_path}\n")
        
        return merged_report


def main():
    """CLI entry point for result merging"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python merge_results.py <project_path> [output_path]")
        print("\nExample:")
        print("  python merge_results.py /path/to/project")
        print("  python merge_results.py tests/ merged_output.json")
        sys.exit(1)
    
    project_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    
    merger = ResultMerger(verbose=True)
    merger.merge_results(project_path, output_path)


if __name__ == "__main__":
    main()
