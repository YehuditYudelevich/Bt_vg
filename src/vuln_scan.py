from ClangFinding import ClangFinding
from llvm_taint import *
from input_processor import InputProcessor
from ClangFinding import ClangStaticAnalyzer, Severity
from asan import *
from pathlib import Path
    
import sys


def vuln_scan():
    text = """
Vulnerability Scanning Module
The vuln_scan module is designed to identify potential security vulnerabilities in C/C++ codebases using multiple analysis engines.

=============================

This module supports three optional engines:

1. **Clang Static Analyzer**
   Install:
       sudo apt install clang clang-tools

2. **CodeQL**
   Install CodeQL CLI:
       https://codeql.github.com/docs/codeql-cli/getting-started-with-the-codeql-cli/
   
   Enables:
       - Building CodeQL databases
       - Running built-in & custom queries

3. **AI Analysis**
   Set API key:
       export AI_API_KEY=...
       you can get free API key using https://console.groq.com/home
       
   Enables:
       - Triage of findings
       - Ranking and explanations

**All components are optional. Use only what you need.**

"""
    print(text)
    print ("enter YES to continue")
    answer = input().strip()
    if answer != "YES":
        print("Exiting vuln_scan.")
        return


def main():
    vuln_scan()
    print("Starting Input Processor...")
    #stage 1: process input
    print("Enter input (file path, project path, or GitHub URL): ")
    input_arg = input().strip()

    processor = InputProcessor(verbose=True)
    try:
        project_path, compile_commands = processor.process_input(input_arg)
        
        # Convert to absolute paths
        project_path = Path(project_path).resolve()
        if compile_commands:
            compile_commands = Path(compile_commands).resolve()

        print(f"Project path: {project_path}")
        print(f"Compile commands: {compile_commands}")

    except Exception as e:
        print(f"\n ERROR: {e}")
        sys.exit(1)

    finally:
        print("yehudit the queen of the world")
        #processor.cleanup() not for now

    #stage 2: run clang static analyzer
    print("\n" + "=" * 70)
    print("STAGE 2: CLANG STATIC ANALYZER")
    print("=" * 70 + "\n")
    
   
    analyzer = ClangStaticAnalyzer()
    
    # Determine input type and analyze accordingly
    input_type = None
    
    # Check if it's a single file
    if Path(project_path).is_file():
        input_type = "single_file"
        print(f"Input type: Single C/C++ file")
        print(f"File: {project_path}\n")
        findings = analyzer.analyze_file(

            project_path, 
            compile_commands_dir=compile_commands
        )
    
    # Check if it's a GitHub repo (cloned to downloaded_repos)
    elif "downloaded_repos" in str(project_path):
        input_type = "github_repo"
        print(f"Input type: GitHub Repository")
        print(f"Cloned to: {project_path}\n")
        findings = analyzer.analyze_project(
            project_path=project_path,
            compile_commands=compile_commands
        )
    
    # Otherwise it's a local project directory
    else:
        input_type = "local_project"
        print(f"Input type: Local Project Directory")
        print(f"Project: {project_path}\n")
        findings = analyzer.analyze_project(
            project_path=project_path,
            compile_commands=compile_commands
        )
    
    # Display results
    print(f"\n{'=' * 70}")
    print("CLANG STATIC ANALYZER RESULTS")
    print(f"{'=' * 70}\n")
    print(f"Input Type: {input_type.upper()}")
    
    if findings:
        print(f"Total findings: {len(findings)}")
        
        # Get high-confidence findings
        high_conf = analyzer.get_high_confidence_findings(findings)
        print(f"High-confidence findings: {len(high_conf)}")
        
        # Display findings by severity
        by_severity = {
            'CRITICAL': [f for f in findings if f.severity == Severity.CRITICAL],
            'HIGH': [f for f in findings if f.severity == Severity.HIGH],
            'MEDIUM': [f for f in findings if f.severity == Severity.MEDIUM],
            'LOW': [f for f in findings if f.severity == Severity.LOW],
        }
        
        for sev, items in by_severity.items():
            if items:
                print(f"\n{sev}: {len(items)} findings")
                for i, f in enumerate(items[:5], 1):  # Show first 5 of each
                    print(f"  {i}. {f.checker}: {f.message}")
                    print(f"     Location: {f.file}:{f.line}")
                if len(items) > 5:
                    print(f"  ... and {len(items) - 5} more")
        
        # Export results
        output_dir = project_path if project_path.is_dir() else project_path.parent
        json_output = output_dir / "clang_results.json"
        sarif_output = output_dir / "clang_results.sarif.json"
        
        print(f"\nExporting results...")
        analyzer.export_to_json(findings, json_output)
        analyzer.export_to_sarif(findings, sarif_output)
        print(f"  JSON: {json_output}")
        print(f"  SARIF: {sarif_output}")

    # Stage 3: LLVM Taint Analysis
    print("\n" + "=" * 70)
    print("STAGE 3: LLVM TAINT ANALYSIS")
    print("=" * 70 + "\n")
    
    taint_analyzer = LLVMTaintAnalyzer()
    
    # Determine what to analyze
    if Path(project_path).is_file():
        # For single file, we need to pass the parent directory
        analysis_path = project_path.parent
        print(f"Analyzing directory containing: {project_path.name}\n")
    else:
        analysis_path = project_path
        print(f"Analyzing project: {analysis_path}\n")
    
    try:
        taint_flows, stats = taint_analyzer.analyze_project(
            project_path=analysis_path,
            compile_commands=compile_commands
        )
        
        # Display results
        print(f"\n{'=' * 70}")
        print("LLVM TAINT ANALYSIS RESULTS")
        print(f"{'=' * 70}\n")
        
        if taint_flows:
            print(f"Total taint flows: {len(taint_flows)}")
            print(f"High-confidence flows: {stats.get('high_confidence', 0)}")
            print(f"Analysis time: {stats.get('duration_seconds', 0):.2f}s")
            
            # Group by severity
            by_severity = {}
            for flow in taint_flows:
                sev = flow.severity.name if hasattr(flow, 'severity') else 'UNKNOWN'
                by_severity.setdefault(sev, []).append(flow)
            
            # Display findings by severity
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                flows = by_severity.get(sev, [])
                if flows:
                    print(f"\n{sev}: {len(flows)} flows")
                    for i, flow in enumerate(flows[:5], 1):
                        print(f"  {i}. {flow.source_type.name} → {flow.sink_type.name}")
                        print(f"     Source: {flow.source_location}")
                        print(f"     Sink: {flow.sink_location}")
                        if hasattr(flow, 'cwe'):
                            print(f"     CWE: {flow.cwe}")
                    if len(flows) > 5:
                        print(f"  ... and {len(flows) - 5} more")
            
            # Export results
            output_dir = analysis_path
            json_output = output_dir / "taint_results.json"
            
            print(f"\nExporting taint analysis results...")
            taint_analyzer.export_to_json(json_output)
            print(f"  JSON: {json_output}")
            
    except Exception as e:
        print(f"Error during taint analysis: {e}")
        import traceback
        traceback.print_exc()
    
    # Stage 4: ASAN Runtime Analysis
    print("\n" + "=" * 70)
    print("STAGE 4: ASAN RUNTIME ANALYSIS")
    print("=" * 70 + "\n")
    
    asan_analyzer = ASANAnalyzer(verbose=True)
    
    # Pass the original project_path (could be file or directory)
    # ASAN will handle file vs directory internally
    print(f"Analyzing: {project_path}\n")
    
    try:
        asan_findings, asan_stats = asan_analyzer.analyze_project(
            project_path=project_path,
            compile_commands=compile_commands
        )
        
        # Display results
        print(f"\n{'=' * 70}")
        print("ASAN RUNTIME ANALYSIS RESULTS")
        print(f"{'=' * 70}\n")
        
        if asan_findings:
            print(f"Total findings: {len(asan_findings)}")
            print(f"Exploitable: {asan_stats.exploitable_count}")
            print(f"Analysis time: {asan_stats.analysis_time:.2f}s")
            
            # Display by error type
            print(f"\nFindings by type:")
            for error_type, count in asan_stats.findings_by_type.items():
                print(f"  {error_type}: {count}")
            
            # Display by severity
            print(f"\nFindings by severity:")
            for severity, count in asan_stats.findings_by_severity.items():
                print(f"  {severity}: {count}")
            
            # Show first 5 findings
            print(f"\nTop findings:")
            for i, finding in enumerate(asan_findings[:5], 1):
                print(f"\n  {i}. {finding.error_type.value}")
                print(f"     Severity: {finding.severity.value}")
                print(f"     Executable: {Path(finding.executable).name}")
                if finding.error_location:
                    print(f"     Location: {finding.error_location.file}:{finding.error_location.line}")
                print(f"     Description: {finding.description[:100]}...")
                if finding.is_exploitable:
                    print(f"       EXPLOITABLE")
            
            if len(asan_findings) > 5:
                print(f"\n  ... and {len(asan_findings) - 5} more findings")
            
            # Export results
            output_dir = project_path if project_path.is_dir() else project_path.parent
            json_output = output_dir / "asan_results.json"
            sarif_output = output_dir / "asan_results.sarif.json"
            
            print(f"\nExporting ASAN results...")
            asan_analyzer.export_to_json(asan_findings, json_output)
            asan_analyzer.export_to_sarif(asan_findings, sarif_output)
            print(f"  JSON: {json_output}")
            print(f"  SARIF: {sarif_output}")
            
    except Exception as e:
        print(f"Error during ASAN analysis: {e}")
        import traceback
        traceback.print_exc()

    
if __name__ == "__main__":
    main()