from ClangFinding import ClangFinding
from llvm_taint import *
from input_processor import InputProcessor
from ClangFinding import ClangStaticAnalyzer, Severity
from asan import *
from static_integer_analyzer import StaticIntegerAnalyzer
from codeql_analyzer import CodeQLAnalyzer
from merge_results import ResultMerger
from ai_analyzer import AIVulnerabilityAnalyzer
from pathlib import Path
    
import sys
import argparse
import os

def delete_old_files(project_path: Path):
    """delete old intermediate analysis files to keep the project directory clean."""
    patterns=[
        "clang_results.json",
        "clang_results.sarif.json",
        "integer_bugs.json",
        "asan_result.json",
        "asan_result.sarif.json",
        "taint_analysis.json",
        "codeql_results.json",
        "codeql_results.sarif.json",

    ]
    for pattern in patterns:
        file_path = project_path / pattern
        if file_path.exists():
            try:
                file_path.unlink()
                print(f"Deleted old file: {file_path}")
            except Exception as e:
                print(f"Could not delete {file_path}: {e}")

def cleanup_analysis_files(project_path: Path, output_dir: Path):
    """
    Clean up ALL intermediate analysis files and directories.
    Keeps only the final merged_results.json report in the specified output directory.
    """
    print("Cleaning up intermediate analysis files...")
    
    # Files to keep (the important reports)
    keep_files = {
        "merged_results.json",
    }
    
    # Directories to remove
    dirs_to_remove = [
        "downloaded_repos",
        "codeql_work",
        ".asan_builds",
        ".ubsan_builds",
        "llvm_ir",
        "clang_analysis",
        "build",
    ]
    
    # Intermediate files to remove
    files_to_remove = [
        "clang_results.json",
        "clang_results.sarif.json",
        "asan_results.json",
        "asan_results.sarif.json",
        "taint_results.json",
        "compile_commands.json",
        "_codeql_build.sh",
    ]
    
    # Remove directories
    for dir_name in dirs_to_remove:
        dir_path = Path(dir_name)
        if dir_path.exists():
            try:
                shutil.rmtree(dir_path)
                print(f"  ✓ Removed directory: {dir_name}")
            except Exception as e:
                print(f"  ✗ Could not remove {dir_name}: {e}")
    
    # Remove intermediate files from project directory
    project_dir = project_path if project_path.is_dir() else project_path.parent
    for file_name in files_to_remove:
        file_path = project_dir / file_name
        if file_path.exists():
            try:
                file_path.unlink()
                print(f"  ✓ Deleted: {file_name}")
            except Exception as e:
                print(f"  ✗ Could not delete {file_name}: {e}")
    
    # Clean up any remaining .json/.sarif files from project dir except kept ones
    if project_dir.is_dir():
        for file_path in project_dir.glob("*.json"):
            if file_path.name not in keep_files:
                try:
                    file_path.unlink()
                    print(f"  ✓ Deleted: {file_path.name}")
                except Exception as e:
                    print(f"  ✗ Could not delete {file_path.name}: {e}")
    
    # Final report is in the specified output directory
    final_report = output_dir / "merged_results.json"
    print(f"\n✓ Cleanup complete! Final report: {final_report}")
    
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
3. ASAN Runtime Analysis
   Install:
         sudo apt install clang clang-tools

4. **AI Analysis**
   Set API key:
       export AI_API_KEY=...
       you can get free API key using https://console.groq.com/home
       
   Enables:
       - Triage of findings
       - Ranking and explanations

**All components are optional. Use only what you need.**
**taint analysis can skip on many vulnerabilities that other engines find, so just know it.**
**Pay attention that if the codebase has no main function, ASAN analysis will be skipped.**


"""
    print(text)
    print ("enter YES to continue")
    answer = input().strip()
    if answer != "YES":
        print("Exiting vuln_scan.")
        return


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Vulnerability Scanner for C/C++ Projects')
    parser.add_argument('--output-dir', '-o', type=str, default='data/results',
                        help='Directory to save the merged results (default: data/results)')
    args = parser.parse_args()
    
    # Setup base output directory
    base_output_dir = Path(args.output_dir).resolve()
    base_output_dir.mkdir(parents=True, exist_ok=True)
    print(f"✓ Base output directory: {base_output_dir}\n")
    
    vuln_scan()

    print("Starting Input Processor...")
    #stage 1: process input
    print("\n" + "=" * 70)
    print("STAGE 1: INPUT PROCESSING")
    print("=" * 70 + "\n")
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
        
        # Create project-specific output directory
        project_name = project_path.name
        output_dir = base_output_dir / project_name
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"✓ Results will be saved to: {output_dir}\n")

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
        json_output = output_dir / "clang_results.json"
        sarif_output = output_dir / "clang_results.sarif.json"
        
        print(f"\nExporting results...")
        analyzer.export_to_json(findings, json_output)
        analyzer.export_to_sarif(findings, sarif_output)
        print(f"  JSON: {json_output}")
        print(f"  SARIF: {sarif_output}")
    
    
    

    #stage 4: run CodeQL analysis
    print("\n" + "=" * 70)
    print("STAGE 4: CODEQL STATIC ANALYSIS")
    print("=" * 70 + "\n")
    print("CODEQL is kaking a lot of time and disk space, enter YES to run CodeQL analysis, or anything else to skip:")
    answer = input().strip()
    if answer =="YES" or answer =="yes":
    
        codeql_analyzer = CodeQLAnalyzer(verbose=True)
        codeql_work_dir = Path.cwd() / "codeql_work"
        
        codeql_result = codeql_analyzer.run_codeql_for_user_input(
            user_input=input_arg,
            base_work_dir=codeql_work_dir,
            pack="security-extended"
        )
        
        if codeql_result and codeql_result.success:
            print(f"CodeQL analysis completed successfully")
            print(f"SARIF output available at: {codeql_result.sarif_path}")
        elif codeql_result and not codeql_result.success:
            print(f"CodeQL analysis failed: {codeql_result.error}")
        else:
            print("CodeQL analysis was skipped (CLI not available)")
    else:
        codeql_result = None
        print("Skipping CodeQL analysis as per user input.")
    # Stage 5: ASAN Runtime Analysis
    print("\n" + "=" * 70)
    print("STAGE 5: ASAN RUNTIME ANALYSIS")
    print("=" * 70 + "\n")   
    print("ASAN requires a main function to run. If the codebase lacks a main function, ASAN analysis will be skipped.")
    print("Enter YES to run ASAN analysis, or anything else to skip:")
    user_input=input().strip()
    if user_input=="YES" or user_input=="yes":
    
        asan_analyzer = ASANAnalyzer(verbose=True)
        
        
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
    else:
        print("Skipping ASAN analysis as per user input.")
    # Stage 6: Merge All Results
    print("\n" + "=" * 70)
    print("STAGE 6: MERGING ALL RESULTS")
    print("=" * 70 + "\n")
    
    merger = ResultMerger(verbose=True)
    
    try:
        # Pass the specific CodeQL JSON file if available
        codeql_json = codeql_result.json_path if (codeql_result and codeql_result.success) else None
        
        # Save merged results to specified output directory
        merged_output_path = output_dir / "merged_results.json"
        
        merged_report = merger.merge_results(
            project_path=output_dir,  # Pass output_dir since that's where result files are saved
            output_path=merged_output_path,  # Save to output directory
            codeql_result=codeql_json
        )
        
        print("\n✓ All analysis stages complete!")
        print(f"✓ Final merged report available with {merged_report['summary']['total_findings']} unique findings")
        print(f"✓ Report saved to: {merged_output_path}")
        
        
    except Exception as e:
        print(f"\n✗ Error merging results: {e}")
        import traceback
        traceback.print_exc()
    
    # Stage 7: AI Analysis
    print(f"\n{'=' * 70}")
    print("STAGE 7: AI EXPLOITABILITY ANALYSIS")
    print(f"{'=' * 70}\n")
    
    # Check if GROQ_API_KEY is available
    if os.environ.get('GROQ_API_KEY'):
        print("AI analysis available. This will analyze findings using AI to determine exploitability.")
        print("Do you want to run AI analysis? (enter YES to continue, NO to skip): ")
        ai_choice = input().strip()
        
        if ai_choice.upper() == "YES":
            try:
                print("\nRunning AI analysis...")
                analyzer = AIVulnerabilityAnalyzer(
                    verbose=True,
                    enable_cache=True,
                    rate_limit_delay=3.0  # 3 seconds between API calls to avoid rate limits
                )
                
                enhanced_results = analyzer.analyze_merged_results(
                    merged_output_path,
                    filter_threshold=0  # Analyze ALL findings
                )
                
                # Save AI-enhanced results
                ai_output_path = output_dir / "ai_enhanced_results.json"
                import json
                with open(ai_output_path, 'w', encoding='utf-8') as f:
                    json.dump(enhanced_results, f, indent=2, ensure_ascii=False)
                
                print(f"\n✓ AI-enhanced results saved to: {ai_output_path}")
                
            except Exception as e:
                print(f"\n✗ AI analysis failed: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("Skipping AI analysis as per user input.")
    else:
        print("⚠ AI analysis not available - GROQ_API_KEY environment variable not set")
        print("  To enable AI analysis, set your Groq API key:")
        print("  export GROQ_API_KEY='gsk_...'")
        print("\nSkipping AI analysis...")

    # Stage 8: Cleanup
    print(f"\n{'=' * 70}")
    print("STAGE 8: CLEANUP")
    print(f"{'=' * 70}\n")
    print("Do you want to cleanup all intermediate analysis files and directories, keeping only the final merged report?")
    print("Enter YES to cleanup, NO to skip cleanup:")
    # Cleanup temporary files and directories, keep only merged_results.json
    user_input=input().strip()
    if user_input=="yes" or user_input=="YES":
        cleanup_analysis_files(project_path, output_dir)
        
        print(f"\n{'=' * 70}")
        print("ANALYSIS COMPLETE!")
        print(f"{'=' * 70}\n")
        print(f"✓ All stages finished successfully")
        print(f"✓ Final report saved to: {output_dir / 'merged_results.json'}")
        print(f"✓ All intermediate files and directories cleaned up")
    elif user_input=="no" or user_input=="NO":
        print("Skipping cleanup as per user input.")
        
        print(f"\n{'=' * 70}")
        print("ANALYSIS COMPLETE!")
        print(f"{'=' * 70}\n")
        print(f"✓ All stages finished successfully")
        print(f"✓ Final report saved to: {Path.cwd() / 'merged_results.json'}")
        print(f" Intermediate files were NOT cleaned up")
    else:
        print("Invalid input. Skipping cleanup.")

    
if __name__ == "__main__":
    main()