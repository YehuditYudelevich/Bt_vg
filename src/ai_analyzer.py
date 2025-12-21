"""
AI-Powered Exploitability Analysis
===================================

Enhanced version with robust error handling, caching, and progress tracking.

Analyzes vulnerability findings using AI to determine:
- Exploitability score (0-100)
- Attack difficulty
- Exploitation path
- Mitigations
- Similar CVEs

Features:
- Two-stage analysis (filter + deep)
- Smart path resolution
- Rate limiting & retry logic
- Result caching
- Progress tracking
- Real cost tracking

Author: Yehudit
Version: 2.0
License: MIT

Usage:
    python ai_analyzer.py data/results/cJSON/merged_results.json

Requirements:
    - groq>=0.4.0
    - GROQ_API_KEY environment variable
    - tqdm (optional, for progress bar)

Example:
    >>> from ai_analyzer import AIVulnerabilityAnalyzer
    >>> analyzer = AIVulnerabilityAnalyzer()
    >>> results = analyzer.analyze_merged_results(Path('merged_results.json'))
"""

from groq import Groq
import json
import os
import sys
import time
import hashlib
import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime

# Optional progress bar
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("Tip: Install tqdm for progress bars: pip install tqdm")


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class AIAnalysis:
    """
    AI analysis result for a single vulnerability finding
    
    Attributes:
        exploitability_score: 0-100, likelihood of successful exploitation
        difficulty: How hard it is to exploit
        is_exploitable: Binary determination
        attack_vector: Detailed explanation of exploitation path
        reasoning: List of factors supporting the score
        mitigations: Recommended fixes
        confidence: AI's confidence in the analysis
        time_to_exploit: Estimated time for skilled attacker
        similar_cves: Known CVEs with similar patterns
    """
    exploitability_score: int  # 0-100
    difficulty: str  # trivial/easy/medium/hard/very_hard
    is_exploitable: bool
    attack_vector: str
    reasoning: List[str]
    mitigations: List[str]
    confidence: str  # low/medium/high/very_high
    time_to_exploit: str
    similar_cves: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class AnalysisStats:
    """Statistics for the analysis run"""
    total_findings: int = 0
    filtered_findings: int = 0
    analyzed_findings: int = 0
    exploitable_count: int = 0
    api_calls: int = 0
    total_cost: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    cache_hits: int = 0
    analysis_time: float = 0.0
    
    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================================
# Main Analyzer Class
# ============================================================================

class AIVulnerabilityAnalyzer:
    """
    Enhanced AI-powered vulnerability analyzer using Groq API
    
    Features:
    - Two-stage analysis (filter + deep analysis)
    - Smart threshold calculation
    - Result caching
    - Rate limiting & retry logic
    - Real token usage tracking
    - Progress bar support
    """
    
    # Groq pricing (per 1M tokens) - approximate
    PRICING = {
        'input': 0.05,   # $0.05 per 1M input tokens
        'output': 0.08,  # $0.08 per 1M output tokens
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        quick_model: str = "llama-3.1-8b-instant",
        deep_model: str = "llama-3.3-70b-versatile",
        max_context_lines: int = 100,
        verbose: bool = True,
        enable_cache: bool = True,
        cache_dir: Optional[Path] = None,
        rate_limit_delay: float = 2.0,
        max_retries: int = 3
    ):
        """
        Initialize AI vulnerability analyzer
        
        Args:
            api_key: Groq API key (reads from env if not provided)
            quick_model: Model for quick filtering (cheap)
            deep_model: Model for deep analysis (accurate)
            max_context_lines: Lines of code context to extract (±N)
            verbose: Print detailed progress
            enable_cache: Cache analysis results
            cache_dir: Directory for cache files
            rate_limit_delay: Seconds between API requests
            max_retries: Maximum retry attempts for failed requests
            
        Raises:
            ValueError: If API key not found
        """
        
        # API configuration
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GROQ_API_KEY not found. Set it via:\n"
                "  export GROQ_API_KEY='gsk_...'\n"
                "or pass it to AIVulnerabilityAnalyzer(api_key='...')"
            )
        
        self.client = Groq(api_key=self.api_key)
        self.quick_model = quick_model
        self.deep_model = deep_model
        self.max_context_lines = max_context_lines
        self.verbose = verbose
        
        # Rate limiting
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = None
        self.max_retries = max_retries
        
        # Caching
        self.enable_cache = enable_cache
        self.cache_dir = cache_dir or (Path.home() / '.vuln_analyzer_cache')
        if self.enable_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistics
        self.stats = AnalysisStats()
        
        # Project context (set during analysis)
        self.project_root = None
    
    def analyze_merged_results(
        self,
        merged_results_path: Path,
        filter_threshold: Optional[float] = None
    ) -> Dict:
        """
        Analyze merged vulnerability results with AI
        
        This is the main entry point. Loads findings, filters them,
        performs deep analysis on promising ones, and returns enhanced results.
        
        Args:
            merged_results_path: Path to merged_results.json
            filter_threshold: Percentage to analyze (0.0-1.0)
                            If None, auto-calculates smart threshold
            
        Returns:
            Enhanced results dictionary with AI analysis added
        """
        
        start_time = datetime.now()
        
        self._log("=" * 70)
        self._log("AI-POWERED EXPLOITABILITY ANALYSIS")
        self._log("=" * 70 + "\n")
        
        # Validate input
        if not merged_results_path.exists():
            raise FileNotFoundError(f"Results file not found: {merged_results_path}")
        
        # Load results
        with open(merged_results_path, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        findings = results.get('findings', [])
        self.stats.total_findings = len(findings)
        
        if not findings:
            self._log("No findings to analyze!")
            return results
        
        self._log(f"Loaded {len(findings)} findings from {merged_results_path.name}")
        
        # Extract project root from metadata to help with path resolution
        project_path = results.get('metadata', {}).get('project_path', 'Unknown')
        self._log(f"Project: {project_path}\n")
        
        # Set project root for path resolution (look for downloaded_repos)
        if project_path != 'Unknown':
            project_path_obj = Path(project_path)
            if 'downloaded_repos' in project_path_obj.parts:
                # Extract up to and including the repo name
                parts = project_path_obj.parts
                idx = parts.index('downloaded_repos')
                if idx + 1 < len(parts):
                    self.project_root = Path.cwd() / 'downloaded_repos' / parts[idx + 1]
                    self._log(f"  Source code root: {self.project_root}\n")
        
        # Stage 1: Quick filter
        self._log("Stage 1: Quick filtering with AI...")
        self._log("=" * 70)
        
        if filter_threshold is None:
            target_count = self._calculate_smart_threshold(len(findings))
            self._log(f"  Auto-calculated target: {target_count} findings "
                     f"({target_count/len(findings)*100:.0f}%)")
        elif filter_threshold == 0:
            # 0 means analyze ALL findings
            target_count = len(findings)
            self._log(f"  Target: ALL {target_count} findings (100%)")
        else:
            target_count = max(1, int(len(findings) * filter_threshold))
            self._log(f"  Target: {target_count} findings ({filter_threshold*100:.0f}%)")
        
        promising_indices = self._quick_filter(findings, target_count)
        self.stats.filtered_findings = len(promising_indices)
        
        self._log(f"\n✓ Filter complete: {len(promising_indices)}/{len(findings)} "
                 f"findings selected for deep analysis\n")
        
        if not promising_indices:
            self._log("No promising findings identified. Analysis complete.")
            return results
        
        # Stage 2: Deep analysis
        self._log("Stage 2: Deep analysis on selected findings...")
        self._log("=" * 70 + "\n")
        
        # Progress tracking
        if HAS_TQDM and self.verbose:
            iterator = tqdm(
                enumerate(promising_indices, 1),
                total=len(promising_indices),
                desc="Analyzing",
                unit="finding",
                ncols=80
            )
        else:
            iterator = enumerate(promising_indices, 1)
        
        for i, finding_idx in iterator:
            finding = findings[finding_idx]
            
            # Display progress (non-tqdm mode)
            if not HAS_TQDM:
                self._log(f"[{i}/{len(promising_indices)}] Analyzing: {finding['id']}")
                self._log(f"    {finding['message'][:70]}...")
            
            # Get code context with enhanced information
            code_context = self._get_enhanced_context(finding)
            
            # Check cache first
            cached_analysis = None
            if self.enable_cache:
                cached_analysis = self._get_cached_analysis(finding)
            
            if cached_analysis:
                ai_analysis = cached_analysis
                self.stats.cache_hits += 1
                if not HAS_TQDM:
                    self._log(f"    💾 Cache hit!")
            else:
                # Perform deep analysis
                try:
                    ai_analysis = self._deep_analysis(finding, code_context)
                    
                    # Cache the result
                    if self.enable_cache:
                        self._cache_analysis(finding, ai_analysis)
                    
                except Exception as e:
                    if not HAS_TQDM:
                        self._log(f"      Analysis failed: {str(e)[:60]}")
                    
                    findings[finding_idx]['ai_analysis'] = self._create_error_analysis(e)
                    continue
            
            # Store results
            findings[finding_idx]['ai_analysis'] = ai_analysis.to_dict()
            findings[finding_idx]['vulnerable_code_line'] = self._get_specific_line(
                finding['file'],
                finding['line']
            )
            self.stats.analyzed_findings += 1
            
            if ai_analysis.is_exploitable:
                self.stats.exploitable_count += 1
            
            # Display result (non-tqdm mode)
            if not HAS_TQDM:
                score = ai_analysis.exploitability_score
                emoji = "🔴" if score >= 70 else "🟠" if score >= 40 else "🟢"
                self._log(f"    {emoji} Score: {score}/100 | "
                         f"Difficulty: {ai_analysis.difficulty} | "
                         f"Exploitable: {ai_analysis.is_exploitable}\n")
        
        # Calculate analysis time
        end_time = datetime.now()
        self.stats.analysis_time = (end_time - start_time).total_seconds()
        
        # Update results with metadata
        results['ai_analysis_metadata'] = {
            'analyzed_at': end_time.isoformat(),
            'analysis_duration_seconds': self.stats.analysis_time,
            'stats': self.stats.to_dict(),
            'models_used': {
                'filter_model': self.quick_model,
                'analysis_model': self.deep_model,
            },
            'parameters': {
                'max_context_lines': self.max_context_lines,
                'filter_threshold': filter_threshold,
                'caching_enabled': self.enable_cache,
                'rate_limit_delay': self.rate_limit_delay,
            }
        }
        
        # Sort findings by AI score (highest first)
        findings_with_scores = []
        findings_without_scores = []
        
        for finding in findings:
            if ('ai_analysis' in finding and 
                'exploitability_score' in finding['ai_analysis'] and
                not finding['ai_analysis'].get('error', False)):
                findings_with_scores.append(finding)
            else:
                findings_without_scores.append(finding)
        
        findings_with_scores.sort(
            key=lambda x: x['ai_analysis']['exploitability_score'],
            reverse=True
        )
        
        results['findings'] = findings_with_scores + findings_without_scores
        
        # Print summary with top findings
        self._print_summary(results)
        
        return results
    
    def _calculate_smart_threshold(self, num_findings: int) -> int:
        """
        Calculate smart number of findings to analyze based on total count
        
        Args:
            num_findings: Total number of findings
            
        Returns:
            Number of findings to analyze
        """
        if num_findings <= 5:
            return num_findings  # Analyze all if few findings
        elif num_findings <= 10:
            return max(num_findings // 2, 3)  # At least 3
        elif num_findings <= 30:
            return min(10, num_findings)  # Cap at 10
        elif num_findings <= 100:
            return min(15, int(num_findings * 0.2))  # 20%, cap at 15
        else:
            return 20  # Max 20 for large sets
    
    def _quick_filter(
        self,
        findings: List[Dict],
        target_count: int
    ) -> List[int]:
        """
        Quick filter to identify promising findings using cheap model
        
        Args:
            findings: List of vulnerability findings
            target_count: Number of findings to select
            
        Returns:
            List of indices of promising findings
        """
        
        # Build summary of findings
        findings_summary = ""
        for i, finding in enumerate(findings):
            file_name = Path(finding['file']).name
            findings_summary += (
                f"{i}. [{finding['severity']}] {finding['tool']}: "
                f"{finding['message'][:80]}\n"
                f"   File: {file_name}:{finding['line']}\n\n"
            )
        
        prompt = f"""You are a security researcher performing initial triage of vulnerability findings.

TASK: Review these {len(findings)} findings and identify the {target_count} most promising ones for deep analysis.

FINDINGS:
{findings_summary}

SELECTION CRITERIA:
✓ HIGH PRIORITY (select these):
  - Buffer overflows, heap overflows, UAF
  - Array out-of-bounds access
  - Integer overflows in size calculations
  - Injection vulnerabilities (command, SQL, etc)
  - Format string vulnerabilities
  - Race conditions
  - Use of untrusted data in dangerous operations

✗ LOW PRIORITY (skip these):
  - Generic "use safer alternative" warnings without context
  - Suggestions to use memcpy_s (unless clear vulnerability)
  - Code style warnings
  - Issues in test/example/demo code
  - Hardcoded values (unless credentials)

SELECT APPROXIMATELY {target_count} findings ({int(target_count/len(findings)*100)}% of total).

Respond with JSON only:
{{
  "promising_indices": [0, 3, 7, 12, ...],
  "reasoning": "Brief explanation of why these were selected"
}}
"""
        
        try:
            response = self._api_call_with_retry(
                lambda: self.client.chat.completions.create(
                    model=self.quick_model,
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0
                )
            )
            
            self.stats.api_calls += 1
            
            # Track usage
            if hasattr(response, 'usage'):
                self._track_usage(response.usage)
            
            # Parse response
            data = self._extract_json_from_response(
                response.choices[0].message.content
            )
            
            promising = data.get('promising_indices', [])
            reasoning = data.get('reasoning', 'No reasoning provided')
            
            # Validate indices
            promising = [i for i in promising if 0 <= i < len(findings)]
            
            self._log(f"  Filter reasoning: {reasoning}")
            
            # Ensure we have results
            if not promising and findings:
                self._log("  Warning: Filter returned empty, using fallback")
                return self._fallback_filter(findings, target_count)
            
            return promising[:target_count]
            
        except Exception as e:
            self._log(f"   Filter failed ({type(e).__name__}: {str(e)[:50]})")
            self._log(f"  Falling back to severity-based selection")
            
            return self._fallback_filter(findings, target_count)
    
    def _fallback_filter(self, findings: List[Dict], target_count: int) -> List[int]:
        """
        Fallback filter based on severity
        
        Args:
            findings: List of findings
            target_count: Number to select
            
        Returns:
            List of indices
        """
        critical = [i for i, f in enumerate(findings) if f['severity'] == 'CRITICAL']
        high = [i for i, f in enumerate(findings) if f['severity'] == 'HIGH']
        medium = [i for i, f in enumerate(findings) if f['severity'] == 'MEDIUM']
        
        return (critical + high + medium)[:target_count]
    
    def _deep_analysis(
        self,
        finding: Dict,
        code_context: str
    ) -> AIAnalysis:
        """
        Perform deep analysis of a single finding using advanced model
        
        Args:
            finding: Vulnerability finding dictionary
            code_context: Code snippet around the vulnerability
            
        Returns:
            AIAnalysis object with detailed results
        """
        
        prompt = self._build_deep_prompt(finding, code_context)
        
        response = self._api_call_with_retry(
            lambda: self.client.chat.completions.create(
                model=self.deep_model,
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
        )
        
        self.stats.api_calls += 1
        
        # Track usage
        if hasattr(response, 'usage'):
            self._track_usage(response.usage)
        
        # Parse response
        data = self._extract_json_from_response(
            response.choices[0].message.content
        )
        
        # Create AIAnalysis object
        return AIAnalysis(
            exploitability_score=int(data.get('exploitability_score', 50)),
            difficulty=data.get('difficulty', 'medium'),
            is_exploitable=bool(data.get('is_exploitable', False)),
            attack_vector=data.get('attack_vector', 'Unknown attack vector'),
            reasoning=data.get('reasoning', []),
            mitigations=data.get('mitigations', []),
            confidence=data.get('confidence', 'medium'),
            time_to_exploit=data.get('time_to_exploit', 'Unknown'),
            similar_cves=data.get('similar_cves', []),
        )
    
    def _build_deep_prompt(self, finding: Dict, code_context: str) -> str:
        """
        Build comprehensive analysis prompt
        
        Args:
            finding: Finding dictionary
            code_context: Code snippet
            
        Returns:
            Formatted prompt string
        """
        
        # Extract information
        file_name = Path(finding['file']).name
        function = finding.get('additional_info', {}).get('issue_context', 'unknown')
        
        prompt = f"""You are an expert security researcher analyzing a potential vulnerability.

**VULNERABILITY REPORT:**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ID:           {finding['id']}
Tool:         {finding['tool']}
Severity:     {finding['severity']}
Rule:         {finding.get('rule_id', 'N/A')}
Message:      {finding['message']}

Location:     {file_name}:{finding['line']}
Function:     {function}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**SOURCE CODE CONTEXT:**
```c
{code_context}
```

**YOUR MISSION:**
You are a CRITICAL security auditor. Your job is to determine if this is a REAL vulnerability or a FALSE POSITIVE.
Many static analysis tools report false positives. Be skeptical and thorough.

**CRITICAL ANALYSIS STEPS:**

1. **Is This a FALSE POSITIVE? (Check First!)**
    Look for evidence this is NOT exploitable:
   - Is memory allocated BEFORE use? (malloc/calloc with correct size)
   - Are there bounds checks? (if statements checking size/length)
   - Is the buffer size calculated correctly? (strlen, sizeof, etc.)
   - Are there safety functions used? (strncpy instead of strcpy, snprintf instead of sprintf)
   - Does the code check return values and error conditions?
   
    Common FALSE POSITIVE patterns:
   - Array access with proper length calculations beforehand
   - Buffer operations where size is pre-calculated
   - Functions that look unsafe but are used correctly by callers
   - Warnings about theoretical issues that can't happen in practice

2. **If NOT False Positive - Validate Real Exploitation:**
   - Can attacker ACTUALLY control the problematic input?
   - Can attacker reach this code path?
   - Are there ANY checks that prevent exploitation?
   - What is the EXACT attack scenario?

3. **Exploitation Difficulty (BE REALISTIC):**
   - Are there memory protections? (ASLR, DEP, Stack Canaries)
   - How complex is triggering the bug?
   - What knowledge/skills needed?

4. **Scoring Guidelines (BE STRICT):**
   - 0-20:   FALSE POSITIVE or not exploitable (use this often!)
   - 20-40:  Theoretical issue, very hard to exploit, strong mitigations
   - 40-60:  Real bug but difficult to exploit, needs specific conditions
   - 60-80:  Exploitable with effort, some mitigations present
   - 80-100: Easily exploitable, high impact, minimal protections
   
5. **Real-World Examples:**
   
   Example 1 - FALSE POSITIVE (Score: 10):
   ```c
   size_t len = calculate_size(input);  // ← Size calculated first
   char *buf = malloc(len);              // ← Correct allocation
   memcpy(buf, input, len);              // ← Safe! Not a bug.
   ```
   
   Example 2 - REAL BUG (Score: 75):
   ```c
   char buf[10];
   strcpy(buf, user_input);  // ← No size check! Attacker controls user_input
   ```
   
   Example 3 - PROTECTED (Score: 35):
   ```c
   if (size > MAX_SIZE) return;  // ← Bounds check present
   memcpy(dest, src, size);       // ← Protected, hard to exploit
   ```

**IMPORTANT:**
- Default to LOW scores (0-40) unless you see CLEAR exploitation path
- If you see ANY safety checks, reduce score significantly
- If memory is allocated properly BEFORE use → FALSE POSITIVE (0-20)
- Only give 60+ if you can describe EXACT exploitation steps
- Don't cite random CVEs - only if truly similar

**OUTPUT FORMAT (JSON ONLY, NO OTHER TEXT):**
{{
  "exploitability_score": <integer 0-100>,
  "difficulty": "<trivial|easy|medium|hard|very_hard>",
  "is_exploitable": <boolean>,
  "attack_vector": "<detailed step-by-step exploitation explanation>",
  "reasoning": [
    "<reason 1: why this score/difficulty>",
    "<reason 2: supporting evidence>",
    "<reason 3: mitigating or aggravating factors>",
    "..."
  ],
  "mitigations": [
    "<fix 1: specific code changes>",
    "<fix 2: defensive measures>",
    "..."
  ],
  "confidence": "<low|medium|high|very_high>",
  "time_to_exploit": "<estimate for skilled attacker, e.g., '1-2 hours', '2-3 days'>",
  "similar_cves": ["<CVE-YYYY-NNNNN>", "..."]
}}

**CRITICAL INSTRUCTIONS:**
- Be realistic and honest about exploitability
- Consider the FULL context, not just the presence of unsafe functions
- Don't over-rate generic warnings without clear attack paths
- Provide actionable, specific reasoning
- If uncertain, state it clearly in confidence level

Respond with VALID JSON only. No markdown, no explanations outside JSON.
"""
        
        return prompt
    
    def _extract_json_from_response(self, text: str) -> dict:
        """
        Robust JSON extraction from AI response
        
        Handles:
        - Markdown code blocks
        - Extra text before/after JSON
        - Malformed responses
        
        Args:
            text: Raw AI response
            
        Returns:
            Parsed JSON dictionary (or default on failure)
        """
        text = text.strip()
        
        # Remove markdown code blocks
        if text.startswith('```json'):
            text = text[7:]
        if text.startswith('```'):
            text = text[3:]
        if text.endswith('```'):
            text = text[:-3]
        text = text.strip()
        
        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try to extract JSON object from text
        start = text.find('{')
        end = text.rfind('}')
        
        if start != -1 and end != -1 and end > start:
            json_str = text[start:end+1]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
        
        # Default fallback structure
        return {
            'exploitability_score': 50,
            'difficulty': 'unknown',
            'is_exploitable': False,
            'attack_vector': 'Failed to parse AI response',
            'reasoning': [f'Parse error. Response: {text[:100]}'],
            'mitigations': ['Manual review required'],
            'confidence': 'low',
            'time_to_exploit': 'Unknown',
            'similar_cves': []
        }
    
    def _api_call_with_retry(
        self,
        func,
        max_retries: Optional[int] = None
    ):
        """
        Execute API call with rate limiting and exponential backoff retry
        
        Args:
            func: Function to call (lambda that returns API response)
            max_retries: Maximum retry attempts (uses self.max_retries if None)
            
        Returns:
            API response
            
        Raises:
            Exception: If all retries fail
        """
        if max_retries is None:
            max_retries = self.max_retries
        
        for attempt in range(max_retries):
            # Rate limiting
            if self.last_request_time:
                elapsed = (datetime.now() - self.last_request_time).total_seconds()
                if elapsed < self.rate_limit_delay:
                    time.sleep(self.rate_limit_delay - elapsed)
            
            try:
                result = func()
                self.last_request_time = datetime.now()
                return result
            
            except Exception as e:
                error_str = str(e).lower()
                
                # Check if error is retryable
                is_retryable = any(x in error_str for x in [
                    'timeout', 'connection', 'network', '5', 'rate'
                ])
                
                if is_retryable and attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    self._log(f"    ⏳ API error, retrying in {wait_time}s... "
                             f"(attempt {attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                
                # Non-retryable error or final attempt
                raise
        
        raise Exception(f"API call failed after {max_retries} attempts")
    
    def _track_usage(self, usage):
        """
        Track actual token usage and calculate cost
        
        Args:
            usage: Usage object from Groq API response
        """
        if hasattr(usage, 'prompt_tokens'):
            input_tokens = usage.prompt_tokens
            output_tokens = usage.completion_tokens
            
            self.stats.total_input_tokens += input_tokens
            self.stats.total_output_tokens += output_tokens
            
            # Calculate actual cost
            cost = (
                (input_tokens / 1_000_000) * self.PRICING['input'] +
                (output_tokens / 1_000_000) * self.PRICING['output']
            )
            self.stats.total_cost += cost
    
    def _get_cache_key(self, finding: Dict) -> str:
        """
        Generate unique cache key for a finding
        
        Args:
            finding: Finding dictionary
            
        Returns:
            SHA256 hash as hex string
        """
        key_data = f"{finding['file']}:{finding['line']}:{finding['message']}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_cached_analysis(self, finding: Dict) -> Optional[AIAnalysis]:
        """
        Try to get cached analysis for a finding
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Cached AIAnalysis or None if not found/invalid
        """
        if not self.enable_cache:
            return None
        
        cache_key = self._get_cache_key(finding)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                return AIAnalysis(**data)
            except Exception:
                # Invalid cache file, ignore
                pass
        
        return None
    
    def _cache_analysis(self, finding: Dict, analysis: AIAnalysis):
        """
        Cache analysis result to disk
        
        Args:
            finding: Finding dictionary
            analysis: AIAnalysis object to cache
        """
        if not self.enable_cache:
            return
        
        cache_key = self._get_cache_key(finding)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(analysis.to_dict(), f, indent=2)
        except Exception:
            # Silently fail if caching doesn't work
            pass
    
    def _resolve_file_path(self, file_path: str) -> Optional[Path]:
        """
        Smart path resolution with multiple fallback strategies
        
        Args:
            file_path: Path to resolve
            
        Returns:
            Resolved Path object or None if not found
        """
        # Strategy 1: Direct path
        path = Path(file_path)
        if path.exists():
            return path
        
        # Strategy 2: Relative to project root (if set)
        if self.project_root:
            # Try relative to project root
            path = self.project_root / Path(file_path).name
            if path.exists():
                return path
            
            # Try searching within project root
            file_name = Path(file_path).name
            for found_file in self.project_root.rglob(file_name):
                return found_file
        
        # Strategy 3: Extract from downloaded_repos onwards
        if 'downloaded_repos' in file_path:
            parts = Path(file_path).parts
            try:
                idx = parts.index('downloaded_repos')
                relative_path = Path(*parts[idx:])
                
                path = Path.cwd() / relative_path
                if path.exists():
                    return path
            except ValueError:
                pass
        
        # Strategy 4: Relative to CWD
        path = Path.cwd() / file_path
        if path.exists():
            return path
        
        # Strategy 5: Search for file by name in common directories
        file_name = Path(file_path).name
        search_dirs = [
            Path.cwd() / 'downloaded_repos',
            Path.cwd() / 'data',
            Path.cwd(),
        ]
        
        for search_dir in search_dirs:
            if search_dir.exists():
                for found_file in search_dir.rglob(file_name):
                    return found_file
        
        return None
    
    def _get_enhanced_context(self, finding: Dict) -> str:
        """
        Get enhanced context including function definition and caller information
        
        Args:
            finding: Vulnerability finding
            
        Returns:
            Enhanced context string with multiple sections
        """
        sections = []
        
        # 1. Main context around vulnerability
        main_context = self._get_code_context(
            finding['file'],
            finding['line'],
            self.max_context_lines
        )
        sections.append("=== CODE AROUND VULNERABILITY ===")
        sections.append(main_context)
        
        # 2. Try to find the function definition
        function_name = finding.get('additional_info', {}).get('issue_context', '')
        if function_name:
            func_def = self._find_function_definition(finding['file'], function_name)
            if func_def:
                sections.append("\n=== FULL FUNCTION DEFINITION ===")
                sections.append(func_def)
        
        # 3. Look for related safety functions (malloc, strlen, sizeof patterns)
        safety_checks = self._find_safety_patterns(finding['file'], finding['line'])
        if safety_checks:
            sections.append("\n=== SAFETY CHECKS FOUND ===")
            sections.append(safety_checks)
        
        return "\n".join(sections)
    
    def _find_function_definition(self, file_path: str, function_name: str) -> Optional[str]:
        """Find and return the complete function definition"""
        try:
            path = self._resolve_file_path(file_path)
            if not path or not function_name:
                return None
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Look for function definition pattern
            in_function = False
            func_lines = []
            brace_count = 0
            
            for i, line in enumerate(lines):
                # Start of function?
                if function_name in line and '(' in line and not in_function:
                    in_function = True
                    func_lines.append(f"{i+1:4d}: {line.rstrip()}")
                    brace_count += line.count('{') - line.count('}')
                elif in_function:
                    func_lines.append(f"{i+1:4d}: {line.rstrip()}")
                    brace_count += line.count('{') - line.count('}')
                    
                    # End of function?
                    if brace_count == 0 and '{' in ''.join(func_lines):
                        break
                
                # Limit size
                if len(func_lines) > 80:
                    func_lines.append("... [function too long, truncated]")
                    break
            
            if func_lines and len(func_lines) > 1:
                return "\n".join(func_lines)
            return None
            
        except Exception:
            return None
    
    def _find_safety_patterns(self, file_path: str, line_number: int) -> Optional[str]:
        """Look for safety patterns like malloc, bounds checks, etc. near the vulnerability"""
        try:
            path = self._resolve_file_path(file_path)
            if not path:
                return None
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Look ±20 lines for safety patterns
            start = max(0, line_number - 20)
            end = min(len(lines), line_number + 20)
            
            safety_patterns = []
            keywords = ['malloc', 'calloc', 'realloc', 'strlen', 'sizeof', 'if', 'CHECK', 'ASSERT']
            
            for i in range(start, end):
                line = lines[i]
                if any(keyword in line for keyword in keywords):
                    safety_patterns.append(f"{i+1:4d}: {line.rstrip()}")
            
            if safety_patterns:
                return "\n".join(safety_patterns[:15])  # Limit to 15 lines
            return None
            
        except Exception:
            return None
    
    def _get_specific_line(self, file_path: str, line_number: int) -> str:
        """
        Extract the specific line of code where vulnerability is located
        
        Args:
            file_path: Path to source file
            line_number: Line number (1-indexed)
            
        Returns:
            The specific line of code (stripped)
        """
        try:
            path = self._resolve_file_path(file_path)
            if not path:
                return "[File not found]"
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if i == line_number:
                        return line.strip()
            
            return "[Line number out of range]"
            
        except Exception as e:
            return f"[Error: {type(e).__name__}]"
    
    def _get_code_context(
        self,
        file_path: str,
        line_number: int,
        window: int
    ) -> str:
        """
        Extract code context around a vulnerability (memory efficient)
        
        Args:
            file_path: Path to source file
            line_number: Line number of the finding
            window: Number of lines before/after to include
            
        Returns:
            Formatted code snippet with line numbers
        """
        
        try:
            path = self._resolve_file_path(file_path)
            if not path:
                return f"[Error: File not found: {file_path}]"
            
            # Calculate bounds
            start_line = max(1, line_number - window)
            end_line = line_number + window
            
            context_lines = []
            
            # Read only the lines we need (memory efficient)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    if i < start_line:
                        continue
                    if i > end_line:
                        break
                    
                    # Mark the vulnerability line
                    marker = "  ← VULNERABILITY" if i == line_number else ""
                    context_lines.append(f"{i:4d}: {line.rstrip()}{marker}")
            
            return "\n".join(context_lines)
            
        except Exception as e:
            return f"[Error reading file: {type(e).__name__}: {str(e)[:50]}]"
    
    def _create_error_analysis(self, error: Exception) -> dict:
        """
        Create informative error analysis structure
        
        Args:
            error: Exception that occurred
            
        Returns:
            Dictionary with error details and safe defaults
        """
        return {
            'error': True,
            'error_type': type(error).__name__,
            'error_message': str(error)[:200],
            'exploitability_score': 0,
            'difficulty': 'unknown',
            'is_exploitable': False,
            'attack_vector': f'Analysis failed: {type(error).__name__}',
            'reasoning': [
                f'Analysis error: {type(error).__name__}',
                'Manual review recommended',
                str(error)[:100]
            ],
            'mitigations': ['Review manually', 'Re-run analysis'],
            'confidence': 'none',
            'time_to_exploit': 'Unknown',
            'similar_cves': []
        }
    
    def _print_summary(self, results: Dict):
        """Print comprehensive analysis summary with top findings"""
        
        self._log("\n" + "=" * 70)
        self._log("ANALYSIS COMPLETE")
        self._log("=" * 70 + "\n")
        
        self._log(" STATISTICS:")
        self._log(f"  Total findings:        {self.stats.total_findings}")
        self._log(f"  Filtered for analysis: {self.stats.filtered_findings}")
        self._log(f"  Successfully analyzed: {self.stats.analyzed_findings}")
        self._log(f"  Exploitable findings:  {self.stats.exploitable_count}")
        
        if self.enable_cache:
            self._log(f"  Cache hits:            {self.stats.cache_hits}")
        
        self._log(f"  API calls made:        {self.stats.api_calls}")
        self._log(f"  Analysis duration:     {self.stats.analysis_time:.1f}s")
        
        # Show actual costs if we have token data
        if self.stats.total_input_tokens > 0:
            self._log(f"\n ACTUAL COSTS:")
            self._log(f"  Input tokens:          {self.stats.total_input_tokens:,}")
            self._log(f"  Output tokens:         {self.stats.total_output_tokens:,}")
            self._log(f"  Total cost:            ${self.stats.total_cost:.4f}")
        
        self._log("")
        
        # Display top exploitable findings
        findings = results.get('findings', [])
        analyzed = [f for f in findings if 'ai_analysis' in f and 
                    not f['ai_analysis'].get('error', False)]
        exploitable = [f for f in analyzed if f['ai_analysis'].get('is_exploitable')]
        
        if exploitable:
            self._log("=" * 70)
            self._log(f" TOP {min(5, len(exploitable))} EXPLOITABLE FINDINGS")
            self._log("=" * 70 + "\n")
            
            for i, finding in enumerate(exploitable[:5], 1):
                ai = finding['ai_analysis']
                file_name = Path(finding['file']).name
                
                self._log(f"{i}. {finding['id']} - Exploitability: {ai['exploitability_score']}/100")
                self._log(f"   {finding['message'][:80]}")
                self._log(f"    Location: {file_name}:{finding['line']}")
                self._log(f"    Difficulty: {ai['difficulty']} | Time: {ai['time_to_exploit']}")
                self._log(f"    Attack: {ai['attack_vector'][:100]}...")
                self._log(f"   Confidence: {ai['confidence']}")
                
                if ai.get('similar_cves'):
                    self._log(f"    Similar CVEs: {', '.join(ai['similar_cves'][:3])}")
                
                self._log("")
        else:
            self._log("\n✓ No exploitable vulnerabilities identified by AI analysis.")
    
    def _log(self, message: str):
        """Print message if verbose mode enabled"""
        if self.verbose:
            print(message)


# ============================================================================
# Helper Functions
# ============================================================================

def display_top_findings(results: Dict, top_n: int = 5):
    """
    Display top N exploitable findings in formatted output
    
    Args:
        results: Enhanced results dictionary
        top_n: Number of top findings to display
    """
    
    findings = results.get('findings', [])
    
    # Filter findings with valid AI analysis
    analyzed = [f for f in findings if 'ai_analysis' in f and 
                not f['ai_analysis'].get('error', False)]
    exploitable = [f for f in analyzed if f['ai_analysis'].get('is_exploitable')]
    
    if not exploitable:
        print("\n✓ No exploitable vulnerabilities identified by AI analysis.")
        return
    
    print(f"\n{'='*70}")
    print(f" TOP {min(top_n, len(exploitable))} EXPLOITABLE FINDINGS")
    print(f"{'='*70}\n")
    
    for i, finding in enumerate(exploitable[:top_n], 1):
        ai = finding['ai_analysis']
        file_name = Path(finding['file']).name
        
        print(f"{i}. {finding['id']} - Exploitability: {ai['exploitability_score']}/100")
        print(f"   {finding['message'][:80]}")
        print(f"   Location: {file_name}:{finding['line']}")
        print(f"    Difficulty: {ai['difficulty']} | Time: {ai['time_to_exploit']}")
        print(f"   Attack: {ai['attack_vector'][:100]}...")
        print(f"   Confidence: {ai['confidence']}")
        
        if ai.get('similar_cves'):
            print(f"    Similar CVEs: {', '.join(ai['similar_cves'][:3])}")
        
        print()


# ============================================================================
# Command-Line Interface
# ============================================================================

def main():
    """
    Command-line interface for AI vulnerability analyzer
    
    Usage:
        python ai_analyzer.py <merged_results.json> [options]
    """
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='AI-Powered Vulnerability Exploitability Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python ai_analyzer.py data/results/cJSON/merged_results.json
  
  # Custom threshold (50% of findings)
  python ai_analyzer.py results.json --threshold 0.5
  
  # Use different model
  python ai_analyzer.py results.json --model llama-3.3-70b-versatile
  
  # Disable caching
  python ai_analyzer.py results.json --no-cache
  
  # Quiet mode
  python ai_analyzer.py results.json --quiet

Environment:
  GROQ_API_KEY    Required. Your Groq API key.
                  Get it from: https://console.groq.com/keys
        """
    )
    
    parser.add_argument(
        'results_file',
        type=Path,
        help='Path to merged_results.json file'
    )
    
    parser.add_argument(
        '--threshold',
        type=float,
        default=None,
        help='Percentage of findings to analyze (0.0-1.0). Auto if not specified.'
    )
    
    parser.add_argument(
        '--model',
        default='llama-3.3-70b-versatile',
        help='Deep analysis model (default: llama-3.3-70b-versatile)'
    )
    
    parser.add_argument(
        '--context-lines',
        type=int,
        default=30,
        help='Lines of code context to extract (default: 30)'
    )
    
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable result caching'
    )
    
    parser.add_argument(
        '--cache-dir',
        type=Path,
        default=None,
        help='Custom cache directory (default: ~/.vuln_analyzer_cache)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=float,
        default=0.5,
        help='Delay between API calls in seconds (default: 0.5)'
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.results_file.exists():
        print(f" Error: File not found: {args.results_file}")
        sys.exit(1)
    
    if args.threshold is not None and not 0.0 <= args.threshold <= 1.0:
        print(f" Error: Threshold must be between 0.0 and 1.0")
        sys.exit(1)
    
    # Check for API key
    if not os.environ.get('GROQ_API_KEY'):
        print(" Error: GROQ_API_KEY environment variable not set")
        print("\nSet it with:")
        print("  export GROQ_API_KEY='gsk_...'")
        print("\nGet your API key from: https://console.groq.com/keys")
        sys.exit(1)
    
    try:
        # Initialize analyzer
        analyzer = AIVulnerabilityAnalyzer(
            deep_model=args.model,
            max_context_lines=args.context_lines,
            verbose=not args.quiet,
            enable_cache=not args.no_cache,
            cache_dir=args.cache_dir,
            rate_limit_delay=args.rate_limit
        )
        
        # Run analysis
        enhanced_results = analyzer.analyze_merged_results(
            args.results_file,
            filter_threshold=args.threshold
        )
        
        # Save results
        output_path = args.results_file.parent / 'ai_enhanced_results.json'
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(enhanced_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n Enhanced results saved to: {output_path}")
        
        # Display top findings (already displayed in analyze_merged_results)
        # display_top_findings(enhanced_results, top_n=5)
        
        print(f"\n{'='*70}")
        print(" Analysis complete! Review ai_enhanced_results.json for full details.")
        print(f"{'='*70}\n")
        
    except KeyboardInterrupt:
        print("\n\n️  Analysis interrupted by user")
        sys.exit(130)
    
    except Exception as e:
        print(f"\n Error during analysis: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()