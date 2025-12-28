# GenAI Integration - LLM-as-a-Judge Implementation

## Overview

VulnMaster now integrates Claude Sonnet 4 (claude-sonnet-4-20250514) to reduce false positives and generate context-aware code fixes. The implementation follows a hybrid approach: regex-based detection triggers LLM analysis for validation.

## Architecture

### 1. LLM Service Layer (`backend/app/services/llm_engine.py`)

**LLMEngine** - Singleton service that wraps Anthropic Async client:

- **Dependency Injection**: Client instantiated once and reused across requests
- **Token Management**: `TokenEstimator` class truncates inputs exceeding 100k tokens
- **Rate Limiting**: `RateLimiter` enforces max 10 AI requests per minute
- **Fail-Safe**: Falls back to regex-only detection if LLM unavailable or fails

**Key Methods:**
- `analyze_false_positive()`: LLM-as-a-Judge for false positive reduction
- `generate_remediation_code()`: Streams secure code fixes via async generator

### 2. Prompt Management (`backend/app/prompts.py`)

All system prompts stored in centralized file:

- **ANALYSIS_SYSTEM_PROMPT**: Instructions for false positive analysis
- **ANALYSIS_USER_PROMPT_TEMPLATE**: Template for vulnerability judgment requests
- **REMEDIATION_SYSTEM_PROMPT**: Instructions for secure code generation
- **REMEDIATION_USER_PROMPT_TEMPLATE**: Template for remediation requests

### 3. Hybrid Detection (`backend/scanners/sqli.py`)

**Modified SQLInjectionScanner** to use hybrid regex + LLM approach:

1. **Regex Detection**: Traditional pattern matching triggers first
2. **LLM Validation**: If regex matches, sanitized response snippet sent to Claude
3. **Confidence Threshold**: Only flags vulnerability if LLM confidence > 0.9
4. **Fallback**: If LLM unavailable, uses regex-only (allows detection)

**Key Changes:**
- Added `llm_engine` parameter to `__init__()`
- Modified `_test_query_parameter()` and `_test_form_input()` methods
- Added `_sanitize_response()` to remove sensitive data (IPs, emails, tokens)

### 4. Automated Remediation (`backend/app/routers/scans.py`)

**New Endpoint**: `POST /api/scans/{scan_id}/vulnerabilities/{vulnerability_id}/remediate`

- Fetches vulnerability details from database
- Streams remediation code via Server-Sent Events (SSE)
- User watches code being "written" live
- Falls back to static recommendation if LLM fails

**Response Format (SSE):**
```
data: {"type": "start", "vulnerability": "SQL Injection"}

data: {"type": "chunk", "content": "from sqlalchemy..."}

data: {"type": "complete"}
```

### 5. Rate Limiting & Cost Control

**RateLimiter** class:
- Sliding window algorithm (60-second window)
- Max 10 requests per minute
- Automatic wait if limit exceeded
- Thread-safe using asyncio.Lock

**Token Management:**
- Rough estimation: 1 token ≈ 4 characters
- Truncates inputs to 100k tokens max
- Logs warnings when truncation occurs

**Fail-Safe Mechanisms:**
- If `ANTHROPIC_API_KEY` not set: LLM features disabled, regex-only mode
- If API call fails: Falls back to regex detection (doesn't block scans)
- If timeout/error: Returns default confidence (0.5) to allow detection

## Configuration

### Environment Variables

```bash
# Required for LLM features
ANTHROPIC_API_KEY=your_api_key_here
```

### Model Configuration

- **Model**: `claude-sonnet-4-20250514`
- **Max Tokens**: 4096 per response
- **Max Input Tokens**: 100,000 (truncated if exceeded)
- **Temperature**: 0.1 (analysis), 0.2 (remediation)

### Rate Limits

- **Max Requests**: 10 per minute
- **Window**: 60 seconds
- **Behavior**: Wait if limit exceeded (prevents API credit drain)

## Usage Examples

### False Positive Analysis (Automatic)

The scanner automatically uses LLM validation when regex triggers:

```python
# In SQLInjectionScanner._test_query_parameter()
if regex_pattern_matches:
    llm_result = await self.llm_engine.analyze_false_positive(
        vulnerability_type="SQL Injection",
        response_snippet=sanitized_snippet,
        payload=payload,
        parameter=param_name
    )
    
    if llm_result["confidence"] > 0.9 and llm_result["is_genuine"]:
        # Flag as vulnerability
        vulnerabilities.append(vuln)
```

### Remediation Generation (API)

```bash
# Request remediation for a vulnerability
curl -X POST http://localhost:8000/api/scans/1/vulnerabilities/5/remediate \
  --no-buffer

# Response (SSE stream):
data: {"type":"start","vulnerability":"SQL Injection"}
data: {"type":"chunk","content":"from sqlalchemy.ext.asyncio import AsyncSession\n"}
data: {"type":"chunk","content":"from sqlalchemy import select\n\n"}
...
data: {"type":"complete"}
```

### Frontend Integration (SSE)

```javascript
const eventSource = new EventSource(
  `/api/scans/${scanId}/vulnerabilities/${vulnId}/remediate`
);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'chunk') {
    // Append code chunk to editor
    codeEditor.append(data.content);
  } else if (data.type === 'complete') {
    eventSource.close();
  }
};
```

## Files Created/Modified

### New Files
- `backend/app/prompts.py` - System prompts for LLM
- `backend/app/services/llm_engine.py` - LLM service layer

### Modified Files
- `backend/scanners/sqli.py` - Added hybrid detection logic
- `backend/app/services/scanner_service.py` - Pass LLM engine to scanners
- `backend/app/routers/scans.py` - Added remediation endpoint
- `backend/requirements.txt` - Added `anthropic>=0.34.0`

## Testing

### Test LLM Engine

```python
from app.services.llm_engine import LLMEngine

llm = LLMEngine.get_instance()

# Test false positive analysis
result = await llm.analyze_false_positive(
    vulnerability_type="SQL Injection",
    response_snippet="Error: SQL syntax near 'OR 1=1'",
    payload="' OR 1=1--",
    parameter="id"
)

print(f"Confidence: {result['confidence']}")
print(f"Is Genuine: {result['is_genuine']}")
```

### Test Remediation

```python
async for chunk in llm.generate_remediation_code(
    vulnerability_type="SQL Injection",
    url="http://example.com/search?id=1",
    parameter="id",
    payload="' OR 1=1--"
):
    print(chunk, end='')
```

## Security Considerations

1. **API Key**: Store `ANTHROPIC_API_KEY` in environment variables, never commit
2. **Data Sanitization**: Response snippets sanitized before sending to LLM (IPs, emails, tokens removed)
3. **Rate Limiting**: Prevents API credit exhaustion during large scans
4. **Fail-Safe**: Tool remains functional even if LLM unavailable

## Performance Impact

- **Detection**: Adds ~1-2 seconds per regex match (LLM API call)
- **Remediation**: Streaming response, no blocking
- **Rate Limiting**: Automatic throttling prevents API overload
- **Token Costs**: ~500-2000 tokens per analysis, ~2000-4000 per remediation

## Future Enhancements

1. **Caching**: Cache LLM responses for similar vulnerabilities
2. **Batch Processing**: Analyze multiple detections in single LLM call
3. **Confidence Tuning**: Make confidence threshold configurable
4. **Multi-Model Support**: Support for other LLM providers (OpenAI, etc.)
5. **Fine-Tuning**: Fine-tune model on vulnerability dataset for better accuracy

## Troubleshooting

### LLM Not Working

1. Check `ANTHROPIC_API_KEY` is set: `echo $ANTHROPIC_API_KEY`
2. Verify API key is valid
3. Check rate limits (max 10 requests/min)
4. Review logs for error messages

### High False Positive Rate

1. Lower confidence threshold (currently 0.9)
2. Improve regex patterns to be more specific
3. Review LLM analysis logs for patterns

### Slow Scans

1. Rate limiting may cause delays (10 req/min)
2. Consider disabling LLM for non-critical scans
3. Use regex-only mode if speed is priority

## License & Ethics

⚠️ **EDUCATIONAL USE ONLY**

This tool is for authorized security testing only. Unauthorized scanning is illegal. The LLM integration is designed to improve accuracy, not to enable malicious activities.

