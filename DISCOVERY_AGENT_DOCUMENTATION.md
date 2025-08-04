# Discovery Agent Documentation

## Overview

The Discovery Agent is the foundational intelligence-gathering system for the AI Bug Bounty Scanner. It transforms the scanner from blind testing to intelligence-driven assessment by running FIRST before any vulnerability testing begins, building comprehensive application understanding through systematic reconnaissance.

## Architecture Transformation

### Before Discovery Agent
- All agents ran simultaneously against target URLs
- Agents made assumptions about what exists rather than discovering what actually exists
- High false positive rates due to blind testing
- Missed real vulnerabilities due to lack of context
- Independent agents with no shared intelligence

### After Discovery Agent
- Discovery Agent runs FIRST and completes before vulnerability testing
- Comprehensive application understanding guides all subsequent testing
- Reduced false positives through targeted testing
- Improved vulnerability detection through context-aware testing
- Coordinated assessment team with shared intelligence

## Core Capabilities

### 1. Application Structure Mapping
- **Purpose**: Systematically explores every accessible page within the application
- **Capabilities**:
  - Recursive crawling with configurable depth and page limits
  - Handles traditional server-rendered applications
  - Supports single-page applications with dynamic content
  - Recognizes complex navigation structures
  - Identifies different page types (login, admin, content, API, error)

### 2. Form Discovery and Analysis
- **Purpose**: Identifies and analyzes every form throughout the application
- **Capabilities**:
  - Catalogs form action URLs and submission methods
  - Analyzes parameter names, types, and validation requirements
  - Distinguishes form types (authentication, search, data entry, upload)
  - Detects hidden fields, default values, and client-side validation
  - Identifies CSRF protection and CAPTCHA mechanisms

### 3. Technology Stack Identification
- **Purpose**: Analyzes multiple indicators to determine underlying technologies
- **Capabilities**:
  - HTTP response header analysis for server and framework information
  - HTML source code analysis for framework-specific patterns
  - Database technology detection through error messages and timing
  - Content management system recognition
  - JavaScript framework and library identification

### 4. Authentication System Analysis
- **Purpose**: Handles authentication requirements and session management
- **Capabilities**:
  - Identifies login mechanisms (form-based, HTTP basic, OAuth)
  - Attempts authentication using provided credentials
  - Maintains session state throughout discovery process
  - Explores both authenticated and unauthenticated areas
  - Handles complex authentication flows and role-based access

## Data Structures

### DiscoveryContext
The central intelligence data structure that serves as the shared knowledge repository:

```python
@dataclass
class DiscoveryContext:
    target_url: str
    base_domain: str
    scan_timestamp: datetime
    pages_discovered: List[PageData]
    forms_discovered: List[FormData]
    technology_stack: TechnologyInfo
    authentication_system: AuthenticationInfo
    site_map: Dict[str, Any]
    input_vectors: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    security_headers: Dict[str, str]
    # ... additional fields
```

### FormData
Comprehensive form information structure:

```python
@dataclass
class FormData:
    url: str
    method: str
    action: str
    parameters: Dict[str, Any]
    hidden_fields: Dict[str, str]
    validation_patterns: List[str]
    form_type: str  # login, search, upload, data_entry, etc.
    csrf_token: Optional[str] = None
    captcha_present: bool = False
    javascript_validation: bool = False
```

### TechnologyInfo
Technology stack information:

```python
@dataclass
class TechnologyInfo:
    web_server: Optional[str] = None
    web_framework: Optional[str] = None
    programming_language: Optional[str] = None
    database: Optional[str] = None
    cms: Optional[str] = None
    javascript_frameworks: List[str] = None
    libraries: List[str] = None
    security_headers: Dict[str, str] = None
    ssl_info: Optional[Dict[str, Any]] = None
```

## Discovery Process

### Phase 1: Initial Reconnaissance (10%)
- Basic connectivity testing
- SSL certificate analysis
- Robots.txt and sitemap analysis
- Basic technology detection from headers

### Phase 2: Application Structure Mapping (30%)
- Main page discovery and analysis
- Recursive crawling of discovered links
- Admin path discovery
- API endpoint discovery
- Site map construction

### Phase 3: Form Discovery and Analysis (50%)
- Comprehensive form extraction from all pages
- Form type detection and classification
- Validation pattern analysis
- Security mechanism detection (CSRF, CAPTCHA)

### Phase 4: Authentication System Analysis (70%)
- Login form identification
- Authentication attempt with provided credentials
- Session management analysis
- Authenticated area discovery

### Phase 5: Technology Stack Identification (85%)
- Page content analysis for technology signatures
- JavaScript and CSS file analysis
- Database technology detection
- CMS identification

### Phase 6: Intelligence Compilation (95%)
- Metadata generation
- Discovery context persistence
- Quality assurance checks

### Phase 7: Validation and Quality Assurance (98%)
- Result validation
- Quality checks
- Error handling

## Integration with Scanner Architecture

### Discovery-First Methodology
The Discovery Agent fundamentally changes how the scanner operates:

1. **Discovery Agent runs FIRST** - Always executes before any vulnerability testing
2. **Intelligence sharing** - Discovery context is available to all subsequent agents
3. **Targeted testing** - Vulnerability agents use discovery intelligence for focused testing
4. **Reduced false positives** - Context-aware testing eliminates blind attempts
5. **Improved coverage** - Comprehensive discovery ensures no attack surfaces are missed

### Agent Integration
Other agents can now access discovery intelligence:

```python
# Example: Web App Agent using discovery intelligence
def scan_target(self, target_url: str, discovery_context: DiscoveryContext = None):
    if discovery_context:
        # Use discovered forms for targeted SQL injection testing
        forms = discovery_context.get_forms_by_type('data_entry')
        for form in forms:
            # Test specific form parameters with appropriate payloads
            self.test_sql_injection(form.url, form.parameters)
    else:
        # Fallback to traditional blind testing
        self.blind_sql_injection_testing(target_url)
```

## Configuration and Usage

### Basic Usage
```python
from agents.discovery_agent import DiscoveryAgent

# Initialize Discovery Agent
discovery_agent = DiscoveryAgent()

# Run discovery scan
results = await discovery_agent.scan_target(
    target_url="http://example.com",
    credentials={'username': 'admin', 'password': 'password'}
)

# Access discovery context
discovery_context = discovery_agent.get_discovery_context()
forms = discovery_agent.get_forms_by_type('login')
api_endpoints = discovery_agent.get_api_endpoints()
```

### Authentication Support
The Discovery Agent supports various authentication scenarios:

```python
# DVWA-style authentication
credentials = {'username': 'admin', 'password': 'password'}

# HTTP Basic Authentication
credentials = {'username': 'user', 'password': 'pass'}

# No authentication (public application)
credentials = None
```

### Configuration Options
The Discovery Agent uses the same configuration system as other agents:

```python
# Discovery Agent respects global scanner configuration
config = SecurityValidator.get_safe_scan_config()
# - User agent settings
# - Timeout configurations
# - Rate limiting
# - Request limits
```

## Validation and Testing

### Test Scenarios
The Discovery Agent includes comprehensive validation:

1. **DVWA Testing** - Validates against known vulnerable web application
2. **Public Application Testing** - Tests against public APIs and services
3. **Authentication Testing** - Validates login and session management
4. **Technology Detection** - Verifies technology stack identification
5. **Error Handling** - Tests graceful failure scenarios

### Quality Assurance
The Discovery Agent implements multiple quality checks:

- Minimum required information validation
- Technology stack completeness verification
- Form discovery validation
- Authentication system analysis verification
- Discovery quality scoring

## Error Handling and Edge Cases

### Network Issues
- Graceful handling of connectivity problems
- Timeout management
- Retry logic for transient failures

### Authentication Failures
- Proper error handling for invalid credentials
- Account lockout detection
- Session timeout handling

### Anti-Automation Measures
- Rate limiting detection and handling
- CAPTCHA recognition
- Bot detection avoidance

### Unusual Architectures
- JavaScript-heavy applications
- Single-page applications
- API-only applications
- Static websites

## Performance Considerations

### Scalability
- Configurable crawling depth and page limits
- Efficient URL deduplication
- Memory-conscious data structures
- Asynchronous request handling

### Resource Management
- Connection pooling
- Request rate limiting
- Memory usage optimization
- Disk I/O for persistence

## Security Considerations

### Safe Discovery
- Respects robots.txt
- Configurable request limits
- Rate limiting compliance
- Non-intrusive scanning

### Data Protection
- Secure storage of discovery data
- Credential handling
- Session data protection
- Audit trail maintenance

## Future Enhancements

### Planned Features
1. **Advanced JavaScript Analysis** - Dynamic content discovery
2. **API Documentation Parsing** - OpenAPI/Swagger integration
3. **GraphQL Endpoint Discovery** - Modern API detection
4. **Microservice Architecture Detection** - Distributed system mapping
5. **Cloud Service Integration** - AWS, Azure, GCP service detection

### Integration Improvements
1. **Real-time Intelligence Sharing** - Live discovery updates
2. **Collaborative Discovery** - Multi-agent discovery coordination
3. **External Tool Integration** - Amass, subfinder, etc.
4. **Machine Learning Enhancement** - Pattern recognition improvements

## Troubleshooting

### Common Issues
1. **Connection Timeouts** - Check network connectivity and target availability
2. **Authentication Failures** - Verify credentials and authentication method
3. **Limited Discovery** - Check for anti-automation measures
4. **Memory Issues** - Reduce crawling depth and page limits

### Debug Information
The Discovery Agent provides comprehensive logging:

```python
import logging
logging.getLogger('agents.discovery_agent').setLevel(logging.DEBUG)
```

### Performance Tuning
- Adjust `max_depth` and `max_pages` parameters
- Configure appropriate timeouts
- Optimize for specific application types
- Use targeted discovery for large applications

## Conclusion

The Discovery Agent represents a fundamental transformation in security scanning methodology. By implementing discovery-first intelligence gathering, it eliminates the blind testing approach that leads to false positives and missed vulnerabilities. The comprehensive intelligence it provides enables all subsequent vulnerability testing agents to operate with full context and understanding of the target application.

This architectural change transforms the scanner from a collection of independent guessing tools into a coordinated assessment platform with shared intelligence, significantly improving both the accuracy and effectiveness of security assessments.