"""
Recon service for managing reconnaissance plans and templates
"""

import json
from typing import Dict, List, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()

class ReconPhase:
    """A phase in a reconnaissance plan"""

    def __init__(self, name: str, description: str, tools: List[Dict], order: int):
        self.name = name
        self.description = description
        self.tools = tools
        self.order = order

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'tools': self.tools,
            'order': self.order
        }

class ReconPlan:
    """Human-readable reconnaissance plan"""

    def __init__(self, name: str, description: str, target_type: str,
                 phases: List[ReconPhase], estimated_duration: int = 0):
        self.name = name
        self.description = description
        self.target_type = target_type
        self.phases = sorted(phases, key=lambda x: x.order)
        self.estimated_duration = estimated_duration
        self.created = datetime.now()
        self.updated = datetime.now()

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'targetType': self.target_type,
            'phases': [phase.to_dict() for phase in self.phases],
            'estimatedDuration': self.estimated_duration,
            'created': self.created.isoformat(),
            'updated': self.updated.isoformat()
        }

class ReconService:
    """Service for managing reconnaissance plans and templates"""

    def __init__(self):
        self.builtin_templates = self._create_builtin_templates()

    def _create_builtin_templates(self) -> Dict[str, ReconPlan]:
        """Create built-in reconnaissance plan templates"""

        templates = {}

        # Quick Domain Recon
        templates['quick_domain'] = ReconPlan(
            name="Quick Domain Reconnaissance",
            description="Fast subdomain enumeration and basic information gathering for a domain",
            target_type="domain",
            phases=[
                ReconPhase(
                    name="Passive Subdomain Enumeration",
                    description="Discover subdomains without direct interaction",
                    tools=[
                        {
                            'tool': 'subfinder',
                            'args': {'passive': True, 'silent': True},
                            'description': 'Fast passive subdomain discovery'
                        },
                        {
                            'tool': 'amass',
                            'args': {'passive': True},
                            'description': 'Comprehensive passive enumeration'
                        }
                    ],
                    order=1
                ),
                ReconPhase(
                    name="DNS Analysis",
                    description="Analyze DNS configuration and records",
                    tools=[
                        {
                            'tool': 'dig',
                            'args': {'type': 'any'},
                            'description': 'DNS record enumeration'
                        }
                    ],
                    order=2
                )
            ],
            estimated_duration=15
        )

        # Full Domain Recon
        templates['full_domain'] = ReconPlan(
            name="Comprehensive Domain Reconnaissance",
            description="Complete domain analysis including active and passive techniques",
            target_type="domain",
            phases=[
                ReconPhase(
                    name="Passive Information Gathering",
                    description="Gather information without direct interaction",
                    tools=[
                        {
                            'tool': 'subfinder',
                            'args': {'all': True},
                            'description': 'Complete subdomain enumeration'
                        },
                        {
                            'tool': 'amass',
                            'args': {'passive': True, 'brute': True},
                            'description': 'Advanced passive enumeration with brute force'
                        }
                    ],
                    order=1
                ),
                ReconPhase(
                    name="DNS Enumeration",
                    description="Comprehensive DNS analysis",
                    tools=[
                        {
                            'tool': 'dnsrecon',
                            'args': {'type': 'axfr'},
                            'description': 'DNS zone transfer attempts'
                        }
                    ],
                    order=2
                ),
                ReconPhase(
                    name="Active Scanning",
                    description="Active network scanning for live hosts",
                    tools=[
                        {
                            'tool': 'nmap',
                            'args': {'ports': 'top-1000', 'service': True},
                            'description': 'Service detection on discovered hosts'
                        }
                    ],
                    order=3
                )
            ],
            estimated_duration=45
        )

        # Web Application Recon
        templates['web_app'] = ReconPlan(
            name="Web Application Reconnaissance",
            description="Comprehensive web application analysis and vulnerability discovery",
            target_type="url",
            phases=[
                ReconPhase(
                    name="Web Discovery",
                    description="Discover web assets and technologies",
                    tools=[
                        {
                            'tool': 'gobuster',
                            'args': {'wordlist': 'common'},
                            'description': 'Directory brute-forcing'
                        }
                    ],
                    order=1
                ),
                ReconPhase(
                    name="Vulnerability Scanning",
                    description="Scan for common web vulnerabilities",
                    tools=[
                        {
                            'tool': 'nuclei',
                            'args': {'severity': 'medium,high,critical'},
                            'description': 'Automated vulnerability scanning'
                        }
                    ],
                    order=2
                )
            ],
            estimated_duration=30
        )

        return templates

    def get_template(self, template_name: str) -> Optional[ReconPlan]:
        """Get a reconnaissance plan template by name"""
        return self.builtin_templates.get(template_name)

    def list_templates(self) -> List[Dict]:
        """List all available templates"""
        return [
            {
                'name': name,
                'description': template.description,
                'target_type': template.target_type,
                'phases': len(template.phases),
                'estimated_duration': template.estimated_duration
            }
            for name, template in self.builtin_templates.items()
        ]

    def generate_plan_for_target(self, target: str, template_name: str = 'auto') -> Optional[ReconPlan]:
        """Generate a reconnaissance plan for a specific target"""
        # Auto-select template based on target type
        if template_name == 'auto':
            if self._is_domain(target):
                template_name = 'quick_domain' if len(target) < 50 else 'full_domain'
            elif self._is_url(target):
                template_name = 'web_app'
            else:
                template_name = 'quick_domain'  # Default fallback

        template = self.get_template(template_name)
        if not template:
            return None

        # Clone the template for customization
        plan = ReconPlan(
            name=f"Recon Plan for {target}",
            description=f"Customized reconnaissance plan for {target} based on {template.name}",
            target_type=template.target_type,
            phases=template.phases.copy(),
            estimated_duration=template.estimated_duration
        )

        return plan

    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain name"""
        import re
        domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, target))

    def _is_url(self, target: str) -> bool:
        """Check if target is a URL"""
        import re
        url_pattern = r'^https?://'
        return bool(re.match(url_pattern, target))

    def customize_plan(self, base_plan: ReconPlan, customizations: Dict) -> ReconPlan:
        """Create a customized version of a plan"""
        customized_phases = []
        for phase in base_plan.phases:
            custom_phase = ReconPhase(
                name=customizations.get('phase_name', phase.name),
                description=phase.description,
                tools=phase.tools.copy(),
                order=phase.order
            )
            customized_phases.append(custom_phase)

        return ReconPlan(
            name=customizations.get('name', f"Customized {base_plan.name}"),
            description=customizations.get('description', base_plan.description),
            target_type=base_plan.target_type,
            phases=customized_phases,
            estimated_duration=customizations.get('estimated_duration', base_plan.estimated_duration)
        )
