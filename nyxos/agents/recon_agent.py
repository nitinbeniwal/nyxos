"""
NyxOS Recon Agent — Specialised OSINT and network reconnaissance orchestrator.

Chains multiple recon tools in the correct order to build a comprehensive
target profile.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from loguru import logger

from nyxos.core.ai_engine.router import AIRouter
from nyxos.core.security.safety_guard import Scope
from nyxos.skills.base_skill import SkillResult
from nyxos.skills.skill_manager import SkillManager


class ReconAgent:
    """
    Orchestrates full OSINT and network reconnaissance in the correct order.

    Chains: WHOIS → DNS → Subdomain Discovery → Email Harvesting → Port Scan
    Aggregates all results into a structured target profile.
    """

    # Ordered recon phases
    RECON_PHASES = [
        {
            "name": "whois",
            "skill": "recon",
            "params_key": "intent",
            "params_value": "whois lookup",
            "description": "WHOIS domain/IP information",
        },
        {
            "name": "dns",
            "skill": "recon",
            "params_key": "intent",
            "params_value": "dns enumeration",
            "description": "DNS record enumeration",
        },
        {
            "name": "subdomains",
            "skill": "recon",
            "params_key": "intent",
            "params_value": "subdomain discovery",
            "description": "Subdomain discovery",
        },
        {
            "name": "emails",
            "skill": "recon",
            "params_key": "intent",
            "params_value": "email harvesting",
            "description": "Email and employee discovery",
        },
        {
            "name": "ports",
            "skill": "nmap",
            "params_key": "scan_type",
            "params_value": "full",
            "description": "Port scanning and service detection",
        },
    ]

    def __init__(self, skills: SkillManager, ai_router: AIRouter) -> None:
        """
        Initialize the ReconAgent.

        Args:
            skills: SkillManager for executing recon tools.
            ai_router: AIRouter for AI-assisted analysis.
        """
        self.skills = skills
        self.ai_router = ai_router
        logger.debug("ReconAgent initialized")

    def run(self, target: str, scope: Scope) -> Dict[str, Any]:
        """
        Execute full reconnaissance against a target.

        Chains multiple recon tools in order, aggregating results into
        a comprehensive target profile.

        Args:
            target: Target IP, domain, or CIDR range.
            scope: Scope constraints.

        Returns:
            Structured target profile dictionary.
        """
        logger.info("Starting full recon on target: {}", target)
        start_time = time.time()

        results: List[SkillResult] = []
        phase_results: Dict[str, Any] = {}

        for phase in self.RECON_PHASES:
            logger.info("Recon phase: {}", phase["name"])

            params = {
                "target": target,
                phase["params_key"]: phase["params_value"],
            }

            try:
                result = self.skills.execute(phase["skill"], params)
                results.append(result)
                phase_results[phase["name"]] = {
                    "success": result.success,
                    "findings": result.findings or [],
                    "output": result.output[:2000] if result.output else "",
                }

                if result.success:
                    logger.info(
                        "Phase '{}' completed: {} findings",
                        phase["name"],
                        len(result.findings or []),
                    )
                else:
                    logger.warning("Phase '{}' failed: {}", phase["name"], result.output[:200] if result.output else "unknown")

            except Exception as exc:
                logger.error("Phase '{}' error: {}", phase["name"], exc)
                phase_results[phase["name"]] = {
                    "success": False,
                    "findings": [],
                    "error": str(exc),
                }

        profile = self._build_target_profile(target, results, phase_results)
        profile["recon_duration_seconds"] = time.time() - start_time

        # AI summary
        profile["ai_summary"] = self._generate_summary(target, profile)

        logger.info(
            "Recon complete for {}: {} total findings in {:.1f}s",
            target,
            profile.get("total_findings", 0),
            profile["recon_duration_seconds"],
        )

        return profile

    def _build_target_profile(
        self,
        target: str,
        results: List[SkillResult],
        phase_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Aggregate all recon results into a structured target profile.

        Args:
            target: The target that was scanned.
            results: List of SkillResult from each phase.
            phase_results: Phase-specific result data.

        Returns:
            Comprehensive target profile dictionary.
        """
        profile: Dict[str, Any] = {
            "target": target,
            "domains": [],
            "subdomains": [],
            "ip_addresses": [],
            "emails": [],
            "open_ports": [],
            "services": [],
            "technologies": [],
            "registrar_info": {},
            "dns_records": [],
            "all_findings": [],
            "total_findings": 0,
            "phases": phase_results,
        }

        seen_values: set = set()

        for result in results:
            for finding in (result.findings or []):
                profile["all_findings"].append(finding)
                ftype = finding.get("type", "")
                value = finding.get("value", finding.get("title", ""))

                # Deduplicate
                dedup_key = f"{ftype}:{value}"
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)

                if ftype == "domain":
                    profile["domains"].append(value)
                elif ftype == "subdomain" or ftype == "domain" and "." in value:
                    profile["subdomains"].append(value)
                elif ftype == "ip_address":
                    profile["ip_addresses"].append(value)
                elif ftype == "email":
                    profile["emails"].append(value)
                elif ftype == "technology":
                    profile["technologies"].append(value)

                # Port/service info from nmap findings
                port = finding.get("port")
                service = finding.get("service", "")
                if port:
                    port_entry = {
                        "port": port,
                        "service": service,
                        "version": finding.get("version", ""),
                        "host": finding.get("host", target),
                    }
                    profile["open_ports"].append(port_entry)
                    if service:
                        profile["services"].append(service)

        # Deduplicate services
        profile["services"] = list(set(profile["services"]))
        profile["total_findings"] = len(profile["all_findings"])

        return profile

    def _generate_summary(self, target: str, profile: Dict[str, Any]) -> str:
        """
        Use AI to generate a human-readable summary of the recon results.

        Args:
            target: The target.
            profile: The built target profile.

        Returns:
            AI-generated summary string.
        """
        try:
            summary_data = {
                "target": target,
                "subdomains_found": len(profile["subdomains"]),
                "emails_found": len(profile["emails"]),
                "open_ports": len(profile["open_ports"]),
                "services": profile["services"],
                "technologies": profile["technologies"],
            }

            prompt = (
                f"Summarize these reconnaissance findings for {target} in 3-5 sentences. "
                f"Highlight the most important findings and potential attack surface.\n\n"
                f"Data: {summary_data}"
            )

            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity reconnaissance analyst. Be concise and actionable.",
                history=[],
                task_type="explain",
            )
            return response.text
        except Exception as exc:
            logger.warning("AI summary generation failed: {}", exc)
            return (
                f"Recon completed for {target}: "
                f"{len(profile['subdomains'])} subdomains, "
                f"{len(profile['emails'])} emails, "
                f"{len(profile['open_ports'])} open ports found."
            )
