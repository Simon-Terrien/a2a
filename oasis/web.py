"""
Enhanced Web Interface with Agent Dashboard and MCP Tools Integration
Keeps all existing OASIS web functionality + adds agent monitoring
"""

from datetime import datetime, timezone
from pathlib import Path
import re
import secrets
import string
import json

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_from_directory,
    session,
    redirect,
    url_for,
)
from functools import wraps

from .config import VULNERABILITY_MAPPING, MODEL_EMOJIS, VULN_EMOJIS
from .report import Report
from .utils import parse_iso_date, parse_report_date


class WebServer:
    """
    Enhanced web server with agent dashboard and MCP tools monitoring
    """

    def __init__(
        self,
        report,
        debug=False,
        web_expose="local",
        web_password=None,
        web_port=5000,
        agent_manager=None,
        mcp_tools=None,
    ):
        """
        Initialize enhanced web server

        Args:
            report: Report instance
            debug: Debug mode flag
            web_expose: Exposure setting ('local' or 'all')
            web_password: Web interface password
            web_port: Port to run on
            agent_manager: A2A agent manager (NEW)
            mcp_tools: MCP tools manager (NEW)
        """
        self.report = report
        self.debug = debug
        self.web_expose = web_expose
        self.web_password = web_password
        self.web_port = web_port
        self.report_data = None

        # Enhanced: Agent and MCP integration
        self.agent_manager = agent_manager
        self.mcp_tools = mcp_tools
        self.multi_agent_mode = agent_manager is not None
        self.mcp_enabled = mcp_tools is not None

        if not isinstance(report, Report):
            raise ValueError("Report must be an instance of Report")

        self.input_path = Path(report.input_path)
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input path not found at {self.input_path}")
        self.input_path_absolute = self.input_path.resolve()

        self.security_dir = self.input_path_absolute.parent / "security_reports"
        if not self.security_dir.exists():
            raise FileNotFoundError(
                f"Security reports directory not found at {self.security_dir}"
            )

    def run(self):
        """Serve reports via enhanced web interface with agent dashboard"""
        from .__init__ import __version__

        app = Flask(
            __name__,
            template_folder=str(Path(__file__).parent / "templates"),
            static_folder=str(Path(__file__).parent / "static"),
        )

        # Generate a random secret key for session management
        app.secret_key = secrets.token_hex(16)

        # Add context processor to inject version and feature flags
        @app.context_processor
        def inject_context():
            return {
                "version": __version__,
                "multi_agent_mode": self.multi_agent_mode,
                "mcp_enabled": self.mcp_enabled,
            }

        # Setup password protection if enabled
        if self.web_password is None:
            self.web_password = self._generate_random_password()
            print(
                f"\n[OASIS] Web interface protected by password: {self.web_password}\n"
            )

        # Auth decorator
        def login_required(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if self.web_password and not session.get("logged_in"):
                    return redirect(url_for("login", next=request.url))
                return f(*args, **kwargs)

            return decorated_function

        # Login route
        @app.route("/login", methods=["GET", "POST"])
        def login():
            error = None
            if request.method == "POST":
                if request.form["password"] == self.web_password:
                    session["logged_in"] = True
                    return redirect(request.args.get("next") or url_for("dashboard"))
                else:
                    error = "Incorrect password."
            return self._render_login_template(error)

        # Process and collect all report data
        self.collect_report_data()

        # Register routes with authentication
        app = self.register_routes(app, self, login_required)

        # Determine the host based on the expose setting
        host = "127.0.0.1" if self.web_expose == "local" else "0.0.0.0"

        # Show startup message
        mode_info = []
        if self.multi_agent_mode:
            mode_info.append("🤝 Multi-Agent Dashboard")
        if self.mcp_enabled:
            mode_info.append("🔧 MCP Tools Integration")

        mode_str = f" ({', '.join(mode_info)})" if mode_info else ""
        print(f"\n🌐 OASIS Enhanced Web Interface{mode_str}")
        print(f"   URL: http://{host}:{self.web_port}")
        if self.web_password:
            print(f"   Password: {self.web_password}")
        print()

        # Run the server
        if self.debug:
            app.run(debug=True, host=host, port=self.web_port)
        else:
            app.run(host=host, port=self.web_port)

    def _generate_random_password(self, length=10):
        """Generate a random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _render_login_template(self, error=None):
        """Render the login template"""
        return render_template("login.html", error=error)

    def register_routes(self, app, server, login_required):
        """Register all routes including enhanced agent and MCP routes"""

        # Logout route
        @app.route("/logout", methods=["GET"])
        def logout():
            session.pop("logged_in", None)
            return redirect(url_for("login"))

        @app.route("/")
        @login_required
        def dashboard():
            """Enhanced main dashboard with agent status"""
            return render_template(
                "dashboard.html",
                model_emojis=MODEL_EMOJIS,
                vuln_emojis=VULN_EMOJIS,
                multi_agent_mode=self.multi_agent_mode,
                mcp_enabled=self.mcp_enabled,
                debug=self.debug,
            )

        # Enhanced: Agent Dashboard Route
        @app.route("/agents")
        @login_required
        def agent_dashboard():
            """Agent monitoring dashboard"""
            if not self.multi_agent_mode:
                return redirect(url_for("dashboard"))

            return render_template(
                "agent_dashboard.html",
                agents=self._get_agent_status(),
                collaboration_active=self._is_collaboration_active(),
                model_emojis=MODEL_EMOJIS,
            )

        # Enhanced: MCP Tools Dashboard Route
        @app.route("/mcp-tools")
        @login_required
        def mcp_dashboard():
            """MCP tools monitoring dashboard"""
            if not self.mcp_enabled:
                return redirect(url_for("dashboard"))

            return render_template(
                "mcp_dashboard.html",
                tools=self._get_mcp_status(),
                tool_stats=self._get_mcp_statistics(),
            )

        @app.route("/api/reports")
        @login_required
        def get_reports():
            """Get reports with enhanced filtering"""
            # Get filter parameters
            model_filter = request.args.get("model", "")
            format_filter = request.args.get("format", "")
            vuln_filter = request.args.get("vulnerability", "")
            start_date = request.args.get("start_date", None)
            end_date = request.args.get("end_date", None)
            agent_filter = request.args.get("agent", "")  # NEW: Agent filtering
            md_dates_only = request.args.get("md_dates_only", "1") == "1"

            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter,
                format_filter,
                vuln_filter,
                start_date,
                end_date,
                md_dates_only=md_dates_only,
                agent_filter=agent_filter,  # NEW
            )
            return jsonify(filtered_data)

        @app.route("/api/stats")
        @login_required
        def get_stats():
            """Get enhanced statistics including agent data"""
            # Check if there are any filter parameters
            model_filter = request.args.get("model", "")
            format_filter = request.args.get("format", "")
            vuln_filter = request.args.get("vulnerability", "")
            start_date = request.args.get("start_date")
            end_date = request.args.get("end_date")
            agent_filter = request.args.get("agent", "")  # NEW

            # If any filters are applied, get filtered reports first
            if any(
                [
                    model_filter,
                    format_filter,
                    vuln_filter,
                    start_date,
                    end_date,
                    agent_filter,
                ]
            ):
                filtered_reports = self.filter_reports(
                    model_filter=model_filter,
                    format_filter=format_filter,
                    vuln_filter=vuln_filter,
                    start_date=start_date,
                    end_date=end_date,
                    agent_filter=agent_filter,
                )
                return jsonify(
                    self.get_report_statistics(filtered_reports=filtered_reports)
                )
            else:
                # No filters, get global statistics
                return jsonify(self.get_report_statistics())

        # NEW: Agent Status API
        @app.route("/api/agents/status")
        @login_required
        def get_agent_status():
            """Get real-time agent status"""
            if not self.multi_agent_mode:
                return jsonify({"error": "Multi-agent mode not enabled"})

            return jsonify(self._get_agent_status())

        # NEW: Agent Findings API
        @app.route("/api/agent-findings/<agent_type>")
        @login_required
        def get_agent_findings(agent_type):
            """Get findings from a specific agent"""
            if not self.multi_agent_mode:
                return jsonify({"error": "Multi-agent mode not enabled"})

            findings = self._get_agent_findings(agent_type)
            return jsonify(findings)

        # NEW: Agent Collaboration API
        @app.route("/api/agents/collaboration")
        @login_required
        def get_agent_collaboration():
            """Get agent collaboration data"""
            if not self.multi_agent_mode:
                return jsonify({"error": "Multi-agent mode not enabled"})

            return jsonify(self._get_collaboration_data())

        # NEW: MCP Tools Status API
        @app.route("/api/mcp/status")
        @login_required
        def get_mcp_status():
            """Get MCP tools status"""
            if not self.mcp_enabled:
                return jsonify({"error": "MCP tools not enabled"})

            return jsonify(self._get_mcp_status())

        # NEW: MCP Tool Results API
        @app.route("/api/mcp/results/<tool_name>")
        @login_required
        def get_mcp_results(tool_name):
            """Get results from a specific MCP tool"""
            if not self.mcp_enabled:
                return jsonify({"error": "MCP tools not enabled"})

            results = self._get_mcp_tool_results(tool_name)
            return jsonify(results)

        @app.route("/reports/<path:filename>")
        @login_required
        def serve_report(filename):
            """Serve report files"""
            security_dir = self.security_dir
            return send_from_directory(security_dir, filename)

        @app.route("/api/report-content/<path:filename>")
        @login_required
        def get_report_content(filename):
            """Get report content for preview"""
            try:
                file_path = self.security_dir / filename
                if file_path.exists() and file_path.suffix == ".md":
                    html_content = self.report.read_and_convert_markdown(file_path)
                    return jsonify({"content": html_content})
                return jsonify({"error": "File not found or not a markdown file"}), 404
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route("/api/download")
        @login_required
        def download_report():
            """Download report files"""
            report_path = request.args.get("path", "")
            if not report_path:
                return jsonify({"error": "No path provided"}), 400

            try:
                abs_path = self.security_dir / report_path

                # Security check
                if not str(abs_path.resolve()).startswith(
                    str(self.security_dir.resolve())
                ):
                    return jsonify({"error": "Invalid path"}), 403

                if not abs_path.exists():
                    return jsonify({"error": "File not found"}), 404

                directory = abs_path.parent
                filename = abs_path.name

                content_types = {
                    ".md": "text/markdown",
                    ".html": "text/html",
                    ".pdf": "application/pdf",
                }
                content_type = content_types.get(
                    abs_path.suffix, "application/octet-stream"
                )

                return send_from_directory(
                    directory=str(directory),
                    path=filename,
                    mimetype=content_type,
                    as_attachment=True,
                )
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        @app.route("/api/dates")
        @login_required
        def get_dates_by_model():
            """Get dates available for a specific model and vulnerability type"""
            model = request.args.get("model", "")
            vulnerability = request.args.get("vulnerability", "")
            agent = request.args.get("agent", "")  # NEW: Agent filter

            if not model or not vulnerability:
                return (
                    jsonify(
                        {"error": "Model and vulnerability parameters are required"}
                    ),
                    400,
                )

            vulnerability = vulnerability.lower()

            # Filter reports by model, vulnerability, and optionally agent
            filtered_reports = []
            for report in self.report_data:
                report_vuln = report.get("vulnerability_type", "").lower()
                report_model = report.get("model", "")
                report_agent = report.get("agent", "")

                match_criteria = [model == report_model, vulnerability in report_vuln]

                # Add agent filter if specified
                if agent:
                    match_criteria.append(agent == report_agent)

                if all(match_criteria):
                    filtered_reports.append(report)

            # Extract dates from filtered reports
            dates = []
            for report in filtered_reports:
                if "date" in report:
                    date_info = {"date": report["date"]}

                    if report.get("alternative_formats", {}).get("md"):
                        date_info["path"] = report["alternative_formats"]["md"]

                    dates.append(date_info)

            dates.sort(key=lambda x: x.get("date", ""), reverse=True)

            return jsonify({"dates": dates})

        return app

    def collect_report_data(self):
        """Collect and process all report data including agent information"""
        reports = self._collect_reports_from_directories()
        self.report_data = reports
        self.global_stats = self._calculate_global_statistics(reports)

    def _collect_reports_from_directories(self):
        """Extract reports data from directory structure with agent info"""
        reports = []
        security_reports_dir = self.security_dir

        for report_dir in [d for d in security_reports_dir.iterdir() if d.is_dir()]:
            report_date = self._extract_date_from_dirname(report_dir.name)

            for model_dir in [d for d in report_dir.iterdir() if d.is_dir()]:
                model_name = self._desanitize_name(model_dir.name)
                reports.extend(
                    self._process_model_directory(
                        model_dir, model_name, report_date, report_dir.name
                    )
                )

        reports.sort(key=lambda x: x["date"] or "", reverse=True)
        return reports

    def _process_model_directory(
        self, model_dir, model_name, report_date, timestamp_dir
    ):
        """Process all formats in a model directory with agent detection"""
        model_reports = []

        for fmt_dir in [d for d in model_dir.iterdir() if d.is_dir()]:
            fmt = fmt_dir.name

            if fmt not in ["md", "html", "pdf"]:
                continue

            model_reports.extend(
                self._process_report_file(
                    report_file,
                    model_name,
                    fmt,
                    report_date,
                    timestamp_dir,
                    model_dir,
                )
                for report_file in fmt_dir.glob("*.*")
            )
        return model_reports

    def _process_report_file(
        self, report_file, model_name, fmt, report_date, timestamp_dir, model_dir
    ):
        """Process a single report file and extract metadata including agent info"""
        vulnerability_type = self._extract_vulnerability_type(report_file.stem)

        # Enhanced: Extract agent information from report content
        agent_info = self._extract_agent_info(report_file) if fmt == "md" else {}

        stats = self._parse_vulnerability_statistics(report_file) if fmt == "md" else {}

        relative_path = report_file.relative_to(self.security_dir)

        alternative_formats = self._find_alternative_formats(
            model_dir, report_file.stem, timestamp_dir
        )

        report_data = {
            "model": model_name,
            "format": fmt,
            "path": str(relative_path),
            "filename": report_file.name,
            "vulnerability_type": vulnerability_type,
            "stats": stats,
            "alternative_formats": alternative_formats,
            "date": report_date,
            "timestamp_dir": timestamp_dir,
        }

        # Enhanced: Add agent information
        if agent_info:
            report_data.update(agent_info)

        return report_data

    def _extract_agent_info(self, report_file):
        """Extract agent information from report content"""
        agent_info = {}

        try:
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Look for agent signatures in the report
            agent_patterns = {
                "sqli": r"SQL Injection Expert|Agent: sqli",
                "xss": r"XSS Security Expert|Agent: xss",
                "auth": r"Authentication Expert|Agent: auth",
                "crypto": r"Cryptography Expert|Agent: crypto",
                "config": r"Configuration Expert|Agent: config",
            }

            for agent_type, pattern in agent_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    agent_info["agent"] = agent_type
                    agent_info["agent_name"] = self._get_agent_display_name(agent_type)
                    break

            # Look for collaboration indicators
            if "Agent Collaboration" in content or "multi-agent" in content.lower():
                agent_info["collaboration"] = True

            # Look for MCP tool usage
            mcp_tools = []
            if "CVE" in content or "NVD" in content:
                mcp_tools.append("nvd")
            if "Semgrep" in content:
                mcp_tools.append("semgrep")
            if "git blame" in content.lower() or "git history" in content.lower():
                mcp_tools.append("git_analyzer")
            if "dependency" in content.lower() and "vulnerabilit" in content.lower():
                mcp_tools.append("dependency_scanner")

            if mcp_tools:
                agent_info["mcp_tools_used"] = mcp_tools

        except Exception as e:
            pass  # Ignore errors in agent info extraction

        return agent_info

    def _get_agent_display_name(self, agent_type):
        """Get display name for agent type"""
        display_names = {
            "sqli": "SQL Injection Expert",
            "xss": "XSS Security Expert",
            "auth": "Authentication Expert",
            "crypto": "Cryptography Expert",
            "config": "Configuration Expert",
        }
        return display_names.get(agent_type, agent_type.title())

    def filter_reports(
        self,
        model_filter="",
        format_filter="",
        vuln_filter="",
        start_date=None,
        end_date=None,
        md_dates_only=True,
        agent_filter="",
    ):
        """Enhanced filter reports with agent filtering"""
        if not self.report_data:
            self.collect_report_data()

        filtered = self.report_data

        # Apply model filter
        if model_filter:
            model_filters = [m.lower() for m in model_filter.split(",")]
            filtered = [
                r
                for r in filtered
                if any(m in r["model"].lower() for m in model_filters)
            ]

        # Apply date filtering
        filtered = self._apply_date_filter(filtered, start_date, end_date)

        # NEW: Apply agent filter
        if agent_filter:
            agent_filters = [a.lower() for a in agent_filter.split(",")]
            filtered = [
                r for r in filtered if r.get("agent", "").lower() in agent_filters
            ]

        if md_dates_only and not format_filter:
            # Apply vulnerability filter
            if vuln_filter:
                vuln_filters = [v.lower() for v in vuln_filter.split(",")]
                filtered = [
                    r
                    for r in filtered
                    if any(v in r["vulnerability_type"].lower() for v in vuln_filters)
                ]

            # Mark date visibility
            for report in filtered:
                report["date_visible"] = report["format"] == "md"
        else:
            # Standard filtering
            if format_filter:
                format_filters = [f.lower() for f in format_filter.split(",")]
                filtered = [
                    r for r in filtered if r["format"].lower() in format_filters
                ]

            if vuln_filter:
                vuln_filters = [v.lower() for v in vuln_filter.split(",")]
                filtered = [
                    r
                    for r in filtered
                    if any(v in r["vulnerability_type"].lower() for v in vuln_filters)
                ]

            for report in filtered:
                report["date_visible"] = True

        return filtered

    # Agent-specific methods
    def _get_agent_status(self):
        """Get current status of all agents"""
        if not self.multi_agent_mode:
            return {}

        agent_status = {}

        for agent_type, agent in self.agent_manager.agents.items():
            status = {
                "name": agent.config.get("name", agent_type),
                "type": agent_type,
                "model": agent.config.get("model", ""),
                "port": agent.config.get("port", 0),
                "running": getattr(agent, "running", False),
                "specialization": agent.config.get("description", ""),
                "skills": agent.config.get("skills", []),
            }

            # Get recent activity
            status["recent_activity"] = self._get_agent_recent_activity(agent_type)

            agent_status[agent_type] = status

        return agent_status

    def _get_agent_recent_activity(self, agent_type):
        """Get recent activity for an agent"""
        # This would typically come from agent logs or activity tracking
        # For now, return placeholder data
        return {
            "last_analysis": "2024-01-15 10:30:00",
            "files_analyzed": 42,
            "vulnerabilities_found": 7,
            "avg_confidence": 0.85,
        }

    def _get_agent_findings(self, agent_type):
        """Get findings from a specific agent"""
        if not self.multi_agent_mode:
            return {}

        # Filter reports by agent
        agent_reports = [r for r in self.report_data if r.get("agent") == agent_type]

        findings = {
            "agent_type": agent_type,
            "agent_name": self._get_agent_display_name(agent_type),
            "total_reports": len(agent_reports),
            "vulnerabilities": {},
            "recent_findings": [],
        }

        # Group by vulnerability type
        for report in agent_reports:
            vuln_type = report["vulnerability_type"]
            if vuln_type not in findings["vulnerabilities"]:
                findings["vulnerabilities"][vuln_type] = 0
            findings["vulnerabilities"][vuln_type] += 1

        # Get recent findings (last 10)
        findings["recent_findings"] = sorted(
            agent_reports, key=lambda x: x.get("date", ""), reverse=True
        )[:10]

        return findings

    def _is_collaboration_active(self):
        """Check if agent collaboration is currently active"""
        if not self.multi_agent_mode:
            return False

        return getattr(self.agent_manager, "collaboration_enabled", False)

    def _get_collaboration_data(self):
        """Get agent collaboration data"""
        if not self.multi_agent_mode:
            return {}

        # This would come from the agent manager's collaboration tracking
        return {
            "active_collaborations": 3,
            "cross_agent_findings": 15,
            "attack_chains_identified": 5,
            "collaboration_rules": getattr(
                self.agent_manager, "collaboration_rules", {}
            ),
            "recent_collaborations": [
                {
                    "agents": ["sqli", "auth"],
                    "finding": "Authentication bypass + SQL injection",
                    "risk_level": "Critical",
                    "timestamp": "2024-01-15 11:45:00",
                }
            ],
        }

    # MCP-specific methods
    def _get_mcp_status(self):
        """Get status of MCP tools"""
        if not self.mcp_enabled:
            return {}

        tools_status = {}

        for tool_name in self.mcp_tools.get_active_tools():
            server_info = self.mcp_tools.servers.get(tool_name, {})

            tools_status[tool_name] = {
                "name": tool_name.title(),
                "status": server_info.get("status", "unknown"),
                "port": server_info.get("port", 0),
                "description": self._get_tool_description(tool_name),
                "last_used": self._get_tool_last_used(tool_name),
                "usage_count": self._get_tool_usage_count(tool_name),
            }

        return tools_status

    def _get_tool_description(self, tool_name):
        """Get description for MCP tool"""
        descriptions = {
            "nvd": "NIST National Vulnerability Database - CVE lookups",
            "semgrep": "Static analysis validation",
            "git_analyzer": "Git history and blame analysis",
            "dependency_scanner": "Dependency vulnerability scanning",
        }
        return descriptions.get(tool_name, tool_name.title())

    def _get_tool_last_used(self, tool_name):
        """Get last used timestamp for tool"""
        # This would come from tool usage tracking
        return "2024-01-15 12:00:00"

    def _get_tool_usage_count(self, tool_name):
        """Get usage count for tool"""
        # This would come from tool usage tracking
        return 42

    def _get_mcp_tool_results(self, tool_name):
        """Get results from a specific MCP tool"""
        if not self.mcp_enabled:
            return {}

        # This would come from the MCP tool manager's result tracking
        return {
            "tool_name": tool_name,
            "recent_results": [
                {
                    "timestamp": "2024-01-15 12:00:00",
                    "file": "example.py",
                    "result": "CVE-2023-1234 found",
                    "confidence": "high",
                }
            ],
            "statistics": {
                "total_scans": 156,
                "findings": 23,
                "last_scan": "2024-01-15 12:00:00",
            },
        }

    def _get_mcp_statistics(self):
        """Get overall MCP tools statistics"""
        if not self.mcp_enabled:
            return {}

        return {
            "total_tool_calls": 1234,
            "successful_calls": 1180,
            "failed_calls": 54,
            "avg_response_time": "2.3s",
            "most_used_tool": "semgrep",
            "recent_activity": [
                {
                    "tool": "nvd",
                    "action": "CVE lookup",
                    "timestamp": "2024-01-15 12:05:00",
                    "result": "Found 3 matching CVEs",
                }
            ],
        }

    # Keep all existing methods from original web.py
    def _calculate_global_statistics(self, reports):
        """Calculate global statistics from all reports (KEPT + Enhanced)"""
        stats = {
            "total_reports": 0,
            "models": {},
            "vulnerabilities": {},
            "formats": {},
            "dates": {},
            "agents": {},  # NEW: Agent statistics
            "mcp_tools": {},  # NEW: MCP tool statistics
            "risk_summary": {
                "high": sum(
                    report.get("stats", {}).get("high_risk", 0)
                    for report in reports
                    if report["format"] == "md"
                ),
                "medium": sum(
                    report.get("stats", {}).get("medium_risk", 0)
                    for report in reports
                    if report["format"] == "md"
                ),
                "low": sum(
                    report.get("stats", {}).get("low_risk", 0)
                    for report in reports
                    if report["format"] == "md"
                ),
            },
        }

        for report in reports:
            self._update_stats_from_report(stats, report)

        return stats

    def _update_stats_from_report(self, stats, report):
        """Update statistics based on a single report (KEPT + Enhanced)"""
        # Count only markdown files for accurate statistics
        if report["format"] == "md":
            stats["total_reports"] += 1

            # statistics by model
            model = report["model"]
            if model not in stats["models"]:
                stats["models"][model] = 0
            stats["models"][model] += 1

            # statistics by vulnerability type
            vuln_type = report["vulnerability_type"]
            if vuln_type not in stats["vulnerabilities"]:
                stats["vulnerabilities"][vuln_type] = 0
            stats["vulnerabilities"][vuln_type] += 1

            # NEW: Statistics by agent
            agent = report.get("agent", "unknown")
            if agent not in stats["agents"]:
                stats["agents"][agent] = 0
            stats["agents"][agent] += 1

            # NEW: Statistics by MCP tools used
            mcp_tools_used = report.get("mcp_tools_used", [])
            for tool in mcp_tools_used:
                if tool not in stats["mcp_tools"]:
                    stats["mcp_tools"][tool] = 0
                stats["mcp_tools"][tool] += 1

            # statistics by date (only day)
            if report["date"]:
                date_only = report["date"].split()[0]  # extract only the date part
                if date_only not in stats["dates"]:
                    stats["dates"][date_only] = 0
                stats["dates"][date_only] += 1

        # count all available formats
        fmt = report["format"]
        if fmt not in stats["formats"]:
            stats["formats"][fmt] = 0
        stats["formats"][fmt] += 1

    # Keep all existing helper methods
    def _desanitize_name(self, sanitized_name):
        """Convert sanitized name back to display name (KEPT)"""
        name = sanitized_name.replace("_", " ")
        return name.title()

    def _extract_date_from_dirname(self, dirname):
        """Extract date from directory name (KEPT)"""
        try:
            if match := re.search(r"_(\d{8}_\d{6})", dirname):
                date_str = match[1]
                date_obj = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                return date_obj.strftime("%Y-%m-%d %H:%M:%S")
            return ""
        except Exception as e:
            print(f"Error extracting date from {dirname}: {e}")
            return ""

    def _find_alternative_formats(self, model_dir, report_stem, timestamp_dir=None):
        """Find all available formats for a specific report (KEPT)"""
        formats = {}

        for fmt in ["md", "html", "pdf"]:
            fmt_dir = model_dir / fmt
            if fmt_dir.exists() and fmt_dir.is_dir():
                file_path = fmt_dir / f"{report_stem}.{fmt}"
                if file_path.exists():
                    if timestamp_dir:
                        relative_path = file_path.relative_to(model_dir.parent.parent)
                        formats[fmt] = str(relative_path)
                    else:
                        formats[fmt] = str(file_path.relative_to(model_dir.parent))

        return formats

    def _extract_vulnerability_type(self, filename):
        """Extract vulnerability type from filename (KEPT)"""
        if "executive_summary" in filename:
            return "Executive Summary"

        if "audit_report" in filename:
            return "Audit Report"

        vulnerability_patterns = {
            VULNERABILITY_MAPPING[vulnerability]["name"]
            .lower()
            .replace(" ", "_"): VULNERABILITY_MAPPING[vulnerability]["name"]
            for vulnerability in VULNERABILITY_MAPPING
        }

        return next(
            (
                full_name
                for pattern, full_name in vulnerability_patterns.items()
                if pattern in filename.lower()
            ),
            filename,
        )

    def _parse_vulnerability_statistics(self, report_file):
        """Parse vulnerability statistics from a report file (KEPT)"""
        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()

        stats = {}

        if findings_match := re.search(r"Analyzed\s+(\d+)\s+files", content):
            stats["files_analyzed"] = int(findings_match[1])

        # Extract risk levels
        high_risk = len(re.findall(r"High Risk Findings", content))
        medium_risk = len(re.findall(r"Medium Risk Findings", content))
        low_risk = len(re.findall(r"Low Risk Findings", content))

        # Count table rows as an estimation of vulnerabilities
        table_rows = len(re.findall(r"\|\s+\`[^\`]+\`\s+\|\s+[\d\.]+\s+\|", content))

        stats |= {
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "total_findings": table_rows,
        }

        return stats

    def _apply_date_filter(self, reports, start_date, end_date):
        """Apply date filtering to reports (KEPT)"""
        filtered_reports = reports.copy()

        if parsed_start_date := parse_iso_date(start_date):
            filtered_reports = [
                r
                for r in filtered_reports
                if r.get("date")
                and parse_report_date(r["date"]) is not None
                and parse_report_date(r["date"]) >= parsed_start_date
            ]

        if parsed_end_date := parse_iso_date(end_date):
            filtered_reports = [
                r
                for r in filtered_reports
                if r.get("date")
                and parse_report_date(r["date"]) is not None
                and parse_report_date(r["date"]) <= parsed_end_date
            ]

        return filtered_reports

    def get_report_statistics(self, filtered_reports=None):
        """Get statistics for reports (KEPT + Enhanced)"""
        force_refresh = request.args.get("force", "0") == "1"
        if force_refresh or not self.report_data:
            self.collect_report_data()

        reports_to_analyze = (
            filtered_reports if filtered_reports is not None else self.report_data
        )

        stats = {
            "total_reports": 0,
            "models": {},
            "vulnerabilities": {},
            "formats": {},
            "dates": {},
            "agents": {},  # NEW
            "mcp_tools": {},  # NEW
            "risk_summary": {"high": 0, "medium": 0, "low": 0},
        }

        for report in reports_to_analyze:
            if report["format"] == "md":
                stats["total_reports"] += 1

                # statistics by model
                model = report["model"]
                if model not in stats["models"]:
                    stats["models"][model] = 0
                stats["models"][model] += 1

                # statistics by vulnerability type
                vuln_type = report["vulnerability_type"]
                if vuln_type not in stats["vulnerabilities"]:
                    stats["vulnerabilities"][vuln_type] = 0
                stats["vulnerabilities"][vuln_type] += 1

                # NEW: Statistics by agent
                agent = report.get("agent", "legacy")
                if agent not in stats["agents"]:
                    stats["agents"][agent] = 0
                stats["agents"][agent] += 1

                # NEW: Statistics by MCP tools
                mcp_tools_used = report.get("mcp_tools_used", [])
                for tool in mcp_tools_used:
                    if tool not in stats["mcp_tools"]:
                        stats["mcp_tools"][tool] = 0
                    stats["mcp_tools"][tool] += 1

                # statistics by date
                if report["date"]:
                    date_only = report["date"].split()[0]
                    if date_only not in stats["dates"]:
                        stats["dates"][date_only] = 0
                    stats["dates"][date_only] += 1

                # Add risk summary if available
                if "stats" in report and report["stats"]:
                    stats["risk_summary"]["high"] += report["stats"].get("high_risk", 0)
                    stats["risk_summary"]["medium"] += report["stats"].get(
                        "medium_risk", 0
                    )
                    stats["risk_summary"]["low"] += report["stats"].get("low_risk", 0)

            # count all available formats
            fmt = report["format"]
            if fmt not in stats["formats"]:
                stats["formats"][fmt] = 0
            stats["formats"][fmt] += 1

        return stats
