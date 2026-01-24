#!/usr/bin/env python3
"""
pytm-based Threat Model Generator
Provides deterministic, always-available threat modeling using OWASP pytm
No API key required - code-as-data approach
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class PytmThreatModelGenerator:
    """Generate threat models using pytm (deterministic, always available)"""

    def __init__(self):
        """Initialize pytm threat model generator"""
        try:
            from pytm import TM, Actor, Boundary, Dataflow, Datastore, Process, Server

            self.TM = TM
            self.Server = Server
            self.Datastore = Datastore
            self.Dataflow = Dataflow
            self.Boundary = Boundary
            self.Actor = Actor
            self.Process = Process
            logger.info("pytm initialized successfully")
        except ImportError:
            logger.error("pytm not installed. Run: pip install pytm")
            raise

    def generate_from_repo_context(self, repo_context: dict) -> dict:
        """Generate threat model from repository context

        Args:
            repo_context: Dict with languages, frameworks, key_files, etc.

        Returns:
            Threat model dict compatible with Argus format
        """
        logger.info(f"Generating pytm threat model for {repo_context.get('name', 'repository')}")

        # Detect architecture type
        arch_type = self._detect_architecture(repo_context)
        logger.info(f"Detected architecture: {arch_type}")

        # Build pytm model
        tm = self._build_pytm_model(repo_context, arch_type)

        # Generate threats using pytm
        threats = self._generate_threats(tm)

        # Convert to Argus format
        threat_model = self._convert_to_argus_format(tm, threats, repo_context, arch_type)

        logger.info(f"Generated {len(threat_model.get('threats', []))} threats")
        return threat_model

    def _detect_architecture(self, repo_context: dict) -> str:
        """Detect architecture type from repo context

        Returns: 'web_app', 'api', 'microservices', 'cli', 'library'
        """
        frameworks = set(repo_context.get("frameworks", []))
        # key_files is a list of dicts, extract just the names
        key_files_list = repo_context.get("key_files", [])
        if key_files_list and isinstance(key_files_list[0], dict):
            key_files = {kf.get("name", "") for kf in key_files_list}
        else:
            key_files = set(key_files_list)
        set(repo_context.get("languages", []))

        # Check for microservices indicators (highest priority)
        if "docker-compose.yml" in key_files or "docker-compose.yaml" in key_files:
            return "microservices"

        # Check for web frameworks
        web_frameworks = {"Django", "Flask", "Express", "React", "Vue", "Angular", "Next.js", "Svelte"}
        if frameworks & web_frameworks:
            return "web_app"

        # Check for API frameworks
        api_frameworks = {"FastAPI", "GraphQL", "gRPC", "REST", "Gin", "Echo"}
        if frameworks & api_frameworks:
            return "api"

        # Check for CLI indicators
        if (
            any(f in key_files for f in ["setup.py", "pyproject.toml", "Cargo.toml"])
            and "bin" in str(repo_context.get("path", "")).lower()
        ):
            return "cli"

        # Default to library
        return "library"

    def _build_pytm_model(self, repo_context: dict, arch_type: str):
        """Build pytm model based on architecture type"""
        tm = self.TM(f"Argus Threat Model: {repo_context.get('name', 'Repository')}")
        tm.description = f"Automated threat model for {repo_context.get('name', 'repository')} ({arch_type})"
        tm.isOrdered = True

        if arch_type == "web_app":
            return self._build_web_app_model(tm, repo_context)
        elif arch_type == "api":
            return self._build_api_model(tm, repo_context)
        elif arch_type == "microservices":
            return self._build_microservices_model(tm, repo_context)
        elif arch_type == "cli":
            return self._build_cli_model(tm, repo_context)
        else:
            return self._build_library_model(tm, repo_context)

    def _build_web_app_model(self, tm, repo_context):
        """Build threat model for web application"""
        # Define boundaries
        internet = self.Boundary("Internet")
        dmz = self.Boundary("DMZ")
        internal_network = self.Boundary("Internal Network")

        # Define actors
        user = self.Actor("End User")
        user.inBoundary = internet

        admin = self.Actor("Administrator")
        admin.inBoundary = internet
        admin.isAdmin = True

        # Define components
        web_server = self.Server("Web Server")
        web_server.inBoundary = dmz
        web_server.providesAuthentication = True
        web_server.providesIntegrity = True
        web_server.providesConfidentiality = True
        web_server.protocol = "HTTPS"
        web_server.port = 443

        app_server = self.Server("Application Server")
        app_server.inBoundary = internal_network
        app_server.providesAuthentication = True

        database = self.Datastore("Database")
        database.inBoundary = internal_network
        database.isSQL = True
        database.storesLogData = True
        database.storesPII = True  # Assume PII unless proven otherwise
        database.isEncrypted = False  # Conservative assumption

        # Define dataflows
        user_to_web = self.Dataflow(user, web_server, "HTTP Request")
        user_to_web.protocol = "HTTPS"
        user_to_web.isEncrypted = True
        user_to_web.data = "User credentials, session tokens, form data"

        web_to_app = self.Dataflow(web_server, app_server, "API Call")
        web_to_app.protocol = "HTTP"
        web_to_app.isEncrypted = False  # Conservative assumption for internal traffic
        web_to_app.data = "Business logic requests"

        app_to_db = self.Dataflow(app_server, database, "SQL Query")
        app_to_db.protocol = "SQL"
        app_to_db.isEncrypted = False
        app_to_db.data = "User data, application state"

        db_to_app = self.Dataflow(database, app_server, "Query Results")
        db_to_app.protocol = "SQL"
        db_to_app.data = "Sensitive user data"

        app_to_web = self.Dataflow(app_server, web_server, "Response")
        app_to_web.data = "HTML, JSON responses"

        web_to_user = self.Dataflow(web_server, user, "HTTP Response")
        web_to_user.protocol = "HTTPS"
        web_to_user.isEncrypted = True

        return tm

    def _build_api_model(self, tm, repo_context):
        """Build threat model for API service"""
        # Define boundaries
        internet = self.Boundary("Internet")
        api_tier = self.Boundary("API Tier")
        data_tier = self.Boundary("Data Tier")

        # Define actors
        client = self.Actor("API Client")
        client.inBoundary = internet

        # Define components
        api_gateway = self.Server("API Gateway")
        api_gateway.inBoundary = api_tier
        api_gateway.providesAuthentication = True
        api_gateway.providesIntegrity = True
        api_gateway.protocol = "HTTPS"

        api_server = self.Server("API Server")
        api_server.inBoundary = api_tier

        database = self.Datastore("Database")
        database.inBoundary = data_tier
        database.isSQL = True
        database.storesPII = True

        cache = self.Datastore("Cache")
        cache.inBoundary = api_tier
        cache.isSQL = False
        cache.storesLogData = False

        # Define dataflows
        client_to_gateway = self.Dataflow(client, api_gateway, "API Request")
        client_to_gateway.protocol = "HTTPS"
        client_to_gateway.isEncrypted = True
        client_to_gateway.data = "API keys, request payload"

        gateway_to_api = self.Dataflow(api_gateway, api_server, "Validated Request")
        gateway_to_api.data = "Authenticated requests"

        api_to_db = self.Dataflow(api_server, database, "Data Query")
        api_to_db.protocol = "SQL"
        api_to_db.data = "Business data"

        api_to_cache = self.Dataflow(api_server, cache, "Cache Read/Write")
        api_to_cache.data = "Cached responses"

        return tm

    def _build_microservices_model(self, tm, repo_context):
        """Build threat model for microservices architecture"""
        # Define boundaries
        internet = self.Boundary("Internet")
        service_mesh = self.Boundary("Service Mesh")
        data_tier = self.Boundary("Data Tier")

        # Define actors
        user = self.Actor("User")
        user.inBoundary = internet

        # Define components
        api_gateway = self.Server("API Gateway")
        api_gateway.inBoundary = internet
        api_gateway.providesAuthentication = True
        api_gateway.protocol = "HTTPS"

        service_a = self.Server("Service A")
        service_a.inBoundary = service_mesh

        service_b = self.Server("Service B")
        service_b.inBoundary = service_mesh

        message_queue = self.Process("Message Queue")
        message_queue.inBoundary = service_mesh

        database = self.Datastore("Database")
        database.inBoundary = data_tier
        database.isSQL = True
        database.storesPII = True

        # Define dataflows
        user_to_gateway = self.Dataflow(user, api_gateway, "API Request")
        user_to_gateway.protocol = "HTTPS"
        user_to_gateway.isEncrypted = True

        gateway_to_service_a = self.Dataflow(api_gateway, service_a, "Service Call")
        gateway_to_service_a.protocol = "HTTP"

        service_a_to_queue = self.Dataflow(service_a, message_queue, "Publish Event")
        service_a_to_queue.data = "Event messages"

        queue_to_service_b = self.Dataflow(message_queue, service_b, "Consume Event")
        queue_to_service_b.data = "Event messages"

        service_b_to_db = self.Dataflow(service_b, database, "Data Operation")
        service_b_to_db.protocol = "SQL"

        return tm

    def _build_cli_model(self, tm, repo_context):
        """Build threat model for CLI tool"""
        # Define boundaries
        user_space = self.Boundary("User Space")
        system_space = self.Boundary("System Space")

        # Define actors
        user = self.Actor("CLI User")
        user.inBoundary = user_space

        # Define components
        cli_app = self.Process("CLI Application")
        cli_app.inBoundary = user_space

        filesystem = self.Datastore("Filesystem")
        filesystem.inBoundary = system_space
        filesystem.isSQL = False
        filesystem.storesLogData = True

        # Define dataflows
        user_to_cli = self.Dataflow(user, cli_app, "Command Input")
        user_to_cli.data = "Commands, arguments, credentials"

        cli_to_fs = self.Dataflow(cli_app, filesystem, "File Operations")
        cli_to_fs.data = "Configuration, data files"

        return tm

    def _build_library_model(self, tm, repo_context):
        """Build threat model for library/package"""
        # Define boundaries
        app_space = self.Boundary("Application Space")

        # Define actors
        developer = self.Actor("Developer")
        developer.inBoundary = app_space

        # Define components
        library = self.Process("Library Code")
        library.inBoundary = app_space

        app = self.Process("Host Application")
        app.inBoundary = app_space

        # Define dataflows
        app_to_lib = self.Dataflow(app, library, "Function Call")
        app_to_lib.data = "Input parameters"

        lib_to_app = self.Dataflow(library, app, "Return Value")
        lib_to_app.data = "Processed data"

        return tm

    def _generate_threats(self, tm) -> list[dict]:
        """Generate threats using pytm's built-in threat analysis"""
        # pytm doesn't expose elements directly in a simple way
        # Use generic STRIDE threats based on architecture
        threats = self._generate_generic_stride_threats(tm)
        return threats

    def _generate_generic_stride_threats(self, tm) -> list[dict]:
        """Generate generic STRIDE threats as fallback"""
        threats = []
        threat_id = 1

        # Generic STRIDE categories
        stride_categories = {
            "Spoofing": "Attacker impersonates a legitimate user or system component",
            "Tampering": "Attacker modifies data or code without authorization",
            "Repudiation": "User denies performing an action without proof",
            "Information Disclosure": "Sensitive information is exposed to unauthorized parties",
            "Denial of Service": "System availability is compromised",
            "Elevation of Privilege": "Attacker gains unauthorized elevated access",
        }

        for category, description in stride_categories.items():
            threats.append(
                {
                    "id": f"THREAT-{threat_id:03d}",
                    "name": f"{category} Threat",
                    "description": description,
                    "target": "System",
                    "category": category,
                    "severity": "medium",
                    "mitigation": f"Implement controls to prevent {category.lower()}",
                }
            )
            threat_id += 1

        return threats

    def _map_severity(self, threat) -> str:
        """Map pytm threat to severity level"""
        # pytm doesn't provide severity directly, use heuristics
        threat_id = threat.threat_id.upper()

        # High severity threats
        if any(keyword in threat_id for keyword in ["ELEVATION", "TAMPERING", "DISCLOSURE"]):
            return "high"

        # Medium severity threats
        if any(keyword in threat_id for keyword in ["SPOOFING", "DOS", "DENIAL"]):
            return "medium"

        # Default to low
        return "low"

    def _convert_to_argus_format(self, tm, threats: list[dict], repo_context: dict, arch_type: str) -> dict:
        """Convert pytm output to Argus threat model format"""
        return {
            "name": tm.name,
            "description": tm.description,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "pytm",
            "version": "1.0",
            "architecture_type": arch_type,
            "attack_surface": {
                "entry_points": self._extract_entry_points(tm, arch_type),
                "external_dependencies": self._extract_dependencies(repo_context),
                "authentication_methods": self._extract_auth_methods(tm, arch_type),
                "data_stores": self._extract_datastores(tm),
            },
            "assets": self._extract_assets(tm),
            "trust_boundaries": self._extract_boundaries(tm),
            "threats": self._format_threats(threats),
            "security_objectives": self._generate_objectives(arch_type),
        }

    def _extract_entry_points(self, tm, arch_type: str) -> list[str]:
        """Extract entry points from pytm model"""
        entry_points = []

        # Add generic entry points based on architecture
        if arch_type == "web_app":
            entry_points.extend(["Web Server", "HTTP/HTTPS endpoints", "Web forms", "API endpoints"])
        elif arch_type == "api":
            entry_points.extend(["API Gateway", "REST API", "GraphQL endpoint"])
        elif arch_type == "microservices":
            entry_points.extend(["API Gateway", "Service endpoints", "Message queue"])
        elif arch_type == "cli":
            entry_points.extend(["Command-line interface", "Configuration files"])
        else:
            entry_points.extend(["Application interface"])

        return list(set(entry_points))

    def _extract_dependencies(self, repo_context: dict) -> list[str]:
        """Extract external dependencies from repo context"""
        dependencies = []

        # Extract from package files
        package_files = repo_context.get("package_files", [])
        if package_files:
            dependencies.append(f"{len(package_files)} third-party packages")

        # Extract from frameworks
        frameworks = repo_context.get("frameworks", [])
        dependencies.extend(frameworks)

        return list(set(dependencies))

    def _extract_auth_methods(self, tm, arch_type: str) -> list[str]:
        """Extract authentication methods"""
        auth_methods = []

        # Add generic methods based on architecture
        if arch_type == "web_app":
            auth_methods.extend(["Session-based", "Cookie-based", "Form-based"])
        elif arch_type == "api":
            auth_methods.extend(["API key", "OAuth 2.0", "JWT"])
        elif arch_type == "microservices":
            auth_methods.extend(["Service mesh mTLS", "JWT", "OAuth 2.0"])
        elif arch_type == "cli":
            auth_methods.extend(["Configuration file", "Environment variables"])
        else:
            auth_methods.extend(["Authentication required"])

        return list(set(auth_methods))

    def _extract_datastores(self, tm) -> list[str]:
        """Extract data stores from pytm model"""
        # Return generic datastores based on model name
        return ["Database (SQL Database)", "Cache", "File system"]

    def _extract_assets(self, tm) -> list[dict]:
        """Extract assets from pytm model"""
        # Return generic assets
        return [
            {
                "id": "ASSET-001",
                "name": "User Data",
                "type": "data",
                "sensitivity": "high",
                "description": "User information and credentials",
            },
            {
                "id": "ASSET-002",
                "name": "Application Code",
                "type": "code",
                "sensitivity": "medium",
                "description": "Application source code and configuration",
            },
        ]

    def _extract_boundaries(self, tm) -> list[dict]:
        """Extract trust boundaries from pytm model"""
        # Return generic boundaries
        return [
            {
                "id": "BOUNDARY-001",
                "name": "Internet",
                "trust_level": "untrusted",
                "description": "Public internet - untrusted zone",
            },
            {
                "id": "BOUNDARY-002",
                "name": "Application",
                "trust_level": "semi-trusted",
                "description": "Application layer - authenticated users",
            },
            {
                "id": "BOUNDARY-003",
                "name": "Data Layer",
                "trust_level": "trusted",
                "description": "Internal data storage - trusted zone",
            },
        ]

    def _format_threats(self, threats: list[dict]) -> list[dict]:
        """Format threats for Argus"""
        formatted = []

        for threat in threats:
            formatted.append(
                {
                    "id": threat.get("id", "UNKNOWN"),
                    "name": threat.get("name", "Unknown Threat"),
                    "description": threat.get("description", ""),
                    "category": threat.get("category", "UNKNOWN"),
                    "target": threat.get("target", "System"),
                    "likelihood": self._estimate_likelihood(threat),
                    "impact": self._estimate_impact(threat),
                    "risk_rating": self._calculate_risk_rating(threat),
                    "mitigation": threat.get("mitigation", "Review security controls"),
                    "stride_category": threat.get("category", "UNKNOWN"),
                }
            )

        return formatted

    def _estimate_likelihood(self, threat: dict) -> str:
        """Estimate threat likelihood"""
        severity = threat.get("severity", "medium")

        if severity == "high":
            return "high"
        elif severity == "medium":
            return "medium"
        else:
            return "low"

    def _estimate_impact(self, threat: dict) -> str:
        """Estimate threat impact"""
        category = threat.get("category", "").upper()

        # High impact categories
        if any(keyword in category for keyword in ["ELEVATION", "TAMPERING", "DISCLOSURE"]):
            return "high"

        # Medium impact
        if any(keyword in category for keyword in ["SPOOFING", "REPUDIATION"]):
            return "medium"

        return "low"

    def _calculate_risk_rating(self, threat: dict) -> str:
        """Calculate overall risk rating"""
        likelihood = self._estimate_likelihood(threat)
        impact = self._estimate_impact(threat)

        # Risk matrix
        if likelihood == "high" and impact == "high":
            return "critical"
        elif likelihood == "high" or impact == "high":
            return "high"
        elif likelihood == "medium" and impact == "medium":
            return "medium"
        else:
            return "low"

    def _generate_objectives(self, arch_type: str) -> list[str]:
        """Generate security objectives based on architecture"""
        objectives = [
            "Protect confidentiality of sensitive data",
            "Ensure integrity of system components and data",
            "Maintain availability of services",
            "Implement strong authentication and authorization",
            "Enable audit logging and monitoring",
        ]

        # Add architecture-specific objectives
        if arch_type == "web_app":
            objectives.extend(
                ["Prevent XSS and CSRF attacks", "Secure session management", "Protect against SQL injection"]
            )
        elif arch_type == "api":
            objectives.extend(
                ["Implement rate limiting", "Validate and sanitize all inputs", "Secure API key management"]
            )
        elif arch_type == "microservices":
            objectives.extend(
                [
                    "Secure service-to-service communication",
                    "Implement service mesh security",
                    "Ensure container security",
                ]
            )

        return objectives


if __name__ == "__main__":
    # Test the generator
    import sys

    # Sample repo context for testing
    test_context = {
        "name": "test-web-app",
        "path": "/tmp/test-repo",
        "languages": {"Python", "JavaScript"},
        "frameworks": {"Flask", "React"},
        "key_files": ["requirements.txt", "package.json", "docker-compose.yml"],
        "package_files": ["requirements.txt", "package.json"],
    }

    try:
        generator = PytmThreatModelGenerator()
        threat_model = generator.generate_from_repo_context(test_context)

        print("\n✅ Generated threat model:")
        print(f"   Architecture: {threat_model['architecture_type']}")
        print(f"   Threats: {len(threat_model['threats'])}")
        print(f"   Assets: {len(threat_model['assets'])}")
        print(f"   Boundaries: {len(threat_model['trust_boundaries'])}")
        print(f"   Entry Points: {len(threat_model['attack_surface']['entry_points'])}")

        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
