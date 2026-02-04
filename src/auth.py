#!/usr/bin/env python3
"""
Authentication module for Certificate Guardian
Supports three modes: local, proxy (Pomerium), and OIDC (Keycloak)
"""
import os
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod

import jwt
import bcrypt
import httpx

logger = logging.getLogger(__name__)

# ==================== User Model ====================

class User:
    """Represents an authenticated user"""
    def __init__(self, id: int = None, username: str = None, email: str = None,
                 role: str = "viewer", groups: list = None):
        self.id = id
        self.username = username
        self.email = email or username
        self.role = role
        self.groups = groups or []

    def has_role(self, required_role: str) -> bool:
        """Check if user has at least the required role level"""
        role_hierarchy = {"viewer": 0, "editor": 1, "admin": 2}
        user_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        return user_level >= required_level

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "groups": self.groups
        }


# ==================== Auth Providers ====================

class AuthProvider(ABC):
    """Base class for authentication providers"""

    @abstractmethod
    async def authenticate(self, request) -> Optional[User]:
        """Authenticate request and return User or None"""
        pass

    @abstractmethod
    def get_mode(self) -> str:
        """Return the auth mode name"""
        pass


class LocalAuthProvider(AuthProvider):
    """Local authentication with username/password and JWT tokens"""

    def __init__(self, db, config: Dict):
        self.db = db
        self.jwt_secret = config.get("jwt_secret") or self._generate_secret()
        self.access_token_expire_minutes = config.get("access_token_expire_minutes", 15)
        self.refresh_token_expire_days = config.get("refresh_token_expire_days", 30)
        self.algorithm = "HS256"

    def _generate_secret(self) -> str:
        """Generate a random secret for JWT signing"""
        return secrets.token_hex(32)

    def get_mode(self) -> str:
        return "local"

    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except Exception:
            return False

    def create_access_token(self, user: User) -> str:
        """Create a short-lived JWT access token"""
        expires = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "exp": expires,
            "type": "access"
        }
        return jwt.encode(payload, self.jwt_secret, algorithm=self.algorithm)

    def create_refresh_token(self, user: User) -> tuple[str, str]:
        """Create a long-lived refresh token. Returns (token, token_hash)"""
        token = secrets.token_urlsafe(64)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = (datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)).isoformat()

        # Store in database
        self.db.store_refresh_token(user.id, token_hash, expires_at)

        return token, token_hash

    def verify_access_token(self, token: str) -> Optional[Dict]:
        """Verify and decode an access token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.algorithm])
            if payload.get("type") != "access":
                return None
            return payload
        except jwt.ExpiredSignatureError:
            logger.debug("Access token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Invalid access token: {e}")
            return None

    def verify_refresh_token(self, token: str) -> Optional[Dict]:
        """Verify a refresh token and return user info"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        token_data = self.db.get_refresh_token(token_hash)

        if not token_data:
            return None

        # Check expiration
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if datetime.utcnow() > expires_at:
            self.db.delete_refresh_token(token_hash)
            return None

        # Check if user is still active
        if not token_data.get('is_active', True):
            return None

        return token_data

    def revoke_refresh_token(self, token: str) -> bool:
        """Revoke a refresh token (logout)"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self.db.delete_refresh_token(token_hash)

    def login(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user with username/password"""
        user_data = self.db.get_user_by_username(username)

        if not user_data:
            return None

        if not user_data.get('is_active', True):
            return None

        if not self.verify_password(password, user_data['password_hash']):
            return None

        user = User(
            id=user_data['id'],
            username=user_data['username'],
            email=user_data.get('email'),
            role=user_data.get('role', 'viewer')
        )

        access_token = self.create_access_token(user)
        refresh_token, _ = self.create_refresh_token(user)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60,
            "user": user.to_dict()
        }

    def refresh(self, refresh_token: str) -> Optional[Dict]:
        """Get new access token using refresh token"""
        token_data = self.verify_refresh_token(refresh_token)

        if not token_data:
            return None

        user = User(
            id=token_data['user_id'],
            username=token_data['username'],
            role=token_data.get('role', 'viewer')
        )

        access_token = self.create_access_token(user)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60
        }

    async def authenticate(self, request) -> Optional[User]:
        """Authenticate request using Bearer token"""
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]  # Remove "Bearer " prefix
        payload = self.verify_access_token(token)

        if not payload:
            return None

        return User(
            id=int(payload['sub']),
            username=payload['username'],
            email=payload.get('email'),
            role=payload.get('role', 'viewer')
        )

    def create_initial_admin(self, username: str, password: str) -> Optional[int]:
        """Create initial admin user if no users exist"""
        if self.db.count_users() > 0:
            return None

        password_hash = self.hash_password(password)
        return self.db.create_user(
            username=username,
            password_hash=password_hash,
            email=f"{username}@local",
            role="admin"
        )


class ProxyAuthProvider(AuthProvider):
    """Authentication via Pomerium proxy with JWT validation"""

    def __init__(self, config: Dict):
        self.jwt_issuer = config.get("jwt_issuer", "")
        self.jwks_url = config.get("jwks_url", "")
        self.email_header = config.get("email_header", "X-Pomerium-Claim-Email")
        self.groups_header = config.get("groups_header", "X-Pomerium-Claim-Groups")
        self.jwt_header = config.get("jwt_header", "X-Pomerium-Jwt-Assertion")
        self.admin_groups = config.get("admin_groups", [])
        self.editor_groups = config.get("editor_groups", [])
        self._jwks_cache = None
        self._jwks_cache_time = None

    def get_mode(self) -> str:
        return "proxy"

    async def _get_jwks(self) -> Dict:
        """Fetch and cache JWKS from Pomerium"""
        # Cache for 1 hour
        if self._jwks_cache and self._jwks_cache_time:
            if datetime.utcnow() - self._jwks_cache_time < timedelta(hours=1):
                return self._jwks_cache

        if not self.jwks_url:
            return {}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_url, timeout=10)
                response.raise_for_status()
                self._jwks_cache = response.json()
                self._jwks_cache_time = datetime.utcnow()
                return self._jwks_cache
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            return self._jwks_cache or {}

    def _determine_role(self, groups: list) -> str:
        """Determine user role based on group membership"""
        if any(g in self.admin_groups for g in groups):
            return "admin"
        if any(g in self.editor_groups for g in groups):
            return "editor"
        return "viewer"

    async def authenticate(self, request) -> Optional[User]:
        """Authenticate request using Pomerium headers/JWT"""
        jwt_token = request.headers.get(self.jwt_header)

        if jwt_token:
            # Validate JWT from Pomerium
            return await self._authenticate_jwt(jwt_token)
        else:
            # Fallback to trusting headers (less secure)
            return self._authenticate_headers(request)

    async def _authenticate_jwt(self, token: str) -> Optional[User]:
        """Authenticate using Pomerium JWT"""
        try:
            jwks = await self._get_jwks()
            if not jwks:
                logger.warning("No JWKS available, falling back to header trust")
                return None

            # Get signing key from JWKS
            from jwt import PyJWKClient
            jwks_client = PyJWKClient(self.jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "RS256"],
                options={"verify_aud": False}
            )

            email = payload.get("email", "")
            groups = payload.get("groups", [])
            role = self._determine_role(groups)

            return User(
                username=email.split("@")[0],
                email=email,
                role=role,
                groups=groups
            )

        except Exception as e:
            logger.error(f"JWT validation failed: {e}")
            return None

    def _authenticate_headers(self, request) -> Optional[User]:
        """Authenticate using trusted headers (fallback)"""
        email = request.headers.get(self.email_header)

        if not email:
            return None

        groups_str = request.headers.get(self.groups_header, "[]")
        try:
            import json
            groups = json.loads(groups_str) if groups_str else []
        except:
            groups = []

        role = self._determine_role(groups)

        return User(
            username=email.split("@")[0],
            email=email,
            role=role,
            groups=groups
        )


class OIDCAuthProvider(AuthProvider):
    """Authentication via OIDC (Keycloak, etc.)"""

    def __init__(self, config: Dict):
        self.issuer = config.get("issuer", "")
        self.client_id = config.get("client_id", "")
        self.client_secret = config.get("client_secret", "")
        self.admin_groups = config.get("admin_groups", [])
        self.editor_groups = config.get("editor_groups", [])
        self._jwks_client = None
        self._metadata = None

    def get_mode(self) -> str:
        return "oidc"

    async def _get_metadata(self) -> Dict:
        """Fetch OIDC discovery metadata"""
        if self._metadata:
            return self._metadata

        discovery_url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url, timeout=10)
                response.raise_for_status()
                self._metadata = response.json()
                return self._metadata
        except Exception as e:
            logger.error(f"Failed to fetch OIDC metadata: {e}")
            return {}

    def _determine_role(self, groups: list, roles: list) -> str:
        """Determine user role based on group/role membership"""
        all_roles = groups + roles
        if any(r in self.admin_groups for r in all_roles):
            return "admin"
        if any(r in self.editor_groups for r in all_roles):
            return "editor"
        return "viewer"

    async def authenticate(self, request) -> Optional[User]:
        """Authenticate request using OIDC JWT"""
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]

        try:
            metadata = await self._get_metadata()
            jwks_uri = metadata.get("jwks_uri")

            if not jwks_uri:
                logger.error("No jwks_uri in OIDC metadata")
                return None

            from jwt import PyJWKClient
            jwks_client = PyJWKClient(jwks_uri)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self.client_id,
                issuer=self.issuer
            )

            email = payload.get("email", "")
            username = payload.get("preferred_username", email.split("@")[0])
            groups = payload.get("groups", [])
            # Keycloak puts roles in realm_access.roles
            realm_roles = payload.get("realm_access", {}).get("roles", [])

            role = self._determine_role(groups, realm_roles)

            return User(
                username=username,
                email=email,
                role=role,
                groups=groups
            )

        except jwt.ExpiredSignatureError:
            logger.debug("OIDC token expired")
            return None
        except Exception as e:
            logger.error(f"OIDC authentication failed: {e}")
            return None


# ==================== Auth Manager ====================

class AuthManager:
    """Main authentication manager that delegates to appropriate provider"""

    def __init__(self, db, config: Dict):
        self.db = db
        self.config = config
        self.mode = config.get("mode", "local")
        self.provider = self._create_provider()

        # Create initial admin for local mode if needed
        if self.mode == "local":
            self._ensure_initial_admin()

    def _create_provider(self) -> AuthProvider:
        """Create the appropriate auth provider based on config"""
        if self.mode == "local":
            return LocalAuthProvider(self.db, self.config.get("local", {}))
        elif self.mode == "proxy":
            return ProxyAuthProvider(self.config.get("proxy", {}))
        elif self.mode == "oidc":
            return OIDCAuthProvider(self.config.get("oidc", {}))
        else:
            raise ValueError(f"Unknown auth mode: {self.mode}")

    def _ensure_initial_admin(self):
        """Ensure there's at least one admin user in local mode"""
        if self.db.count_users() == 0:
            # Create default admin user
            default_password = os.environ.get("CERT_GUARDIAN_ADMIN_PASSWORD", "admin")
            provider = self.provider
            if isinstance(provider, LocalAuthProvider):
                user_id = provider.create_initial_admin("admin", default_password)
                if user_id:
                    logger.info("Created initial admin user (username: admin)")
                    if default_password == "admin":
                        logger.warning("Using default admin password - CHANGE IT IMMEDIATELY!")

    def get_mode(self) -> str:
        return self.mode

    async def authenticate(self, request) -> Optional[User]:
        """Authenticate a request"""
        return await self.provider.authenticate(request)

    def login(self, username: str, password: str) -> Optional[Dict]:
        """Login (local mode only)"""
        if not isinstance(self.provider, LocalAuthProvider):
            raise ValueError("Login only available in local auth mode")
        return self.provider.login(username, password)

    def refresh(self, refresh_token: str) -> Optional[Dict]:
        """Refresh access token (local mode only)"""
        if not isinstance(self.provider, LocalAuthProvider):
            raise ValueError("Token refresh only available in local auth mode")
        return self.provider.refresh(refresh_token)

    def logout(self, refresh_token: str) -> bool:
        """Logout / revoke refresh token (local mode only)"""
        if not isinstance(self.provider, LocalAuthProvider):
            return True  # No-op for proxy/OIDC
        return self.provider.revoke_refresh_token(refresh_token)

    def hash_password(self, password: str) -> str:
        """Hash a password (local mode only)"""
        if not isinstance(self.provider, LocalAuthProvider):
            raise ValueError("Password hashing only available in local auth mode")
        return self.provider.hash_password(password)
