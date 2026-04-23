"""
NyxOS Authentication Manager
Location: nyxos/core/security/auth.py

Protects: AUTHENTICATION & ACCESS CONTROL
Defends against:
- Brute force attacks (rate limiting + lockout)
- Dictionary attacks (strong password requirements)
- Session hijacking (secure session tokens)
- Privilege escalation (role-based access)
"""

import os
import json
import time
from typing import Optional, Dict
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from loguru import logger
from .encryption import EncryptionManager


@dataclass
class Session:
    """Active user session"""
    session_id: str
    username: str
    role: str
    created_at: str
    expires_at: str
    ip_address: str = "local"
    is_active: bool = True


class AuthManager:
    """
    Handles user authentication for NyxOS.
    
    Security measures:
    1. Passwords hashed with bcrypt (12 rounds)
    2. Rate limiting on login attempts
    3. Account lockout after failed attempts
    4. Session tokens with expiration
    5. All auth events logged for audit
    """

    USERS_FILE = os.path.expanduser("~/.nyxos/config/users.json")
    MAX_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    SESSION_TIMEOUT_MINUTES = 60

    def __init__(self, encryption: EncryptionManager):
        self.encryption = encryption
        self._failed_attempts: Dict[str, list] = {}
        self._active_sessions: Dict[str, Session] = {}
        self._users = self._load_users()

    def _load_users(self) -> dict:
        """Load user database"""
        if os.path.exists(self.USERS_FILE):
            with open(self.USERS_FILE, "r") as f:
                return json.load(f)
        return {}

    def _save_users(self):
        """Save user database with secure permissions"""
        os.makedirs(os.path.dirname(self.USERS_FILE), mode=0o700, exist_ok=True)
        with open(self.USERS_FILE, "w") as f:
            json.dump(self._users, f, indent=2)
        os.chmod(self.USERS_FILE, 0o600)

    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        """
        Create a new NyxOS user.
        
        Password requirements (NIST 800-63B):
        - Minimum 12 characters
        - No maximum length restriction
        - Check against common passwords
        """
        # Validate password strength
        issues = self._check_password_strength(password)
        if issues:
            logger.warning(f"Weak password for {username}: {issues}")
            return False

        if username in self._users:
            logger.warning(f"User {username} already exists")
            return False

        self._users[username] = {
            "password_hash": EncryptionManager.hash_password(password),
            "role": role,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "is_locked": False,
            "locked_until": None,
        }

        self._save_users()
        logger.info(f"User {username} created with role {role}")
        return True

    def _check_password_strength(self, password: str) -> list:
        """Check password against security requirements"""
        issues = []

        if len(password) < 12:
            issues.append("Password must be at least 12 characters")

        # Check against common passwords
        common_passwords = [
            "password1234", "admin1234567", "letmein12345",
            "qwerty123456", "123456789012", "password12345"
        ]
        if password.lower() in common_passwords:
            issues.append("Password is too common")

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

        if not (has_upper and has_lower and has_digit):
            issues.append("Password should contain uppercase, lowercase, and digits")

        return issues

    def authenticate(self, username: str, password: str) -> Optional[Session]:
        """
        Authenticate a user.
        
        Defenses:
        - Rate limiting (max 5 attempts per 15 minutes)
        - Account lockout after max attempts
        - Constant-time comparison (bcrypt handles this)
        - All attempts logged
        """
        # Check if account is locked
        if self._is_locked(username):
            remaining = self._lockout_remaining(username)
            logger.warning(f"Account {username} is locked. {remaining}s remaining.")
            return None

        # Check rate limiting
        if self._is_rate_limited(username):
            logger.warning(f"Rate limit exceeded for {username}")
            return None

        # Verify credentials
        if username not in self._users:
            self._record_failed_attempt(username)
            logger.warning(f"Failed login: unknown user {username}")
            return None

        user = self._users[username]

        if not EncryptionManager.verify_password(password, user["password_hash"]):
            self._record_failed_attempt(username)
            attempts = len(self._failed_attempts.get(username, []))
            remaining = self.MAX_ATTEMPTS - attempts
            logger.warning(f"Failed login for {username}. {remaining} attempts remaining.")

            if attempts >= self.MAX_ATTEMPTS:
                self._lock_account(username)

            return None

        # Success — clear failed attempts
        self._failed_attempts.pop(username, None)

        # Create session
        session = Session(
            session_id=EncryptionManager.generate_secure_token(32),
            username=username,
            role=user["role"],
            created_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(minutes=self.SESSION_TIMEOUT_MINUTES)).isoformat(),
        )

        self._active_sessions[session.session_id] = session

        # Update last login
        self._users[username]["last_login"] = datetime.now().isoformat()
        self._save_users()

        logger.info(f"User {username} authenticated successfully")
        return session

    def _record_failed_attempt(self, username: str):
        """Record a failed login attempt"""
        if username not in self._failed_attempts:
            self._failed_attempts[username] = []

        self._failed_attempts[username].append(time.time())

        # Clean old attempts (older than lockout duration)
        cutoff = time.time() - (self.LOCKOUT_MINUTES * 60)
        self._failed_attempts[username] = [
            t for t in self._failed_attempts[username] if t > cutoff
        ]

    def _is_rate_limited(self, username: str) -> bool:
        """Check if user has exceeded rate limit"""
        attempts = self._failed_attempts.get(username, [])
        cutoff = time.time() - 60  # 1 minute window
        recent = [t for t in attempts if t > cutoff]
        return len(recent) >= 3  # Max 3 attempts per minute

    def _is_locked(self, username: str) -> bool:
        """Check if account is locked"""
        if username not in self._users:
            return False
        user = self._users[username]
        if not user.get("is_locked"):
            return False
        if user.get("locked_until"):
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now() > locked_until:
                user["is_locked"] = False
                user["locked_until"] = None
                self._save_users()
                return False
        return True

    def _lock_account(self, username: str):
        """Lock an account after too many failed attempts"""
        if username in self._users:
            locked_until = datetime.now() + timedelta(minutes=self.LOCKOUT_MINUTES)
            self._users[username]["is_locked"] = True
            self._users[username]["locked_until"] = locked_until.isoformat()
            self._save_users()
            logger.warning(f"Account {username} locked until {locked_until}")

    def _lockout_remaining(self, username: str) -> int:
        """Get remaining lockout time in seconds"""
        if username in self._users and self._users[username].get("locked_until"):
            locked_until = datetime.fromisoformat(self._users[username]["locked_until"])
            remaining = (locked_until - datetime.now()).total_seconds()
            return max(0, int(remaining))
        return 0

    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate an active session"""
        session = self._active_sessions.get(session_id)
        if not session:
            return None

        if datetime.now() > datetime.fromisoformat(session.expires_at):
            del self._active_sessions[session_id]
            logger.info(f"Session expired for {session.username}")
            return None

        return session

    def logout(self, session_id: str):
        """End a session"""
        if session_id in self._active_sessions:
            username = self._active_sessions[session_id].username
            del self._active_sessions[session_id]
            logger.info(f"User {username} logged out")
