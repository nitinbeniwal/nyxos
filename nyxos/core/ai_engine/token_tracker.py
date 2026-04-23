"""
NyxOS Token Usage Tracker
Location: nyxos/core/ai_engine/token_tracker.py

Tracks and manages AI token consumption.
Protects users from unexpected API costs.
"""

import os
import json
from datetime import datetime, date
from typing import Tuple
from loguru import logger
from ..config.settings import TokenConfig


class TokenTracker:
    """
    Tracks token usage across all providers.
    Enforces daily and monthly budgets.
    """

    USAGE_FILE = os.path.expanduser("~/.nyxos/data/token_usage.json")

    def __init__(self, config: TokenConfig):
        self.config = config
        self.usage = self._load_usage()

    def _load_usage(self) -> dict:
        """Load usage data from disk"""
        if os.path.exists(self.USAGE_FILE):
            try:
                with open(self.USAGE_FILE, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        return {
            "daily": {},
            "monthly": {},
            "total": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "requests": 0},
            "by_provider": {},
            "history": []
        }

    def _save_usage(self):
        """Save usage data to disk"""
        os.makedirs(os.path.dirname(self.USAGE_FILE), mode=0o700, exist_ok=True)
        with open(self.USAGE_FILE, "w") as f:
            json.dump(self.usage, f, indent=2, default=str)
        os.chmod(self.USAGE_FILE, 0o600)

    def record_usage(self, provider: str, model: str,
                     input_tokens: int, output_tokens: int, total_tokens: int):
        """Record token usage from an AI call"""
        today = date.today().isoformat()
        month = datetime.now().strftime("%Y-%m")

        # Daily tracking
        if today not in self.usage["daily"]:
            self.usage["daily"][today] = {"total_tokens": 0, "requests": 0}
        self.usage["daily"][today]["total_tokens"] += total_tokens
        self.usage["daily"][today]["requests"] += 1

        # Monthly tracking
        if month not in self.usage["monthly"]:
            self.usage["monthly"][month] = {"total_tokens": 0, "requests": 0}
        self.usage["monthly"][month]["total_tokens"] += total_tokens
        self.usage["monthly"][month]["requests"] += 1

        # Total tracking
        self.usage["total"]["input_tokens"] += input_tokens
        self.usage["total"]["output_tokens"] += output_tokens
        self.usage["total"]["total_tokens"] += total_tokens
        self.usage["total"]["requests"] += 1

        # Per-provider tracking
        if provider not in self.usage["by_provider"]:
            self.usage["by_provider"][provider] = {
                "total_tokens": 0, "requests": 0, "models_used": []
            }
        self.usage["by_provider"][provider]["total_tokens"] += total_tokens
        self.usage["by_provider"][provider]["requests"] += 1
        if model not in self.usage["by_provider"][provider]["models_used"]:
            self.usage["by_provider"][provider]["models_used"].append(model)

        self._save_usage()

        # Check warning threshold
        self._check_warnings()

    def check_budget(self, estimated_tokens: int = 0) -> Tuple[bool, str]:
        """Check if token budget allows this request"""
        today = date.today().isoformat()
        month = datetime.now().strftime("%Y-%m")

        # Check daily budget
        if self.config.daily_budget > 0:
            daily_used = self.usage.get("daily", {}).get(today, {}).get("total_tokens", 0)
            if daily_used + estimated_tokens > self.config.daily_budget:
                return False, f"Daily budget exceeded ({daily_used}/{self.config.daily_budget} tokens)"

        # Check monthly budget
        if self.config.monthly_budget > 0:
            monthly_used = self.usage.get("monthly", {}).get(month, {}).get("total_tokens", 0)
            if monthly_used + estimated_tokens > self.config.monthly_budget:
                return False, f"Monthly budget exceeded ({monthly_used}/{self.config.monthly_budget} tokens)"

        return True, "Within budget"

    def _check_warnings(self):
        """Warn user when approaching budget limits"""
        today = date.today().isoformat()
        month = datetime.now().strftime("%Y-%m")

        if self.config.daily_budget > 0:
            daily_used = self.usage.get("daily", {}).get(today, {}).get("total_tokens", 0)
            usage_pct = daily_used / self.config.daily_budget
            if usage_pct >= self.config.warning_threshold:
                logger.warning(
                    f"⚠️ Daily token usage at {usage_pct:.0%} "
                    f"({daily_used}/{self.config.daily_budget})"
                )

        if self.config.monthly_budget > 0:
            monthly_used = self.usage.get("monthly", {}).get(month, {}).get("total_tokens", 0)
            usage_pct = monthly_used / self.config.monthly_budget
            if usage_pct >= self.config.warning_threshold:
                logger.warning(
                    f"⚠️ Monthly token usage at {usage_pct:.0%} "
                    f"({monthly_used}/{self.config.monthly_budget})"
                )

    def get_stats(self) -> dict:
        """Get comprehensive usage statistics"""
        today = date.today().isoformat()
        month = datetime.now().strftime("%Y-%m")

        daily_used = self.usage.get("daily", {}).get(today, {}).get("total_tokens", 0)
        monthly_used = self.usage.get("monthly", {}).get(month, {}).get("total_tokens", 0)

        return {
            "today": {
                "tokens_used": daily_used,
                "budget": self.config.daily_budget,
                "remaining": max(0, self.config.daily_budget - daily_used) if self.config.daily_budget > 0 else "unlimited",
                "requests": self.usage.get("daily", {}).get(today, {}).get("requests", 0)
            },
            "this_month": {
                "tokens_used": monthly_used,
                "budget": self.config.monthly_budget,
                "remaining": max(0, self.config.monthly_budget - monthly_used) if self.config.monthly_budget > 0 else "unlimited",
                "requests": self.usage.get("monthly", {}).get(month, {}).get("requests", 0)
            },
            "all_time": self.usage.get("total", {}),
            "by_provider": self.usage.get("by_provider", {})
        }

    def reset_daily(self):
        """Reset daily counter (called automatically at midnight)"""
        today = date.today().isoformat()
        self.usage["daily"][today] = {"total_tokens": 0, "requests": 0}
        self._save_usage()
