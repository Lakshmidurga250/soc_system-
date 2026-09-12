"""SentinelAI Discrete-Time Markov Chain (DTMC) Sequence Anomaly Detector.

Analyzes sequential patterns of process creations, system calls, and commands.
Computes transition log-likelihoods with Laplace smoothing and perplexity scoring to identify
anomalous execution chains (e.g., Living-Off-The-Land bin execution, living-off-the-land chains).
100% offline mathematical statistical model.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


class MarkovProcessChainDetector:
    """Markov Chain sequence model for process parent-child transitions and shell command chains."""

    def __init__(self, alpha_smoothing: float = 0.05):
        self.alpha: float = alpha_smoothing
        # Transition frequency counts: counts[state_a][state_b] = N
        self.transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.state_totals: Dict[str, int] = defaultdict(int)
        self.vocabulary: set[str] = set()
        self.total_sequences_trained: int = 0
        self.baseline_perplexity_mean: float = 1.0
        self.baseline_perplexity_std: float = 0.5
        self._seed_enterprise_baselines()

    def train_sequence(self, sequence: List[str]) -> None:
        """Trains transition matrix on a sequential list of process/command states."""
        if len(sequence) < 2:
            return

        normalized = [self._normalize_state(s) for s in sequence if s]
        for i in range(len(normalized) - 1):
            s_from = normalized[i]
            s_to = normalized[i + 1]
            self.transitions[s_from][s_to] += 1
            self.state_totals[s_from] += 1
            self.vocabulary.add(s_from)
            self.vocabulary.add(s_to)

        self.total_sequences_trained += 1

    def transition_probability(self, s_from: str, s_to: str) -> float:
        """Calculates smoothed transition probability P(s_to | s_from) using Laplace smoothing."""
        s_from_norm = self._normalize_state(s_from)
        s_to_norm = self._normalize_state(s_to)

        v_size = max(len(self.vocabulary), 1)
        count_from_to = self.transitions[s_from_norm].get(s_to_norm, 0)
        total_from = self.state_totals[s_from_norm]

        prob = (count_from_to + self.alpha) / (total_from + self.alpha * v_size)
        return prob

    def score_sequence(self, sequence: List[str]) -> Dict[str, Any]:
        """Calculates log-likelihood, perplexity, and individual step anomaly scores for a sequence.

        Lower log-likelihood / higher perplexity indicates anomalous sequence.
        """
        if not sequence or len(sequence) < 2:
            return {
                "sequence": sequence,
                "is_anomalous": False,
                "log_likelihood": 0.0,
                "perplexity": 1.0,
                "anomaly_score": 0.0,
                "transition_breakdown": [],
            }

        normalized = [self._normalize_state(s) for s in sequence if s]
        log_likelihood = 0.0
        breakdown: List[Dict[str, Any]] = []

        for i in range(len(normalized) - 1):
            s_from = normalized[i]
            s_to = normalized[i + 1]
            p = self.transition_probability(s_from, s_to)
            step_log = math.log(p)
            log_likelihood += step_log

            # Step score: 1.0 when transition is extremely unlikely
            step_rarity = max(0.0, min(1.0, -step_log / 10.0))

            breakdown.append({
                "from_state": s_from,
                "to_state": s_to,
                "probability": round(p, 5),
                "log_prob": round(step_log, 3),
                "is_rare_transition": p < 0.01,
                "step_rarity": round(step_rarity, 3),
            })

        n_transitions = len(normalized) - 1
        avg_neg_log = -log_likelihood / max(n_transitions, 1)
        perplexity = math.exp(avg_neg_log)

        # Anomaly score between 0.0 and 1.0 based on perplexity and rare transitions
        rare_count = sum(1 for b in breakdown if b["is_rare_transition"])
        rare_ratio = rare_count / max(n_transitions, 1)

        # Sigmoid-scaled anomaly score
        normalized_perp_z = (perplexity - 2.0) / 5.0
        anomaly_score = max(0.0, min(1.0, 0.4 * rare_ratio + 0.6 * (1.0 / (1.0 + math.exp(-normalized_perp_z)))))

        is_anomalous = anomaly_score >= 0.60 or rare_count >= 2

        return {
            "sequence": normalized,
            "is_anomalous": is_anomalous,
            "anomaly_score": round(anomaly_score, 3),
            "log_likelihood": round(log_likelihood, 3),
            "perplexity": round(perplexity, 2),
            "rare_transitions_count": rare_count,
            "transition_breakdown": breakdown,
        }

    @staticmethod
    def _normalize_state(state: str) -> str:
        """Extracts executable basename and normalizes lower case."""
        clean = state.strip().replace("\\", "/").split("/")[-1].lower()
        if " " in clean:
            clean = clean.split()[0]
        return clean or "unknown"

    def _seed_enterprise_baselines(self):
        """Seeds common enterprise execution chains to establish legitimate baseline transitions."""
        normal_chains = [
            ["explorer.exe", "chrome.exe", "chrome.exe"],
            ["explorer.exe", "msedge.exe", "msedge.exe"],
            ["explorer.exe", "outlook.exe", "acrord32.exe"],
            ["explorer.exe", "teams.exe", "teams.exe"],
            ["explorer.exe", "code.exe", "node.exe", "git.exe"],
            ["services.exe", "svchost.exe", "taskhostw.exe"],
            ["services.exe", "spoolsv.exe"],
            ["wininit.exe", "services.exe", "svchost.exe"],
            ["winlogon.exe", "userinit.exe", "explorer.exe"],
            ["system", "smss.exe", "autochk.exe"],
            ["explorer.exe", "excel.exe", "splwow64.exe"],
            ["explorer.exe", "powerpnt.exe"],
            ["cmd.exe", "conhost.exe", "ping.exe"],
            ["cmd.exe", "conhost.exe", "ipconfig.exe"],
            ["powershell.exe", "conhost.exe"],
            ["sshd", "bash", "grep", "cat"],
            ["systemd", "cron", "rsyslogd"],
            ["nginx", "php-fpm", "mysql"],
        ]

        for chain in normal_chains:
            # Train each baseline sequence multiple times to build strong priors
            for _ in range(50):
                self.train_sequence(chain)


# Singleton
markov_detector = MarkovProcessChainDetector()
