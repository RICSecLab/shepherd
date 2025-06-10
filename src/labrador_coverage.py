from CFG_recover import BB, Funcnode, CFG, Path, XREF
from typing import List, Dict, Set
import Levenshtein


def levenshtein_distance(s1: bytes, s2: bytes) -> int:
    return Levenshtein.distance(s1, s2)


def _LCS(s1, s2):
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    max_length = 0
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
                max_length = max(max_length, dp[i][j])
    return max_length


def _SIM(s1, s2):
    return max(
        1 - (levenshtein_distance(s1, s2) / (max(len(s1), len(s2)))),
        _LCS(s1, s2) / min(len(s1), len(s2)),
    )
