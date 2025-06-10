from typing import List, Tuple, NamedTuple, DefaultDict, Set, FrozenSet, Union
from collections import defaultdict
from AhoCorasick import AhoCorasick, ReversedAhoCorasick
import bisect


class MatchItem(NamedTuple):
    pat_idx: int
    # The gap field is either a list of (begin, end) tuples or a frozenset of nested pattern indices.
    gaps: Union[List[Tuple[int, int]], FrozenSet[int]]
    begin: int
    end: int


def query_filler(
    matches: List[MatchItem], begin: int, end: int, min_idx: int
) -> Tuple[int, bool]:
    """
    Starting from min_idx, find the first match with begin >= 'begin' and end <= 'end'.
    If found, return (index+1, True); if a match starts at or after 'end', return (index, False).
    """
    for idx in range(min_idx, len(matches)):
        mi = matches[idx]
        if mi.begin >= end:
            return idx, False
        if mi.begin >= begin and mi.end <= end:
            return idx + 1, True
    return len(matches), False


def select_longest_matches(matches: List[MatchItem], text_len: int) -> List[MatchItem]:
    """
    Greedily select longest non-overlapping matches from the sorted list,
    and for each selected match, search within each captured gap for nested matches.
    """
    selected = []
    occupied_end = 0
    i = 0
    while i < len(matches) and occupied_end < text_len:
        next_idx, has_hit = query_filler(matches, occupied_end, text_len, i)
        if not has_hit:
            i = next_idx
            continue
        filler_idx = next_idx - 1
        candidate = matches[filler_idx]
        inner_pat_idx_set: Set[int] = set()
        # For each captured gap, try to find a nested match.
        for gap_begin, gap_end in candidate.gaps:
            next_idx_gap, has_hit_gap = query_filler(
                matches, gap_begin, gap_end, next_idx
            )
            if not has_hit_gap:
                continue
            filler_idx_gap = next_idx_gap - 1
            inner_pat_idx_set.add(matches[filler_idx_gap].pat_idx)
        occupied_end = candidate.end
        i = next_idx
        # Replace the gap field with the set of inner pattern indices (as a frozenset).
        selected.append(
            MatchItem(
                candidate.pat_idx,
                frozenset(inner_pat_idx_set),
                candidate.begin,
                candidate.end,
            )
        )
    return selected


class SeqMatcher:
    def __init__(self, patterns: Tuple[Tuple[bytes, ...], ...]):
        """
        `patterns` is a tuple of tuples. Each inner tuple represents the atoms (as bytes)
        obtained by splitting an original string pattern.
        """
        self.patterns: Tuple[Tuple[bytes, ...], ...] = patterns
        # For each occurrence, we store (pattern index, atom offset)
        self.atom_info: List[Tuple[int, int]] = []
        # Mapping from a unique atom (bytes) to the set of indices in `atom_info` where it occurs.
        self.pattern_to_indices: DefaultDict[bytes, Set[int]] = defaultdict(set)
        # The list of unique atoms to be used for building the Aho–Corasick automata.
        self.unique_atoms: List[bytes] = []
        self._gen_matcher()

    def _gen_matcher(self):
        """
        Instead of adding every atom to the Aho–Corasick automata,
        we deduplicate them. We build a map from each unique atom (bytes) to the set
        of positions (indices) in self.atom_info where it occurs.
        """
        self.atom_info = []
        self.pattern_to_indices = defaultdict(set)
        self.unique_atoms = []
        unique_atom_set: Set[bytes] = set()

        for pat_idx, atoms in enumerate(self.patterns):
            for atom_idx, atom in enumerate(atoms):
                current_index = len(self.atom_info)
                self.atom_info.append((pat_idx, atom_idx))
                self.pattern_to_indices[atom].add(current_index)
                if atom not in unique_atom_set:
                    unique_atom_set.add(atom)
                    self.unique_atoms.append(atom)
        assert len(self.unique_atoms) == len(unique_atom_set)

        # Build the automata with the deduplicated list.
        self.ac: AhoCorasick = AhoCorasick(self.unique_atoms)
        self.rac: ReversedAhoCorasick = ReversedAhoCorasick(self.unique_atoms)

    def _get_full_matches(
        self,
        pat_matches: DefaultDict[int, List[Tuple[int, int, int]]],
        newline_positions: List[int],
    ) -> List[MatchItem]:
        """
        For each pattern, find sequences of atoms in order without newlines in between.
        """
        fullpat_matches: List[MatchItem] = []
        for pat_idx, matches in pat_matches.items():
            # Ensure matches are sorted by start position (and then by -end for longest match).
            assert matches == sorted(matches, key=lambda x: (x[1], -x[2]))
            # Organize matches by atom offset.
            atoms_matches: DefaultDict[int, List[Tuple[int, int]]] = defaultdict(list)
            for atom_off, start_idx, end_idx in matches:
                atoms_matches[atom_off].append((start_idx, end_idx))

            first_atom_matches: List[Tuple[int, int]] = atoms_matches.get(0, [])
            cur_forefront: int = 0
            for start_idx, end_idx in first_atom_matches:
                gaps: List[Tuple[int, int]] = []
                last_end: int = end_idx
                valid: bool = True
                for atom_off in range(1, len(self.patterns[pat_idx])):
                    next_matches: List[Tuple[int, int]] = atoms_matches.get(
                        atom_off, []
                    )
                    next_idx = bisect.bisect_left(next_matches, (last_end, 0))
                    if next_idx >= len(next_matches):
                        valid = False
                        break
                    next_start, next_end = next_matches[next_idx]
                    if self._has_newline_between(
                        newline_positions, last_end, next_start
                    ):
                        valid = False
                        break
                    gaps.append((last_end, next_start))
                    last_end = next_end

                if valid:
                    if last_end <= cur_forefront:
                        assert last_end == cur_forefront, (
                            "Dealing with unordered matches"
                        )
                        fullpat_matches.pop()
                    fullpat_matches.append(
                        MatchItem(pat_idx, gaps, start_idx, last_end)
                    )
                    cur_forefront = last_end
        return fullpat_matches

    def search(self, text: bytes) -> List[MatchItem]:
        """
        Search for pattern matches in `text` using the deduplicated Aho–Corasick automata.
        This method collects the match positions and then finds full pattern matches
        by sequencing the individual atom matches.
        """
        newline_positions: List[int] = [
            idx for idx, c in enumerate(text) if c == ord("\n")
        ]
        assert newline_positions == sorted(newline_positions)

        # Search using the reversed automaton to get positions.
        reverse_matches: List[Tuple[int, int, int]] = self.rac.search_with_positions(
            text
        )
        pat_matches: DefaultDict[int, List[Tuple[int, int, int]]] = defaultdict(list)
        # For each match from the unique automaton, expand it to all original occurrences.
        for unique_atom_idx, start_idx, end_idx in reversed(reverse_matches):
            atom = self.unique_atoms[unique_atom_idx]
            for orig_index in self.pattern_to_indices[atom]:
                pat_idx, atom_off = self.atom_info[orig_index]
                pat_matches[pat_idx].append((atom_off, start_idx, end_idx))

        fullpat_matches: List[MatchItem] = self._get_full_matches(
            pat_matches, newline_positions
        )
        # Sort matches by start position and descending end.
        fullpat_matches.sort(key=lambda x: (x.begin, -x.end))
        selected_matches = select_longest_matches(fullpat_matches, len(text))
        return selected_matches

    def _has_newline_between(
        self, newline_positions: List[int], start: int, end: int
    ) -> bool:
        """
        Returns whether there is a newline character in text[start:end].
        """
        assert newline_positions == sorted(newline_positions)
        idx: int = bisect.bisect_left(newline_positions, start)
        return idx < len(newline_positions) and newline_positions[idx] < end
