import re
import logging
from CFG_recover import CFG, XREF, BB
from SeqMatcher import SeqMatcher, MatchItem, select_longest_matches
from typing import List, Set, NamedTuple, Dict
from labrador_coverage import _SIM

pattern = rb"""
        %                   # Literal percent sign
        [0 #+-]?            # Optional flags
        [0-9*]*             # Optional width (digit or *)
        \.?                 # Optional dot
        \d*                 # Optional precision
        [hl]{0,2}           # Optional length modifier
        [jztL]?             # Optional size modifier
        [diuoxXeEfgGaAcpsSn%] # Conversion type
    """


class MatchInfo(NamedTuple):
    xref: XREF
    has_format: bool


class LabradorMatcher:
    def __init__(self, cfg: CFG, epsilon: int):
        self.cfg = cfg
        self.line_to_xrefs_cache: Dict[bytes, Set[XREF]] = {}
        self.epsilon = epsilon

    def get_labrador_bbs(self, response: bytes) -> Set[BB]:
        xrefs = self.get_labrador_xrefs(response)
        coverage: Set[BB] = set()
        for xref in xrefs:
            coverage.update(xref.bbs)
        return coverage

    def get_labrador_bbs_no_cache(self, response: bytes) -> Set[BB]:
        xrefs = self.get_labrador_xrefs_no_cache(response)
        coverage: Set[BB] = set()
        for xref in xrefs:
            coverage.update(xref.bbs)
        return

    def get_labrador_xrefs(self, response: bytes) -> Set[XREF]:
        response_lines = response.splitlines(keepends=True)
        xref_set: Set[XREF] = set()
        for line in response_lines:
            if len(line) == 0:
                continue
            if line in self.line_to_xrefs_cache:  # cache hit
                xref_set.update(self.line_to_xrefs_cache[line])
                continue
            line_xrefs: Set[XREF] = set()  # xrefs associated with the line bytes
            for xref in self.cfg.string_xref.values():
                if _SIM(line, xref.literal) > self.epsilon:
                    line_xrefs.add(xref)
                    xref_set.add(xref)
            self.line_to_xrefs_cache[line] = line_xrefs
        return xref_set

    def get_labrador_xrefs_no_cache(self, response: bytes) -> Set[XREF]:
        response_lines = response.splitlines(keepends=True)
        xref_set: Set[XREF] = set()
        for line in response_lines:
            if len(line) == 0:
                continue
            line_xrefs: Set[XREF] = set()
            for xref in self.cfg.string_xref.values():
                if _SIM(line, xref.literal) > self.epsilon:
                    line_xrefs.add(xref)
                    xref_set.add(xref)
        return xref_set


def find_nearby_xrefs(
    result_idx: int,
    results: List[MatchItem],
    sub_xref: List[XREF],
    idx_to_match_info: List[MatchInfo],
    context_size,
) -> List[XREF]:
    nearby_xrefs: List[XREF] = []
    nearby_xrefs.extend(sub_xref)
    for i in range(1, context_size + 1):
        succ_idx = result_idx + i
        pred_idx = result_idx - i
        if succ_idx < len(results):
            succ_xref = idx_to_match_info[results[succ_idx].pat_idx].xref
            nearby_xrefs.append(succ_xref)
        if pred_idx >= 0:
            pred_xref = idx_to_match_info[results[pred_idx].pat_idx].xref
            nearby_xrefs.append(pred_xref)
    return nearby_xrefs[:context_size]


def CDBI(
    match_items: List[MatchItem], idx_to_match_info: List[MatchInfo], cfg
) -> Set[BB]:
    """
    Context-Driven Block Identification (CDBI) algorithm for BB matching.
    """
    context_size = 5
    beam_width = 10

    match_bbs: Set[BB] = set()
    for i, (pat_idx, gap_matches, _, _) in enumerate(match_items):
        assert isinstance(gap_matches, frozenset)
        xref = idx_to_match_info[pat_idx].xref
        sub_xref = list(map(lambda x: idx_to_match_info[x].xref, gap_matches))
        # Also walks inside the %s, %d, etc. patterns
        for sxref in sub_xref:
            if len(sxref.bbs) == 1:
                match_bbs.update(sxref.bbs)

        bbs = xref.bbs
        if len(bbs) > 1:
            """
            We have multiple candidates BBs for this string pattern:
                decide which one is more likely by distance-based heuristic
            """
            nearby_xrefs = find_nearby_xrefs(
                i, match_items, sub_xref, idx_to_match_info, context_size
            )

            initial_beam = [(bb, 0) for bb in bbs]  # (current_bb, accumulated_distance)

            for nearby_xref in nearby_xrefs:
                nearby_bbs = nearby_xref.bbs
                next_beam = []
                for cur_bb, cur_dist in initial_beam:
                    for neighbor_bb in nearby_bbs:
                        distance = cfg.get_bb_distance(cur_bb, neighbor_bb)
                        next_beam.append((cur_bb, cur_dist + distance))
                next_beam.sort(key=lambda item: item[1])
                initial_beam = next_beam[:beam_width]

            if initial_beam:
                # The bbs with the smallest distance is regarded as "passed"
                best_bb, best_dist = initial_beam[0]
                for bb, dist in initial_beam:
                    if dist != best_dist:
                        break
                    match_bbs.add(bb)
                match_bbs.add(best_bb)

        else:
            match_bbs.update(bbs)
    return match_bbs


class RegexMatcher:
    # Replace each format specifier with a "([^\\n]*)" regex,
    # so that any format specifier (like %d, %s, etc.) is treated as any non-newline sequence
    # and captured for nested matching.
    def __init__(self, cfg: CFG):
        self.idx_to_match_info: List[MatchInfo] = []
        self.cfg = cfg
        # List of tuples (compiled_pattern, xref)
        self.xref_patterns = []
        self._gen_matcher(cfg)
        self.line_to_matchitems_cache: Dict[bytes, List[MatchItem]] = {}

    def _gen_matcher(self, cfg: CFG):
        """
        For each xref in the cfg, generate a regex pattern from its literal.
        In the literal, any format specifier (matched using the given 'pattern')
        is first removed via splitting and then the literal parts are concatenated
        with the regex "[^\n]*", following the BBMatcher approach.
        """
        fs_regex = re.compile(pattern, re.VERBOSE)
        self.xref_patterns = []
        for xref in cfg.string_xref.values():
            literal = xref.literal.rstrip(b"\n")
            parts = fs_regex.split(literal)
            has_format = len(parts) > 1
            len_all_parts = sum(len(part) for part in parts if part)
            if len_all_parts <= 3:
                continue

            escaped_parts = [re.escape(part) for part in parts if part]
            # Join the escaped parts with "[^\n]*" in between.
            new_pattern = b"([^\\n]*)".join(escaped_parts)
            try:
                compiled_pat = re.compile(new_pattern)
            except re.error as e:
                logging.error(f"Error compiling regex for xref {xref}: {e}")
                continue
            self.idx_to_match_info.append(MatchInfo(xref, has_format))
            self.xref_patterns.append((compiled_pat, xref))

    def search_bbs(self, text: bytes) -> Set[BB]:
        """
        Line-level caching version of search_bbs:
        Processes the text one line at a time. For each line, it checks whether the match items
        are already cached. If not, it computes the match items for that line and caches them.
        After processing all lines, it combines the match items and applies the CDBI logic.
        """
        match_items: List[MatchItem] = []
        for line in text.splitlines(keepends=True):
            if line == b"\n":
                continue
            if line in self.line_to_matchitems_cache:
                line_matches = self.line_to_matchitems_cache[line]
            else:
                line_matches = []
                for pat_idx, (compiled_pat, xref) in enumerate(self.xref_patterns):
                    for m in compiled_pat.finditer(line):
                        if m.start() == m.end():
                            continue
                        gap_spans = []
                        if m.lastindex:
                            for i in range(1, m.lastindex + 1):
                                gap_spans.append(m.span(i))
                        line_matches.append(
                            MatchItem(pat_idx, gap_spans, m.start(), m.end())
                        )
                # Sort and select longest matches on this line.
                line_matches.sort(key=lambda mi: (mi.begin, -mi.end))
                line_matches = select_longest_matches(line_matches, len(line))
                self.line_to_matchitems_cache[line] = line_matches
            match_items.extend(line_matches)

        return CDBI(match_items, self.idx_to_match_info, self.cfg)


class BBMatcher:
    def __init__(self, cfg: CFG):
        self.idx_to_match_info: List[MatchInfo] = []
        self.cfg = cfg
        self._gen_matcher(cfg)
        # Initialize the line-level cache for match items (mapping a line to its MatchItems).
        self.line_to_matchitems_cache: Dict[bytes, List[MatchItem]] = {}

    def _gen_matcher(self, cfg: CFG):
        regex = re.compile(pattern, re.VERBOSE)
        pattern_list = []
        for xref in cfg.string_xref.values():
            literal = xref.literal.rstrip(b"\n")
            parts = regex.split(literal)
            has_format = len(parts) > 1
            len_all_parts = sum(len(part) for part in parts)
            if len_all_parts <= 3:
                continue
            parts = [part for part in parts if part]
            pattern_list.append(tuple(parts))
            self.idx_to_match_info.append(MatchInfo(xref, has_format))
        pattern_tuple = tuple(pattern_list)
        self.seq_matcher = SeqMatcher(pattern_tuple)

    def search(self, text: bytes) -> List[int]:
        results = self.seq_matcher.search(text)
        matched_pat_idx_set = set()
        for pat_idx, _, _, _ in results:
            matched_pat_idx_set.add(pat_idx)
        return list(matched_pat_idx_set)

    def search_bbs_without_beam(self, text: bytes) -> Set[BB]:
        match_items: List[MatchItem] = []
        for line in text.splitlines(keepends=True):
            if line == b"\n":
                continue
            if line in self.line_to_matchitems_cache:
                line_matches = self.line_to_matchitems_cache[line]
            else:
                raise ValueError(
                    "search_bbs needs to run beforehand: experiment is done wrong"
                )
            match_items.extend(line_matches)

        match_bbs = set()
        for pat_idx, gap_matches, _, _ in match_items:
            assert isinstance(gap_matches, frozenset)
            xref = self.idx_to_match_info[pat_idx].xref
            sub_xref = list(map(lambda x: self.idx_to_match_info[x].xref, gap_matches))
            for sxref in sub_xref:
                match_bbs.update(sxref.bbs)
            match_bbs.update(xref.bbs)
        return match_bbs

    def search_bbs_no_cache(self, text: bytes) -> Set[BB]:
        results: List[MatchItem] = self.seq_matcher.search(text)
        return CDBI(results, self.idx_to_match_info, self.cfg)

    # New method: process text line by line with caching.
    def search_bbs(self, text: bytes) -> Set[BB]:
        # Split the text by newline and process each line individually.
        match_items: List[MatchItem] = []
        for line in text.splitlines(keepends=True):
            if line == b"\n":
                continue
            # Use cached match items for the line if available.
            if line in self.line_to_matchitems_cache:
                match_items.extend(self.line_to_matchitems_cache[line])
            else:
                line_matches = self.seq_matcher.search(line)
                match_items.extend(line_matches)
                self.line_to_matchitems_cache[line] = line_matches
            # Apply Context-Driven Block Identification (CDBI) on the line's matches.
        return CDBI(match_items, self.idx_to_match_info, self.cfg)


def augment_dominators(orig_bbs: Set[BB]) -> Set[BB]:
    bbs = orig_bbs.copy()
    new_bbs = set()
    for bb in bbs:
        new_bbs.update(bb.doms | bb.pdoms)
    old_num = len(bbs)
    bbs.update(new_bbs)
    new_num = len(bbs)
    logging.debug(f"Dominator Augmentation: {old_num} -> {new_num}")
    return bbs


def augment_must_bbs(orig_bbs: Set[BB]) -> Set[BB]:
    match_bbs = augment_dominators(orig_bbs)
    implicate_bbs = set()
    for bb in match_bbs:
        """
        Prototype-level edge-inference focusing on BBs with single predecessor/successor
        """
        if len(bb.pred_bbs) == 1:
            pred = next(iter(bb.pred_bbs))
            implicate_bbs.update(pred.edge_implicate_bbs[bb])
        if len(bb.dst_bbs) == 1:
            succ = next(iter(bb.dst_bbs))
            implicate_bbs.update(bb.edge_implicate_bbs[succ])
    old_num = len(match_bbs)
    match_bbs.update(implicate_bbs)
    new_num = len(match_bbs)

    logging.debug(f"MUST-BB Augmentation: {old_num} -> {new_num}")

    return match_bbs


def aggressive_augment(orig_bbs) -> Set[BB]:
    """
    In minimized CFG infers that we have passed edge (bb1, bb2) iff both bb1 and bb2 are
    in the original BB set and add implicated BBs by those edges.
    This is aggressive and can easily add false-positives.
    For example, cosider the following CFG and the original BB set is {bb1, bb2, bb3}
    (bb1) ---------------> (bb3)
           \-> (bb2) -/^
    When the actual execution passed (bb1 -> bb2 -> bb3), we still infer that the execution
    have passed (bb1 -> bb3) because both of bb1 and bb3 belong to the original BB set.
    This requires further investigation to see if we should make the edge inference more conservative.
    """
    match_bbs = augment_dominators(orig_bbs)
    implicate_bbs = set()
    for bb in match_bbs:
        for succ in bb.dst_bbs:
            if succ in match_bbs:
                implicate_bbs.update(bb.edge_implicate_bbs[succ])

    old_num = len(match_bbs)
    match_bbs.update(implicate_bbs)
    new_num = len(match_bbs)
    logging.debug(f"Aggressive Augmentation: {old_num} -> {new_num}")
    return match_bbs
