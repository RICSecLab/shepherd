from typing import List, Dict, Set, DefaultDict, Deque, Tuple
from collections import deque, defaultdict


class AhoCorasick:
    def __init__(self, patterns: List[bytes]):
        self.patterns = patterns
        self.goto: Dict[int, Dict[int, int]] = {}
        self.output: DefaultDict[int, List[int]] = defaultdict(list)
        self.failure: Dict[int, int] = {}
        self._build()

    def _build(self):
        # Build goto (trie)
        self.goto[0] = {}
        for i, pat in enumerate(self.patterns):
            cur_node = 0
            for char in pat:
                if cur_node in self.goto and char in self.goto[cur_node]:
                    cur_node = self.goto[cur_node][char]
                else:
                    new_node = len(self.goto)
                    if cur_node not in self.goto:
                        self.goto[cur_node] = {}
                    self.goto[cur_node][char] = new_node
                    self.goto[new_node] = {}
                    cur_node = new_node
            self.output[cur_node].append(i)

        # Build failure funcs
        queue: Deque[int] = deque()
        for char in self.goto[0]:
            queue.append(self.goto[0][char])
            self.failure[self.goto[0][char]] = 0

        while queue:
            node = queue.popleft()
            for char in self.goto[node]:
                failure = self.failure[node]
                while failure > 0 and char not in self.goto[failure]:
                    failure = self.failure[failure]
                if char in self.goto[failure]:
                    failure = self.goto[failure][char]

                next_node = self.goto[node][char]
                queue.append(next_node)

                self.failure[next_node] = failure
                if failure in self.output:
                    self.output[next_node].extend(self.output[failure])
        # for each output, sort the items by its length in descending order
        for out_items in self.output.values():
            out_items.sort(key=lambda x: len(self.patterns[x]))

    # Small deviation from normal Aho-Corasick:
    # We are interested only in the matched patterns
    def search(self, text: bytes) -> Set[int]:
        results = set()
        cur_node = 0

        for char in text:
            while cur_node > 0 and char not in self.goto[cur_node]:
                cur_node = self.failure[cur_node]
            if char in self.goto[cur_node]:
                cur_node = self.goto[cur_node][char]

            if cur_node in self.output:
                for pattern_index in self.output[cur_node]:
                    results.add(pattern_index)

        return results

    def search_with_positions(self, text: bytes) -> List[Tuple[int, int, int]]:
        res = []
        # Cache attribute lookups in local variables
        goto = self.goto
        failure = self.failure
        output = self.output
        patterns = self.patterns
        cur_node = 0

        for idx, char in enumerate(text):
            while cur_node and char not in goto[cur_node]:
                cur_node = failure[cur_node]
            cur_node = goto[cur_node].get(char, 0)
            outs = output.get(cur_node)
            if outs:
                # Instead of calling append for each match, we create the list and extend once.
                res.extend((pi, idx - len(patterns[pi]) + 1, idx + 1) for pi in outs)
        # The assertion guarantees the results are sorted as required
        assert res == sorted(res, key=lambda x: (x[2], -x[1]))
        return res


# We care about the order of the Aho-Corasick results
# By reversing the search patterns and the text, we can get a nice order
class ReversedAhoCorasick(AhoCorasick):
    def __init__(self, patterns: List[bytes]):
        reversed_patterns = [pattern[::-1] for pattern in patterns]
        super().__init__(reversed_patterns)

    def search_with_positions(self, text: bytes) -> List[Tuple[int, int, int]]:
        return [
            (idx, len(text) - end, len(text) - start)
            for idx, start, end in super().search_with_positions(text[::-1])
        ]
