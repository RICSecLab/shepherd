import os
import unittest
import sys
from typing import List, Tuple

pwd = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(pwd, "..", "src"))
from SeqMatcher import SeqMatcher  # noqa: E402


class testSeqMatcher(unittest.TestCase):
    def wrap(
        self, patterns: List[List[bytes]], text: bytes
    ) -> List[Tuple[int, int, int]]:
        patterns_as_tuples = tuple([tuple(pattern) for pattern in patterns])
        matcher = SeqMatcher(patterns_as_tuples)
        raw_results = matcher.search(text)
        tuple_results = [
            (match.pat_idx, match.begin, match.end) for match in raw_results
        ]
        return tuple_results

    def test_simple_repeat(self):
        pat0 = [[b"w"]]
        pat1 = [[b"ww"]]
        pat2 = [[b"ww", b"ww"]]
        pat3 = [[b"ww", b"ww", b"ww"]]
        for i in range(100):
            text = b"wwwwww" * i
            num0 = len(self.wrap(pat0, text))
            num1 = len(self.wrap(pat1, text))
            num2 = len(self.wrap(pat2, text))
            num3 = len(self.wrap(pat3, text))
            self.assertEqual(num0, 6 * i)
            self.assertEqual(num1, 3 * i)
            self.assertEqual(num2, 6 * i // 4)
            self.assertEqual(num3, i)

    def test_1(self):
        patterns = [
            [b"hello"],
            [b"Exif"],
            [b"BEGIN", b"aaa"],
            [b"[Exif]"],
            [b"long long string"],
            [b"hello world"],
            [b"hello", b"world"],
            [b"good", b"morning"],
            [b"Good", b"morning"],
            [b"example", b"pattern"],
            [b"sample", b"text"],
            [b"hello", b"beautiful", b"world"],
        ]
        text: bytes = b"hellong long string[Exif] hello hello world. This is a hello amazing world. And here is a sample\ntext. gGoodGood morning everyone! hello world BEGINaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        results = self.wrap(patterns, text)
        matched_cites = [text[match[1] : match[2]] for match in results]
        expected = [
            b"hello",
            b"[Exif]",
            b"hello",
            b"hello world",
            b"hello amazing world",
            b"Good morning",
            b"hello world",
            b"BEGINaaa",
        ]
        self.assertEqual(matched_cites, expected)

    def test_overlaps(self):
        patterns = [
            [b"S", b"A"],
            [b"S", b"B"],
            [b"S", b"C"],
            [b"S", b"D"],
        ]
        text = b"S.....A....B.....C....D"
        results = self.wrap(patterns, text)
        self.assertEqual(results, [(3, 0, len(text))])

    def test_AC_unsorted_starts(self):
        patterns = [
            [b"www", b"w"],
        ]
        text = b"wwww"
        results = self.wrap(patterns, text)
        self.assertEqual(results, [(0, 0, len(text))])


if __name__ == "__main__":
    unittest.main()
