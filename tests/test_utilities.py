"""Real boundary and fidelity checks for text utilities."""

import hashlib
import json
import threading
import unittest

from networkluki_cyberlab.utilities import compare_text, format_json, MAX_INPUT_BYTES


class UtilityTests(unittest.TestCase):
    def test_preserves_exact_numbers_and_unicode(self):
        source = '{"n":123456789012345678901234567890,"f":0.12345678901234567890,"z":-0,"small":1e-9999,"text":"räksmörgås"}'
        result = format_json(source)
        for token in ("123456789012345678901234567890", "0.12345678901234567890", "-0", "1e-9999", "räksmörgås"):
            self.assertIn(token, result["formatted"])
        self.assertEqual(result["input_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(format_json(result["formatted"])["formatted"], result["formatted"])
        huge_integer = "9" * 5000
        self.assertEqual(format_json(huge_integer)["formatted"], huge_integer)
        self.assertEqual(json.loads(format_json('"\\ud83d\\ude80"')["formatted"]), "🚀")

    def test_json_scalars_and_empty_containers(self):
        for source in ('null', 'false', '123', '"hello"', '[]', '{}'):
            self.assertEqual(json.loads(format_json(source)["formatted"]), json.loads(source))

    def test_rejects_ambiguous_nonstandard_or_invalid_json(self):
        for source in ('{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":NaN}', 'Infinity', '{"a":}', '"\\ud800"'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                format_json(source)

    def test_json_depth_is_bounded_but_brackets_in_strings_are_ignored(self):
        with self.assertRaises(ValueError):
            format_json('[' * 65 + '0' + ']' * 65)
        self.assertIn('"[[["', format_json('{"text":"[[["}')["formatted"])
        self.assertEqual(json.loads(format_json('[' * 64 + '0' + ']' * 64)["formatted"]), json.loads('[' * 64 + '0' + ']' * 64))

    def test_byte_and_expansion_limits(self):
        with self.assertRaises(ValueError):
            format_json('"' + 'ö' * (MAX_INPUT_BYTES // 2) + '"')
        with self.assertRaises(ValueError):
            format_json('[' * 63 + '[' + ','.join(['0'] * 3000) + ']' * 64)
        with self.assertRaises(ValueError):
            compare_text('x' * (MAX_INPUT_BYTES + 1), '')

    def test_diff_addition_and_final_newline(self):
        result = compare_text('one\ntwo', 'one\nthree\n')
        self.assertTrue(result['changed'])
        self.assertIn('-two\n\\ No newline at end of file\n', result['diff'])
        self.assertIn('+three\n', result['diff'])
        self.assertIn('--- before', result['diff'])
        self.assertEqual(result['before_sha256'], hashlib.sha256(b'one\ntwo').hexdigest())

    def test_empty_equal_and_line_ending_changes(self):
        self.assertEqual(compare_text('', '')['diff'], '')
        self.assertFalse(compare_text('same\n', 'same\n')['changed'])
        self.assertTrue(compare_text('same', 'same\n')['changed'])
        self.assertIn('\\ No newline', compare_text('same', 'same\n')['diff'])
        self.assertTrue(compare_text('same\r\n', 'same\n')['changed'])

    def test_diff_line_limit_and_cancellation(self):
        with self.assertRaises(ValueError):
            compare_text('line\n' * 1001, '')
        cancel = threading.Event()
        cancel.set()
        for function, arguments in ((format_json, ('{}',)), (compare_text, ('a', 'b'))):
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                function(*arguments, cancel=cancel)


if __name__ == '__main__':
    unittest.main()
