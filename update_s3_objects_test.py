"""
Test S3 interaction
"""
import base64
import unittest
from typing import List
from update_s3_objects import decode, encode, generate_actions


class TestAddressEncoding(unittest.TestCase):
    """
    Test encoding
    """
    def test_encode(self) -> None:
        """Test that addresses are correctly encoded."""
        test_cases = [
            "t1WSKwCDL1QYRRUrCCknEs5tDLhtGVYu9KM",
            "t1g7wowvQ8gn2v8jrU1biyJ26sieNqNsBJy",
            "test@example.com",
            "1234567890",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "!@#$%^&*()_+-=[]{}|;:,.<>/?",
            "a" * 50,
            "",
        ]

        for address in test_cases:
            encoded = encode(address)
            self.assertNotIn('=', encoded)
            self.assertNotIn('+', encoded)
            self.assertNotIn('/', encoded)

            # Check that we can manually decode it correctly without our decode
            # function
            pad_len = (4 - len(encoded) % 4) % 4
            padded = encoded + '=' * pad_len
            decoded_bytes = base64.urlsafe_b64decode(padded)
            self.assertEqual(decoded_bytes.decode(), address)

    def test_decode(self) -> None:
        """Test that encoded addresses are correctly decoded."""
        test_cases = [
            # t1WSKwCDL1QYRRUrCCknEs5tDLhtGVYu9KM
            "dDFXU0t3Q0RMMVFZUlJVckNDa25FczV0RExodEdWWXU5S00",
            # t1g7wowvQ8gn2v8jrU1biyJ26sieNqNsBJy
            "dDFnN3dvd3ZROGduMnY4anJVMWJpeUoyNnNpZU5xTnNCSnk",
            # test@example.com
            "dGVzdEBleGFtcGxlLmNvbQ",
            # 1234567890
            "MTIzNDU2Nzg5MA",
            # abcdefghijklmnopqrstuvwxyz
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo",
        ]

        for encoded in test_cases:
            decoded = decode(encoded)
            re_encoded = encode(decoded)
            self.assertEqual(re_encoded, encoded)

    def test_roundtrip(self) -> None:
        """Test encoding and then decoding returns the original address."""
        test_cases = [
            "t1WSKwCDL1QYRRUrCCknEs5tDLhtGVYu9KM",
            "t1g7wowvQ8gn2v8jrU1biyJ26sieNqNsBJy",
            "test@example.com",
            "1234567890",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "!@#$%^&*()_+-=[]{}|;:,.<>/?",
            "a" * 50,
            "",
        ]

        for original in test_cases:
            encoded = encode(original)
            decoded = decode(encoded)
            self.assertEqual(decoded, original)

    def test_padding_handling(self) -> None:
        """Test that the functions correctly handle padding."""
        test_cases: List[str] = []
        test_cases.append("abc")  # 3 bytes = 4 base64 chars, no padding
        test_cases.append("abcd")  # 4 bytes = 6 base64 chars, 2 padding chars
        test_cases.append("abcde")  # 5 bytes = 8 base64 chars, 1 padding char

        for original in test_cases:
            encoded = encode(original)
            decoded = decode(encoded)
            self.assertEqual(decoded, original)


class TestGenerateActions(unittest.TestCase):
    """
    Test action generation based on every combination of set relationships
    """
    def test_empty_lists(self):
        """Test with empty lists"""
        result = generate_actions([], [])
        self.assertEqual(result, [])

    def test_identical_lists(self):
        """Test with identical lists"""
        test_list = ["addr1", "addr2", "addr3"]
        result = generate_actions(test_list, test_list)
        self.assertEqual(result, [])

    def test_completely_different_lists(self):
        """Test with lists that don't have any common elements"""
        true_list = ["addr1", "addr2", "addr3"]
        mirror_list = ["addr4", "addr5", "addr6"]
        result = generate_actions(true_list, mirror_list)

        # Check all items from true_list have 'add' actions
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 3)
        self.assertTrue(
            all(item['address'] in true_list for item in add_actions)
        )

        # Check all items from mirror_list have 'remove' actions
        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 3)
        self.assertTrue(
            all(item['address'] in mirror_list for item in remove_actions)
        )

        # Total actions should be sum of both lists' lengths
        self.assertEqual(len(result), len(true_list) + len(mirror_list))

    def test_partially_overlapping_lists(self):
        """Test with lists that have some common elements"""
        true_list = ["addr1", "addr2", "addr3", "addr4"]
        mirror_list = ["addr3", "addr4", "addr5", "addr6"]
        result = generate_actions(true_list, mirror_list)

        # Check for correct add actions: addr1, addr2
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 2)
        add_addresses = [item['address'] for item in add_actions]
        self.assertIn("addr1", add_addresses)
        self.assertIn("addr2", add_addresses)

        # Check for correct remove actions: addr5, addr6
        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 2)
        remove_addresses = [item['address'] for item in remove_actions]
        self.assertIn("addr5", remove_addresses)
        self.assertIn("addr6", remove_addresses)

        # Total actions should be 4
        self.assertEqual(len(result), 4)

    def test_true_list_subset_of_mirror(self):
        """Test when true_list is a subset of mirror_list"""
        true_list = ["addr1", "addr2"]
        mirror_list = ["addr1", "addr2", "addr3", "addr4"]
        result = generate_actions(true_list, mirror_list)

        # Check no add actions
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 0)

        # Check for correct remove actions: addr3, addr4
        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 2)
        remove_addresses = [item['address'] for item in remove_actions]
        self.assertIn("addr3", remove_addresses)
        self.assertIn("addr4", remove_addresses)

        # Total actions should be 2
        self.assertEqual(len(result), 2)

    def test_mirror_list_subset_of_true(self):
        """Test when mirror_list is a subset of true_list"""
        true_list = ["addr1", "addr2", "addr3", "addr4"]
        mirror_list = ["addr1", "addr2"]
        result = generate_actions(true_list, mirror_list)

        # Check for correct add actions: addr3, addr4
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 2)
        add_addresses = [item['address'] for item in add_actions]
        self.assertIn("addr3", add_addresses)
        self.assertIn("addr4", add_addresses)

        # Check no remove actions
        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 0)

        # Total actions should be 2
        self.assertEqual(len(result), 2)

    def test_duplicate_elements(self):
        """
        Test with duplicate elements in the lists. This would be unexpected,
        but an error in the SDN or our scripts could produce such a
        pathological case
        """
        true_list = ["addr1", "addr1", "addr2", "addr3"]
        mirror_list = ["addr2", "addr3", "addr3", "addr4"]
        result = generate_actions(true_list, mirror_list)

        # Duplicates should be ignored (as sets are used)
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 1)  # Only addr1
        self.assertEqual(add_actions[0]['address'], "addr1")

        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 1)  # Only addr4
        self.assertEqual(remove_actions[0]['address'], "addr4")

    def test_with_non_string_elements(self):
        """Test with non-string elements. Another one that shouldn't happen"""
        true_list = [1, 2, 3]
        mirror_list = [3, 4, 5]
        result = generate_actions(true_list, mirror_list)

        # Check for correct add actions: 1, 2
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 2)
        add_addresses = [item['address'] for item in add_actions]
        self.assertIn(1, add_addresses)
        self.assertIn(2, add_addresses)

        # Check for correct remove actions: 4, 5
        remove_actions = [
            item for item in result if item['action'] == 'remove'
        ]
        self.assertEqual(len(remove_actions), 2)
        remove_addresses = [item['address'] for item in remove_actions]
        self.assertIn(4, remove_addresses)
        self.assertIn(5, remove_addresses)


if __name__ == "__main__":
    unittest.main()
