"""
Test S3 interaction
"""
import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from update_s3_objects import (
    create_s3_object,
    decode,
    delete_s3_object,
    encode,
    format_result_message,
    generate_actions,
    process_action_chunk,
    read_sanctioned_addresses,
)


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
        test_cases: list[str] = []
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

    # Empty SDN list should generate remove actions
    def test_empty_sdn_with_existing_s3_objects(self):
        """
        Test that when SDN list is empty but S3 has objects,
        remove actions are generated for all S3 objects.
        This catches a where an empty SDN would cause early exit.
        """
        true_list = []  # Empty SDN
        mirror_list = ["addr1", "addr2", "addr3"]  # S3 has objects
        result = generate_actions(true_list, mirror_list)

        # Should generate remove actions for all S3 objects
        remove_actions = [item for item in result if item['action'] == 'remove']
        self.assertEqual(len(remove_actions), 3)

        # No add actions
        add_actions = [item for item in result if item['action'] == 'add']
        self.assertEqual(len(add_actions), 0)

        # All S3 addresses should be in remove actions
        remove_addresses = [item['address'] for item in remove_actions]
        self.assertEqual(set(remove_addresses), set(mirror_list))


class TestReadSanctionedAddresses(unittest.TestCase):
    """Test reading sanctioned addresses from files"""

    def setUp(self):
        """Set up temporary directory for test files"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up temporary directory"""
        self.temp_dir.cleanup()

    def test_read_single_file(self):
        """Test reading a single sanctioned addresses file"""
        test_file = self.temp_path / "sanctioned_addresses_XBT.txt"
        addresses = ["addr1", "addr2", "addr3"]
        with open(test_file, 'w') as f:
            f.write('\n'.join(addresses))

        result = read_sanctioned_addresses(str(self.temp_path))
        self.assertEqual(result, set(addresses))

    def test_read_multiple_files(self):
        """Test reading multiple sanctioned addresses files"""
        xbt_file = self.temp_path / "sanctioned_addresses_XBT.txt"
        eth_file = self.temp_path / "sanctioned_addresses_ETH.txt"

        xbt_addresses = ["xbt1", "xbt2"]
        eth_addresses = ["eth1", "eth2"]

        with open(xbt_file, 'w') as f:
            f.write('\n'.join(xbt_addresses))
        with open(eth_file, 'w') as f:
            f.write('\n'.join(eth_addresses))

        result = read_sanctioned_addresses(str(self.temp_path))
        expected = set(xbt_addresses + eth_addresses)
        self.assertEqual(result, expected)

    def test_deduplicate_addresses_across_files(self):
        """Test that duplicate addresses across files are deduplicated"""
        file1 = self.temp_path / "sanctioned_addresses_XBT.txt"
        file2 = self.temp_path / "sanctioned_addresses_ETH.txt"

        with open(file1, 'w') as f:
            f.write("addr1\naddr2\naddr3")
        with open(file2, 'w') as f:
            f.write("addr2\naddr3\naddr4")  # addr2 and addr3 are duplicates

        result = read_sanctioned_addresses(str(self.temp_path))
        self.assertEqual(result, {"addr1", "addr2", "addr3", "addr4"})

    def test_ignore_empty_lines(self):
        """Test that empty lines are ignored"""
        test_file = self.temp_path / "sanctioned_addresses_XBT.txt"
        with open(test_file, 'w') as f:
            f.write("addr1\n\naddr2\n  \naddr3\n")

        result = read_sanctioned_addresses(str(self.temp_path))
        self.assertEqual(result, {"addr1", "addr2", "addr3"})

    # Empty directory should return empty set, not crash
    def test_empty_directory(self):
        """
        Test that empty directory (no sanctioned address files) returns empty set.
        This is critical if the script should not exit early, but should proceed to
        clean up S3 objects.
        """
        result = read_sanctioned_addresses(str(self.temp_path))
        self.assertEqual(result, set())

    # All files deleted (OFAC removed all assets)
    def test_directory_with_no_matching_files(self):
        """
        Test directory with files but no sanctioned_addresses_*.txt files.
        Should return empty set and allow cleanup to proceed.
        """
        # Create some other files that don't match the pattern
        other_file = self.temp_path / "other_file.txt"
        with open(other_file, 'w') as f:
            f.write("some content")

        result = read_sanctioned_addresses(str(self.temp_path))
        self.assertEqual(result, set())


class TestProcessActionChunk(unittest.TestCase):
    """Test action processing logic"""

    def setUp(self):
        """Set up mock S3 client"""
        self.mock_s3_client = Mock()

    # Verify successful adds are counted correctly
    def test_successful_add_actions(self):
        """
        Test that successful add actions are counted correctly.
        """
        actions = [
            {'action': 'add', 'address': 'addr1'},
            {'action': 'add', 'address': 'addr2'},
        ]

        with patch('update_s3_objects.create_s3_object', return_value=(True, None)):
            result = process_action_chunk(
                actions, 'test-bucket', '', False, self.mock_s3_client
            )

        self.assertEqual(result['created'], 2)
        self.assertEqual(result['removed'], 0)
        self.assertEqual(result['errors'], 0)

    # Verify successful removes are counted correctly
    def test_successful_remove_actions(self):
        """
        Test that successful remove actions are counted correctly.
        """
        actions = [
            {'action': 'remove', 'address': 'addr1'},
            {'action': 'remove', 'address': 'addr2'},
        ]

        with patch('update_s3_objects.delete_s3_object', return_value=(True, None)):
            result = process_action_chunk(
                actions, 'test-bucket', '', False, self.mock_s3_client
            )

        self.assertEqual(result['created'], 0)
        self.assertEqual(result['removed'], 2)
        self.assertEqual(result['errors'], 0)

    # Verify failed actions are counted as errors
    def test_failed_actions_counted_as_errors(self):
        """Test that failed actions are correctly counted as errors"""
        actions = [
            {'action': 'add', 'address': 'addr1'},
            {'action': 'remove', 'address': 'addr2'},
        ]

        with patch(
            'update_s3_objects.create_s3_object',
            return_value=(False, "Add failed")
        ):
            with patch(
                'update_s3_objects.delete_s3_object',
                return_value=(False, "Delete failed")
            ):
                result = process_action_chunk(
                    actions, 'test-bucket', '', False, self.mock_s3_client
                )

        self.assertEqual(result['created'], 0)
        self.assertEqual(result['removed'], 0)
        self.assertEqual(result['errors'], 2)

    # Mixed success and failure
    def test_mixed_success_and_failure(self):
        """Test mixture of successful and failed operations"""
        actions = [
            {'action': 'add', 'address': 'addr1'},
            {'action': 'add', 'address': 'addr2'},
            {'action': 'remove', 'address': 'addr3'},
            {'action': 'remove', 'address': 'addr4'},
        ]

        # Mock create_s3_object: first succeeds, second fails
        create_side_effect = [(True, None), (False, "Creation failed")]
        # Mock delete_s3_object: first succeeds, second fails
        delete_side_effect = [(True, None), (False, "Deletion failed")]

        with patch(
            'update_s3_objects.create_s3_object',
            side_effect=create_side_effect
        ):
            with patch(
                'update_s3_objects.delete_s3_object',
                side_effect=delete_side_effect
            ):
                result = process_action_chunk(
                    actions, 'test-bucket', '', False, self.mock_s3_client
                )

        self.assertEqual(result['created'], 1)
        self.assertEqual(result['removed'], 1)
        self.assertEqual(result['errors'], 2)


class TestS3Operations(unittest.TestCase):
    """Test individual S3 operations"""

    def setUp(self):
        """Set up mock S3 client"""
        self.mock_s3_client = Mock()

    def test_create_s3_object_success(self):
        """Test successful S3 object creation"""
        success, error = create_s3_object(
            'test_address', 'test-bucket', '', False, self.mock_s3_client
        )

        self.assertTrue(success)
        self.assertIsNone(error)
        self.mock_s3_client.upload_fileobj.assert_called_once()

    def test_create_s3_object_failure(self):
        """Test failed S3 object creation"""
        self.mock_s3_client.upload_fileobj.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
            'PutObject'
        )

        success, error = create_s3_object(
            'test_address', 'test-bucket', '', False, self.mock_s3_client
        )

        self.assertFalse(success)
        self.assertIsNotNone(error)
        self.assertIn('Error creating S3 object', error)

    def test_delete_s3_object_success(self):
        """Test successful S3 object deletion"""
        # Mock head_object to raise 404 (object doesn't exist after deletion)
        self.mock_s3_client.head_object.side_effect = ClientError(
            {'Error': {'Code': '404', 'Message': 'Not Found'}},
            'HeadObject'
        )

        success, error = delete_s3_object(
            'test_address', 'test-bucket', '', False, self.mock_s3_client
        )

        self.assertTrue(success)
        self.assertIsNone(error)
        self.mock_s3_client.delete_object.assert_called_once()

    def test_dry_run_create(self):
        """Test that dry run doesn't actually create objects"""
        success, error = create_s3_object(
            'test_address', 'test-bucket', '', True, self.mock_s3_client
        )

        self.assertTrue(success)
        self.assertIsNone(error)
        self.mock_s3_client.upload_fileobj.assert_not_called()

    def test_dry_run_delete(self):
        """Test that dry run doesn't actually delete objects"""
        success, error = delete_s3_object(
            'test_address', 'test-bucket', '', True, self.mock_s3_client
        )

        self.assertTrue(success)
        self.assertIsNone(error)
        self.mock_s3_client.delete_object.assert_not_called()


class TestFormatResultMessage(unittest.TestCase):
    """Test result message formatting"""

    def test_only_additions(self):
        """Test message with only additions"""
        result = format_result_message(5, 0)
        self.assertIn("added 5 addresses", result)
        self.assertNotIn("removed", result)

    def test_only_removals(self):
        """Test message with only removals"""
        result = format_result_message(0, 3)
        self.assertIn("removed 3 addresses", result)
        self.assertNotIn("added", result)

    def test_both_additions_and_removals(self):
        """Test message with both additions and removals"""
        result = format_result_message(2, 3)
        self.assertIn("added 2 addresses", result)
        self.assertIn("removed 3 addresses", result)

    def test_no_changes(self):
        """Test message when no changes were made"""
        result = format_result_message(0, 0)
        self.assertIn("No changes", result)

    def test_singular_address(self):
        """Test that singular 'address' is used correctly"""
        result = format_result_message(1, 0)
        self.assertIn("1 address", result)
        self.assertNotIn("addresses", result)


if __name__ == "__main__":
    unittest.main()
