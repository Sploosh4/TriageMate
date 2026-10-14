"""Local lifecycle delegates complete schema verification; never starts PostgreSQL."""

import unittest
from unittest.mock import patch
import manage


class MetadataTests(unittest.TestCase):
    def test_existing_setup_verifies_complete_baseline(self):
        with (
            patch.object(manage, "initialize"),
            patch.object(manage, "start"),
            patch.object(manage, "connect") as connect,
            patch("builtins.print") as output,
            patch.object(manage, "install_schema", return_value=False) as install,
        ):
            cursor = connect.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = (1,)
            manage.setup()
            self.assertEqual(cursor.execute.call_count, 1)
            install.assert_called_once_with(
                manage.LocalDatabase(manage.TARGET), profile="synthetic"
            )
            output.assert_called_once_with(
                "Existing database baseline verified; no data reseeded."
            )
            connect.return_value.close.assert_called_once()

    def test_new_setup_creates_only_database_before_shared_install(self):
        with (
            patch.object(manage, "initialize"),
            patch.object(manage, "start"),
            patch.object(manage, "connect") as connect,
            patch("builtins.print") as output,
            patch.object(manage, "install_schema", return_value=True) as install,
        ):
            cursor = connect.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = None
            manage.setup()
            self.assertEqual(cursor.execute.call_count, 3)
            install.assert_called_once_with(
                manage.LocalDatabase(manage.TARGET), profile="synthetic"
            )
            output.assert_called_once_with(
                "Created and verified the complete synthetic database baseline."
            )

    def test_invalid_existing_baseline_propagates_without_success(self):
        with (
            patch.object(manage, "initialize"),
            patch.object(manage, "start"),
            patch.object(manage, "connect") as connect,
            patch("builtins.print") as output,
            patch.object(manage, "install_schema", side_effect=ValueError("drift")),
        ):
            cursor = connect.return_value.cursor.return_value.__enter__.return_value
            cursor.fetchone.return_value = (1,)
            with self.assertRaisesRegex(ValueError, "drift"):
                manage.setup()
            self.assertEqual(cursor.execute.call_count, 1)
            output.assert_not_called()
