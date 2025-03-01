import unittest
import os
import time
import struct
import socket
import tkinter as tk
from tkinter import ttk
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Secure_File.SFT import (
    hash_password,
    derive_key,
    pad_data,
    unpad_data,
    decrypt_data,
    register_user,
    authenticate_user,
    center_window,
    FileTransferApp
)


class TestCryptoHelpers(unittest.TestCase):
    def test_hash_password_consistency(self):
        """Test that using the same salt reproduces the same hash."""
        password = "testpassword"
        hashed1, salt1 = hash_password(password)
        hashed2, _ = hash_password(password, salt1)
        self.assertEqual(hashed1, hashed2, "Hashes should be consistent when salt is provided.")

    def test_derive_key(self):
        """Test that derived keys are 32 bytes and consistent for the same password."""
        key1 = derive_key("test")
        key2 = derive_key("test")
        key3 = derive_key("different")
        self.assertEqual(len(key1), 32, "Key length should be 32 bytes.")
        self.assertEqual(key1, key2, "Keys derived from the same password should match.")
        self.assertNotEqual(key1, key3, "Keys derived from different passwords should differ.")

    def test_padding_unpadding(self):
        """Ensure that padding then unpadding returns the original data."""
        data = b"Test data that is not a multiple of block size."
        padded = pad_data(data)
        unpadded = unpad_data(padded)
        self.assertEqual(data, unpadded, "Unpadded data should match the original.")

    def test_decrypt_data(self):
        """Encrypt data using AES-CBC and ensure that decrypt_data correctly decrypts it."""
        password = "testpassword"
        key = derive_key(password)
        plaintext = b"Secret message that needs encryption."
        padded = pad_data(plaintext)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded) + encryptor.finalize()
        data = iv + encrypted
        decrypted = decrypt_data(key, data)
        self.assertEqual(plaintext, decrypted, "Decrypted text must equal the original plaintext.")


class TestDatabaseFunctions(unittest.TestCase):
    @mock.patch('mysql.connector.connect')
    def test_register_user_success(self, mock_connect):
        """Test that register_user returns True on successful insertion."""
        # Set up a mock connection and cursor.
        mock_conn = mock.Mock()
        mock_cursor = mock.Mock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        # Simulate a successful INSERT.
        mock_cursor.execute.return_value = None
        result = register_user("testuser", "testpass")
        self.assertTrue(result, "User should be registered successfully.")
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

    @mock.patch('mysql.connector.connect')
    def test_register_user_integrity_error(self, mock_connect):
        """Test that register_user returns False when a duplicate user is inserted."""
        # Set up a mock connection and cursor.
        mock_conn = mock.Mock()
        mock_cursor = mock.Mock()
        # Simulate an IntegrityError when executing the INSERT.
        from mysql.connector import IntegrityError
        mock_cursor.execute.side_effect = IntegrityError("Duplicate entry")
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        result = register_user("testuser", "testpass")
        self.assertFalse(result, "Duplicate registration should return False.")
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

    @mock.patch('mysql.connector.connect')
    def test_authenticate_user_success(self, mock_connect):
        """Test that authenticate_user returns True for correct credentials."""
        mock_conn = mock.Mock()
        mock_cursor = mock.Mock()
        # Prepare a valid hashed password and salt.
        hashed, salt = hash_password("testpass")
        mock_cursor.fetchone.return_value = (hashed, salt)
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        result = authenticate_user("testuser", "testpass")
        self.assertTrue(result, "User authentication should succeed with correct credentials.")
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()

    @mock.patch('mysql.connector.connect')
    def test_authenticate_user_failure(self, mock_connect):
        """Test that authenticate_user returns False if the user is not found."""
        mock_conn = mock.Mock()
        mock_cursor = mock.Mock()
        # Simulate no record found.
        mock_cursor.fetchone.return_value = None
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        result = authenticate_user("nonexistent", "testpass")
        self.assertFalse(result, "Authentication should fail for a nonexistent user.")
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()


class TestGUIHelpers(unittest.TestCase):
    def test_center_window(self):
        """Test that center_window sets the geometry string correctly."""
        root = tk.Tk()
        root.withdraw() 

        center_window(root, 300, 200)

        root.update()  
        geom = root.geometry()
        print(f"Expected: 300x200, Actual: {geom}")  

        self.assertTrue(geom.startswith("300x200"), f"Unexpected geometry: {geom}")

        root.destroy()

    def test_get_ip(self):
        """Test that get_ip returns a string (even if it's the fallback '127.0.0.1')."""
        app = FileTransferApp("dummy")
        ip = app.get_ip()
        self.assertIsInstance(ip, str, "The IP address should be returned as a string.")
        app.destroy()

    def test_toggle_password(self):
        """Test that toggle_password properly toggles between hidden and visible."""
        root = tk.Tk()
        entry = ttk.Entry(root, show="*")
        entry.pack()
        btn = ttk.Button(root, text="Show")
        btn.pack()
        app = FileTransferApp("dummy")
        self.assertEqual(entry.cget("show"), "*", "Initially, password should be hidden.")
        app.toggle_password(entry, btn)
        self.assertEqual(entry.cget("show"), "", "Password should be visible after toggle.")
        self.assertEqual(btn.cget("text"), "Hide", "Button text should be updated to 'Hide'.")
        app.toggle_password(entry, btn)
        self.assertEqual(entry.cget("show"), "*", "Password should be hidden after second toggle.")
        self.assertEqual(btn.cget("text"), "Show", "Button text should revert to 'Show'.")
        root.destroy()
        app.destroy()


if __name__ == '__main__':
    unittest.main()