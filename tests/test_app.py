import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from cipherkavach import main as cli_main
from cipherkavach_crypto import (
    InvalidEncryptedFileError,
    UnsupportedFormatError,
    decrypt_bytes,
    encrypt_bytes,
)


class CipherKavachTests(unittest.TestCase):
    def setUp(self):
        self.temp_root = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.app = create_app({
            "TESTING": True,
            "MAX_FILE_SIZE": 1024,
            "MAX_CONTENT_LENGTH": 200_000,
            "TEMP_DIR": self.temp_root.name,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_root.cleanup()

    def post_file(self, action, name="input.bin", content=b"data", password="test-pass", confirm=None):
        form = {"password": password}
        if confirm is not None:
            form["confirm_password"] = confirm
        return self.client.post(
            f"/api/{action}",
            data={"file": (io.BytesIO(content), name), **form},
            content_type="multipart/form-data",
        )

    def test_home_page_renders_brand_and_file_size_limit(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CipherKavach", response.data)
        self.assertIn(b"Encrypt &amp; Download", response.data)
        self.assertIn(b"50 MB", response.data)
        self.assertIn(b"Local processing", response.data)

    def test_hosted_page_discloses_server_side_processing(self):
        app = create_app({"TESTING": True, "HOSTED": True})
        response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Hosted server processing", response.data)
        self.assertIn(b"sent over HTTPS to this server", response.data)
        self.assertIn(b"hosting server, not in your browser", response.data)

    def test_text_and_binary_round_trip_through_web(self):
        # The test fixture has a deliberately small upload limit, so use a second app here.
        app = create_app({"TESTING": True, "MAX_FILE_SIZE": 1024, "MAX_CONTENT_LENGTH": 200_000, "TEMP_DIR": self.temp_root.name})
        client = app.test_client()
        for original in (b"A readable text file\n", bytes(range(256)) + b"\x00\xff\x80"):
            encrypted_response = client.post(
                "/api/encrypt",
                data={"file": (io.BytesIO(original), "sample.bin"), "password": "correct horse", "confirm_password": "correct horse"},
                content_type="multipart/form-data",
            )
            self.assertEqual(encrypted_response.status_code, 200)
            encrypted = encrypted_response.data
            encrypted_response.close()
            self.assertNotEqual(encrypted, original)
            decrypted_response = client.post(
                "/api/decrypt",
                data={"file": (io.BytesIO(encrypted), "sample.bin.ckv"), "password": "correct horse"},
                content_type="multipart/form-data",
            )
            self.assertEqual(decrypted_response.status_code, 200)
            self.assertEqual(decrypted_response.data, original)
            self.assertIn("sample.bin", decrypted_response.headers["Content-Disposition"])
            decrypted_response.close()

    def test_crypto_wrong_password_corruption_and_invalid_formats(self):
        encrypted = encrypt_bytes(b"payload", "right")
        with self.assertRaises(InvalidEncryptedFileError):
            decrypt_bytes(encrypted, "wrong")
        changed = bytearray(encrypted)
        changed[-1] ^= 0x01
        with self.assertRaises(InvalidEncryptedFileError):
            decrypt_bytes(bytes(changed), "right")
        with self.assertRaises(UnsupportedFormatError):
            decrypt_bytes(b"not an encrypted file", "right")
        with self.assertRaises(UnsupportedFormatError):
            decrypt_bytes(b"CKAV\x02" + bytes(40), "right")
        with self.assertRaises(InvalidEncryptedFileError):
            decrypt_bytes(b"CKAV\x01" + bytes(5), "right")

    def test_web_wrong_password_and_invalid_file_have_safe_errors(self):
        encrypted = encrypt_bytes(b"payload", "right")
        wrong = self.post_file("decrypt", "secret.ckv", encrypted, "wrong")
        self.assertEqual(wrong.status_code, 400)
        self.assertIn("password may be wrong", wrong.json["error"])
        invalid = self.post_file("decrypt", "other.bin", b"plain data", "right")
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("not a supported", invalid.json["error"])

    def test_missing_inputs_confirmation_and_size_validation(self):
        missing_file = self.client.post("/api/encrypt", data={"password": "x", "confirm_password": "x"})
        self.assertEqual(missing_file.status_code, 400)
        self.assertIn("Choose a file", missing_file.json["error"])
        missing_password = self.client.post("/api/encrypt", data={"file": (io.BytesIO(b"a"), "a.txt"), "confirm_password": ""})
        self.assertEqual(missing_password.status_code, 400)
        mismatch = self.post_file("encrypt", "a.txt", b"a", "first", "second")
        self.assertEqual(mismatch.status_code, 400)
        self.assertIn("does not match", mismatch.json["error"])
        tiny_app = create_app({"TESTING": True, "MAX_FILE_SIZE": 4, "MAX_CONTENT_LENGTH": 200_000, "TEMP_DIR": self.temp_root.name})
        oversized = tiny_app.test_client().post(
            "/api/encrypt",
            data={"file": (io.BytesIO(b"12345"), "large.bin"), "password": "pass", "confirm_password": "pass"},
            content_type="multipart/form-data",
        )
        self.assertEqual(oversized.status_code, 413)
        self.assertIn("4 bytes limit", oversized.json["error"])

    def test_temporary_files_cleaned_after_success_and_error(self):
        response = self.post_file("encrypt", "a.bin", b"a", "pass", "pass")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(Path(self.temp_root.name).iterdir()), [])
        response.close()
        failed = self.post_file("decrypt", "wrong.ckv", b"not ckv", "pass")
        self.assertEqual(failed.status_code, 400)
        failed.close()
        self.assertEqual(list(Path(self.temp_root.name).iterdir()), [])

    def test_cli_output_is_compatible_with_web_decryption(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as work:
            source = Path(work) / "cli-source.dat"
            source.write_bytes(bytes([0, 255, 13, 10, 42]))
            with patch("sys.argv", ["cipherkavach.py", "encrypt", str(source)]), patch("getpass.getpass", side_effect=["cli-secret", "cli-secret"]):
                self.assertEqual(cli_main(), 0)
            encrypted_path = Path(str(source) + ".ckv")
            encrypted = encrypted_path.read_bytes()
            response = self.client.post(
                "/api/decrypt",
                data={"file": (io.BytesIO(encrypted), encrypted_path.name), "password": "cli-secret"},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, source.read_bytes())
            response.close()
            with patch("sys.argv", ["cipherkavach.py", "decrypt", str(encrypted_path)]), patch("getpass.getpass", return_value="cli-secret"):
                self.assertEqual(cli_main(), 0)
            self.assertEqual(source.read_bytes(), bytes([0, 255, 13, 10, 42]))


if __name__ == "__main__":
    unittest.main()
