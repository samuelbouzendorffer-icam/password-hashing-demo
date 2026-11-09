import unittest

import hashing_demo as hd

FAST = 1000  # peu d'itérations pour que les tests restent rapides


class TestHashing(unittest.TestCase):
    def test_format(self):
        parts = hd.hash_password("secret", FAST).split("$")
        self.assertEqual(parts[0], "pbkdf2_sha256")
        self.assertEqual(parts[1], str(FAST))
        self.assertEqual(len(parts), 4)

    def test_correct_password_verifies(self):
        stored = hd.hash_password("Mot2Passe!", FAST)
        self.assertTrue(hd.verify_password("Mot2Passe!", stored))

    def test_wrong_password_rejected(self):
        stored = hd.hash_password("Mot2Passe!", FAST)
        self.assertFalse(hd.verify_password("mot2passe!", stored))

    def test_same_password_gives_different_hashes(self):
        self.assertNotEqual(hd.hash_password("secret", FAST), hd.hash_password("secret", FAST))

    def test_fixed_salt_is_deterministic(self):
        salt = b"0123456789abcdef"
        self.assertEqual(hd.hash_password("x", FAST, salt), hd.hash_password("x", FAST, salt))

    def test_tampered_or_malformed_hash_is_rejected(self):
        stored = hd.hash_password("secret", FAST)
        self.assertFalse(hd.verify_password("secret", stored[:-4] + "AAAA"))
        self.assertFalse(hd.verify_password("secret", "n'importe quoi"))
        self.assertFalse(hd.verify_password("secret", "md5$1$abc$def"))
        self.assertFalse(hd.verify_password("secret", "pbkdf2_sha256$abc$!!$!!"))

    def test_naive_sha256_known_value(self):
        self.assertEqual(hd.naive_sha256("abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()
