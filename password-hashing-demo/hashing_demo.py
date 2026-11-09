#!/usr/bin/env python3
"""hashing_demo : comment stocker correctement des mots de passe (démonstration).

On ne stocke jamais un mot de passe en clair, ni avec un simple hash rapide.
Bonne pratique : un hash LENT et SALÉ (ici PBKDF2-HMAC-SHA256, bibliothèque standard).
Format stocké : pbkdf2_sha256$itérations$sel_base64$hash_base64
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import time

ALGO = "pbkdf2_sha256"
# Nombre d'itérations recommandé par l'OWASP pour PBKDF2-HMAC-SHA256 au moment
# de l'écriture. Cette valeur évolue : à vérifier dans le "Password Storage Cheat Sheet".
DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS, salt: bytes = None) -> str:
    """Retourne une chaîne contenant l'algorithme, le coût, le sel et le hash."""
    if salt is None:
        salt = os.urandom(SALT_BYTES)  # sel aléatoire, unique pour chaque mot de passe
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGO}${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Vérifie un mot de passe. Retourne False (sans exception) si `stored` est invalide."""
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
        if algo != ALGO:
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations), len(expected))
    except (ValueError, TypeError):
        return False
    # Comparaison en temps constant : évite de révéler la position de la première différence.
    return hmac.compare_digest(candidate, expected)


def naive_sha256(password: str) -> str:
    """À NE PAS FAIRE : hash rapide sans sel (sert uniquement à la démonstration)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def benchmark(iterations: int = DEFAULT_ITERATIONS, rounds: int = 20000) -> dict:
    """Compare le coût d'un SHA-256 simple et d'un PBKDF2 (en secondes par mot de passe)."""
    start = time.perf_counter()
    for i in range(rounds):
        naive_sha256(f"motdepasse{i}")
    fast = (time.perf_counter() - start) / rounds
    start = time.perf_counter()
    hash_password("motdepasse", iterations)
    slow = time.perf_counter() - start
    return {"sha256_s": fast, "pbkdf2_s": slow, "ratio": slow / fast if fast else float("inf")}


def demo() -> None:
    print("Deux utilisateurs choisissent le même mot de passe : 'soleil123'\n")
    print("1) SHA-256 sans sel (mauvaise pratique) :")
    print("   alice :", naive_sha256("soleil123"))
    print("   bob   :", naive_sha256("soleil123"))
    print("   -> empreintes identiques : on voit qui partage le même mot de passe,")
    print("      et une table précalculée casse tout le monde d'un coup.\n")
    print("2) PBKDF2 avec sel aléatoire (bonne pratique) :")
    print("   alice :", hash_password("soleil123", iterations=100_000))
    print("   bob   :", hash_password("soleil123", iterations=100_000))
    print("   -> empreintes différentes, et chaque essai coûte du temps à un attaquant.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Démonstration de stockage de mots de passe.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="montre l'intérêt du sel et du hash lent")
    sub.add_parser("hash", help="hache un mot de passe (saisie masquée)")
    p = sub.add_parser("verify", help="vérifie un mot de passe contre un hash stocké")
    p.add_argument("stored", help="chaîne produite par la commande hash")
    p = sub.add_parser("benchmark", help="compare SHA-256 simple et PBKDF2")
    p.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    args = parser.parse_args()

    if args.command == "demo":
        demo()
    elif args.command == "hash":
        print(hash_password(getpass.getpass("Mot de passe : ")))
    elif args.command == "verify":
        ok = verify_password(getpass.getpass("Mot de passe : "), args.stored)
        print("Mot de passe valide." if ok else "Mot de passe invalide.")
        raise SystemExit(0 if ok else 1)
    else:
        r = benchmark(args.iterations)
        print(f"SHA-256 simple : {r['sha256_s'] * 1e6:8.2f} µs par mot de passe")
        print(f"PBKDF2 ({args.iterations} it.) : {r['pbkdf2_s'] * 1e3:8.2f} ms par mot de passe")
        print(f"PBKDF2 est environ {r['ratio']:.0f} fois plus lent : c'est voulu.")


if __name__ == "__main__":
    main()
