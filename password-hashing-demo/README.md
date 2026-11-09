# password-hashing-demo

Démonstration en Python (bibliothèque standard uniquement) de **la bonne façon de stocker des mots de passe** : un hash lent et salé (PBKDF2-HMAC-SHA256), comparé à un simple SHA-256.

## Utilisation

```bash
python3 hashing_demo.py demo        # montre l'intérêt du sel
python3 hashing_demo.py benchmark   # compare SHA-256 simple et PBKDF2
python3 hashing_demo.py hash        # hache un mot de passe (saisie masquée)
python3 hashing_demo.py verify 'pbkdf2_sha256$600000$...$...'
```

Exemple de sortie de `demo` (les hashs salés changent à chaque exécution) :

```
1) SHA-256 sans sel (mauvaise pratique) :
   alice : 939b08112dfd60f1bb0456afc3a114794405c86d271e061611399c980f88fdaa
   bob   : 939b08112dfd60f1bb0456afc3a114794405c86d271e061611399c980f88fdaa
   -> empreintes identiques : on voit qui partage le même mot de passe,
      et une table précalculée casse tout le monde d'un coup.

2) PBKDF2 avec sel aléatoire (bonne pratique) :
   alice : pbkdf2_sha256$100000$yJM7dzn7pvBtxO1PTMgKFQ==$oxMzmPAAdwPK2g7mZGCFTYxwNdKK01Fy5TJtSFnYmmo=
   bob   : pbkdf2_sha256$100000$UhGO3VBrH7uDz5ZRkZ/96g==$yjgZzKfdZDOg5AfHyVPpI3hYcc4NbaS+v73hlvJRZ3g=
```

Exemple de `benchmark` (dépend de la machine) : un SHA-256 simple prend environ 1 µs, PBKDF2 avec 600 000 itérations environ 190 ms. Cet écart est voulu : il rend chaque essai de mot de passe très coûteux pour un attaquant.

## Concepts illustrés

- **Hash lent** : le coût (nombre d'itérations) est stocké avec le hash et peut être augmenté avec le temps.
- **Sel aléatoire** (`os.urandom`) : deux mots de passe identiques donnent deux hashs différents, ce qui rend inefficaces les tables précalculées.
- **Comparaison en temps constant** (`hmac.compare_digest`) : évite de laisser fuiter des informations par le temps de réponse.
- **Format auto-descriptif** : `algorithme$itérations$sel$hash`, pour pouvoir changer d'algorithme plus tard.
- Un hash corrompu ou mal formé est refusé proprement, sans exception.

## Tests

```bash
python3 -m unittest -v
```

## Limites

PBKDF2 est choisi ici parce qu'il est inclus dans la bibliothèque standard. Pour une vraie application, l'OWASP recommande en priorité **Argon2id** (puis scrypt ou bcrypt selon le contexte) et fait évoluer ses valeurs conseillées : à vérifier dans le *Password Storage Cheat Sheet*. En pratique, on utilise la bibliothèque de son framework plutôt que son propre code.

## Pistes d'amélioration

- Ajouter Argon2id avec la bibliothèque `argon2-cffi`.
- Gérer la migration : re-hacher un mot de passe avec un coût plus élevé à la connexion.
- Ajouter un « poivre » (*pepper*) stocké hors de la base de données.

## Licence

MIT, voir [LICENSE](LICENSE).

---


