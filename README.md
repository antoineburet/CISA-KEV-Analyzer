# CISA KEV Analyzer 🛡️

Cet outil est un script Python en ligne de commande permettant d'interroger, d'analyser et d'enrichir le catalogue **Known Exploited Vulnerabilities (KEV)** de CISA.

À l'origine un simple challenge technique pour un entretien de stage, ce projet a été étendu pour devenir un outil de portfolio complet, démontrant la gestion d'API, la mise en cache, l'enrichissement de données (via NVD) et une sortie structurée.

---

## 🚀 Fonctionnalités

* **Interrogation du KEV** : Récupère la liste la plus récente des vulnérabilités activement exploitées.
* **Mise en cache intelligente** : Un cache local pour les données KEV et CVSS afin de minimiser les appels API et d'accélérer les exécutions.
* **Enrichissement CVSS (Idée 1)** : Interroge l'API NVD 2.0 du NIST pour récupérer le **score CVSS** et le niveau de **sévérité** pour les vulnérabilités trouvées.
* **Filtrage avancé** : Filtrez les résultats par :
    * Nombre de jours (`-d`)
    * Nombre de résultats (`-n`)
    * Fournisseur (`-s` ou `--search-vendor`)
* **Statistiques des fournisseurs** : Affiche un Top `N` des fournisseurs les plus présents dans le catalogue KEV.
* **Formats de sortie multiples (Idée 2)** : Affichez les résultats dans la `console` ou exportez-les en `json` ou `csv` pour les intégrer à d'autres outils.

---

## 🛠️ Installation et Configuration

### 1. Prérequis

* Python 3.7+
* Git

### 2. Installation

1.  Clonez le dépôt :
    ```bash
    git clone [https://github.com/](https://github.com/)[VOTRE_NOM_UTILISATEUR]/[NOM_DU_PROJET].git
    cd [NOM_DU_PROJET]
    ```

2.  (Recommandé) Créez un environnement virtuel :
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # Sur Windows: .\venv\Scripts\activate
    ```

3.  Installez les dépendances :
    ```bash
    pip install -r requirements.txt
    ```

### 3. Configuration (Importante !)

L'enrichissement CVSS (`--enrich`) interroge l'API NVD, qui impose des **limites de requêtes (rate limits)**.

* **Sans clé API** : Vous serez limité à ~5 requêtes par 30 secondes. L'enrichissement sera **très lent**.
* **Avec une clé API (Gratuite)** : Vous pouvez effectuer ~50 requêtes par 30 secondes.

**Il est fortement recommandé d'obtenir une clé API NVD :**

1.  Allez sur la [page NVD API](https://nvd.nist.gov/developers/request-an-api-key) et demandez une clé.
2.  Exportez votre clé comme variable d'environnement.

    * **Sur macOS/Linux :**
        ```bash
        export NVD_API_KEY="VOTRE_CLE_API_NVD_ICI"
        ```
    * **Sur Windows (PowerShell) :**
        ```powershell
        $Env:NVD_API_KEY = "VOTRE_CLE_API_NVD_ICI"
        ```

Le script `kev_analyzer.py` détectera et utilisera automatiquement cette clé.

---

## 📖 Exemples d'utilisation

➡️ **Afficher l'aide**
```bash
python3 kev_analyzer.py -h
```

➡️ **Utilisation de base** (Affiche les 5 dernières vulnérabilités des 30 derniers jours et le Top 10 des fournisseurs)
```bash
python3 kev_analyzer.py
```

➡️ **Enrichissement CVSS** (Affiche les 2 dernières vulnérabilités des 60 derniers jours, AVEC leur score CVSS)
```bash
python3 kev_analyzer.py -n 2 -d 60 --enrich
```
Sortie attendue :
```bash
[INFO] Enrichissement CVSS pour 2 vulnérabilité(s). (Cela peut prendre du temps...)
[INFO] [1/2] Traitement CVE-202X-XXXXX...
[INFO] Enrichissement CVSS pour CVE-202X-XXXXX (Appel API NVD...)
[INFO] [2/2] Traitement CVE-202X-YYYYY...

--- 1. Analyse des vulnérabilités (Total: 2) ---

  CVE ID:         CVE-202X-XXXXX
  Score CVSS:     9.8 (CRITICAL)
  Vendor/Product: Microsoft / Windows
  Date Added:     2025-11-14

  CVE ID:         CVE-202X-YYYYY
  Score CVSS:     7.5 (HIGH)
  Vendor/Product: Apple / iOS
  Date Added:     2025-11-12
...
```

➡️ **Recherche par fournisseur et export JSON** (Trouve les 10 dernières vulnérabilités "Microsoft" des 180 derniers jours et sauvegarde tout en JSON)
```bash
python3 kev_analyzer.py -n 10 -d 180 -s "Microsoft" -f json -o microsoft_report.json
```

➡️ **Export CSV de toutes les vulnérabilités "Fortinet"** (Le -n 9999 sert à récupérer "toutes" les entrées)
```bash
python3 kev_analyzer.py -n 9999 -d 3650 -s "Fortinet" -f csv -o fortinet.csv
```

➡️ **Forcer le rafraîchissement des caches**
```bash
python3 kev_analyzer.py --force-refresh
```
