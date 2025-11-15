#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
KEV Analyzer - Outil d'analyse du CISA KEV Catalog.

Ce script interroge le catalogue KEV de CISA, l'enrichit avec les scores
CVSS via l'API NVD, et permet de filtrer et d'exporter les résultats.

Challenge technique Formind
Porté en projet de portfolio par : Antoine Buret
"""

# --- Bibliothèques externes ---
import requests

# --- Bibliothèques standard ---
import json
import os
import argparse
import logging
import sys
import csv
import time
from datetime import datetime, timedelta, date
from collections import Counter
from typing import List, Dict, Any, Optional

# --- Configuration du Logging ---
# Utiliser logging au lieu de print() pour une gestion pro
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# --- Constantes ---
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# Clé API NVD (optionnelle mais RECOMMANDÉE pour éviter le rate limiting)
# Le script tentera de lire la variable d'environnement 'NVD_API_KEY'
NVD_API_KEY = os.environ.get('NVD_API_KEY')
NVD_REQUEST_DELAY = 6 if NVD_API_KEY else 10  # Secondes entre les appels NVD (6s avec clé, 10-12s sans)

# Caching
CISA_CACHE_FILE = "cisa_kev_cache.json"
CVSS_CACHE_FILE = "cvss_scores_cache.json"
CACHE_DURATION_HOURS = 4


class KevAnalyzer:
    """
    Classe principale pour gérer la récupération, l'analyse
    et l'export des données KEV.
    """
    def __init__(self, force_refresh=False):
        self.force_refresh = force_refresh
        self.cisa_cache_duration = CACHE_DURATION_HOURS * 3600
        # Le cache CVSS est gardé plus longtemps car les scores changent peu
        self.cvss_cache_duration = (24 * 7) * 3600  # 1 semaine
        
        self.kev_data = self._load_data(
            url=CISA_KEV_URL,
            cache_file=CISA_CACHE_FILE,
            cache_duration=self.cisa_cache_duration,
            data_key="vulnerabilities"
        )
        
        self.cvss_cache = self._load_data(
            url=None, # Pas d'URL, c'est un cache pur
            cache_file=CVSS_CACHE_FILE,
            cache_duration=self.cvss_cache_duration,
            data_key=None
        ) or {} # S'assurer que c'est un dict
    
    def _load_data(self, url: Optional[str], cache_file: str, cache_duration: int, data_key: Optional[str]) -> Optional[Any]:
        """
        Fonction générique de chargement/mise en cache.
        Si 'url' est None, charge juste le cache.
        """
        if os.path.exists(cache_file) and not self.force_refresh:
            try:
                file_mod_time = os.path.getmtime(cache_file)
                cache_age = datetime.now().timestamp() - file_mod_time
                if cache_age < cache_duration:
                    logging.info(f"Chargement des données depuis le cache : {cache_file}")
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
            except Exception as e:
                logging.warning(f"Erreur de lecture du cache {cache_file} : {e}. Re-téléchargement...")

        if not url: # Si on voulait juste charger le cache
            return None if data_key else {}

        logging.info(f"Interrogation de l'API : {url.split('?')[0]}...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Extraire la partie pertinente des données
            data_to_cache = data.get(data_key) if data_key else data
            if data_to_cache is None:
                 logging.error(f"Clé '{data_key}' non trouvée dans la réponse de l'API.")
                 return None

            logging.info(f"Données récupérées avec succès. ({len(data_to_cache)} éléments)")

            # Mise à jour du cache
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data_to_cache, f, indent=2)
                    logging.info(f"Cache mis à jour : {cache_file}")
            except IOError as e:
                logging.warning(f"Impossible d'écrire dans le fichier cache : {e}")

            return data_to_cache

        except requests.exceptions.RequestException as err:
            logging.error(f"Erreur critique lors de la récupération des données : {err}")
            return None

    def _get_cvss_score(self, cve_id: str) -> Dict[str, Any]:
        """
        (IDÉE 1) Enrichissement CVSS pour un seul CVE.
        Utilise son propre cache.
        """
        # 1. Vérifier le cache d'abord
        if cve_id in self.cvss_cache:
            cache_entry = self.cvss_cache[cve_id]
            cache_age = datetime.now().timestamp() - cache_entry.get('timestamp', 0)
            if cache_age < self.cvss_cache_duration and not self.force_refresh:
                logging.debug(f"Score CVSS pour {cve_id} trouvé dans le cache.")
                return cache_entry['data']
        
        # 2. Si pas dans le cache ou obsolète, interroger l'API NVD
        logging.info(f"Enrichissement CVSS pour {cve_id} (Appel API NVD...)")
        headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
        try:
            # Respecter le rate limit
            time.sleep(NVD_REQUEST_DELAY) 
            
            response = requests.get(f"{NVD_API_URL}{cve_id}", headers=headers, timeout=10)
            response.raise_for_status()
            nvd_data = response.json()
            
            score_data = {"cvss_score": None, "cvss_severity": None}
            
            if nvd_data.get('vulnerabilities'):
                cve_item = nvd_data['vulnerabilities'][0]['cve']
                # On cherche le score V3.1, sinon V3.0
                metrics = cve_item.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    metric = metrics['cvssMetricV31'][0]['cvssData']
                    score_data["cvss_score"] = metric.get('baseScore')
                    score_data["cvss_severity"] = metric.get('baseSeverity')
                elif 'cvssMetricV30' in metrics:
                    metric = metrics['cvssMetricV30'][0]['cvssData']
                    score_data["cvss_score"] = metric.get('baseScore')
                    score_data["cvss_severity"] = metric.get('baseSeverity')

            # 3. Mettre à jour le cache
            self.cvss_cache[cve_id] = {
                "timestamp": datetime.now().timestamp(),
                "data": score_data
            }
            return score_data

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logging.warning(f"NVD n'a pas (encore) d'info pour {cve_id}.")
                return {"cvss_score": "N/A", "cvss_severity": "N/A"}
            logging.error(f"Erreur HTTP NVD pour {cve_id}: {e}")
            return {"cvss_score": "Error", "cvss_severity": "Error"}
        except Exception as e:
            logging.error(f"Erreur NVD inattendue pour {cve_id}: {e}")
            return {"cvss_score": "Error", "cvss_severity": "Error"}

    def _save_cvss_cache(self):
        """Sauvegarde le cache CVSS en fin de script."""
        try:
            with open(CVSS_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.cvss_cache, f, indent=2)
                logging.debug("Cache CVSS sauvegardé.")
        except IOError as e:
            logging.warning(f"Impossible de sauvegarder le cache CVSS : {e}")

    def get_filtered_vulnerabilities(self, count: int, days: int, search_vendor: Optional[str], enrich: bool) -> List[Dict[str, Any]]:
        """
        Filtre la liste KEV et l'enrichit (si demandé).
        """
        if not self.kev_data:
            return []

        date_limit = date.today() - timedelta(days=days)
        
        # 1. Tri et filtrage
        sorted_vulns = sorted(self.kev_data, key=lambda x: x['dateAdded'], reverse=True)
        
        filtered_list = []
        for vuln in sorted_vulns:
            vuln_date = date.fromisoformat(vuln['dateAdded'])
            
            # Filtre par date
            if vuln_date < date_limit:
                continue # Trop vieux
            
            # (NOUVEAU) Filtre par fournisseur
            if search_vendor and search_vendor.lower() not in vuln.get('vendorProject', '').lower():
                continue # Ne correspond pas au fournisseur
                
            filtered_list.append(vuln)
        
        # 2. Application du 'count' APRÈS filtrage
        final_list = filtered_list[:count]
        
        # 3. (IDÉE 1) Enrichissement
        if enrich:
            logging.info(f"Enrichissement CVSS pour {len(final_list)} vulnérabilité(s). (Cela peut prendre du temps...)")
            enriched_list = []
            for i, vuln in enumerate(final_list):
                logging.info(f"[{i+1}/{len(final_list)}] Traitement {vuln['cveID']}...")
                cvss_data = self._get_cvss_score(vuln['cveID'])
                vuln.update(cvss_data) # Ajoute les clés 'cvss_score' et 'cvss_severity'
                enriched_list.append(vuln)
            
            # Sauvegarder le cache CVSS après la boucle
            self._save_cvss_cache()
            return enriched_list
        else:
            return final_list
            
    def get_vendor_statistics(self, top_n: int) -> List[tuple]:
        """
        Calcule les statistiques des fournisseurs.
        """
        if not self.kev_data:
            return []
            
        try:
            vendor_list = [vuln.get('vendorProject', 'Unknown') for vuln in self.kev_data]
            vendor_counts = Counter(vendor_list)
            return vendor_counts.most_common(top_n)
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse des fournisseurs : {e}")
            return []

    def format_output(self, vuln_data: List[Dict], stats_data: List[tuple], output_format: str, output_file: Optional[str]):
        """
        (IDÉE 2) Gère la sortie des données (console, JSON, CSV).
        """
        # Préparer le conteneur de données
        output_data = {
            "vulnerabilities": vuln_data,
            "vendor_statistics": [{"vendor": v, "count": c} for v, c in stats_data]
        }
        
        # Déterminer la destination (stdout ou fichier)
        destination = open(output_file, 'w', encoding='utf-8') if output_file else sys.stdout

        try:
            if output_format == 'json':
                json.dump(output_data, destination, indent=2)
            
            elif output_format == 'csv':
                # Pour le CSV, on ne sort que les vulnérabilités
                if not vuln_data:
                    logging.info("Aucune vulnérabilité à exporter en CSV.")
                    return
                
                writer = csv.DictWriter(destination, fieldnames=vuln_data[0].keys())
                writer.writeheader()
                writer.writerows(vuln_data)
            
            else: # 'console' (défaut)
                self._format_console(destination, output_data)
        
        finally:
            if output_file:
                destination.close()
                logging.info(f"Résultats sauvegardés dans : {output_file}")

    def _format_console(self, dest, data):
        """Helper pour un affichage console propre."""
        
        # 1. Affichage des vulnérabilités
        vuln_list = data.get('vulnerabilities', [])
        if vuln_list:
            dest.write(f"\n--- 1. Analyse des vulnérabilités (Total: {len(vuln_list)}) ---\n")
            for vuln in vuln_list:
                dest.write(f"\n  CVE ID:         {vuln.get('cveID')}\n")
                # Afficher le score CVSS s'il a été enrichi
                if 'cvss_score' in vuln:
                    dest.write(f"  Score CVSS:     {vuln.get('cvss_score')} ({vuln.get('cvss_severity')})\n")
                dest.write(f"  Vendor/Product: {vuln.get('vendorProject')} / {vuln.get('product')}\n")
                dest.write(f"  Date Added:     {vuln.get('dateAdded')}\n")
        else:
             dest.write(f"\n--- 1. Analyse des vulnérabilités ---\n")
             dest.write("[!] Aucune vulnérabilité ne correspond à vos critères de filtre.\n")

        # 2. Affichage des statistiques
        stats_list = data.get('vendor_statistics', [])
        dest.write(f"\n--- 2. Statistiques des fournisseurs (Top {len(stats_list)}) ---\n")
        if stats_list:
            for item in stats_list:
                dest.write(f"  {item['vendor']:<25} : {item['count']} vulnérabilité(s)\n")
        else:
            dest.write("[!] Pas de statistiques à afficher.\n")


def main():
    """
    Fonction principale orchestrant l'exécution
    et gérant les arguments en ligne de commande.
    """
    parser = argparse.ArgumentParser(
        description="Outil d'analyse du CISA KEV Catalog, enrichi avec les scores CVSS.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # --- Arguments de Filtre ---
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=5,
        help="Nombre max de vulnérabilités à afficher.\nPar défaut : 5"
    )
    parser.add_argument(
        "-d", "--days",
        type=int,
        default=30,
        help="Filtrer les vulnérabilités ajoutées depuis X jours.\nPar défaut : 30"
    )
    parser.add_argument(
        "-s", "--search-vendor",
        type=str,
        help="Filtrer par nom de fournisseur (ex: 'Microsoft', 'Apple').\nNon sensible à la casse."
    )
    
    # --- Arguments d'Enrichissement ---
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Activer l'enrichissement CVSS (via API NVD).\nPEUT ÊTRE TRÈS LENT SANS CLÉ API."
    )
    
    # --- Arguments de Statistiques ---
    parser.add_argument(
        "-vn", "--vendor-number",
        type=int,
        default=10,
        help="Nombre de fournisseurs à afficher dans le top stats.\nPar défaut : 10"
    )

    # --- Arguments de Sortie (IDÉE 2) ---
    parser.add_argument(
        "-o", "--output-file",
        type=str,
        help="Sauvegarder la sortie dans un fichier (ex: report.json)."
    )
    parser.add_argument(
        "-f", "--output-format",
        choices=['console', 'json', 'csv'],
        default='console',
        help="Format de la sortie.\nPar défaut : console"
    )

    # --- Arguments de Cache ---
    parser.add_argument(
        "--force-refresh",
        action="store_true",
        help="Force le rafraîchissement des données en ignorant les caches."
    )
    
    args = parser.parse_args()
    
    if not NVD_API_KEY and args.enrich:
        logging.warning("Aucune variable d'environnement 'NVD_API_KEY' trouvée.")
        logging.warning(f"Les appels API NVD seront TRES lents (1 appel / {NVD_REQUEST_DELAY}s).")
        logging.warning("Créez une clé gratuite sur le site de NVD pour accélérer le processus.")

    try:
        analyzer = KevAnalyzer(force_refresh=args.force_refresh)
        
        # 1. Obtenir les vulnérabilités filtrées et (optionnellement) enrichies
        vuln_data = analyzer.get_filtered_vulnerabilities(
            count=args.number,
            days=args.days,
            search_vendor=args.search_vendor,
            enrich=args.enrich
        )
        
        # 2. Obtenir les statistiques
        stats_data = analyzer.get_vendor_statistics(top_n=args.vendor_number)
        
        # 3. Formater et afficher la sortie
        analyzer.format_output(
            vuln_data=vuln_data,
            stats_data=stats_data,
            output_format=args.output_format,
            output_file=args.output_file
        )

    except Exception as e:
        logging.error(f"Une erreur imprévue est survenue : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
