# Sigma - Format générique de signatures pour les systèmes SIEM

<a href="https://sigmahq.io/">
<p align="center">
<br />
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./images/sigma_logo_dark.png">
  <img width="454" alt="Sigma Logo" src="./images/sigma_logo_light.png">
</picture>
</p>
</a>
<br />

<p align="center">
<a href="https://github.com/SigmaHQ/sigma/actions?query=branch%3Amaster"><img src="https://github.com/SigmaHQ/sigma/actions/workflows/sigma-test.yml/badge.svg?branch=master" alt="Sigma Build Status"></a> <a href="https://sigmahq.io/"><img src="https://cdn.jsdelivr.net/gh/SigmaHQ/sigmahq.github.io@master/images/Sigma%20Official%20Badge.svg" alt="Sigma Official Badge"></a> <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/SigmaHQ/sigma">
<img alt="GitHub all releases" src="https://img.shields.io/github/downloads/SigmaHq/Sigma/total">
<br />
<a href="https://opensourcesecurityindex.io/" target="_blank" rel="noopener">
<img style="width: 170px;" src="https://opensourcesecurityindex.io/badge.svg" alt="Open Source Security Index - Fastest Growing Open Source Security Projects" width="170" />
</a>
</p>

Bienvenue dans le dépôt principal des règles Sigma.
C’est ici que les ingénieurs en détection, threat hunters et autres praticiens 
de la sécurité défensive collaborent pour créer et partager des règles de 
détection.
Le dépôt contient plus de 3000 règles de détection de différents types, avec 
pour objectif de rendre des détections fiables accessibles à tous, gratuitement.

Actuellement, le référentiel propose trois types de règles :

* [Règles de détection génériques](./rules/) - Elles sont indépendantes de la menace, leur objectif est de détecter un comportement ou la mise en œuvre d'une technique ou d'une procédure qui a été, peut être ou sera utilisée par un acteur malveillant potentiel.
* [Règles de recherche des menaces](./rules-threat-hunting/) - Elles ont une portée plus large et visent à donner à l'analyste un point de départ pour rechercher des activités potentiellement suspectes ou malveillantes.
* [Règles relatives aux menaces émergentes](./rules-emerging-threats/) - Il s'agit de règles qui couvrent des menaces spécifiques, qui sont opportunes et pertinentes pendant certaines périodes. Ces menaces comprennent des campagnes APT spécifiques, l'exploitation de vulnérabilités Zero-Day, des logiciels malveillants spécifiques utilisés lors d'une attaque, etc.

## Explorer Sigma

Pour commencer à explorer l'écosystème Sigma, rendez-vous sur le site officiel [sigmahq.io](https://sigmahq.io)

### Qu'est-ce que Sigma ?

Sigma est un format de signature générique et ouvert qui vous permet de décrire de manière simple les événements pertinents consignés dans les journaux. Le format des règles est très flexible, facile à écrire et applicable à tout type de fichier journal.

L'objectif principal de ce projet est de fournir un formulaire structuré dans lequel les chercheurs ou les analystes peuvent décrire les méthodes de détection qu'ils ont développées et les partager avec d'autres.

Sigma est aux fichiers journaux ce que [Snort](https://www.snort.org/) est au trafic réseau et [YARA](https://github.com/VirusTotal/yara) aux fichiers.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./images/Sigma_description_dark.png">
  <img alt="Sigma Description - A diagram showing Yaml Files (Sigma Rules) moving through a Sigma Convertor, and coming out as many SIEM logos, showing how Sigma rules can be converted to many different available SIEM query languages" src="./images/Sigma_description_light.png">
</picture>

### Pourquoi Sigma ?

Aujourd'hui, tout le monde collecte des données de journalisation à des fins d'analyse. Les gens commencent à travailler de leur côté, traitant de nombreux livres blancs, articles de blog et directives d'analyse des journaux, extrayant les informations nécessaires et créant leurs propres recherches et tableaux de bord. Certaines de leurs recherches et corrélations sont excellentes et très utiles, mais elles ne disposent pas d'un format standardisé leur permettant de partager leur travail avec d'autres.

D'autres fournissent d'excellentes analyses, incluent des IOC et des règles YARA pour détecter les fichiers malveillants et les connexions réseau, mais n'ont aucun moyen de décrire une méthode de détection spécifique ou générique dans les événements de journalisation. Sigma est destiné à être une norme ouverte dans laquelle ces mécanismes de détection peuvent être définis, partagés et collectés afin d'améliorer les capacités de détection pour tous.

### 🌟 Caractéristiques principales

* Une liste sans cesse croissante de règles de détection et de recherche, évaluées par une communauté d'ingénieurs professionnels spécialisés dans la détection.
* Règles de détection indépendantes du fournisseur.
* Facilement partageable entre les communautés et les rapports

## 🏗️ Création de règles

Pour commencer à rédiger des règles Sigma, veuillez consulter les guides suivants :

* [Guide de création de règles](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)
* [Comment rédiger des règles Sigma - Nextron Systems](https://www.nextron-systems.com/2018/02/10/write-sigma-rules/)

## 🔎 Contribuer et faire des PR



Veuillez consulter le guide [CONTRIBUER](./CONTRIBUTING.md) pour obtenir des instructions détaillées sur la manière dont vous pouvez commencer à contribuer à l'ajout de nouvelles règles.

## 📦 Ensembles de règles

Vous pouvez télécharger les derniers ensembles de règles depuis la [page de publication](https://github.com/SigmaHQ/sigma/releases/latest) et commencer à exploiter les règles Sigma dès aujourd'hui.

## 🧬 Utilisation et conversion des règles

Vous pouvez commencer dès aujourd'hui à convertir les règles Sigma à l'aide de Sigma CLI ou de l'interface graphique sigconverter.io.

* Vous pouvez commencer dès aujourd'hui à convertir les règles Sigma à l'aide de [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) ou de l'interface graphique [sigconverter.io](https://sigconverter.io).

* Pour intégrer les règles Sigma dans votre propre chaîne d'outils ou vos propres produits, utilisez [pySigma](https://github.com/SigmaHQ/pySigma).

## 🚨 Signaler les faux positifs ou proposer de nouvelles règles

Si vous trouvez un faux positif ou souhaitez proposer une nouvelle règle de détection, mais que vous n'avez pas le temps d'en créer une, veuillez créer un nouveau ticket sur le [référentiel GitHub](https://github.com/SigmaHQ/sigma/issues/new/choose) en sélectionnant l'un des modèles disponibles.

## 📚 Ressources et lectures complémentaires

* [Hack.lu 2017 Sigma - Generic Signatures for Log Events by Thomas Patzke](https://www.youtube.com/watch?v=OheVuE9Ifhs)
* [MITRE ATT&CK® and Sigma Alerting SANS Webcast Recording](https://www.sans.org/webcasts/mitre-att-ck-sigma-alerting-110010 "MITRE ATT&CK® and Sigma Alerting")
* [Sigma - Generic Signatures for SIEM Systems by Florian Roth](https://www.slideshare.net/secret/gvgxeXoKblXRcA)

## Projets ou produits qui utilisent ou intègrent les règles Sigma
* [AlphaSOC](https://docs.alphasoc.com/detections_and_findings/sigma_community/) - Leverages Sigma rules to increase coverage across all supported log sources
* [alterix](https://github.com/mtnmunuklu/alterix) - Converts Sigma rules to the query language of CRYPTTECH's SIEM
* [AttackIQ](https://www.attackiq.com/2024/01/10/sigmaiq-attackiqs-latest-innovation-for-actionable-detections/) - Sigma Rules integrated in AttackIQ's platform, and [SigmAIQ](https://github.com/AttackIQ/SigmAIQ) for Sigma rule conversion and LLM apps
* [Atomic Threat Coverage](https://github.com/atc-project/atomic-threat-coverage) (Since December 2018)
* [AttackRuleMap - Mapping of Atomic Red Team tests and Sigma Rules](https://attackrulemap.com/)
* [Confluent Sigma](https://github.com/confluentinc/confluent-sigma) - Kafka Streams supported Sigma rules
* [Detection Studio](https://detection.studio/?ref=sigmahq_readme) - Convert Sigma rules to any supported SIEM.
* [IBM QRadar](https://community.ibm.com/community/user/security/blogs/gladys-koskas1/2023/08/02/qradar-natively-supports-sigma-for-rules-creation)
* [Impede Detection Platform](https://impede.ai/)
* [Joe Sandbox](https://www.joesecurity.org/blog/8225577975210857708)
* [LimaCharlie](https://limacharlie.io/)
* [MISP](http://www.misp-project.org/2017/03/26/MISP.2.4.70.released.html) (Since Version 2.4.70, March 2017)
* [Nextron's Aurora Agent](https://www.nextron-systems.com/aurora/)
* [Nextron's THOR Scanner](https://www.nextron-systems.com/thor/) - Scan with Sigma rules on endpoints
* [RANK VASA](https://globenewswire.com/news-release/2019/03/04/1745907/0/en/RANK-Software-to-Help-MSSPs-Scale-Cybersecurity-Offerings.html)
* [Security Onion](https://docs.securityonion.net/en/latest/sigma.html)
* [Sekoia.io XDR](https://www.sekoia.io) - XDR supporting Sigma and Sigma Correlation rules languages
* [sigma2stix](https://github.com/muchdogesec/sigma2stix) - Converts the entire SigmaHQ Ruleset into STIX 2.1 Objects.
  * A versioned archive of sigma2stix STIX 2.1 data is also available to [download here](https://github.com/muchdogesec/cti_knowledge_base_store/tree/main/sigma-rules).
* [SIΣGMA](https://github.com/3CORESec/SIEGMA) - SIEM consumable generator that utilizes Sigma for query conversion
* [SOC Prime](https://tdm.socprime.com/sigma/)
* [TA-Sigma-Searches](https://github.com/dstaulcu/TA-Sigma-Searches) (Splunk App)
* [TimeSketch](https://github.com/google/timesketch/commit/0c6c4b65a6c0f2051d074e87bbb2da2424fa6c35)
* [ypsilon](https://github.com/P4T12ICK/ypsilon) - Automated Use Case Testing

## 📜 Responsables de maintenance

* [Nasreddine Bencherchali (@nas_bench)](https://twitter.com/nas_bench)
* [Florian Roth (@cyb3rops)](https://twitter.com/cyb3rops)
* [Christian Burkard (@phantinuss)](https://twitter.com/phantinuss)
* [François Hubaut (@frack113)](https://twitter.com/frack113)
* [Thomas Patzke (@blubbfiction)](https://twitter.com/blubbfiction)

## Crédits

Ce projet n'aurait jamais atteint un tel niveau sans l'aide de centaines de contributeurs. Merci à tous les contributeurs passés et présents pour leur aide.

## Licences

Le contenu de ce référentiel est publié sous licence [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
