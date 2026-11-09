# Triage — corpus complet (all) — 2026-11-06

Run du 2026-11-06 (skill `frieren-sigma-backlog`, milestone **all**).
File rafraîchie par `review_queue_all.sh` (140 PR candidates), réconciliation
`reconcile_queue.py all`, état traqué `state/sigma-prs.json` + brouillons
`state/reviews/`. Les deux scripts frères du Step 3 ont été exécutés :
`air_responded.py` et `answered_after_review.py`.

Rappel méthode appliqué : une entrée de sync avec `last_verdict: none` et pas de
brouillon **n'est pas une revue** — c'est une revue complète à faire. C'est pour
quoi les 127 `NEVER-REVIEWED` + 3 `UNTRACKED` forment le lot.

## État de départ (buckets de la réconciliation, 140 PR)

| bucket | n° | PR |
|---|---|---|
| NEVER-REVIEWED | 127 | dont 2 `request_changes` (#6242, #6277) et 2 own (#6279, #6305) |
| UNTRACKED | 3 | #6569, #6570, #6571 (crées 2026-11-06, aucune entrée sigma-prs.json) |
| REVIEWED-UNPUBLISHED | 4 | #6474, #6511, #5980, #6104 (brouillon local, points ouverts) |
| REVIEWED-NO-DRAFT | 1 | #5245 (own frack113, Rustdesk, verdict comment) |
| APPROVED-ON-HEAD | 4 | #6444, #6276, #6255, #6307 (NEEDS-2ND-APPROVAL, head déplacé) |
| SKIP-OWN-PR | 1 | #6544 (own frack113) |

## Lot « jamais revues » (126) — ordre d'ouverture, plus ancien d'abord

Raison commune : jamais de verdict frack113, pas de brouillon local, head
courant sans approbation frack113, pas de label `Author Input Required`, PR open.
CI **pas vérifiée ce run** (règle : ne pas reviewer) — à reproduire à l'ouverture
de chaque PR. `HM` = head déplacé après la sync du 2026-10-24. `new` = sans
entrée sigma-prs.json.

| # | PR | ouverte | dernier commit | flag |
|---|---|---|---|---|
| 1 | #6086 | 2026-06-27 | 2026-10-18 | |
| 2 | #6092 | 2026-06-29 | 2026-10-18 | HM |
| 3 | #6110 | 2026-07-05 | 2026-10-24 | HM |
| 4 | #6127 | 2026-07-10 | 2026-10-24 | HM |
| 5 | #6129 | 2026-07-12 | 2026-08-21 | |
| 6 | #6134 | 2026-07-13 | 2026-07-14 | |
| 7 | #6146 | 2026-07-16 | 2026-07-16 | |
| 8 | #6152 | 2026-07-18 | 2026-10-24 | HM |
| 9 | #6176 | 2026-07-25 | 2026-10-24 | HM |
| 10 | #6177 | 2026-07-26 | 2026-10-24 | HM |
| 11 | #6195 | 2026-07-31 | 2026-10-26 | HM |
| 12 | #6194 | 2026-07-31 | 2026-10-24 | HM |
| 13 | #6200 | 2026-08-03 | 2026-10-24 | HM |
| 14 | #6219 | 2026-08-11 | 2026-10-24 | HM |
| 15 | #6218 | 2026-08-11 | 2026-10-24 | HM |
| 16 | #6217 | 2026-08-11 | 2026-10-24 | HM |
| 17 | #6230 | 2026-08-14 | 2026-10-24 | HM |
| 18 | #6229 | 2026-08-14 | 2026-10-24 | HM |
| 19 | #6234 | 2026-08-15 | 2026-10-24 | HM |
| 20 | #6233 | 2026-08-15 | 2026-10-24 | HM |
| 21 | #6238 | 2026-08-16 | 2026-10-24 | HM |
| 22 | #6236 | 2026-08-16 | 2026-10-24 | HM |
| 23 | #6241 | 2026-08-18 | 2026-10-24 | HM |
| 24 | #6240 | 2026-08-18 | 2026-10-24 | HM |
| 25 | #6243 | 2026-08-20 | 2026-10-24 | HM |
| 26 | #6253 | 2026-08-24 | 2026-10-24 | HM |
| 27 | #6252 | 2026-08-24 | 2026-10-24 | HM |
| 28 | #6257 | 2026-08-26 | 2026-10-24 | HM |
| 29 | #6264 | 2026-08-28 | 2026-10-24 | HM |
| 30 | #6273 | 2026-09-02 | 2026-10-24 | HM |
| 31 | #6280 | 2026-09-08 | 2026-10-24 | HM |
| 32 | #6285 | 2026-09-10 | 2026-10-24 | HM |
| 33 | #6294 | 2026-09-13 | 2026-10-24 | HM |
| 34 | #6293 | 2026-09-13 | 2026-10-24 | HM |
| 35 | #6299 | 2026-09-15 | 2026-10-24 | HM |
| 36 | #6306 | 2026-09-18 | 2026-10-24 | HM |
| 37 | #6308 | 2026-09-19 | 2026-10-24 | HM |
| 38 | #6314 | 2026-09-21 | 2026-10-24 | HM |
| 39 | #6313 | 2026-09-21 | 2026-10-24 | HM |
| 40 | #6312 | 2026-09-21 | 2026-10-24 | HM |
| 41 | #6320 | 2026-09-23 | 2026-10-24 | HM |
| 42 | #6326 | 2026-09-24 | 2026-10-24 | HM |
| 43 | #6335 | 2026-09-26 | 2026-10-24 | HM |
| 44 | #6333 | 2026-09-26 | 2026-10-24 | HM |
| 45 | #6332 | 2026-09-26 | 2026-10-24 | HM |
| 46 | #6331 | 2026-09-26 | 2026-10-24 | HM |
| 47 | #6329 | 2026-09-26 | 2026-10-24 | HM |
| 48 | #6354 | 2026-09-29 | 2026-10-24 | HM |
| 49 | #6352 | 2026-09-29 | 2026-10-24 | HM |
| 50 | #6359 | 2026-09-30 | 2026-10-24 | HM |
| 51 | #6358 | 2026-09-30 | 2026-10-24 | HM |
| 52 | #6357 | 2026-09-30 | 2026-10-24 | HM |
| 53 | #6362 | 2026-10-01 | 2026-10-24 | HM |
| 54 | #6419 | 2026-10-02 | 2026-10-24 | HM |
| 55 | #6418 | 2026-10-02 | 2026-10-24 | HM |
| 56 | #6423 | 2026-10-03 | 2026-10-24 | HM |
| 57 | #6422 | 2026-10-03 | 2026-10-24 | HM |
| 58 | #6421 | 2026-10-03 | 2026-10-24 | HM |
| 59 | #6426 | 2026-10-04 | 2026-10-24 | HM |
| 60 | #6424 | 2026-10-04 | 2026-10-24 | HM |
| 61 | #6432 | 2026-10-06 | 2026-10-24 | HM |
| 62 | #6440 | 2026-10-07 | 2026-10-24 | HM |
| 63 | #6439 | 2026-10-07 | 2026-10-24 | HM |
| 64 | #6438 | 2026-10-07 | 2026-10-24 | HM |
| 65 | #6437 | 2026-10-07 | 2026-10-24 | HM |
| 66 | #6436 | 2026-10-07 | 2026-10-24 | HM |
| 67 | #6435 | 2026-10-07 | 2026-10-24 | HM |
| 68 | #6434 | 2026-10-07 | 2026-10-24 | HM |
| 69 | #6443 | 2026-10-08 | 2026-10-24 | HM |
| 70 | #6450 | 2026-10-11 | 2026-10-24 | HM |
| 71 | #6449 | 2026-10-11 | 2026-10-24 | HM |
| 72 | #6456 | 2026-10-12 | 2026-10-24 | HM |
| 73 | #6452 | 2026-10-12 | 2026-10-24 | HM |
| 74 | #6458 | 2026-10-13 | 2026-10-24 | HM |
| 75 | #6464 | 2026-10-14 | 2026-10-14 | HM |
| 76 | #6463 | 2026-10-14 | 2026-10-24 | HM |
| 77 | #6470 | 2026-10-15 | 2026-10-24 | HM |
| 78 | #6473 | 2026-10-16 | 2026-10-24 | HM |
| 79 | #6478 | 2026-10-17 | 2026-10-24 | HM |
| 80 | #6482 | 2026-10-18 | 2026-10-24 | HM |
| 81 | #6479 | 2026-10-18 | 2026-10-24 | HM |
| 82 | #6488 | 2026-10-19 | 2026-10-24 | HM |
| 83 | #6484 | 2026-10-19 | 2026-10-24 | HM |
| 84 | #6491 | 2026-10-20 | 2026-10-21 | HM |
| 85 | #6501 | 2026-10-21 | 2026-10-21 | |
| 86 | #6500 | 2026-10-21 | 2026-10-21 | |
| 87 | #6495 | 2026-10-21 | 2026-10-21 | |
| 88 | #6507 | 2026-10-22 | 2026-11-03 | HM |
| 89 | #6503 | 2026-10-22 | 2026-10-23 | |
| 90 | #6509 | 2026-10-22 | 2026-10-22 | |
| 91 | #6508 | 2026-10-22 | 2026-10-22 | |
| 92 | #6517 | 2026-10-25 | 2026-11-04 | HM |
| 93 | #6516 | 2026-10-25 | 2026-11-04 | HM |
| 94 | #6519 | 2026-10-25 | 2026-10-25 | |
| 95 | #6515 | 2026-10-25 | 2026-10-25 | |
| 96 | #6526 | 2026-10-26 | 2026-10-26 | |
| 97 | #6525 | 2026-10-26 | 2026-10-26 | |
| 98 | #6521 | 2026-10-26 | 2026-10-26 | |
| 99 | #6531 | 2026-10-27 | 2026-10-27 | |
| 100 | #6530 | 2026-10-27 | 2026-10-27 | |
| 101 | #6529 | 2026-10-27 | 2026-10-27 | |
| 102 | #6533 | 2026-10-27 | 2026-10-26 | HM |
| 103 | #6532 | 2026-10-27 | 2026-10-26 | HM |
| 104 | #6538 | 2026-10-28 | 2026-10-28 | |
| 105 | #6537 | 2026-10-28 | 2026-10-28 | |
| 106 | #6536 | 2026-10-28 | 2026-10-28 | |
| 107 | #6535 | 2026-10-28 | 2026-10-28 | |
| 108 | #6534 | 2026-10-28 | 2026-10-28 | |
| 109 | #6540 | 2026-10-29 | 2026-11-06 | HM |
| 110 | #6539 | 2026-10-29 | 2026-11-05 | HM |
| 111 | #6541 | 2026-10-30 | 2026-11-04 | HM |
| 112 | #6543 | 2026-10-30 | 2026-10-30 | |
| 113 | #6542 | 2026-10-30 | 2026-10-30 | |
| 114 | #6548 | 2026-10-31 | 2026-10-31 | |
| 115 | #6547 | 2026-10-31 | 2026-10-30 | HM |
| 116 | #6551 | 2026-11-01 | 2026-11-01 | |
| 117 | #6556 | 2026-11-02 | 2026-11-02 | |
| 118 | #6558 | 2026-11-03 | 2026-11-05 | HM |
| 119 | #6557 | 2026-11-03 | 2026-11-03 | |
| 120 | #6564 | 2026-11-04 | 2026-11-04 | |
| 121 | #6561 | 2026-11-04 | 2026-11-04 | |
| 122 | #6566 | 2026-11-05 | 2026-11-05 | |
| 123 | #6568 | 2026-11-06 | 2026-11-06 | |
| 124 | #6569 | 2026-11-06 | 2026-11-06 | new |
| 125 | #6570 | 2026-11-06 | 2026-11-06 | new |
| 126 | #6571 | 2026-11-06 | 2026-11-06 | new |

## Exclusions du lot (et pourquoi)

- **#6242, #6277** — verdict `request_changes` enregistré (1 pt ouvert), pas de
  brouillon → **revues**, pas de re-revue (règle : une entrée avec un verdict est
  une revue, même sans brouillon).
- **#6279, #6305, #6544, #5245, #6477** — PR de frack113 (own) → skip.
- **#6474, #6511, #5980, #6104** — REVIEWED-UNPUBLISHED : brouillon local + points
  ouverts → revue, pas « jamais revue ».
- **#6444, #6276, #6255, #6307** — APPROVED-ON-HEAD (NEEDS-2ND-APPROVAL) :
  approbation frack113 sur un head antérieur, head déplacé → delta uniquement.

## Surfaced par le Step 3 (pas dans le lot, à signaler)

**AIR/ADD dont l'auteur a répondu depuis le label (plus en attente de l'auteur) :**
- CI verte → candidats : #6459 (redsand), #6416 (swachchhanda000), #6115 (st0pp3r),
  #6093 (einlamye), #6005 (privet-username), #5895 (kurisukun).
- CI rouge → skip, l'auteur doit corriger d'abord : #6282, #6281 (roromer0),
  #6199 (ashish-cybersec), #6105 (OriolesMagic333), #5747 (louiselalanne).
- CI « attend ton approbation » (4 workflows `action_required`) : 47 PR au total —
  à déblocer par approbation du run (`gh api -X POST .../runs/<id>/approve`),
  pas une re-revue.

**Revues dont l'auteur a répondu / poussé depuis la revue (Step 3b) :**
- AUTHOR-ANSWERED (relire la réponse avant re-revue) : #6183 (warlocksmurf, pts 12),
  #5873 (Aadith1422, pts 2, CI verte).
- AUTHOR-PUSHED (re-vérifier les points au nouveau head) : #6506, #6459, #6444,
  #6322, #6319, #6318, #6316, #6277, #6276, #6242, #6179, #6168, #6124, #6104,
  #6020, #5903.
- HEAD-MOVED (rebase/merge par un tiers : ancres peut-être décalées) : #6445,
  #6429, #6356, #6278, #6274, #6258, #6212, #6209, #6201, #6187, #6186, #6166,
  #6165, #6162, #6122, #6106, #6105, #6081, #6065, #6022, #6006, #5995, #5991,
  #5988, #5980, #5957, #5956, #5955, #5944.

## Ce qui reste (point de départ du prochain run)

- Les 126 du lot ci-dessus, à prendre **un par un**, #6086 en premier
  (ouvert le 2026-06-27).
- Les 6 AIR CI-verte à insérer dans la file (pas réinjectées manuellement).
- Les 47 heads `action_required` à déblocer sur instruction.
- Les AUTHOR-ANSWERED / AUTHOR-PUSHED / HEAD-MOVED revues : re-vérifier au head
  courant, ne pas re-publier les points morts.

## Pannes externes

- Aucune rencontrée ce run (pas de 403/525, pas de 403 secondary rate limit
  bloquant — le script de file a géré le backoff).

## Rappel méthode (faux négatifs connus)

- `state/sigma-prs.json` `last_verdict: none` + pas de brouillon ≠ revue
  (c'est la règle qui alimente le lot de 126).
- `posted: true` n'est pas une preuve : à confirmer par `github_truth.py` avant
  de déclarer une PR close (pas appliqué ce run, aucune PR déclarée close).
- Le motif « jamais revue par toi » imprimé par le script est une constante :
  ne pas le citer comme un constat.
