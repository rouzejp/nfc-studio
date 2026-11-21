#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NFC Studio — lire et écrire des tags NFC Type 2 (NTAG21x, MIFARE Ultralight).

Lecteur : ACS ACR1552 (072f:2303) — et tout lecteur CCID exposant les
pseudo-APDU PC/SC 2.01 (FF CA = UID, FF B0 = READ, FF D6 = UPDATE).

Dépendances : python3-pyscard (dépôt openSUSE) + ndeflib (pip, dans le venv).

Usage CLI :
  nfc-studio --cli info              # lecteurs + tag présent + NDEF décodé
  nfc-studio --cli dump              # vidage hexadécimal des pages
  nfc-studio --cli write-text "..."  # écrit un enregistrement texte
  nfc-studio --cli write-url "https://..."   # écrit un enregistrement URI
  nfc-studio --cli erase             # efface le message NDEF

Sans --cli : interface graphique.
"""

import argparse
import sys
import traceback

from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.System import readers as sc_readers
from smartcard.util import toHexString

import ndef

UID_APDU = [0xFF, 0xCA, 0x00, 0x00, 0x00]
SW_OK = 0x9000

# capacité NDEF (octets de mémoire utilisateur) -> nom de puce probable
CHIPS = {
    48: "MIFARE Ultralight (48 o)",
    64: "MIFARE Ultralight C / EV1 (64 o)",
    144: "NTAG213 (144 o)",
    208: "NTAG213 clone / Ultralight EV1 128 (208 o)",
    496: "NTAG215 (496 o)",
    872: "NTAG216 (872 o)",
}


class TagError(Exception):
    pass


def xmit(conn, apdu):
    data, sw1, sw2 = conn.transmit(apdu)
    return list(data), (sw1 << 8) | sw2


def list_readers():
    return [str(r) for r in sc_readers()]


def pick_reader(name=None):
    """Choisit le lecteur : slot PICC (sans contact) plutôt que le slot SAM."""
    rl = list(sc_readers())
    if not rl:
        raise TagError("Aucun lecteur PC/SC détecté (pcscd en marche ? lecteur branché ?)")
    if name:
        for r in rl:
            if name.lower() in str(r).lower():
                return r
        raise TagError("Lecteur « %s » introuvable" % name)
    for r in rl:
        s = str(r).upper()
        if "PICC" in s or "ICC" in s and "SAM" not in s:
            return r
    for r in rl:
        if "SAM" not in str(r).upper():
            return r
    return rl[0]


def connect(name=None):
    reader = pick_reader(name)
    try:
        conn = reader.createConnection()
        conn.connect()
    except NoCardException:
        raise TagError("Lecteur « %s » : aucun tag posé dessus." % reader)
    except CardConnectionException as e:
        raise TagError("Connexion au tag impossible : %s" % e)
    return reader, conn


def read_card(refresh_card=True):
    """Renvoie (nom_lecteur, connection) sur un tag présent."""
    return connect()


def get_uid(conn):
    data, sw = xmit(conn, UID_APDU)
    if sw != SW_OK or not data:
        return None
    return toHexString(data).replace(" ", "")


def read_pages(conn, start, count=4):
    """Lit count pages (count*4 octets) à partir de la page start."""
    if count < 1:
        return []
    data, sw = xmit(conn, [0xFF, 0xB0, 0x00, start, count * 4])
    if sw == SW_OK and len(data) == count * 4:
        return data
    out = []
    for i in range(count):
        d, sw = xmit(conn, [0xFF, 0xB0, 0x00, start + i, 4])
        if sw != SW_OK or len(d) != 4:
            raise TagError("Lecture de la page %d refusée (SW=%04X)" % (start + i, sw))
        out += d
    return out


def read_pages_soft(conn, start, count=4):
    """Comme read_pages mais renvoie None au lieu de lever (fin de mémoire)."""
    try:
        return read_pages(conn, start, count)
    except TagError:
        return None


def write_page(conn, page, four):
    data, sw = xmit(conn, [0xFF, 0xD6, 0x00, page, 4] + list(four))
    if sw != SW_OK:
        raise TagError("Écriture de la page %d refusée (SW=%04X) — tag verrouillé ?" % (page, sw))


def probe_memory(conn):
    """Mesure la mémoire utilisateur en lisant jusqu'à l'échec (pages >= 4)."""
    page = 4
    size = 0
    while page < 256:
        block = read_pages_soft(conn, page, 4)
        if block is None:
            one = read_pages_soft(conn, page, 1)
            if one is None:
                break
            size += 4
            page += 1
            continue
        size += len(block)
        page += 4
    return size


def tag_info(conn):
    uid = get_uid(conn)
    head = read_pages(conn, 0, 4)          # pages 0..3 (16 o)
    cc = head[12:16]
    info = {
        "uid": uid,
        "atr": toHexString(list(conn.getATR())).replace(" ", ""),
        "cc": toHexString(cc).replace(" ", ""),
        "formatted": cc[0] == 0xE1 and cc[1] == 0x10,
        "capacity": None,
        "chip": "inconnu",
        "access": None,
        "raw_head": head,
    }
    if info["formatted"]:
        info["capacity"] = cc[2] * 8
        info["access"] = "lecture seule" if (cc[3] & 0x0F) == 0x0F else "lecture/écriture"
        info["chip"] = CHIPS.get(info["capacity"], "Type 2 — capacité %d o" % info["capacity"])
    else:
        mem = probe_memory(conn)
        info["memory_size"] = mem
        info["chip"] = CHIPS.get(mem, "Type 2 — mémoire %d o (non formaté)" % mem)
    return info


def read_ndef(conn, capacity):
    """Renvoie (message_ndef ou None, octets_bruts)."""
    pages = max(1, capacity // 4)
    data = []
    page = 4
    while len(data) < capacity and page < 4 + pages:
        block = read_pages_soft(conn, page, 4)
        if block is None:
            break
        data += block
        page += 4
    data = data[:capacity]
    raw = bytes(data)
    # TLV : on cherche le bloc 0x03
    i = 0
    msg = None
    while i < len(raw):
        t = raw[i]
        if t == 0x00:
            i += 1
            continue
        if t == 0xFE:
            break
        if i + 1 >= len(raw):
            break
        ln = raw[i + 1]
        i += 2
        if ln == 0xFF:
            if i + 2 > len(raw):
                break
            ln = (raw[i] << 8) | raw[i + 1]
            i += 2
        val = raw[i:i + ln]
        if t == 0x03:
            msg = val
            break
        i += ln
    return msg, raw


def describe_ndef(msg):
    if not msg:
        return ["(aucun message NDEF)"]
    lines = []
    try:
        for rec in ndef.message_decoder(msg):
            kind = type(rec).__name__
            txt = getattr(rec, "text", None)
            uri = getattr(rec, "uri", None)
            if txt is not None:
                lines.append("[%s] %s" % (kind, txt))
            elif uri is not None:
                lines.append("[%s] %s" % (kind, uri))
            else:
                lines.append("[%s] %r" % (kind, rec))
    except Exception as e:  # noqa: BLE001
        lines.append("(NDEF illisible : %s) brut=%s" % (e, msg.hex()))
    return lines


def format_tag(conn, size_bytes):
    """Écrit la Capability Container d'un tag vierge."""
    if size_bytes <= 0 or size_bytes % 8:
        raise TagError("Mémoire utilisateur inattendue (%d o) — formatage refusé" % size_bytes)
    cc = [0xE1, 0x10, size_bytes // 8, 0x00]
    write_page(conn, 3, cc)
    return cc


def write_ndef(conn, msg_bytes, info):
    capacity = info.get("capacity")
    if not info["formatted"]:
        mem = info.get("memory_size") or probe_memory(conn)
        format_tag(conn, mem)
        info["capacity"] = mem
        info["formatted"] = True
        capacity = mem
    if capacity is None:
        raise TagError("Capacité du tag inconnue")
    n = len(msg_bytes)
    if n == 0:
        tlv = bytes([0x03, 0x00, 0xFE])
    elif n < 0xFF:
        tlv = bytes([0x03, n]) + msg_bytes + b"\xFE"
    else:
        tlv = bytes([0x03, 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + msg_bytes + b"\xFE"
    if len(tlv) > capacity:
        raise TagError("Message trop long : %d o pour une capacité de %d o" % (len(tlv), capacity))
    tlv += b"\x00" * ((-len(tlv)) % 4)
    page = 4
    for off in range(0, len(tlv), 4):
        write_page(conn, page, tlv[off:off + 4])
        page += 1


def do_write_text(conn, text, info):
    msg = b"".join(ndef.message_encoder([ndef.TextRecord(text, language="fr")]))
    write_ndef(conn, msg, info)


def do_write_url(conn, url, info):
    msg = b"".join(ndef.message_encoder([ndef.UriRecord(url)]))
    write_ndef(conn, msg, info)


def do_erase(conn, info):
    write_ndef(conn, b"", info)


def dump_pages(conn, info, upto=None):
    capacity = info.get("capacity") or info.get("memory_size") or 64
    limit = upto or (16 + capacity)
    lines = []
    for page in range(0, limit, 4):
        block = read_pages_soft(conn, page, 4)
        if block is None:
            one = read_pages_soft(conn, page, 1)
            if one is None:
                break
            block = one
        lines.append("%02X: %s" % (page, toHexString(block)))
    return lines



# ------------------------------------------------------- MIFARE Classic (MF1)

# clés essayées dans l'ordre : d'abord celles d'usine, puis les clés normalisées NFC Forum
CLASSIC_KEYS = [
    ("FFFFFFFFFFFF", "clé d'usine NXP"),
    ("A0A1A2A3A4A5", "clé MAD (annuaire)"),
    ("D3F7D3F7D3F7", "clé NDEF NFC Forum"),
    ("000000000000", "clé nulle"),
    ("A0A1A2A3A4A5", "clé MAD"),
]

# SAK -> (nom, nombre de secteurs, taille en octets)
SAK_TYPES = {
    0x08: ("MIFARE Classic 1K", 16, 1024),
    0x18: ("MIFARE Classic 4K", 40, 4096),
    0x09: ("MIFARE Mini", 5, 320),
    0x88: ("MIFARE Classic 1K (Infineon)", 16, 1024),
}

DEFAULT_ACCESS = "FF078069"


def classic_load_key(conn, key_hex, slot=0):
    key = bytes.fromhex(key_hex)
    if len(key) != 6:
        raise TagError("Clé de 6 octets attendue")
    data, sw = xmit(conn, [0xFF, 0x82, 0x00, slot, 0x06] + list(key))
    if sw != SW_OK:
        raise TagError("Chargement de clé refusé (SW=%04X)" % sw)


def classic_auth(conn, block, keytype="A", slot=0):
    """Authentifie le secteur du bloc. keytype A = 0x60, B = 0x61."""
    kt = 0x60 if keytype.upper() == "A" else 0x61
    data, sw = xmit(conn, [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, kt, slot])
    return sw == SW_OK


def classic_read_block(conn, block):
    data, sw = xmit(conn, [0xFF, 0xB0, 0x00, block, 0x10])
    if sw != SW_OK or len(data) != 16:
        raise TagError("Lecture du bloc %d refusée (SW=%04X)" % (block, sw))
    return data


def classic_sector_blocks(sector):
    if sector < 32:
        return [sector * 4 + i for i in range(4)]
    return [128 + (sector - 32) * 16 + i for i in range(16)]


def classic_try_sector(conn, sector, extra_keys=()):
    """Cherche une clé qui ouvre le secteur. Renvoie (keytype, key_hex, label) ou None."""
    blocks = classic_sector_blocks(sector)
    candidats = list(CLASSIC_KEYS) + [("".join(k), "clé fournie") for k in extra_keys]
    for key_hex, label in candidats:
        for keytype in ("A", "B"):
            try:
                classic_load_key(conn, key_hex)
            except TagError:
                continue
            if classic_auth(conn, blocks[0], keytype):
                return keytype, key_hex, label
    return None


def classic_identify(conn):
    """Tente une lecture authentifiée du bloc 0. Renvoie None si ce n'est pas une Classic."""
    for key_hex, _label in CLASSIC_KEYS:
        try:
            classic_load_key(conn, key_hex)
        except TagError:
            continue
        if classic_auth(conn, 0, "A") or classic_auth(conn, 0, "B"):
            try:
                block0 = classic_read_block(conn, 0)
            except TagError:
                continue
            sak = block0[5]
            nom, secteurs, taille = SAK_TYPES.get(sak, ("MIFARE Classic (SAK %02X)" % sak, 16, 1024))
            return {
                "uid": toHexString(block0[0:4]).replace(" ", ""),
                "bcc": "%02X" % block0[4],
                "sak": sak,
                "sak_hex": "%02X" % sak,
                "atqa": toHexString(block0[6:8]),
                "fabricant": bytes(block0[8:16]).decode("latin-1", "replace"),
                "modele": nom,
                "secteurs": secteurs,
                "taille": taille,
                "block0": block0,
            }
    return None


def mad_decode(bloc_mad1, bloc_mad2):
    """Décode l'annuaire MIFARE : bloc 1 = secteurs 1..15, bloc 2 = secteurs 16..39."""
    noms = {0x03E1: "NFC Forum NDEF", 0x0002: "MIFARE Application Directory",
            0x0001: "Transport", 0x0004: "Accès", 0x0005: "Loisirs", 0x0006: "Sécurité",
            0x0003: "??", 0x0008: "??"}
    entrees = []
    for base, bloc in ((1, bloc_mad1), (16, bloc_mad2)):
        if not bloc:
            continue
        for i in range(0, 16, 2):
            aid = (bloc[i] << 8) | bloc[i + 1]
            if aid in (0x0000, 0xFFFF):
                continue
            secteur = base + (i // 2)
            entrees.append((secteur, aid, noms.get(aid, "AID 0x%04X" % aid)))
    version = "MAD version 1" if (bloc_mad1 and bloc_mad1[0] == 0x01) else ""
    return entrees, version


def classic_dump(conn, extra_keys=(), keep_open=True):
    """Vidage complet : authentification secteur par secteur, données + clés + annuaire."""
    ident = classic_identify(conn)
    if not ident:
        raise TagError("Ce tag n'est pas une MIFARE Classic lisible (ou clé inconnue sur le secteur 0).")
    resultat = {"tag": ident, "secteurs": [], "cles_trouvees": [], "mad": [], "mad_version": ""}
    for secteur in range(ident["secteurs"]):
        entree = {"secteur": secteur, "cle": None, "type_cle": None, "blocs": {}, "trailer": None,
                  "cles_usine": False, "acces_usine": False, "lue": False}
        trouve = classic_try_sector(conn, secteur, extra_keys)
        if not trouve:
            resultat["secteurs"].append(entree)
            continue
        keytype, key_hex, label = trouve
        entree.update({"cle": key_hex, "type_cle": keytype, "cle_label": label, "lue": True})
        if key_hex.upper() not in [k.upper() for k in resultat["cles_trouvees"]]:
            resultat["cles_trouvees"].append(key_hex.upper())
        blocs = []
        for bloc in classic_sector_blocks(secteur):
            try:
                blocs.append(classic_read_block(conn, bloc))
            except TagError:
                blocs.append(None)
        entree["blocks_list"] = blocs
        entree["blocs"] = {bloc: (toHexString(d).replace(" ", "") if d else None)
                           for bloc, d in zip(classic_sector_blocks(secteur), blocs)}
        trailer = blocs[-1]
        if trailer:
            entree["trailer"] = toHexString(trailer).replace(" ", "")
            cle_a = toHexString(trailer[0:6]).replace(" ", "")
            cle_b = toHexString(trailer[10:16]).replace(" ", "")
            entree["cle_a_stockee"] = cle_a
            entree["cle_b_stockee"] = cle_b
            entree["acces_hex"] = toHexString(trailer[6:10]).replace(" ", "")
            entree["gpb"] = "%02X" % trailer[9]
            entree["cles_usine"] = cle_a.upper() == "FFFFFFFFFFFF" and cle_b.upper() == "FFFFFFFFFFFF"
            entree["acces_usine"] = toHexString(trailer[6:9]).replace(" ", "").upper() == DEFAULT_ACCESS
        resultat["secteurs"].append(entree)
        if secteur == 0:
            resultat["mad"], resultat["mad_version"] = mad_decode(blocs[1] if len(blocs) > 1 else None,
                                                                  blocs[2] if len(blocs) > 2 else None)
    resultat["cles_trouvees"].sort()
    return resultat


def classic_rapport(res):
    t = res["tag"]
    lignes = []
    lignes.append("Modèle      : %s (SAK %s / ATQA %s)" % (t["modele"], t["sak_hex"], t["atqa"]))
    lignes.append("UID         : %s   (BCC %s)" % (t["uid"], t["bcc"]))
    lignes.append("Fabricant   : %r" % t["fabricant"])
    lignes.append("Taille      : %d octets, %d secteurs" % (t["taille"], t["secteurs"]))
    if res["mad"]:
        lignes.append("Annuaire MAD :")
        for secteur, aid, nom in res["mad"]:
            lignes.append("  secteur %02d : AID 0x%04X — %s" % (secteur, aid, nom))
    if res["cles_trouvees"]:
        lignes.append("Clés trouvées : %s" % ", ".join(res["cles_trouvees"]))
    lignes.append("")
    non_lues = []
    for s in res["secteurs"]:
        if not s["lue"]:
            non_lues.append(s["secteur"])
            lignes.append("Secteur %02d : %s" % (s["secteur"], "NON LU — aucune clé connue"))
            continue
        drapeaux = []
        if s["cles_usine"]:
            drapeaux.append("CLÉS D'USINE")
        if s["acces_usine"]:
            drapeaux.append("accès d'usine")
        suffixe = (" [" + ", ".join(drapeaux) + "]") if drapeaux else ""
        lignes.append("Secteur %02d : clé %s %s (%s)%s" % (s["secteur"], s["type_cle"], s["cle"], s.get("cle_label", ""), suffixe))
        for bloc, data in s["blocs"].items():
            lignes.append("   bloc %03d : %s" % (bloc, data or "lecture refusée"))
        if s.get("gpb") and s["gpb"] not in ("00", "69"):
            lignes.append("   GPB non usine : %s" % s["gpb"])
    ndef_classic = classic_ndef_from_dump(res)
    if ndef_classic:
        _charge, msg = ndef_classic
        lignes.append("")
        secteur_ndef = next((s for s, aid, _n in res.get("mad", []) if aid == 0x03E1), None)
        lignes.append("NDEF dans le secteur %02d :" % (secteur_ndef if secteur_ndef is not None else -1))
        for ligne in describe_ndef(msg):
            lignes.append("   " + ligne)
    if non_lues:
        lignes.append("")
        lignes.append("Secteurs non lus : %s (clés non connues de la liste essayée)" % ", ".join(str(x) for x in non_lues))
    return lignes


def classic_ndef_from_dump(res):
    """Si la MAD designe un secteur NDEF (AID 03E1), extrait le TLV 0x03 et le decode."""
    secteurs = [s for s, aid, _nom in res.get("mad", []) if aid == 0x03E1]
    if not secteurs:
        return None
    secteur = secteurs[0]
    entree = next((x for x in res["secteurs"] if x["secteur"] == secteur), None)
    if not entree or not entree.get("blocks_list"):
        return None
    data = b"".join(bytes(b) for b in entree["blocks_list"] if b)
    i = 0
    while i < len(data):
        t = data[i]
        if t == 0x00:
            i += 1
            continue
        if t == 0xFE or i + 1 >= len(data):
            return None
        longueur = data[i + 1]
        if longueur == 0xFF:
            if i + 3 >= len(data):
                return None
            longueur = (data[i + 2] << 8) | data[i + 3]
            debut = i + 4
        else:
            debut = i + 2
        if t == 0x03:
            charge = data[debut:debut + longueur]
            try:
                return charge, list(ndef.message_decoder(charge))
            except Exception:  # noqa: BLE001
                return None
        i = debut + longueur
    return None


def classic_mfd(res):
    """Image binaire .mfd (blocs dans l'ordre, secteurs illisibles à zéro)."""
    total = res["tag"]["taille"]
    image = bytearray(b"\x00" * total)
    for s in res["secteurs"]:
        for bloc, data in zip(classic_sector_blocks(s["secteur"]), s.get("blocks_list") or []):
            if data:
                offset = bloc * 16
                if offset + 16 <= total:
                    image[offset:offset + 16] = bytes(data)
    return bytes(image)


def classic_sauvegarde(res, outdir=None):
    """Écrit dump.json, dump.mfd, rapport.txt et cles.txt dans dumps/<horodatage>_<uid>/."""
    import json, os, time
    base = outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "dumps")
    dossier = os.path.join(base, "%s_%s" % (time.strftime("%Y%m%d-%H%M%S"), res["tag"]["uid"]))
    os.makedirs(dossier, exist_ok=True)
    sans_blocs = dict(res)
    sans_blocs["secteurs"] = [{k: v for k, v in s.items() if k != "blocks_list"} for s in res["secteurs"]]
    with open(os.path.join(dossier, "dump.json"), "w", encoding="utf-8") as f:
        json.dump(sans_blocs, f, indent=2, ensure_ascii=False)
    with open(os.path.join(dossier, "dump.mfd"), "wb") as f:
        f.write(classic_mfd(res))
    with open(os.path.join(dossier, "rapport.txt"), "w", encoding="utf-8") as f:
        f.write("NFC Studio — vidage MIFARE Classic\n")
        f.write("date: %s\n\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
        f.write("\n".join(classic_rapport(res)) + "\n")
    with open(os.path.join(dossier, "cles.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(res["cles_trouvees"]) + "\n")
    return dossier



# --------------------------------------------------- étiquettes QIDI Box (FM11RF08S)

QIDI_BLOCK = 4                 # secteur 1, bloc 0 : material / color / manufacturer
QIDI_KEYS = ["D3F7D3F7D3F7", "FFFFFFFFFFFF"]

QIDI_MATERIALS = {
    1: "PLA", 2: "PLA Matte", 3: "PLA Metal", 4: "PLA Silk", 5: "PLA-CF", 6: "PLA-Wood",
    7: "PLA Basic", 8: "PLA Matte Basic", 11: "ABS", 12: "ABS-GF", 13: "ABS-Metal",
    14: "ABS-Odorless", 18: "ASA", 19: "ASA-AERO", 24: "UltraPA", 25: "PA-CF",
    26: "UltraPA-CF25", 27: "PA12-CF", 30: "PAHT-CF", 31: "PAHT-GF", 32: "Support PAHT",
    33: "Support PET/PA", 34: "PC/ABS-FR", 37: "PET-CF", 38: "PET-GF", 39: "PETG Basic",
    40: "PETG Tough", 41: "PETG Rapido", 42: "PETG-CF", 43: "PETG-GF", 44: "PPS-CF",
    45: "PETG Translucent", 47: "PVA", 49: "TPU-Aero", 50: "TPU",
}

QIDI_COLORS = {
    1: ("#FAFAFA", "blanc"), 2: ("#060606", "noir"), 3: ("#D9E3ED", "gris"),
    4: ("#5CF30F", "vert clair"), 5: ("#63E492", "menthe"), 6: ("#2850FF", "bleu"),
    7: ("#FE98FE", "rose clair"), 8: ("#DFD628", "jaune"), 9: ("#228332", "vert"),
    10: ("#99DEFF", "bleu clair"), 11: ("#1714B0", "bleu foncé"), 12: ("#CEC0FE", "lavande"),
    13: ("#CADE4B", "lime"), 14: ("#1353AB", "bleu royal"), 15: ("#5EA9FD", "bleu ciel"),
    16: ("#A878FF", "violet"), 17: ("#FE717A", "rose"), 18: ("#FF362D", "rouge"),
    19: ("#E2DFCD", "beige"), 20: ("#898F9B", "argent"), 21: ("#6E3812", "brun"),
    22: ("#CAC59F", "kaki"), 23: ("#F28636", "orange"), 24: ("#B87F2B", "bronze"),
}


def qidi_material_num(valeur):
    """Accepte un numéro (1..50) ou un nom (« PLA », « petg-cf »)."""
    if valeur is None:
        raise TagError("Matériau manquant")
    texte = str(valeur).strip()
    if texte.isdigit():
        num = int(texte)
        if num not in QIDI_MATERIALS:
            raise TagError("Code matériau %d inconnu (voir --cli qidi-tables)" % num)
        return num
    cle = texte.lower().replace(" ", "").replace("-", "").replace("_", "")
    for num, nom in QIDI_MATERIALS.items():
        if nom.lower().replace(" ", "").replace("-", "").replace("_", "") == cle:
            return num
    for num, nom in QIDI_MATERIALS.items():
        if cle in nom.lower().replace(" ", "").replace("-", "").replace("_", ""):
            return num
    raise TagError("Matériau « %s » inconnu (voir --cli qidi-tables)" % texte)


def qidi_color_num(valeur):
    """Accepte un numéro (1..24), un nom français, ou une couleur #RRGGBB (la plus proche)."""
    if valeur is None:
        raise TagError("Couleur manquante")
    texte = str(valeur).strip()
    if texte.isdigit():
        num = int(texte)
        if num not in QIDI_COLORS:
            raise TagError("Code couleur %d inconnu (1..24, voir --cli qidi-tables)" % num)
        return num
    if texte.startswith("#") and len(texte) == 7:
        try:
            rgb = tuple(int(texte[i:i + 2], 16) for i in (1, 3, 5))
        except ValueError:
            raise TagError("Couleur hexadécimale invalide : %s" % texte)
        meilleur, distance = None, None
        for num, (hexa, _nom) in QIDI_COLORS.items():
            r, g, b = (int(hexa[i:i + 2], 16) for i in (1, 3, 5))
            d = (r - rgb[0]) ** 2 + (g - rgb[1]) ** 2 + (b - rgb[2]) ** 2
            if distance is None or d < distance:
                meilleur, distance = num, d
        return meilleur
    cle = texte.lower()
    for num, (_hexa, nom) in QIDI_COLORS.items():
        if nom == cle:
            return num
    for num, (_hexa, nom) in QIDI_COLORS.items():
        if cle in nom:
            return num
    raise TagError("Couleur « %s » inconnue (1..24, voir --cli qidi-tables)" % texte)


def qidi_trouver_cle(conn, bloc=QIDI_BLOCK):
    for key_hex in QIDI_KEYS + [k for k, _l in CLASSIC_KEYS]:
        for keytype in ("A", "B"):
            try:
                classic_load_key(conn, key_hex)
            except TagError:
                continue
            if classic_auth(conn, bloc, keytype):
                return key_hex, keytype
    return None, None


def qidi_lire(conn):
    cle, keytype = qidi_trouver_cle(conn)
    if not cle:
        raise TagError("Aucune clé connue n'ouvre le secteur 1 (bloc 4) : "
                       "étiquette non QIDI, ou clé propriétaire.")
    donnees = classic_read_block(conn, QIDI_BLOCK)
    material, couleur, fabricant = donnees[0], donnees[1], donnees[2]
    return {
        "cle": cle, "type_cle": keytype,
        "material": material, "color": couleur, "fabricant": fabricant,
        "material_nom": QIDI_MATERIALS.get(material, "inconnu"),
        "color_hex": QIDI_COLORS.get(couleur, ("?", "?"))[0],
        "color_nom": QIDI_COLORS.get(couleur, ("?", "?"))[1],
        "brut": toHexString(donnees).replace(" ", ""),
        "vide": material == 0 and couleur == 0,
        "signature": bytes(donnees[12:16]) == b"QIDI",
    }


JEUX_CLES = {
    "d3f7": "D3F7D3F7D3F7",
    "ffff": "FFFFFFFFFFFF",
}


def qidi_ecrire(conn, material, couleur, fabricant=1, corriger_cles=False, signature=True):
    material = qidi_material_num(material)
    couleur = qidi_color_num(couleur)
    if not 0 <= int(fabricant) <= 255:
        raise TagError("Code fabricant hors 0..255")
    cle, keytype = qidi_trouver_cle(conn)
    if not cle:
        raise TagError("Aucune clé connue n'ouvre le secteur 1 (bloc 4).")
    # octets 0-2 : matériau, couleur, fabricant ; octets 3-11 : zéros ;
    # octets 12-15 : « QIDI » en ASCII sur les étiquettes de l'application Android
    charge = [material, couleur, int(fabricant)] + [0x00] * 9 + (list(b"QIDI") if signature else [0x00] * 4)
    classic_load_key(conn, cle)
    if not classic_auth(conn, QIDI_BLOCK, keytype):
        raise TagError("Authentification perdue avant écriture.")
    data, sw = xmit(conn, [0xFF, 0xD6, 0x00, QIDI_BLOCK, 0x10] + charge)
    if sw != SW_OK:
        raise TagError("Écriture du bloc 4 refusée (SW=%04X) — étiquette verrouillée ?" % sw)
    if corriger_cles:
        # trailer du secteur 1 : clés d'origine QIDI (D3F7) ou clés d'usine (FFFF)
        jeu = str(corriger_cles).lower()
        if jeu in ("true", "1", "d3f7"):
            jeu = "d3f7"
        elif jeu in ("ffff", "usine", "default"):
            jeu = "ffff"
        if jeu not in JEUX_CLES:
            raise TagError("Jeu de clés inconnu : %s (d3f7 ou ffff)" % corriger_cles)
        cle_trailer = bytes.fromhex(JEUX_CLES[jeu])
        trailer = list(cle_trailer) + [0xFF, 0x07, 0x80, 0x69] + list(cle_trailer)
        classic_load_key(conn, cle)
        if not classic_auth(conn, 7, keytype):
            raise TagError("Authentification perdue avant la correction des clés du secteur 1.")
        data, sw = xmit(conn, [0xFF, 0xD6, 0x00, 0x07, 0x10] + trailer)
        if sw != SW_OK:
            raise TagError("Réécriture du trailer du secteur 1 refusée (SW=%04X)" % sw)
    # relecture de contrôle
    cle2, _kt = qidi_trouver_cle(conn)
    if not cle2:
        raise TagError("Écriture faite mais secteur 1 devenu illisible : vérifier la clé.")
    controle = classic_read_block(conn, QIDI_BLOCK)
    return {"material": controle[0], "color": controle[1], "fabricant": controle[2],
            "cle_relue": cle2, "brut": toHexString(controle).replace(" ", "")}


def qidi_tables():
    lignes = ["Matériaux QIDI (code : nom) :"]
    for num in sorted(QIDI_MATERIALS):
        lignes.append("  %2d : %s" % (num, QIDI_MATERIALS[num]))
    lignes.append("")
    lignes.append("Couleurs QIDI (code : #hex : nom) :")
    for num in sorted(QIDI_COLORS):
        hexa, nom = QIDI_COLORS[num]
        lignes.append("  %2d : %s : %s" % (num, hexa, nom))
    return lignes


# ---------------------------------------------------------------- interface

def cli(argv):
    ap = argparse.ArgumentParser(prog="nfc-studio --cli")
    ap.add_argument("action", choices=["info", "dump", "classic", "qidi-read", "qidi-write", "qidi-tables",
                                       "write-text", "write-url", "erase", "readers"])
    ap.add_argument("value", nargs="?")
    ap.add_argument("--reader", default=None)
    ap.add_argument("--keys", default="", help="clés MIFARE Classic en plus, séparées par des virgules (12 hex)")
    ap.add_argument("--out", default=None, help="dossier de sauvegarde des vidages Classic")
    ap.add_argument("--material", default=None, help="matériau QIDI : numéro (1..50) ou nom (PLA, PETG-CF…)")
    ap.add_argument("--color", default=None, help="couleur QIDI : numéro (1..24), nom (rouge…) ou #RRGGBB")
    ap.add_argument("--manuf", default="1", help="code fabricant QIDI (défaut 1)")
    ap.add_argument("--no-signature", action="store_true",
                    help="ne pas écrire « QIDI » dans les octets 12-15 du bloc 4")
    ap.add_argument("--fix-keys", nargs="?", const="d3f7", default=None,
                    help="réécrit le trailer du secteur 1 : d3f7 (défaut) ou ffff")
    a = ap.parse_args(argv)

    if a.action == "qidi-tables":
        for ligne in qidi_tables():
            print(ligne)
        return 0

    if a.action == "readers":
        for i, r in enumerate(list_readers()):
            print("%d: %s" % (i, r))
        return 0

    extra = [k.strip() for k in a.keys.split(",") if k.strip()]
    reader, conn = connect(a.reader)
    print("Lecteur : %s" % reader)

    ident = classic_identify(conn)
    if ident:
        print("Type    : %s (SAK %s / ATQA %s)" % (ident["modele"], ident["sak_hex"], ident["atqa"]))
        print("UID     : %s" % ident["uid"])
        print("ATR     : %s" % toHexString(conn.getATR()))
        print("")
        if a.action == "qidi-read":
            info_q = qidi_lire(conn)
            if info_q["vide"]:
                print("Étiquette vierge (matériau 0, couleur 0) — clé %s %s" % (info_q["type_cle"], info_q["cle"]))
            else:
                print("Matériau    : %d — %s" % (info_q["material"], info_q["material_nom"]))
                print("Couleur     : %d — %s (%s)" % (info_q["color"], info_q["color_nom"], info_q["color_hex"]))
                print("Fabricant   : %d" % info_q["fabricant"])
                print("Clé secteur : %s %s" % (info_q["type_cle"], info_q["cle"]))
                print("Signature   : %s" % ("QIDI présente (octets 12-15)" if info_q["signature"]
                                             else "absente (zéros)"))
                print("Bloc 4 brut : %s" % info_q["brut"])
            return 0
        if a.action == "qidi-write":
            if a.material is None or a.color is None:
                raise TagError("Indiquer --material et --color (voir --cli qidi-tables)")
            res = qidi_ecrire(conn, a.material, a.color, a.manuf, a.fix_keys,
                              signature=not a.no_signature)
            print("Écrit : matériau %d (%s), couleur %d (%s), fabricant %d" % (
                res["material"], QIDI_MATERIALS.get(res["material"], "?"),
                res["color"], QIDI_COLORS.get(res["color"], ("?", "?"))[1], res["fabricant"]))
            print("Contrôle : bloc 4 = %s (clé %s)" % (res["brut"], res["cle_relue"]))
            return 0
        if a.action in ("classic", "info", "dump"):
            res = classic_dump(conn, extra)
            for line in classic_rapport(res):
                print(line)
            dossier = classic_sauvegarde(res, a.out)
            print("")
            print("Sauvegarde : %s" % dossier)
            print("  dump.json + dump.mfd (%d o) + rapport.txt + cles.txt" % res["tag"]["taille"])
            return 0
        raise TagError("Action « %s » sans objet sur une MIFARE Classic : utiliser « classic », "
                       "« qidi-read » ou « qidi-write »." % a.action)

    info = tag_info(conn)
    print("UID     : %s" % (info["uid"] or "?"))
    print("ATR     : %s" % info["atr"])
    print("Puce    : %s" % info["chip"])
    print("CC      : %s" % info["cc"])
    if info.get("capacity"):
        print("Capacité: %d o (%s)" % (info["capacity"], info.get("access")))

    if a.action == "info":
        msg, raw = read_ndef(conn, info.get("capacity") or 0)
        for line in describe_ndef(msg):
            print("NDEF    : %s" % line)
    elif a.action == "dump":
        for line in dump_pages(conn, info):
            print(line)
    elif a.action == "write-text":
        if not a.value:
            raise TagError("Texte manquant")
        do_write_text(conn, a.value, info)
        print("Écrit : texte « %s »" % a.value)
    elif a.action == "write-url":
        if not a.value:
            raise TagError("URL manquante")
        do_write_url(conn, a.value, info)
        print("Écrit : URL %s" % a.value)
    elif a.action == "erase":
        do_erase(conn, info)
        print("Message NDEF effacé")

    info = tag_info(conn)
    msg, _ = read_ndef(conn, info.get("capacity") or 0)
    if a.action != "dump":
        print("Contrôle: %s" % " | ".join(describe_ndef(msg)))
    return 0


def gui():
    import tkinter as tk
    from tkinter import messagebox, ttk

    # rendre Tk conscient du DPI : sans cela, à 150 % de mise à l'échelle une fenêtre
    # de 780 px logiques occupe 1 170 px physiques et dépasse un écran 1024x768
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001
        pass

    root = tk.Tk()
    root.title("NFC Studio — lecteur ACS ACR1552")
    root.geometry("900x640+0+0")

    try:
        ttk.Style().theme_use("breeze")
    except Exception:  # noqa: BLE001
        pass

    state = {"info": None, "conn": None, "classic": None}

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    ttk.Label(top, text="Lecteur :").grid(row=0, column=0, sticky="w")
    lbl_reader = ttk.Label(top, text="—")
    lbl_reader.grid(row=0, column=1, sticky="w")
    ttk.Label(top, text="Tag :").grid(row=1, column=0, sticky="w")
    lbl_tag = ttk.Label(top, text="—")
    lbl_tag.grid(row=1, column=1, sticky="w")

    btns = ttk.Frame(root, padding=(8, 0))
    btns.pack(fill="x")

    log = tk.Text(root, height=6, wrap="word")
    log.pack(fill="both", expand=True, padx=8, pady=8)

    def say(msg, clear=False):
        if clear:
            log.delete("1.0", "end")
        log.insert("end", msg + "\n")
        log.see("end")
        root.update_idletasks()

    def refresh(read=True):
        try:
            reader, conn = connect()
        except TagError as e:
            lbl_reader.config(text="—")
            lbl_tag.config(text="aucun tag")
            state["info"] = None
            state["classic"] = None
            say(str(e), clear=True)
            return None
        ident = classic_identify(conn)
        state["classic"] = ident
        if ident:
            state["info"] = None
            lbl_reader.config(text=str(reader))
            lbl_tag.config(text="%s · UID %s" % (ident["modele"], ident["uid"]))
            say("Tag %s — UID %s" % (ident["modele"], ident["uid"]), clear=True)
            say("MIFARE Classic : bouton « Classic : vidage + sauvegarde » (pas de NDEF ici).")
            # Le remplissage automatique n'a lieu que sur une LECTURE (read=True).
            # Sur un chemin d'écriture (read=False) il écraserait la sélection en cours.
            hook = state.get("sur_classic")
            if hook and read:
                hook(conn)
            return conn
        info = tag_info(conn)
        state["info"] = info
        lbl_reader.config(text=str(reader))
        lbl_tag.config(text="%s · UID %s" % (info["chip"], info["uid"]))
        say("Tag %s — UID %s" % (info["chip"], info["uid"]), clear=True)
        if info.get("capacity"):
            say("Capacité NDEF : %d o (%s)" % (info["capacity"], info["access"]))
        if read:
            msg, _ = read_ndef(conn, info.get("capacity") or 0)
            for line in describe_ndef(msg):
                say("NDEF : " + line)
        return conn

    def on_read():
        try:
            refresh(read=True)
        except TagError as e:
            say(str(e))

    def on_dump():
        try:
            conn = refresh(read=False)
            if conn:
                for line in dump_pages(conn, state["info"]):
                    say(line)
        except TagError as e:
            say(str(e))

    def on_write_text():
        txt = ent_text.get()
        if not txt:
            messagebox.showinfo("NFC Studio", "Saisir un texte à écrire.")
            return
        try:
            conn = refresh(read=False)
            if not conn:
                return
            do_write_text(conn, txt, state["info"])
            say("Écrit : texte « %s »" % txt)
            refresh(read=True)
        except TagError as e:
            say("ERREUR : %s" % e)

    def on_write_url():
        url = ent_url.get()
        if not url:
            messagebox.showinfo("NFC Studio", "Saisir une URL à écrire.")
            return
        try:
            conn = refresh(read=False)
            if not conn:
                return
            do_write_url(conn, url, state["info"])
            say("Écrit : URL %s" % url)
            refresh(read=True)
        except TagError as e:
            say("ERREUR : %s" % e)

    def on_erase():
        try:
            conn = refresh(read=False)
            if not conn:
                return
            do_erase(conn, state["info"])
            say("Message NDEF effacé.")
            refresh(read=True)
        except TagError as e:
            say("ERREUR : %s" % e)

    def on_classic():
        try:
            conn = refresh(read=False)
            if not conn:
                return
            if not state.get("classic"):
                say("Ce tag n'est pas une MIFARE Classic lisible.")
                return
            res = classic_dump(conn)
            for line in classic_rapport(res):
                say(line)
            dossier = classic_sauvegarde(res)
            say("")
            say("Sauvegarde : %s" % dossier)
            say("  dump.json + dump.mfd (%d o) + rapport.txt + cles.txt" % res["tag"]["taille"])
        except TagError as e:
            say("ERREUR : %s" % e)

    ttk.Button(btns, text="Lire le tag", command=on_read).grid(row=0, column=0, padx=4, pady=4)
    ttk.Button(btns, text="Vidage mémoire", command=on_dump).grid(row=0, column=1, padx=4)
    ttk.Button(btns, text="Effacer le NDEF", command=on_erase).grid(row=0, column=2, padx=4)
    ttk.Button(btns, text="Classic : vidage + sauvegarde", command=on_classic).grid(row=1, column=0, padx=4, pady=4, sticky="w")

    form = ttk.Frame(root, padding=(8, 4))
    form.pack(fill="x")
    ttk.Label(form, text="Texte :").grid(row=0, column=0, sticky="w")
    ent_text = ttk.Entry(form, width=48)
    ent_text.grid(row=0, column=1, sticky="we", padx=4, pady=2)
    ttk.Button(form, text="Écrire ce texte", command=on_write_text).grid(row=0, column=2, padx=4)
    ttk.Label(form, text="URL :").grid(row=1, column=0, sticky="w")
    ent_url = ttk.Entry(form, width=48)
    ent_url.grid(row=1, column=1, sticky="we", padx=4, pady=2)
    ttk.Button(form, text="Écrire cette URL", command=on_write_url).grid(row=1, column=2, padx=4)
    form.columnconfigure(1, weight=1)

    # ------------------------------------------------- étiquettes QIDI (ergonomique)
    libelles_mat = ["%02d · %s" % (n, QIDI_MATERIALS[n]) for n in sorted(QIDI_MATERIALS)]
    libelles_col = ["%02d · %s  %s" % (n, QIDI_COLORS[n][1], QIDI_COLORS[n][0]) for n in sorted(QIDI_COLORS)]
    MANUFACTURIERS = {0: "Générique", 1: "QIDI"}
    libelles_man = ["%d · %s" % (n, MANUFACTURIERS[n]) for n in (1, 0)]

    qidi = ttk.LabelFrame(root, text="Étiquette QIDI Box — secteur 1, bloc 4", padding=8)
    qidi.pack(fill="x", padx=8, pady=(0, 8), before=log)

    ttk.Label(qidi, text="Matériau :").grid(row=0, column=0, sticky="w")
    cb_mat = ttk.Combobox(qidi, values=libelles_mat, state="readonly", width=22,
                          height=min(len(libelles_mat), 22))
    cb_mat.grid(row=0, column=1, padx=4, sticky="w")

    ttk.Label(qidi, text="Couleur :").grid(row=0, column=2, sticky="w")
    cb_col = ttk.Combobox(qidi, values=libelles_col, state="readonly", width=24,
                          height=min(len(libelles_col), 22))
    cb_col.grid(row=0, column=3, padx=4, sticky="w")
    pastille = tk.Label(qidi, text="", width=3, bg="#FFFFFF", relief="solid", bd=1)
    pastille.grid(row=0, column=4, padx=(0, 6))

    ttk.Label(qidi, text="Fabricant :").grid(row=1, column=0, sticky="w", pady=(6, 0))
    cb_man = ttk.Combobox(qidi, values=libelles_man, state="readonly", width=16)
    cb_man.grid(row=1, column=1, padx=4, sticky="w", pady=(6, 0))

    ttk.Label(qidi, text="Couleur mesurée :").grid(row=1, column=2, sticky="w", pady=(6, 0))
    ent_hex = ttk.Entry(qidi, width=10)
    ent_hex.grid(row=1, column=3, padx=4, sticky="w", pady=(6, 0))
    ttk.Button(qidi, text="la plus proche",
               command=lambda: choisir_couleur_proche()).grid(row=1, column=4, sticky="w", pady=(6, 0))

    apercu = ttk.Label(qidi, text="Bloc 4 : —", font=("TkDefaultFont", 9))
    apercu.grid(row=2, column=0, columnspan=5, sticky="w", pady=(8, 0))

    def num_mat():
        texte = cb_mat.get()
        return int(texte.split(" · ")[0]) if texte else None

    def num_col():
        texte = cb_col.get()
        return int(texte.split(" · ")[0]) if texte else None

    def num_man():
        texte = cb_man.get()
        return int(texte.split(" · ")[0]) if texte else 1

    def selection_changee(_e=None):
        """Journalise la sélection réelle : un clic à côté se voit immédiatement."""
        say("Sélection : %s · %s · %s" % (cb_mat.get(), cb_col.get(), cb_man.get()))
        maj_apercu()

    def maj_apercu(*_a):
        c = num_col()
        if c:
            pastille.config(bg=QIDI_COLORS[c][0])
        m = num_mat()
        if m is None or c is None:
            apercu.config(text="Bloc 4 : —")
            return
        fin = list(b"QIDI") if var_signature.get() else [0x00] * 4
        bloc = bytes([m, c, num_man()] + [0x00] * 9 + fin).hex(" ")
        apercu.config(text="Bloc 4 : %s" % bloc)
        sauver_reglages(m, c, num_man())

    def sauver_reglages(m, c, man):
        import json, os
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "reglages-qidi.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"material": m, "color": c, "fabricant": man}, f)
        except OSError:
            pass

    def charger_reglages():
        import json, os
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "reglages-qidi.json"),
                      encoding="utf-8") as f:
                r = json.load(f)
        except (OSError, ValueError):
            r = {"material": 1, "color": 1, "fabricant": 1}
        r["fabricant"] = r.get("fabricant", 1)
        if r["fabricant"] not in MANUFACTURIERS:
            r["fabricant"] = 1
        cb_mat.set("%02d · %s" % (r["material"], QIDI_MATERIALS.get(r["material"], "?")))
        cb_col.set("%02d · %s  %s" % (r["color"], QIDI_COLORS[r["color"]][1], QIDI_COLORS[r["color"]][0]))
        cb_man.set("%d · %s" % (r["fabricant"], MANUFACTURIERS.get(r["fabricant"], "?")))
        maj_apercu()

    def choisir_couleur_proche():
        texte = ent_hex.get().strip()
        if not texte:
            return
        try:
            n = qidi_color_num(texte)
        except TagError as e:
            say("ERREUR : %s" % e)
            return
        cb_col.set("%02d · %s  %s" % (n, QIDI_COLORS[n][1], QIDI_COLORS[n][0]))
        maj_apercu()

    def on_qidi_read():
        try:
            conn = refresh(read=False)
            if not conn:
                return
            q = qidi_lire(conn)
            if q["vide"]:
                say("Étiquette QIDI vierge (matériau 0, couleur 0) — clé %s %s" % (q["type_cle"], q["cle"]))
                return
            say("QIDI : matériau %d (%s) · couleur %d (%s, %s) · fabricant %d · clé %s %s" % (
                q["material"], q["material_nom"], q["color"], q["color_nom"], q["color_hex"],
                q["fabricant"], q["type_cle"], q["cle"]))
            say("Bloc 4 : %s — signature %s" % (q["brut"], "QIDI" if q["signature"] else "absente"))
            if q["material"] in QIDI_MATERIALS:
                cb_mat.set("%02d · %s" % (q["material"], QIDI_MATERIALS[q["material"]]))
            if q["color"] in QIDI_COLORS:
                cb_col.set("%02d · %s  %s" % (q["color"], QIDI_COLORS[q["color"]][1], QIDI_COLORS[q["color"]][0]))
            cb_man.set("%d · %s" % (q["fabricant"], MANUFACTURIERS.get(q["fabricant"], "inconnu")))
            maj_apercu()
        except TagError as e:
            say("ERREUR : %s" % e)

    def ecrire_qidi(fix_keys):
        m, c, man = num_mat(), num_col(), num_man()
        if m is None or c is None:
            say("Choisir un matériau et une couleur dans les listes.")
            return
        try:
            conn = refresh(read=False)
            if not conn:
                return
            # contrôle : la sélection ne doit pas avoir bougé pendant la connexion
            if (num_mat(), num_col(), num_man()) != (m, c, man):
                say("La sélection a changé pendant la connexion — écriture annulée, relancer.")
                return
            say("Demande : %s / %s / fabricant %s" % (cb_mat.get(), cb_col.get(), cb_man.get()))
            res = qidi_ecrire(conn, m, c, man, fix_keys, signature=var_signature.get())
            if (res["material"], res["color"], res["fabricant"]) != (m, c, man):
                say("INCOHÉRENCE : relu %d/%d/%d alors que la demande était %d/%d/%d" % (
                    res["material"], res["color"], res["fabricant"], m, c, man))
            say("QIDI écrit : %d (%s) · %d (%s) · fabricant %d — contrôle : %s" % (
                res["material"], QIDI_MATERIALS.get(res["material"], "?"),
                res["color"], QIDI_COLORS.get(res["color"], ("?", "?"))[1],
                res["fabricant"], res["brut"]))
            if fix_keys:
                say("Trailer du secteur 1 réécrit (jeu de clés %s)." % fix_keys)
        except TagError as e:
            say("ERREUR : %s" % e)

    btns_qidi = ttk.Frame(qidi)
    btns_qidi.grid(row=3, column=0, columnspan=5, sticky="w", pady=(8, 0))
    var_signature = tk.BooleanVar(master=root, value=True)
    ttk.Checkbutton(btns_qidi, text="signer « QIDI » (octets 12-15)", variable=var_signature,
                    command=maj_apercu).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
    ttk.Button(btns_qidi, text="Lire l'étiquette", command=on_qidi_read).grid(row=0, column=0, padx=(0, 6))
    ttk.Button(btns_qidi, text="Écrire", command=lambda: ecrire_qidi(False)).grid(row=0, column=1, padx=(0, 6))
    ttk.Button(btns_qidi, text="Écrire + clés FFFF", command=lambda: ecrire_qidi("ffff")).grid(row=0, column=2)
    ttk.Button(btns_qidi, text="+ clés D3F7", command=lambda: ecrire_qidi("d3f7")).grid(row=0, column=3, padx=(6, 0))

    def auto_remplir(conn):
        """Remplit les listes avec ce que contient réellement l'étiquette posée."""
        try:
            q = qidi_lire(conn)
        except TagError:
            return
        if q["vide"]:
            say("Étiquette QIDI vierge — choisir matériau et couleur puis « Écrire ».")
            return
        if q["material"] in QIDI_MATERIALS:
            cb_mat.set("%02d · %s" % (q["material"], QIDI_MATERIALS[q["material"]]))
        if q["color"] in QIDI_COLORS:
            cb_col.set("%02d · %s  %s" % (q["color"], QIDI_COLORS[q["color"]][1], QIDI_COLORS[q["color"]][0]))
        cb_man.set("%d · %s" % (q["fabricant"], MANUFACTURIERS.get(q["fabricant"], "inconnu")))
        maj_apercu()
        say("Contenu actuel : %s · %s · fabricant %d (clé %s)" % (
            q["material_nom"], q["color_nom"], q["fabricant"], q["cle"]))

    state["sur_classic"] = auto_remplir
    for widget in (cb_mat, cb_col, cb_man):
        widget.bind("<<ComboboxSelected>>", selection_changee)
    charger_reglages()

    def taille_ecran():
        """Taille reelle de l'ecran maintenant (winfo reste fige apres un changement RDP)."""
        try:
            import ctypes
            l = ctypes.windll.user32.GetSystemMetrics(0)
            h = ctypes.windll.user32.GetSystemMetrics(1)
            if l > 0 and h > 0:
                return l, h
        except Exception:  # noqa: BLE001
            pass
        return root.winfo_screenwidth(), root.winfo_screenheight()

    def ajuster_fenetre():
        root.update_idletasks()
        ecran_l, ecran_h = taille_ecran()
        larg = min(1000, max(700, ecran_l - 16))
        haut = min(700, max(500, ecran_h - 62))
        root.geometry("%dx%d+0+0" % (larg, haut))
        root.update_idletasks()
        try:
            import os
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui-diagnostic.txt"), "w",
                      encoding="utf-8") as f:
                f.write("ecran %dx%d\n" % (ecran_l, ecran_h))
                f.write("fenetre demandee %dx%d\n" % (larg, haut))
                f.write("fenetre reelle %dx%d a %d,%d\n" % (root.winfo_width(), root.winfo_height(),
                                                             root.winfo_x(), root.winfo_y()))
                f.write("requis %dx%d\n" % (root.winfo_reqwidth(), root.winfo_reqheight()))
        except OSError:
            pass

    say("Lecteurs détectés : " + (", ".join(list_readers()) or "aucun"))
    def surveiller_ecran():
        """La resolution change (RDP, VM) : recaler la fenetre si elle deborde."""
        try:
            el, eh = taille_ecran()
            if (root.winfo_x() + root.winfo_width() > el - 4
                    or root.winfo_y() + root.winfo_height() > eh - 62):
                ajuster_fenetre()
        except Exception:  # noqa: BLE001
            pass
        root.after(2000, surveiller_ecran)

    ajuster_fenetre()
    root.after(2500, surveiller_ecran)
    root.after(200, on_read)
    root.mainloop()
    return 0


def main():
    if "--cli" in sys.argv:
        argv = [a for a in sys.argv[1:] if a != "--cli"]
        try:
            return cli(argv)
        except TagError as e:
            print("ERREUR : %s" % e, file=sys.stderr)
            return 2
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            return 3
    try:
        return gui()
    except TagError as e:
        print("ERREUR : %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
