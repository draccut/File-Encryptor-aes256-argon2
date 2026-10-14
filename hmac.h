#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>

/**
 * Berechnet den HMAC-SHA256 über einen Speicherbereich.
 *
 * Verknüpft die Daten kryptografisch mit einem geheimen MAC-Schlüssel,
 * um Manipulationen im Nachgang manipulationssicher zu erkennen.
 *
 * @param[in]  key       Zeiger auf den geheimen HMAC-Schlüssel.
 * @param[in]  key_len   Länge des Schlüssels (für dieses Setup MAC_LEN / 32 Bytes).
 * @param[in]  data      Zeiger auf den zu validierenden Datenbereich.
 * @param[in]  data_len  Länge des Datenbereichs in Bytes.
 * @param[out] hmac_out  Zielpuffer für das Ergebnis (mindestens 32 Bytes).
 */
void compute_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *hmac_out);

/**
 * Leitet einen kombinierten 64-Byte-Schlüssel mittels Argon2id ab.
 *
 * Speziell für das Encrypt-then-MAC-Verfahren, um parallel einen 32-Byte-AES-
 * und einen 32-Byte-HMAC-Schlüssel aus demselben Passwort zu generieren.
 *
 * @param[in]  password        Das Benutzerpasswort im Klartext.
 * @param[in]  pwd_len         Die Länge des Passworts in Bytes.
 * @param[in]  salt            Zeiger auf den 16-Byte-Salt-Puffer.
 * @param[out] master_key_out  Zielpuffer für den 64-Byte-Gesamtschlüssel.
 *
 * @return Gibt ARGON2_OK (0) bei Erfolg zurück, andernfalls einen Argon2-Fehlercode.
 */
int derive_keys_64b(const char *password, size_t pwd_len,
                    const uint8_t *salt, uint8_t *master_key_out);

#endif
