# File-Encryptor-aes256-argon2

Eine standalone C-Implementierung zur Datei-Verschlüsselung: AES256, Argon2, SHA256, HMAC

----

## Projektbegründung

In der Softwareentwicklung neigen Kryptographie-Bibliotheken dazu, monolithisch und unüberschaubar zu werden. Große Codebasen erhöhen die Angriffsfläche für Sicherheitslücken und erschweren unabhängige Quellcode-Audits.

Keine umfangreichen externen Abhängigkeiten. Das Kernprojekt besteht ausschließlich aus den Quelldateien main.c und hmac.c der Rest ist nicht von mir.

Trotz der geringen Größe kommen bei den Krypto-Verfahren und beim Binary-Hardening etablierte Standards zum Einsatz. Ein vollständiges Audit des Quellcodes ist mit minimalem Zeitaufwand möglich.

----

## Kryptographische Verfahren

Das System schützt Daten durch eine mehrschichtige Verteidigungsarchitektur:

1. Schlüsselableitung (Key Derivation):
   * Argon2id (PHC-Winner): Verhindert GPU- und ASIC-basierte Brute-Force-Angriffe auf Passwörter durch konfigurierbaren Zeit- und Speicheraufwand.
   * Key-Splitting: Es wird ein 64-Byte-Masterkey generiert, der strikt in einen 32-Byte-Schlüssel für AES und einen 32-Byte-Schlüssel für den HMAC aufgeteilt wird.

2. Verschlüsselung (Confidentiality):
   * AES-256-CBC: Symmetrische Verschlüsselung mit einer Blockgröße von 16 Bytes und kryptographisch sicheren, zufälligen IVs aus /dev/urandom für jeden einzelnen Vorgang.

3. Integritätsschutz (Authenticity):
   * Encrypt-then-MAC (EtM): Ein HMAC-SHA256 sichert die Datei von außen ab. Die Gültigkeit der Daten wird überprüft, bevor die AES-Entschlüsselung startet. Dies eliminiert das Risiko von Padding-Oracle-Angriffen vollständig.
   * Redundante Sicherung: Ein zusätzlicher innerer Klartext-SHA256-Hash validiert die Daten nach der Entschlüsselung als Ende-zu-Ende-Prüfung.

----

## Binäres Datei-Layout (Zwiebel)

Die verschlüsselte Datei wird nach der Generierung im folgenden Layout auf das Speichermedium geschrieben:

| Innen           | +             | +                | +                    | +               |
| ---             | ---           | ---              | ---                  | ---             |
│ 16 Bytes Salt   │ 16 Bytes IV   │ AES-Ciphertext   │ 32 Bytes SHA-256     │ 32 Bytes HMAC   │

----


## Binary Hardening (Sicherheit auf OS-Ebene)

Der Kompilierungsprozess nutzt restriktive Compiler-Flags, um Angriffe zur Laufzeit effektiv zu blockieren:
* -fstack-protector-strong: Schutz gegen Stack Buffer Overflows.
* -fPIE / -pie: Aktiviert positionsunabhängigen Code zur optimalen Nutzung von ASLR (Address Space Layout Randomization).
* -Wl,-z,relro,-z,now: Setzt die Global Offset Table (GOT) auf Read-Only, um GOT-Overwrite-Angriffe zu verhindern.
* -Wl,-z,noexecstack: Deklariert den Stack als nicht-ausführbar (verhindert Code-Execution auf dem Stack).

----

## Integrierte Unit-Tests

Das Projekt verfügt über eine autarke Test-Suite, die direkt im Quellcode integriert ist und über das Makro -D_TEST aktiviert werden kann.

Getestete Kernkomponenten:
* test_random_bytes_unique: Validiert die Einzigartigkeit und Entropie des System-Zufallsgenerators.
* test_write_read_file: Prüft den fehlerfreien Binär-Rundlauf beim Schreiben und Lesen von Dateien auf dem Dateisystem.
* test_encrypt_decrypt_roundtrip: Führt eine vollständige Ende-zu-Ende-Verschlüsselung und anschließende Entschlüsselung durch. Verifiziert die Bit-Integrität (XOR-Gleichheit), das PKCS#7-Padding, die zeitkonstanten Vergleiche (equals) sowie die HMAC-Validierung.

---

## CLI-Nutzung

### Kompilieren
```bash
nix-shell
make test
make clean
make
```

### Befehle
* Verschlüsseln: `./AES256 e <passwort> <datei>`
* Entschlüsseln: `./AES256 d <passwort> <datei>`

