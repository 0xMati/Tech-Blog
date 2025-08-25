# Entra ID Password Protection – Logic for Normalization, Substitutions, Variants, and Phonetic Matching
🗓️ Published: 2025-08-07

Entra ID Password Protection evaluates passwords not only by their complexity (length, character types) but also by how closely they match known weak passwords or user-defined banned terms, even when obfuscated. The evaluation includes normalization, tokenization, substitutions, and phonetic analysis.

## 1. Visual Character Substitutions (Leetspeak Normalization)

The engine detects common character substitutions used to disguise banned words. These mappings are automatically normalized before evaluation.

**Examples:**  
- `P@ssw0rd` becomes `password`  
- `M1cr0$0ft` becomes `microsoft`

| Original Character | Recognized Substitutions |
|--------------------|--------------------------|
| a                  | @, 4                     |
| b                  | 8                        |
| e                  | 3                        |
| g                  | 9                        |
| i                  | 1, !, l                  |
| l                  | 1, i                     |
| o                  | 0                        |
| s                  | 5, $                     |
| t                  | 7                        |
| z                  | 2                        |

## 2. Case and Diacritics Normalization

- All characters are converted to lowercase.
- Accented or special characters are replaced with their closest base equivalents:

| Accented Characters | Normalized Form |
|---------------------|------------------|
| é, è, ê, ë          | e                |
| ç                   | c                |
| ï                   | i                |
| ñ                   | n                |

## 3. Tokenization

Passwords are split into discrete tokens to better detect embedded banned words. This process uses:

- Case transitions  
- Character class transitions (e.g., letter → number)  
- Separators like `-`, `_`, `@`, `!`, etc.  
- Pattern matches like years, brands, or known strings

**Examples:**  
- `Az!r3@D-2025` → `az`, `re`, `ad`, `2025`  
- `M1cro$oftSecu!23` → `micro`, `soft`, `secu`, `23`

## 4. Fuzzy and Partial Matching

Matching does not require an exact string match. The system detects:

- Normalized matches (e.g., `P@ssw0rd` → `password`)  
- Prefix/suffix patterns (`admin123`, `123admin`)  
- Embedded tokens (`MyEntraMicrosoft2024` → `Entra`, `microsoft`)  
- Partial substring matches (`spring2025` → `spring`)

## 5. Phonetic Matching (Sound-Alike Detection)

The system applies phonetic evaluation (similar to Soundex/Metaphone) to detect sound-alike variations of banned words.

**Examples:**  
- `Tr0ub4dor` → `troubadour`  
- `SeQur1ty` → `security`  
- `Adm1n1str8r` → `administrator`

## 6. Pattern-Based Heuristics

Passwords are rejected if they match risky structures, even without directly containing a banned word:

- Common name + year (`Mathias2025`, `Company2024`)  
- Welcome phrases (`Hello123`, `Welcome@1`)  
- Common tech terms (`Login!Secure`, `Support2023`)  
- Repeating patterns (`aaaBBB111!`, `QwertyQwerty`)  
- Similarity to usernames or tenant names

## 7. Implicitly Banned Words and Patterns

Microsoft maintains a dynamic global banned password list that includes:

- Common passwords: `password`, `admin`, `123456`, `letmein`, etc.  
- Seasons and months: `spring`, `summer`, `january`, `mars`, etc.  
- Brands and services: `microsoft`, `google`, `Entra`  
- Years and formats: `2024`, `FY25`, `Q1`, etc.  
- Variants and substitutions of all of the above

## 8. Evaluation Outcome and Threshold

Each password receives a score based on:

- Number of matched tokens  
- Type of match (exact, normalized, phonetic)  
- Overall entropy and complexity

If the score is below an internal threshold, the password is rejected.
