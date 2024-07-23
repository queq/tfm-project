# Corpus features

| Class | Sample count | % of total |
| ----- | ------------ | ---------- |
| `legitimate` | 1241079 | 50% |
| `phishing` | 1241079 | 50% |
| **Total** | **2482158** | **100%**|

<br>

| #  | Feature name | Description | Data type |
| -- | ------------ | ----------- | --------- |
| 0 | `url` | Plain URL | `string` |
|  1 | `url_length` | Length of URL in characters | `int` |
|  2 | `starts_with_ip` | Does the URL use IP address instead of domain? | `bool` |
|  3 | `url_entropy` | Entropy of characters in URL | `float` |
|  4 | `has_punycode` | Does the URL contain punycode characters? | `bool` |
|  5 | `digit_letter_ratio` | Digit count / Letter count | `float` |
|  6 | `dot_count` | Count of `.` occurrences within URL | `int` |
|  7 | `at_count` | Count of `@` occurrences within URL | `int` |
|  8 | `dash_count` | Count of `-` occurrences within URL | `int` |
|  9 | `tld_count` | Count of TLD occurrences within URL (not including the domain itself) | `int` |
| 10 | `domain_has_digits` | Does the domain name contain digits? | `bool` |
| 11 | `domain_age_days` | Domain age in days, according to WHOIS | `int` |
| 12 | `subdomain_count` | Count of subdomain levels  | `int` |
| 13 | `nan_char_entropy` | Entropy of non-alphanumeric characters | `float` |
| 14 | `has_internal_links` | Does the URL feature additional URLs in the subdirectory? | `float` |