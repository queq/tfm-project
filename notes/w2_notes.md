<h1>Data sources</h1>

- [PhishTank](#phishtank)
- [OpenPhish](#openphish)
  - [Community tier](#community-tier)
  - [Premium tier](#premium-tier)
- [Phishing Websites - UCI Machine Learning Repository](#phishing-websites---uci-machine-learning-repository)
- [CheckPhish](#checkphish)
- [Misc. feeds](#misc-feeds)
- [Previous comparison](#previous-comparison)


# [PhishTank](https://www.phishtank.com/)

- Connection type: HTTP request (capped anonymous access, sign up disabled until further notice).
- Update rate: Hourly, though according to new manual user input.
- Volume: ~57k websites.

| Column name | Data type | Description |
| ----------- | --------- | ----------- |
| `phish_id` | `integer` | The ID number by which Phishtank refers to a phish submission. All data in PhishTank is tied to this ID. This will always be a positive integer. |
| `phish_detail_url` | `text` | PhishTank detail url for the phish, where you can view data about the phish, including a screenshot and the community votes. |
| `url` | `text` | The phish URL. This is always a string, and in the XML feeds may be a CDATA block. |
| `submission_time` | `timestamp` | The date and time at which this phish was reported to Phishtank. This is an ISO 8601 formatted date. |
| `verified` | `boolean` (yes/no) | Whether or not this phish has been verified by our community. In these data files, this will always be the string 'yes' since we only supply verified phishes in these files. |
| `verification_time` | `timestamp` | The date and time at which the phish was verified as valid by our community. This is an ISO 8601 formatted date. |
| `online` | `boolean` (yes/no) | Whether or not the phish is online and operational. In these data files, this will always be the string 'yes' since we only supply online phishes in these files. |
| `target` | `text` | The name of the company or brand the phish is impersonating, if it's known. |
| `details` | `array[]` | Networking details such as IP address/CIDR block. |

# [OpenPhish](https://openphish.com/)

- Connection type: Different tiers of access (all given by request). Mainly by HTTP request for downloading a whole file feed.
- Update rate: 12 hours (Community).
- Volume: 500 websites (Community). 3 websites (Premium sample).

## Community tier

| Column name | Data type | Description    |
| ----------- | --------- | -------------- |
| `url`       | `text`    | The phish URL. |

## Premium tier

| Column name | Data type | Description    |
| ----------- | --------- | -------------- |
| `sector`    | `text`    | Affected brand sector. |
| `url`       | `text`    | The phish URL. |
| `ip`        | `text`    | Origin IP address |
| `brand`     | `text`    | Affected brand name, if any. |
| `isotime`   | `text`    | TBC |
| `asn_name`  | `text`    | ASN name. |
| `discover_time` | `timestamp`    | Timestamp of discovery. |
| `asn`       | `text`    | [Autonomous System Number](https://www.cloudflare.com/learning/network-layer/what-is-an-autonomous-system/). |
| `family_id` | `text`    | TBC |
| `host`      | `text`    | Host name(?). |
| `country_code` | `text`    | Country code of origin. |
| `tld`       | `text`    | Top-level domain |
| `country_name` | `text`    | Origin country. |

# [Phishing Websites - UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/327/phishing+websites)

- Connection type: HTTP request for downloading a whole static dataset.
- Update rate: N/A (static since 2012).
- Volume: ~11k websites.

| Column name | Data type | Description |
| ----------- | --------- | ----------- |
| `having_ip_address` | `integer` | Does the URL contain an IP address instead of domain? |
| `url_length` | `integer` | URL length. |
| `shortening_service` | `integer` | Does the URL use a shortening service? |
| `having_at_symbol` | `integer` | Does the URL contain an `@` symbol? |
| `double_slash_redirecting` | `integer` | Does the URL contain double slashes after pos. 7? |
| `prefix_suffix` | `integer` | Does the URL contain a dash? |
| `having_sub_domain` | `integer` | Does the URL contain more than 1 dot? |
| `sslfinal_state` | `integer` | Does the URL use https and issuer is trusted and age of certificate is less than a year? |
| `domain_registration_length` | `integer` | Will the domain expire in less than a year? |
| `favicon` | `integer` | Is the favicon loaded from an external domain? |
| `port` | `integer` | Does the website use a non-standard port? |
| `https_token` | `integer` | Does the `https` token appear in the domain name? |
| `request_url` | `integer` | Do the objects contained in the website load from external origins? |
| `url_of_anchor` | `integer` | Do the `<a>` tags inside the website lead to an external website or anchors? |
| `links_in_tags` | `integer` | Does the website include `<meta>` tags? |
| `sfh` | `integer` | Do the server form handlers lead to an external website or `about:blank`? |
| `submitting_to_email` | `integer` | Does form submitting use `mail()` PHP function or `mailto:` links ?|
| `abnormal_url` | `integer` | Is the host name not included in the URL? |
| `redirect` | `integer` | Has the website been redirected more than 4 times? |
| `on_mouseover` | `integer` | Do onmouseover events change the status bar? |
| `rightclick` | `integer` | Is right click disabled in the website? |
| `popupwindow` | `integer` | Do popup windows contain text fields? |
| `iframe` | `integer` | Does the website use iframes? |
| `age_of_domain` | `integer` | Is the domain age less than 6 months? |
| `dnsrecord` | `integer` | Are there no DNS records for the domain? |
| `web_traffic` | `integer` | Is the website rank less than 100,000? |
| `page_rank` | `integer` | Is the page rank less than 0.2? |
| `google_index` | `integer` | Is the webpage not indexed by Google? |
| `links_pointing_to_page` | `integer` | Are there no links pointing to the webpage? |
| `statistical_report` | `integer` | Does the host belong to top phishing IPs or top phishing domains? |

# [CheckPhish](https://checkphish.bolster.ai/)

- Connection type: API query for scanning single websites (quick and full scan modes). Limited to 25 scans/day and 250 scans/month on the free plan. Mentions that bulk scans are possible but they don't explain how.
- Update rate: Real-time (TBC). By querying a website, an engine is triggered, which evaluates the website, DOM, WHOIS and other kinds of information.
- Volume: ~1B websites.

| Column name | Data type | Description |
| ----------- | --------- | ----------- |
| `jobID` | `uuid` | jobID of the scan |
| `status` | `text` |  Status of whether the job has completed. Returns DONE when completed |
| `url` | `text` | URL submitted for scanning |
| `url_sha256` | `text` | SHA256 of the url submitted for scanning |
| `brand` | `text` | Brand being targeted by the URL |
| `insights` | `text` | insights link |
| `resolved` | `boolean` | True if the URL resolved. Else False |
| `screenshot_path` | `text` | storage location of the screenshot for the scan |
| `disposition` | `text` | the list of dispositions can be found below |
| `scan_start_ts` | `integer` | Unix Timestamp of when the scan the triggered |
| `scan_end_ts` | `integer` | Unix Timestamp of when the scan ended |
| `categories` | `array[]` | List of categories from our webpage category detection model |

# Misc. feeds

- ✅ [Cloudfare Radar](https://radar.cloudflare.com/)
- ✅ [Web Filter](https://www.fortiguard.com/webfilter)
- [Google Safe Browsing search](https://transparencyreport.google.com/safe-browsing/search)
- [Kaspersky TI Portal](https://opentip.kaspersky.com/)
- [Palo Alto URL Filtering](https://urlfiltering.paloaltonetworks.com/)
- [Norton Safe Web](https://safeweb.norton.com/)
- ✅ [Cisco Talos Intelligence](https://talosintelligence.com/)
- ✅ [urlscan.io](https://urlscan.io/)
- [ZScaler Zulu URL Risk Analyzer](https://zulu.zscaler.com/)
- ✅✅ [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database?tab=readme-ov-file)
- [LevelBlue Open Threat Exchange](https://otx.alienvault.com/)
- [PhishStats](https://phishstats.info/)

# Previous comparison

![Feed data comparison](https://bolster.ai/wp-content/uploads/2023/10/Screenshot-2023-06-06-at-4.13.46-PM.png)
Source: [Compare the Top 8 Open Source Phishing Threat Intel Feeds (bolster.ai)](https://bolster.ai/blog/phishing-threat-intelligence)