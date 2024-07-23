"""
functions - WIP
"""

import time
import os
import logging

from collections import Counter
from math import log, ceil
from typing import Pattern
from datetime import date, datetime, timezone
from dateparser.search import search_dates


from retry import retry
import regex
import tldextract
import whois
import pandas as pd
import numpy as np

RETRY_DELAY_SECONDS = .3
logging.basicConfig()

def to_datetime(d: np.datetime64):
    """
    Converts a numpy datetime64 object to a python datetime object.
    Source:
    https://gist.github.com/blaylockbk/1677b446bc741ee2db3e943ab7e4cabd?permalink_comment_id=3775327
    Input:
      date - a np.datetime64 object
    Output:
      DATE - a python datetime object
    """
    timestamp = ((d - np.datetime64('1970-01-01T00:00:00'))
                 / np.timedelta64(1, 's'))
    return datetime.fromtimestamp(timestamp, timezone.utc)

def char_count(url: str):
    """
    fn char_count - WIP
    """
    return len(url)

def starts_with_ip_addr(url: str):
    """
    fn starts_with_ip_addr - WIP
    """
    return bool(regex.match(
                r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$",
                tldextract.extract(url).domain))

def url_entropy(url: str, expr: Pattern[str] = None):
    """
    fn url_entropy - WIP
    Taken from: https://www.reddit.com/r/learnpython/comments/g1sdkh/comment/fnhdecy
    """

    counts = expr_counter_group(url, expr)
    frequencies = ((i / len(url)) for i in counts.values())

    return -sum(f * log(f, 2) for f in frequencies)

def has_punycode(url: str):
    """
    fn has_punycode - WIP
    """

    def cmp_punycode(s):
        try:
            return (s != s.encode("idna").decode()) or (s != s.encode().decode("idna"))
        except UnicodeError:
            # Decoding fails when str begins with a dot, retry with a str slice from pos 1
            return cmp_punycode(s[1:])

    # url.encode("idna") is currently limited to 64 characters
    max_char = 64

    if len(url) < max_char:
        return cmp_punycode(url)

    # I decided to check long strings by 64-char slices

    # It's a little bit sketchy but I'm hoping that the chance of cutting
    # a long string exactly in the middle of a punycode is rather uncommon
    parts = ceil(len(url) / max_char)

    for i in range(parts):
        start = i*max_char
        end = ((i+1) * max_char) - 1

        if end > (len(url)-1):
            end = len(url) - 1

        if cmp_punycode(url[start:end]) is True:
            return True

    return False

def expr_counter_group(url: str, expr: Pattern[str] = None):
    """
    fn expr_counter_group - WIP
    """

    counts = Counter(url)

    if expr is not None:
        for k in list(counts.keys()):
            if not bool(regex.match(expr, k)):
                del counts[k]

    return counts

def expr_counter(url: str, expr: Pattern[str]):
    """
    fn expr_counter - WIP
    """

    return sum(i for i in expr_counter_group(url, expr).values())

def digit_letter_ratio(url: str):
    """
    fn digit_letter_ratio - WIP
    """

    try:
        return float(expr_counter(url, r"\d")) / float(expr_counter(url, r"\p{L}"))
    except ZeroDivisionError:
        print(url)
        return None

def get_base_url(url: str):
    """
    fn get_base_url - WIP
    """

    url_extract = tldextract.extract(url)
    return '.'.join(list(filter(lambda x: len(x) > 0, [url_extract.subdomain, url_extract.domain, url_extract.suffix])))

def tld_count(url: str):
    """
    fn tld_count - WIP
    """

    count = 0

    base_url = get_base_url(url)
    base_match = regex.search(rf"(https?\:\/\/)?{base_url}\/?", url, regex.IGNORECASE)

    if base_match is not None:
        url_subdir = url.replace(base_match.group(0), '')

        for s in regex.findall(r"[a-z0-9_.]+\.[a-z]{2,3}", url_subdir, regex.IGNORECASE):
            ex = tldextract.extract(s)

            if ex.suffix != '':
                count += 1

    return count

def has_internal_links(url: str):
    """
    fn has_internal_links - WIP
    """

    return tld_count(url) > 0

def domain_has_digits(url: str):
    """
    fn domain_has_digits - WIP
    """

    return len(regex.findall(r"[0-9]+", tldextract.extract(url).domain)) > 0

def subdomain_count(url: str):
    """
    fn subdomain_count - WIP
    """

    return len(list(filter(lambda x: len(x) > 0, tldextract.extract(url).subdomain.split('.'))))

def nan_char_entropy(url: str):
    """
    fn nan_char_entropy - WIP
    """

    return url_entropy(url, r"[#-\$\*\(\[\{\)\]\};:'\/!%_\?,=&~\.\+@]")

@retry(tries=10, delay=RETRY_DELAY_SECONDS)
def get_whois(url: str):
    """
    fn domain_info - WIP
    """

    try:
        time.sleep(RETRY_DELAY_SECONDS)
        return whois.whois(url)
    except whois.parser.PywhoisError:
        return None

def get_domain_info(url_col_name: str, out_col_name: str, df: pd.DataFrame):
    """
    fn get_domain_info - WIP
    """

    whois_record_max_age_days = 90

    def _calculate_record_age(r: datetime):
        if isinstance(r, datetime):
            return (datetime.now(timezone.utc) - r).days
        else:
            return None

    df_temp = df.copy()
    df_temp['__temp_base_url__'] = df_temp[url_col_name].map(get_base_url)

    whois_file_path = "./files/out/whois.json"
    whois_schema = {'__whois_domain__': str, '__whois_result__': whois.parser.WhoisCom, '__whois_last_downloaded_at__': datetime}

    if os.path.exists(whois_file_path):
        whois_df = pd.read_json(whois_file_path, orient="table")
    else:
        whois_df = pd.DataFrame(columns=whois_schema)
        os.makedirs(os.path.dirname(whois_file_path), exist_ok=True)

    df_temp = df_temp.merge(whois_df, left_on='__temp_base_url__', right_on='__whois_domain__', how='left')
    df_temp['__temp_snapshot_age_days__'] = df_temp['__whois_last_downloaded_at__'].map(_calculate_record_age)

    whois_missing_df = df_temp[ (pd.isna(df_temp['__temp_snapshot_age_days__'])) | (df_temp['__temp_snapshot_age_days__'] > whois_record_max_age_days) ]

    i = 1
    n = len(whois_missing_df.index)
    for index, row in whois_missing_df.iterrows():
        progress = 0
        base_url = row['__temp_base_url__']

        if base_url not in whois_df['__whois_domain__'].values:
            try:
                whois_result = get_whois(base_url)
            except Exception as exc:
                # Save current file content as a failsafe
                whois_df.to_json(whois_file_path, index=False, orient="table")
                raise exc

            if whois_result is not None:
                whois_df = pd.concat([ whois_df, pd.DataFrame([[base_url, whois_result, datetime.now(timezone.utc)]], columns=whois_df.columns) ], ignore_index=True)

        if i % int(n // 10) == 0:
            # Update every 10% progress
            progress = round((i + 1) / float(n) * 100, 2)
            print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - whois.whois - {i + 1} of {n} records ({progress}%)")

            whois_df.to_json(whois_file_path, index=False, orient="table")

        i = i + 1


    df_temp = df.copy()
    df_temp['__temp_base_url__'] = df_temp[url_col_name].map(get_base_url)

    df_temp = df_temp.merge(whois_df, left_on='__temp_base_url__', right_on='__whois_domain__', how='left')

    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]} - whois.whois - {n} of {n} records (100%)")
    whois_df.to_json(whois_file_path, index=False, orient="table")

    return df_temp.drop('__temp_base_url__', axis='columns')

def parse_date(s: str):
    """
    fn parse_date - WIP
    """

    base_r = {
        'yyyy': r"(2([0-9])[0-9]{2})",
        'mm': r"((0[1-9])|(1[0-2]))",
        'dd': r"(([0-2][0-9])|(3[0-1]))",
        'HH': r"(([0-1][0-9])|(2[0-3]))",
        'MM': r"([0-5][0-9])",
        'SS': r"([0-5][0-9])",
        'ff': r"[0-9]{,6}"
    }

    full_expr = [
        {
            'name': "yyyymmddHHMMSS",
            'regex': rf"{base_r['yyyy']}{base_r['mm']}{base_r['dd']}{base_r['HH']}{base_r['MM']}{base_r['SS']}",
            'date': "%Y%m%d%H%M%S"
        }
    ]

    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        pass

    try:
        expr = next(e for e in full_expr if e['name'] == "yyyymmddHHMMSS")
        regex_match = regex.search(expr['regex'], s).group(0)
        return datetime.strptime(regex_match, expr['date'])
    except AttributeError:
        pass

    try:
        return search_dates(s)[0][1]
    except TypeError:
        # raise TypeError(f"Error parsing date string: {s}") from exc
        print(f"Error parsing date string: '{s}'")

# def domain_age(url: str):
#     """
#     fn domain_age - WIP
#     """

#     dom_info = get_domain_info(url)

#     if dom_info is None:
#         return None

#     if not isinstance(dom_info, dict):
#         return None

#     if "creation_date" not in dom_info.keys():
#         return None

#     creation_date = dom_info["creation_date"][0] if isinstance(dom_info["creation_date"], list) else dom_info["creation_date"]

#     if isinstance(creation_date, str):
#         creation_date = parse_date(creation_date)

#     if isinstance(creation_date, datetime):
#         creation_date = creation_date.date()

#     if not isinstance(creation_date, date):
#         return None

#     return (date.today() - creation_date).days
