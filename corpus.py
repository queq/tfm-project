"""
Corpus.py docstring
"""

# Published modules import
# import time
# import pandas as pd
# from pyspark.sql import SparkSession


# Custom modules import
from phishing.corpus.base import PhishingURLModel
import phishing.corpus.functions as fn
import whois
import pandas as pd
from datetime import datetime, timezone
import tldextract
from dateutil.parser import parse
import datefinder
import regex
import os

# spark = SparkSession.builder.getOrCreate()

model = PhishingURLModel(
    urls_col="url",
    label_col="label",
    sources={
        "phishing": [
            "PhishTank",
            "Phishing.Database",
            "OpenPhish-Community"
        ],
        "legitimate": [
            "Cisco-Umbrella",
            "Majestic"
        ]
    },
    max_size=1e6,
    sample_seed=123
)

# model.add_map_col("url_length", fn.char_count)
# model.add_map_col("starts_with_ip", fn.starts_with_ip_addr)
# model.add_map_col("url_entropy", fn.url_entropy)
# model.add_map_col("has_punycode", fn.has_punycode)
# model.add_map_col("digit_letter_ratio", fn.digit_letter_ratio)
# model.add_map_col("dot_count", lambda x: fn.expr_counter(url=x, expr=r"\."))
# model.add_map_col("at_count", lambda x: fn.expr_counter(url=x, expr=r"@"))
# model.add_map_col("dash_count", lambda x: fn.expr_counter(url=x, expr=r"-"))
# model.add_map_col("tld_count", fn.tld_count)
# model.add_map_col("domain_has_digits", fn.domain_has_digits)
# model.add_lookup_col("domain_age_days", fn.domain_age)
# model.add_map_col("subdomain_count", fn.subdomain_count)
# model.add_map_col("nan_char_entropy", fn.nan_char_entropy)
# model.add_map_col("has_internal_links", fn.has_internal_links)

model.add_lookup_col("base_url", fn.get_domain_info)

df = model.setup()


print(df.head(50))
# model.export("./files/out/out.csv")

# from dateparser.search import search_dates

# print(search_dates("2016-12-19T02:33:34.000"))

# print(datetime.strptime("2016/01/01", "%Y-%m-%dT%H:%M:%S.%f"))

# print(parse("0-UANIC 20180919194642", fuzzy=True))

# test_str = "0-UANIC 20180919194642"
# print(regex.search(r"(({0,2}))?", test_str))
# (0|1)[0-3][0-9]


# print(list(datefinder.find_dates("20180919194642")))

# print(fn.parse_date("0-UANIC 20180919194642"))

