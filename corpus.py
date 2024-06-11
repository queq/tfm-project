"""
Corpus.py docstring
"""

# Published modules import
# import time
# import pandas as pd
# from pyspark.sql import SparkSession


# Custom modules import
from phishing.corpus.base import PhishingURLModel

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
    max_size=3e6,
    sample_seed=123
)

# start_time = time.time()

pd_df = model.setup()

# print(f"--- {time.time() - start_time} seconds ---")

# df = pd_df.groupby("label").apply(lambda x: x.sample(n=200))
# df.reset_index(drop=True, inplace=True)

# print(df.head(10))
print(pd_df.count())
print(pd_df.groupby(["source", "label"]).count())
print(pd_df.groupby(["label"]).count())

model.export("./files/out/out.csv")

# print(len(pd_df[pd_df["label"] == "phishing"]))
