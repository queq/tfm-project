"""
base - WIP
"""

# from typing import Any, Dict, Generic, List, Optional, TypeVar, TYPE_CHECKING
from typing import Optional
import os
import requests
import pandas as pd


class PhishingURLModel:
    """
    Class PhishingURLModel docstrings WIP
    """

    def __init__(
        self,
        *,
        urls_col: str = "url",
        label_col: str = "label",
        sources: dict[str, list] = {
            "phishing": ["Phishing.Database"],
            "legitimate": ["Cisco-Umbrella"]
        },
        max_size: Optional[int] = 1e6,
        sample_seed: Optional[int] = 42
    ):
        self.urls_col = urls_col
        self.label_col = label_col
        self.sources = sources
        self.max_size = max_size
        self.sample_seed = sample_seed

    def setup(self):
        """
        setup fn docstrings WIP
        """

        out_cols = [self.urls_col, "source", self.label_col]
        out_df = pd.DataFrame(columns=out_cols)

        for s in set(self.sources["phishing"]):
            if s == "PhishTank":
                file_path = "./files/phishing/PhishTank/online-valid.csv"
                self.__get_feed_file(
                    "http://data.phishtank.com/data/online-valid.csv",
                    file_path
                )

                src_df = pd.read_csv(file_path)
                to_append_df = src_df[src_df["verified"] == "yes"][["url"]].copy()
                to_append_df.loc[:, "source"] = "PhishTank"
            elif s == "Phishing.Database":
                file_path = "./files/phishing/Phishing.Database/ALL-phishing-links.tar.gz"
                self.__get_feed_file(
                    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-links.tar.gz",
                    file_path
                )

                src_df = pd.read_csv(
                    file_path,
                    compression="gzip",
                    header=0,
                    sep="¡º",
                    names=["url"],
                    engine="python"
                )
                to_append_df = src_df[["url"]].copy()
                to_append_df.loc[:, "source"] = "Phishing.Database"
            elif s == "OpenPhish-Community":
                file_path = "./files/phishing/OpenPhish-Community/feed.txt"
                self.__get_feed_file(
                    "https://openphish.com/feed.txt",
                    file_path
                )

                src_df = pd.read_csv(
                    file_path,
                    header=0,
                    names=["url"]
                )
                to_append_df = src_df[["url"]].copy()
                to_append_df.loc[:, "source"] = "OpenPhish-Community"

            to_append_df.loc[:, self.label_col] = "phishing"
            to_append_df.columns = out_cols
            out_df = pd.concat([out_df, to_append_df[out_cols]], ignore_index=True)

        for s in set(self.sources["legitimate"]):
            if s == "Cisco-Umbrella":
                file_path = "./files/legitimate/Cisco-Umbrella/top-1m.csv.zip"
                self.__get_feed_file(
                    "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
                    file_path
                )

                src_df = pd.read_csv(
                    file_path,
                    compression="zip",
                    header=0,
                    names=["rank", "url"]
                )
                to_append_df = src_df[["url"]].copy()
                to_append_df.loc[:, "source"] = "Cisco-Umbrella"
            elif s == "Majestic":
                file_path = "./files/legitimate/Majestic/majestic_million.csv"
                self.__get_feed_file(
                    "https://downloads.majestic.com/majestic_million.csv",
                    file_path
                )

                src_df = pd.read_csv(file_path)
                to_append_df = src_df[["Domain"]].copy()
                to_append_df.loc[:, "source"] = "Majestic"

            to_append_df.loc[:, self.label_col] = "legitimate"
            to_append_df.columns = out_cols
            out_df = pd.concat([out_df, to_append_df[out_cols]], ignore_index=True).drop_duplicates(subset=[self.urls_col, self.label_col], keep="last")

        phishing_cnt = len(out_df[out_df[self.label_col] == "phishing"])
        legit_cnt = len(out_df[out_df[self.label_col] == "legitimate"])

        sample_size = min(
            int(self.max_size//2),
            phishing_cnt,
            legit_cnt
        )

        out_df_strat = out_df.groupby(self.label_col).apply(lambda x: x.sample(n=sample_size, random_state=self.sample_seed))

        return out_df_strat.reset_index(drop=True)

    def export(self, out_path):
        """
        export fn docstrings WIP
        """

        out_model = self.setup()
        out_model.to_csv(out_path, index=False)

    def __get_feed_file(self, url, path):
        file_path = os.path.join(
            os.path.abspath(''),
            path
        )

        if not os.path.exists(file_path):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            response = requests.get(
                url,
                timeout=10
            )

            with open(file_path, mode="wb") as file:
                file.write(response.content)
