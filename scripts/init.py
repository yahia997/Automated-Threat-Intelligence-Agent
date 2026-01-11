# This file makes bulk request to get last 120 days (max possible)
# To add data to show in the dashboard only
# Run on time at first

import os
from dotenv import load_dotenv
from fetch_class import Fetch_CVEs

load_dotenv() # to load the vars from .env file
NVD_API_KEY = os.getenv("NVD_API_KEY")

# lastest 120 days min from now
last_120_days = Fetch_CVEs(nvd_api_key=NVD_API_KEY, interval_min=172800)

last_120_days.parse()