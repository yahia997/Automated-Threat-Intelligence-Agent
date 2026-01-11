# This script will be scheduled to run every 10 min
# gets the lasted data from 10 min from the time to run

import os
from dotenv import load_dotenv
from fetch_class import Fetch_CVEs

load_dotenv() # to load the vars from .env file
NVD_API_KEY = os.getenv("NVD_API_KEY")

# lastest 10 min from now
last_10_min = Fetch_CVEs(nvd_api_key=NVD_API_KEY, interval_min=10)

last_10_min.parse()