import requests
from datetime import datetime, timedelta
import json

class Fetch_CVEs:
  def __init__(self, nvd_api_key, time_start=None, time_end=datetime.now(), interval_min=10):

    # organize the object's attrs
    self.nvd_api_key= nvd_api_key

    # Last 10 min (default)
    self.time_end = time_end
    self.time_start = self.time_end - timedelta(minutes=interval_min)
    self.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    self.keywords=[
       # mentioned in the task (pdf)
    "scada", "plc", "hmi", "siemens", "rockwell", "schneider",
    "modbus", "dnp3"

      # we can add more keywords later
  ]

  def _load(self, keyword):
    response_headers = {
      "apiKey": self.nvd_api_key
    }

    url_params = {
      # max range of days is 120 day means (172800 min)
      "pubStartDate": self.time_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
      "pubEndDate": self.time_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
      "resultsPerPage": 2000, # max is 2000 (means max 2000 cves per reques)
      "keywordSearch": keyword
    }

    res = requests.get(self.url, headers=response_headers, params=url_params)

    data = res.json()

    # get the vulnerabilities or empty list
    CVES = data.get('vulnerabilities', [])

    # json object is returned
    return CVES
  
  def get_local_ai_insight(self, cve_id, description, cvss, cvss_details):
    # Ollama runs a local server on port 11434 by default
    url = "http://localhost:11434/api/generate"
    
    # provide cve-id (can give more information if the model is updated)
    # and gives cve description
    prompt = f"""
    You are an OT Cybersecurity Expert. Analyze the following vulnerability.

    Step 1: Determine if this vulnerability affects Industrial Control Systems (ICS), SCADA, PLCs, or manufacturing environments. If it is strictly a standard IT issue (e.g., web browsers, office software), state 'CLASSIFICATION: IT' only and stop.

    Step 2: If it is OT-related, provide a formal 2-sentence explanation of "why this is dangerous for a factory ?".
    
    Vulnerability Data:
    - CVE-ID: {cve_id}, 
    - Description: {description}
    - Metrics: {cvss_details}

    Make your tone formal as the results will be displayed in a website, not personal to me.
    """
    
    payload = {
      "model": "llama3.2",
      "prompt": prompt,
      "stream": False  # full text response
    }
    
    try:
        response = requests.post(url, json=payload)
        # The response comes back as a JSON object
        return response.json().get("response", "").strip()
    except Exception as e:
        return f"Local AI Error: {e}"
  
  # save to local json file
  def save_json(self, data):
    with open("cve_data.json", "w", encoding="utf-8") as f:
      json.dump(data, f, indent=4, ensure_ascii=False)

  # if these is old data to merge with
  def load_old_json(self):
    try:
      with open("cve_data.json", "r") as f:
        return json.load(f)
      
    except:
      return dict()
  
  def parse(self):
    # load old json data (load to know old data to skip or to merge)
    old = self.load_old_json()

    data = dict() # to store and organize the data it

    # make the get request
    cves = []

    # go through each keyword in our keywords that is related to OT/ICS vulnerabilities
    # best for performance (prefiltering)
    # get request for each keyword as the API does not provide "Or" option
    for kw in self.keywords:
      part = self._load(keyword=kw)
      cves.extend(part)

    # go through each vulnerability
    # customized only -> To avoid killing my GPU :)) (not for production)
    for cve in cves[:100]:
      content = cve["cve"]

      cve_id = content["id"]
      
      # if found in the old data, skip, saves resources
      if old.get(cve_id):
        continue

      publish_date = content["published"]

      
      metrics = content.get("metrics", {})

      # they are in different schemas
      cvss_priority = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

      # Default values
      cvss_score = None
      cvss_details = {
          "baseSeverity": None,
          "exploitabilityScore": None,
          "impactScore": None,
          "vector_attack": None,      
          "vector_complexity": None,  
          "vector_auth": None,        
          "confidentialityImpact": None,
          "integrityImpact": None,
          "availabilityImpact": None,
          "userInteractionRequired": None,
          "cvssVersion": None
      }

      for version in cvss_priority:
          cvss_list = metrics.get(version, [])
          if not cvss_list:
              continue

          # Find the Primary entry, or fall back to the first available
          selected_metric = next((m for m in cvss_list if m.get("type") == "Primary"), cvss_list[0])
          
          cvss_data = selected_metric.get("cvssData", {})
          cvss_score = cvss_data.get("baseScore")

          if cvss_score is not None:
              # 1. Map version-specific Vector fields
              if "v2" in version:
                  cvss_details["vector_attack"] = cvss_data.get("accessVector")
                  cvss_details["vector_complexity"] = cvss_data.get("accessComplexity")
                  cvss_details["vector_auth"] = cvss_data.get("authentication")
                  # Handle v2 Boolean -> String conversion
                  ui_val = selected_metric.get("userInteractionRequired")
                  cvss_details["userInteractionRequired"] = "REQUIRED" if ui_val is True else "NONE" if ui_val is False else None
              else:
                  cvss_details["vector_attack"] = cvss_data.get("attackVector")
                  cvss_details["vector_complexity"] = cvss_data.get("attackComplexity")
                  cvss_details["vector_auth"] = cvss_data.get("privilegesRequired")
                  # Handle v3 String (NONE/REQUIRED)
                  cvss_details["userInteractionRequired"] = cvss_data.get("userInteraction")

              # 2. Map Standard Impact fields
              cvss_details["baseSeverity"] = cvss_data.get("baseSeverity") or selected_metric.get("baseSeverity")
              cvss_details["exploitabilityScore"] = selected_metric.get("exploitabilityScore")
              cvss_details["impactScore"] = selected_metric.get("impactScore")
              cvss_details["confidentialityImpact"] = cvss_data.get("confidentialityImpact")
              cvss_details["integrityImpact"] = cvss_data.get("integrityImpact")
              cvss_details["availabilityImpact"] = cvss_data.get("availabilityImpact")
              cvss_details["cvssVersion"] = version
              
              break

      descriptions = content.get("descriptions", [])
      description_conactenated_en = "" # starter

      # go through descs
      for desc in descriptions:

        # english only
        if desc.get("lang") == "en":
          description_conactenated_en += desc["value"]

      # simple text preprocessing
      description_conactenated_en = description_conactenated_en.strip().lower()

      # LLM work
      ai_response = self.get_local_ai_insight(
           cve_id, 
           description_conactenated_en, 
           cvss_score,
           cvss_details)
      
      # additional filtering from LLM
      if 'CLASSIFICATION: IT' in ai_response.upper():
        continue

      data[cve_id] = {
        "cvss_score": cvss_score,
        "original_description": description_conactenated_en,
        "publish_date": publish_date,
        "ai_response": ai_response,
        "metrics": cvss_details,
      }

    # if new data only
    if len(data):
      # merge old cves with new ones
      # no duplicates as I used hashtables (dictionaries in python), best for performance also
      old.update(data)

      # to produce report in json format and save it
      self.save_json(data=old)

    # for later use
    return data