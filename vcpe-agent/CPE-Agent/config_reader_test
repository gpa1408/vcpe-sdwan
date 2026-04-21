import requests

class ConfigReader:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8383/restconf/data/sdwan-cpe:sdwan"
        self.headers = {"Accept": "application/yang-data+json"}

    def get_sdwan_root(self):
        r = requests.get(self.base_url, headers=self.headers, timeout=5)
        r.raise_for_status()
        return r.json()["sdwan-cpe:sdwan"]
