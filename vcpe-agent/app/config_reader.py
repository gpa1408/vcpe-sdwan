import json
import requests

class ConfigReader:
    def __init__(self):
        self.url = "http://127.0.0.1:8383/restconf/data/sdwan-cpe:sdwan"                      # Fixed RESTCONF URL for the top-level "sdwan" container in Clixon datastore
        self.headers = {                                                                      # Ask Clixon to return YANG JSON
            "Accept": "application/yang-data+json"                                             
        }

    def get_intended_config(self):
        response = requests.get(self.url, headers=self.headers, timeout=5)                     # Send HTTP GET request to Clixon RESTCONF
        response.raise_for_status()                                                            # Raise error for HTTP failures, for example 404 or 500
        data = response.json()                                                                 # Convert JSON response to Python dictionary
      
        if "sdwan-cpe:sdwan" not in data:                                                      # Check expected top-level key
            raise ValueError("Expected key 'sdwan-cpe:sdwan' not found in RESTCONF response")
 
        return data["sdwan-cpe:sdwan"]                                                         # Return only the inner sdwan container

if __name__ == "__main__":
    reader = ConfigReader()
    try:
        config = reader.get_intended_config()
        print("\nFull intended config:")
        print(json.dumps(config, indent=2))
    except Exception as e:
        print("Error reading config:", e)
