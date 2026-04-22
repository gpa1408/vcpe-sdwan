import copy
import json
import requests


class ConfigReader:

    def __init__(self):
         
        self.url = "http://127.0.0.1:8383/restconf/data/sdwan-cpe:sdwan"       # Fixed RESTCONF URL for the top-level "sdwan" container in clixon datarore

        self.headers = {                                      
            "Accept": "application/yang-data+json"                             # HTTP header asking Clixon to return data in YANG JSON format
        }
        
        self.last_config = None                                                # Stores the previously read config snapshot

    def get_intended_config(self):

        
        response = requests.get(self.url, headers=self.headers, timeout=5)    # Send an HTTP GET request to the RESTCONF URL
        
        response.raise_for_status()                                           # Raise an exception if the HTTP status code is not successful.Ex: 404, 500, etc.
       
        data = response.json()                                                # Convert the HTTP JSON reply into a Python dictionary
       
        if "sdwan-cpe:sdwan" not in data:                                     # Check that the expected top-level key exists in the response
            raise ValueError("Expected key 'sdwan-cpe:sdwan' not found in RESTCONF response")

        return data["sdwan-cpe:sdwan"]                                        # Return only the inner sdwan container

    def get_config_with_change_flag(self):
        
        current_config = self.get_intended_config()                          # Read the latest intended config from RESTCONF
        
        changed = current_config != self.last_config                         # Compare the newly read config with the previously stored one

        if changed:
            self.last_config = copy.deepcopy(current_config)                 # If changed, a deepcopy is used because config is a nested structure

        return current_config, changed                                       # Return the config and the change status

if __name__ == "__main__":
    
    reader = ConfigReader()                                                  # Create an object of the ConfigReader class

    try:
        
        config, changed = reader.get_config_with_change_flag()              # Read the latest config and also check whether it changed

        print("Config changed:", changed)
        print("\nFull intended config:")
        print(json.dumps(config, indent=2))

    except Exception as e:
        print("Error reading config:", e)

