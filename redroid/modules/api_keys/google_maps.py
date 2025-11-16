#!/usr/bin/env python3
"""
Google Maps API Key Testing
"""

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

def scan_gmaps(apikey):
    vulnerable_services = []
    separator = "-" * 60

    print("\n" + separator)
    print(f"{Fore.CYAN}Starting Google Maps API scan...{Style.RESET_ALL}")
    print(separator)
    
    def colored_status(status):
        if status in [200, 302]:
            return f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        else:
            return f"{Fore.RED}{status}{Style.RESET_ALL}"
    
    def test_get(service_name, url, vulnerability_condition):
        try:
            response = requests.get(url, verify=False)
        except Exception as e:
            print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
            print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f" Status : {Fore.RED}Error: {e}{Style.RESET_ALL}")
            print(separator)
            return False

        status_colored = colored_status(response.status_code)
        vulnerable, reason = vulnerability_condition(response)
        
        print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
        print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
        print(f" Status : {status_colored}")
        if vulnerable:
            print(f" Result : {Fore.GREEN}VULNERABLE{Style.RESET_ALL}")
        else:
            print(f" Result : {Fore.RED}Not Vulnerable{Style.RESET_ALL}")
        print(f" Details: {reason}")
        print(separator)
        
        if vulnerable:
            vulnerable_services.append(service_name)
        return vulnerable

    def test_post(service_name, url, postdata, headers, vulnerability_condition):
        try:
            response = requests.post(url, data=postdata, verify=False, headers=headers)
        except Exception as e:
            print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
            print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
            print(f" Status : {Fore.RED}Error: {e}{Style.RESET_ALL}")
            print(separator)
            return False

        status_colored = colored_status(response.status_code)
        vulnerable, reason = vulnerability_condition(response)
        
        print(f"{Fore.YELLOW}[{service_name}]{Style.RESET_ALL}")
        print(f" URL    : {Fore.CYAN}{url}{Style.RESET_ALL}")
        print(f" Status : {status_colored}")
        if vulnerable:
            print(f" Result : {Fore.GREEN}VULNERABLE{Style.RESET_ALL}")
        else:
            print(f" Result : {Fore.RED}Not Vulnerable{Style.RESET_ALL}")
        print(f" Details: {reason}")
        print(separator)
        
        if vulnerable:
            vulnerable_services.append(service_name)
        return vulnerable

    def no_error_condition(response):
        if response.status_code != 200:
            return False, f"HTTP {response.status_code} received."
        try:
            data = response.json()
            if ("error_message" not in data) and ("errorMessage" not in data):
                return True, "No error message found."
            else:
                err = data.get("error_message") or data.get("errorMessage")
                return False, f"Error: {err}"
        except Exception as e:
            return False, str(e)
    
    def static_maps_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        elif b"PNG" in response.content:
            return False, "PNG content returned."
        else:
            return False, f"Response: {response.content.decode(errors='ignore')}"
    
    def street_view_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        elif b"PNG" in response.content:
            return False, "PNG content returned."
        else:
            return False, f"Response: {response.content.decode(errors='ignore')}"
    
    def places_photo_condition(response):
        if response.status_code == 302:
            return True, "HTTP 302 (redirect) received."
        else:
            return False, "No redirect."
    
    def fcm_condition(response):
        if response.status_code == 200:
            return True, "HTTP 200 received."
        else:
            try:
                data = response.json()
                return False, f"Error: {data.get('error', 'Unknown error')}"
            except:
                return False, response.text

    def nearest_roads_condition(response):
        if response.status_code != 200:
            return False, f"HTTP {response.status_code} received."
        try:
            data = response.json()
            if "error" not in data:
                return True, "No error returned."
            else:
                return False, data["error"].get("message", "Error returned.")
        except Exception as e:
            return False, str(e)
    
    test_get("Static Maps API",
             "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=" + apikey,
             static_maps_condition)
    
    test_get("Street View API",
             "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key=" + apikey,
             street_view_condition)
    
    test_get("Directions API",
             "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key=" + apikey,
             no_error_condition)
    
    test_get("Geocoding API",
             "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=" + apikey,
             no_error_condition)
    
    test_get("Distance Matrix API",
             ("https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998"
              "&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592"
              "%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592"
              "%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271"
              "%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524"
              "%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key=" + apikey),
             no_error_condition)
    
    test_get("Find Place from Text API",
             ("https://maps.googleapis.com/maps/api/place/findplacefromtext/json?"
              "input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&"
              "fields=photos,formatted_address,name,rating,opening_hours,geometry&key=" + apikey),
             no_error_condition)
    
    test_get("Autocomplete API",
             "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key=" + apikey,
             no_error_condition)
    
    test_get("Elevation API",
             "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key=" + apikey,
             no_error_condition)
    
    test_get("Timezone API",
             "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key=" + apikey,
             no_error_condition)
    
    test_get("Nearest Roads API",
             "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key=" + apikey,
             nearest_roads_condition)
    
    test_post("Geolocation API",
              "https://www.googleapis.com/geolocation/v1/geolocate?key=" + apikey,
              postdata={'considerIp': 'true'},
              headers={'Content-Type': 'application/json', 'Authorization': 'key=' + apikey},
              vulnerability_condition=no_error_condition)
    
    test_get("Snap to Roads API",
             "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key=" + apikey,
             no_error_condition)
    
    test_get("Speed Limits API",
             "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key=" + apikey,
             no_error_condition)
    
    test_get("Place Details API",
             "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key=" + apikey,
             no_error_condition)
    
    test_get("Nearby Search-Places API",
             "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key=" + apikey,
             no_error_condition)
    
    test_get("Text Search-Places API",
             "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key=" + apikey,
             no_error_condition)
    
    test_get("Places Photo API",
             "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key=" + apikey,
             places_photo_condition)
    
    test_post("FCM API",
              "https://fcm.googleapis.com/fcm/send",
              postdata="{'registration_ids':['ABC']}",
              headers={'Content-Type': 'application/json', 'Authorization': 'key=' + apikey},
              vulnerability_condition=fcm_condition)
    
    print("\n" + separator)
    print(f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
    if vulnerable_services:
        for service in vulnerable_services:
            print(f"- {service}")
    else:
        print("No vulnerable services detected.")
    print("\nPricing references:")
    print("https://cloud.google.com/maps-platform/pricing")
    print("https://developers.google.com/maps/billing/gmp-billing")
    
    js_filename = "jsapi_test.html"
    js_content = (
        '<!DOCTYPE html><html><head>'
        '<script src="https://maps.googleapis.com/maps/api/js?key=' + apikey +
        '&callback=initMap&libraries=&v=weekly" defer></script>'
        '<style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style>'
        '<script>function initMap(){var map=new google.maps.Map(document.getElementById("map"),'
        '{center:{lat:-34.397,lng:150.644},zoom:8});}</script>'
        '</head><body><div id="map"></div></body></html>'
    )
    try:
        with open(js_filename, "w+") as f:
            f.write(js_content)
        print(f"\nJS API test file '{js_filename}' generated automatically.")
        print("Open it in your browser to verify the JavaScript API functionality.")
    except Exception as e:
        print(f"Error generating JS API test file: {e}")
    
    return True


