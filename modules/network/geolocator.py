import requests

#works but there's room for a lot of improvement (VPN, proxies, mobile with ap-api.com)

def geolocator():
    ip = input("Enter the ip address to scan(IPv4-IPv6): ")
    url = f"http://ip-api.com/json/{ip}"
    
    try: 
        response = requests.get(url, timeout = 10)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            return {"error": f"API returned HTTP status: {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"Connection failed: {e}"}

"""
response = requests.get(url, timeout=10)
response.raise_for_status()  # Triggers an exception if status is NOT 200-299
return response.json()
"""

if __name__ == "__main__":
    result = geolocator()
    print(result)