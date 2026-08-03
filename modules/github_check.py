import requests

def check_github(username):
    url = f"https://api.github.com/users/{username}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                "found": True,
                "profile_url": f"https://github.com/{username}",
                "details": f"Name: {data.get('name')} | Public Repos: {data.get('public_repos')}"
            }
        else:
            return {"found": False}
    except requests.RequestException:
        return {"found": False, "error": "Connection failed"}