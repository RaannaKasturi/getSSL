import requests

def get_proxies():
    """Read proxies from a file and return them as a list."""
    proxies = []
    with open("proxies.txt", "r") as f:
        # Read lines and strip whitespace
        proxies = [line.strip() for line in f if line.strip()]
    return proxies

def write(data):
    """Append valid proxy to a file."""
    with open("validproxy.txt", "a") as f:
        f.write(data + "\n")

def check_proxies():
    """Check each proxy for validity and write valid ones to a file."""
    valid_proxies = []
    proxies = get_proxies()
    
    for proxy in proxies:
        try:
            # Check the proxy by making a request to ipinfo.io
            r = requests.get("https://ipinfo.io/json",
                             proxies={"http": proxy, "https": proxy},
                             timeout=5)
            if r.status_code == 200:
                valid_proxies.append(proxy)
                print(f"Valid proxy: {proxy}")
                write(proxy)
        except requests.exceptions.RequestException as e:
            print(f"Invalid proxy: {proxy} - {e}")
            continue

if __name__ == "__main__":
    check_proxies()