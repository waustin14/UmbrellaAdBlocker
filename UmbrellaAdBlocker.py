#!C:\Users\Will\AppData\Local\Programs\Python\Python39\python.exe

# Cisco Umbrella Integration to Block Adware
# Based on AdBlocker by chrivand

import requests, re, json, math, time
from datetime import datetime

def getDomainList(): 
    """Returns a list of domains listed on the Steven Black hosts file"""

    HOSTS_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
    HEADERS = {
        'Accept': 'text/*'
    }
    COMMENT_FILTER = r'#'
    DOMAIN_FILTER = r'([a-z0-9]+\.)+[a-z]+'
    ALLOWED_DOMAINS = ['localhost.localdomain']

    # Download hosts file and convert to list of strings (line by line)
    hosts_file = requests.get(url=HOSTS_URL, headers=HEADERS).text.split('\n')
    domains = []

    # Check line by line to see if it contains a domain name and append it to the domain name list
    for line in hosts_file:
        comment_match = re.search(COMMENT_FILTER, line)
        domain_match = re.search(DOMAIN_FILTER, line)
        if comment_match or not domain_match:
            continue
        else:
            dn = domain_match.group(0)
            if dn in ALLOWED_DOMAINS:
                continue
            else:
                domains.append(domain_match.group(0))
    print(f'Retrieved {len(domains)} domains from the Steven Black hosts file')
    return domains

def createEvent(dn, time):
    """Returns a dictionary in the Cisco Umbrella Enforcement API format to block a domain name with a given timestamp"""

    return dict(
        alertTime = time,
        deviceId = "ba6a59f4-e692-4724-ba36-c28132c761df",
        deviceVersion = "1.0",
        dstDomain = dn,
        dstUrl = f"http://{dn}",
        eventTime = time,
        protocolVersion = "1.0",
        providerName = "Steven Black Hosts"
    )

def createEvents(domains, time):
    """Returns a list of dictionaries in the Cisco Umbrella Enforcement API format"""

    events = []

    for dom in domains:
        events.append(createEvent(dom, time))
    
    return events

def writeEventsToFile(events, file):
    """Writes formatted events into a file"""

    # Write events to file as a list of JSON objects
    with open(file, 'w') as f:
        print('[', file=f)
        for event in events:
            if event == events[-1]:
                print(f'\t{json.dumps(event, indent=4)}', file=f)
            else:
                print(f'\t{json.dumps(event, indent=4)},', file=f)
        print(']', file=f)
    
    return

def postEvents(event_file):
    # Umbrella Threat Enforcement API URL w/ Customer Key
    URL = 'https://s-platform.api.opendns.com/1.0/events?customerKey=60023d0e-575b-425d-86d6-fb35c0c7ca1b'

    # Post Events File to Umbrella Enforcement API
    POST_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Create a session object to persist the TCP connection
    session = requests.Session()
    session.headers = POST_HEADERS

    # Read Event File as a List of Dictionaries
    with open(event_file, 'r') as f:
        events = json.load(f)
    
    # Slice Event List and Post 5000 Events at a Time
    SLICE_SIZE = 5000
    N_SLICES = math.ceil(len(events)/SLICE_SIZE)
    # Create a delay parameter to avoid triggering the rate limiter without wasting too much time
    DELAY = 10
    for i in range(0, N_SLICES):
        if i == N_SLICES - 1:
            event_block = events[i*SLICE_SIZE:]
        else:
            event_block = events[i*SLICE_SIZE:(i+1)*SLICE_SIZE]
        try:
            response = session.post(url=URL, headers=POST_HEADERS, data=json.dumps(event_block))
            if response.status_code in range(200,210):
                print(f'POST -> {response.status_code}: Added {SLICE_SIZE} records')
                print(f'Sleeping for {DELAY} seconds')
                # Slow down requests to not violate rate limits
                time.sleep(DELAY)
            elif response.status_code == 429:
                print(f'POST -> {response.status_code} - Sleeping for {DELAY} seconds')
                time.sleep(DELAY)
                DELAY += 5
            else:
                response.raise_for_status
        except Exception as e:
            session.close()
            print(f'{type(e)},{e}')
    
    session.close()
    
    return

def getBlockedDomains():
    """Retrieves currently blocked domains"""

    URL = 'https://s-platform.api.opendns.com/1.0/domains?customerKey=60023d0e-575b-425d-86d6-fb35c0c7ca1b'
    HEADERS = {
        'Accept': 'application/json'
    }

    # Create a session object to persist the TCP connection
    session = requests.Session()
    session.headers = HEADERS
    
    # Retrieve domain names from the Umbrella Enforcement API and store them in a list
    domains = []
    while URL:
        try: 
            response = session.get(url=URL, headers=HEADERS)
            status = response.status_code
            print(f'GET -> {status}')
            if status != 200:
                continue
            else:
                ans = json.loads(response.text)
                URL = ans['meta']['next']
                data = ans['data']
                for dn in data:
                    domains.append(dn['name'])
        except:
            # If the request fails, wait two seconds and try again
            print('Something happened...')
            time.sleep(2)
            continue
    session.close()
    print(f'Retrieved {len(domains)} domains that are already blocked')
    return domains

def countBlockedDomains():
    """Returns the number of domains currently blocked by the Umbrella Enforcement API"""

    URL = 'https://s-platform.api.opendns.com/1.0/domains?customerKey=60023d0e-575b-425d-86d6-fb35c0c7ca1b&limit=200'
    HEADERS = {
        'Accept': 'application/json'
    }

    # Create a session object to persist the TCP connection
    session = requests.Session()
    session.headers = HEADERS

    count = 0
    while URL:
        try: 
            # Wait two seconds to avoid requests in rapid succession
            #time.sleep(1)
            response = session.get(url=URL, headers=HEADERS)
            status = response.status_code
            print(f'GET -> {status}')
            if status != 200:
                continue
            else:
                ans = json.loads(response.text)
                URL = ans['meta']['next']
                if URL: 
                    count += 200
                else:
                    count += len(ans['data'])
        except Exception as e:
            # If the request fails, wait two seconds and try again
            print(f'Error of Type {type(e)}: {e}')
            time.sleep(1)
            continue
    
    session.close()
    return count

def deltaDomains(new_dn, old_dn):
    """Compares domains in the new host file with domains that are already blocked
       Returns a list of domains that need to be added to the blocked domains list within Umbrella"""
    starting_length = len(new_dn)
    for dn in new_dn:
        if dn in old_dn:
            new_dn.remove(dn)
    
    print(f'There are {len(new_dn)} domains to add.')

    return new_dn

def __main__():


    FNAME = 'events.json'

    # Create the current timestamp
    time = datetime.now().isoformat(sep='T')+'Z'

    # Pull the latest domains, compare them to already blocked domains, and create new event objects
    new_domains = getDomainList()
    old_domains = getBlockedDomains()
    add_domains = deltaDomains(new_domains, old_domains)
    events = createEvents(add_domains, time)
    del(new_domains)
    del(old_domains)

    # Write events to file
    writeEventsToFile(events, FNAME)
    del(events)

    # Read events file and post to Umbrella Enforcement API
    postEvents(FNAME)

    return

if __name__ == '__main__':

    __main__()