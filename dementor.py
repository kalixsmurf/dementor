import requests
import dns.resolver

banner = """ 
 ____ _____           _____       _    ___
|  _ \___ / _ __ ___ |___ / _ __ | |_ / _ \ _ __
| | | ||_ \| '_ ` _ \  |_ \| '_ \| __| | | | '__|
| |_| |__) | | | | | |___) | | | | |_| |_| | |
|____/____/|_| |_| |_|____/|_| |_|\__|\___/|_|
    Written by Z3R0D4Y
"""

def whois(ip:str):
    if(ip==""):
        return
    url = "https://rdap.arin.net/registry/ip/"+ip
    response = eval(requests.get(url).content.decode('utf-8'))
    #Parse response data
    startAddress = response['startAddress']
    endAddress = response['endAddress']
    ipVersion = response['ipVersion']
    name = response['name']
    status = response['status'][0]
    #Entity parsing is a bit complex
    entityDict = {}
    entityList = response['entities']
    for entityDictObj in entityList:
        entityDict[entityDictObj['handle']] = entityDictObj['vcardArray'][1]
    for key in entityDict:
        print(f"""Organization ID : {key}
Organization name : {entityDict[key][1][-1]}\n""")
    print(f"""Network range : {startAddress} - {endAddress}
IP version : {ipVersion}
Name : {name}
Status : {status}""")
    #End of entity parsing


def printList(printList:list):
    for item in printList:
        if(printList.index(item) == (len(printList)-1)):
            print("%s\n" % item)
            return
        print("%s ," % item, end="")

def printCPE(printList:list):
    for item in printList:
        if(item == printList[-1]):
            print(f"""|    ˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳
-->  |{item}{(50-len(item))*' '}|
     ˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚\n""")
        else:
            print(f"""|    ˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳˳
-->  |{item}{(50-len(item))*' '}|
|    ˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚˚""")
        
def dns_lookup(ip_address):
    recordList = ['A', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'SRV', 'TXT', 'RP', 'DHCID']

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resultJson = {}
    for i in range(len(recordList)):
        try:
            record = recordList[i]
            response = resolver.resolve(ip_address,record)
            resultJson[record] = response.response
        except dns.resolver.NoAnswer:
            continue

    print("DNS servers: \n")
    for dnsServer in resolver._nameservers:
        print(dnsServer, end="\n")
    print("Response:\n")
    for record in resultJson:
        print(f"Record type {record}\n\n{resultJson[record]}\n=============================\n")
    
    if(resultJson.get('A')):
        for answer in list(resultJson['A'].answer):
            if(str(answer).split(' ')[-2] == "A"):
                return str(answer).split(' ')[-1]
            
    return ""





#Evaluate the dictionary
def evaluateResult(shodanResponse:dict):
    print(shodanResponse)
    openPortList = []
    usedTechCpeList  = []
    hostnameList  = []
    vulnerabilityList  = []
    #Evaluate 
    if(shodanResponse.get('ports') and len(shodanResponse['ports'])>0):
        openPortList = list(shodanResponse['ports'])
    if(shodanResponse.get('cpes') and len(shodanResponse['cpes'])>0):
        usedTechCpeList = list(shodanResponse['cpes'])
    if(shodanResponse.get('hostnames') and len(shodanResponse['hostnames'])>0):
        hostnameList = list(shodanResponse['hostnames'])
    if(shodanResponse.get('vulns') and len(shodanResponse['vulns'])>0):
        vulnerabilityList = list(shodanResponse['vulns'])


    #Output the results
    print("\n\n(*) Retrieving passive recon results\n")
    if(shodanResponse.get('ip')!=None):
        print(f"\nTarget ip --> {shodanResponse['ip']}\n")
    else:
        print("(!) Passive scan error. Check network connectivity.\n")
    if(len(openPortList)>0):
        print("Open ports --> ", end="")
        printList(openPortList)

    cpeBanner="""˳˳˳˳˳˳˳˳˳˳˳˳
|Found CPEs|
˚˚˚˚˚˚˚˚˚˚˚˚
|"""

    #print(f"Found CPEs --> ", end="")
    if(len(usedTechCpeList)>0):
        print(cpeBanner)
        printCPE(usedTechCpeList)
    else:
        print("(-) No cpe could be found\n")
    if(len(hostnameList)>0):
        print(f"Found domains and subdomains --> ", end="")
        printList(list(hostnameList))
    else:
        print("(-) No domain info could be found. Check DNS configuration.\n")
    if(len(vulnerabilityList) >0):
        print(f"Vulnerabilities on the server --> ", end="")
        printList(vulnerabilityList)
        print("Vulnerability reference links:\n|")
        referenceLinks = []
        for vuln in vulnerabilityList:
            referenceLinks.append(f"https://nvd.nist.gov/vuln/detail/{vuln}")
        printCPE(referenceLinks)
    else:
        print("(!) Services seem to be up to date, no vulnerability could be found.\n\n")

    #=======================

def main():
    print("%s" % banner)
    domainName = input("Enter target domain: ")
    print("\n============================\nDNS query results\n============================\n")

    ip = dns_lookup(domainName)

    url = "https://internetdb.shodan.io/"+ip
    response = requests.get(url)
    #Create the dictionary object from shodan response
    shodanJson = eval(response.content.decode('utf-8'))
    #Call evaluation functions
    evaluateResult(shodanJson)
    whois(ip)


if __name__ == "__main__":
    main()