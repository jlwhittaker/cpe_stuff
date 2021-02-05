
import json
import time
import os
from flask import Flask, request, jsonify
app = Flask(__name__)


cveMap = {}
cpeMap = {}
fileNames = os.listdir("./jsontest")

@app.route('/', methods=['GET'])
def main():
	return "TEST"

@app.route('/', methods=['POST'])
def handler():
	data = request.data
	return "TEST"
#    return json.loads(request.data)["foo"]
#    cpeName = json.loads(request.data)["cpe"]
#    CVEs = cpeMap[cpeName]
#    CVE = CVEs[0]
#    configs = cveMap[CVE[0]]
#    relevantConfig = configs[CVE[2]][CVE[2]]
#    return json.dumps(CVEs)
    # return jsonify(request)



def main():
    for file in ["./jsontest/"+f for f in fileNames]:
        with open(file, "r") as f:
            parseJSON(f)
    # while True:
    #     cpeName = input("Enter a cpe name\n")
    #     print(cpeMap[cpeName])
    #     cve = input("Enter a cve name\n")
    #     print(cveMap[cve])


def parseJSON(file):
    lineNum = 1
    jsonString = '{'
    cveID = ''
    bracketBalance = 1
    inObject = False
    for line in file:
        # start lookin
        if '"ID" :' in line:
            # ugly string processing to pull out CVE ID
            cveID = line.split()[-1].replace(',','').replace('"','')
        elif '"configurations" :' in line and not inObject:
            objStart = lineNum
            # start collecting configObject
            inObject = True
        elif inObject:
            if '{' in line:
                bracketBalance += 1
            if '}' in line:
                bracketBalance -= 1
            if bracketBalance == 0:
                # end of 'configurations' object
                jsonString += '}'
                objStop = lineNum
                configObject = json.loads(jsonString)
                configObject["cve"] = cveID
                # time.sleep(0.5)
                try:
                    processConfigObject(configObject)
                except Exception as e:
                    print(f"bad object, started line {objStart}, stopped line {objStop}")
                    exit()
                jsonString = '{'
                inObject = False
                bracketBalance = 1
            else:
                jsonString += line.strip('\n')
        lineNum += 1






def processConfigObject(configObject):
    #config is array of group, maybe one group or two, depending on if AND is found
    configNum = 0;
    cveMap[configObject["cve"]] = []

    for config in configObject["nodes"]:
        # new config, will append to cveMap[configObject["cve"]]
        newConfig = []
        groupNum = 0
        isOrGroup = True
        if config["operator"] == "AND": # multiple groups, AND with each other
            try:
                groups = [g for g in config["children"]]
            except Exception:
                #children not used
                isOrGroup = False
                groups = [g for g in config["cpe_match"]]
                pass
                
        else:
            groups = [config] # one group
        for group in groups:
            # new group, will append to newConfig
            configOrGroup = []
            if isOrGroup == False:
                groupList = groups
            else:
                groupList = group["cpe_match"]
            for cpe in groupList:
                cpeName = cpe["cpe23Uri"]
                if cpeName not in cpeMap:
                    cpeMap[cpeName] = []
                cpeMap[cpeName].append((configObject["cve"],configNum,groupNum))
                configOrGroup.append( 
                                        {
                                        "cpe": cpeName,
                                        "vStartIn": configObject.get("versionStartIncluding"),
                                        "vStartEx": configObject.get("versionStartExcluding"),
                                        "vStopIn": configObject.get("versionStopIncluding"),
                                        "vStopEx": configObject.get("versionStopExcluding"),
                                        }
                )
            newConfig.append(configOrGroup)        
            groupNum += 1
        # print(f"adding config number {configNum} to {configObject['cve']}")
        # time.sleep(0.3)
        cveMap[configObject["cve"]].append(newConfig) 
        configNum += 1


main()
if __name__ == "__main__":
	main()
	app.run(host="0.0.0.0", port=8989)


