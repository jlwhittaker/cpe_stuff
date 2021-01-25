import sys

pattern = '"cpe23Uri"'
cpeList = set()

def readCPEs(inputFile, outputFile):
    for line in inputFile:
        split = line.split()
        if pattern in split:
            cpeName = split[-1].replace(',','').replace('"','') # cpe name should be last list element
            cpeList.add(cpeName)
    
    for cpeName in cpeList:
        outputFile.write(cpeName+'\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: cpe.py <inputFileName> <outputFileName>")
        exit()
    inputFileName = sys.argv[1]
    outputFileName = sys.argv[2]
    with open(inputFileName, "r") as inputFile, open(outputFileName, "w+") as outputFile:
        readCPEs(inputFile, outputFile)
