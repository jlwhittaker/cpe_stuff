import sys

pattern = '"cpe23Uri"'

def readCPEs(inputFile, outputFile):
    prev = [] # store previous cpe to avoid duplicates
    for line in inputFile:
        split = line.split()
        if pattern in split and pattern != prev:
            # cpe found and is not a duplicate

            # get rid of commas and quotes
            cpeName = split[-1].replace(',','').replace('"','') # cpe name should be last list element
            outputFile.write(cpeName+"\n")
            prev = split


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: cpe.py <inputFileName> <outputFileName>")
        exit()
    inputFileName = sys.argv[1]
    outputFileName = sys.argv[2]
    with open(inputFileName, "r") as inputFile, open(outputFileName, "w+") as outputFile:
        readCPEs(inputFile, outputFile)
