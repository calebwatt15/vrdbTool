###################################################################
#                                                                 #
#       Vulnerability Reporting Database Edit Tool - V 0.1        #
#       Authors: Caleb Watt (@calebwwatt15), Mike Mason (         #
#       License: Creative Commons ShareAlike 3.0                  #
#       http://creativecommons.org/licenses/by-sa/3.0/            #
#                                                                 #
###################################################################

import json, os, sys, time

SchemeProp = 'vrdb.properties'
InputJson = 'vrdb.json'


def genScheme(ret = False):
        # Main scheme data variable that will hold the final product!
        schemeData = {}
        with open(InputJson, 'r') as f:
                # Will hold the locations without names since we are not parsing the json yet. we will do that in the verification step
                schemeList = []
                # Finds the current location in the file. This should always be 0 at this point
                lastpos = f.tell()
                # Reads the entire line
                line = f.readline()
                # Will help us later to determine whether or not we are inside a dictionary
                foundScheme = False
                # If there is data, this will be true. However when re reach EOF it will be false and close out
                while line:
                        # This tells us where the next line starts (Since we read the line above our new location is at the next line)
                        newpos = f.tell()
                        # Strips any extra spaces and checks if the first characcter is a { (Indicating its the start of a dictionary
                        if len(line.strip()) and line.strip()[0] == "{":
                                # If so, then we can go ahead and creatre a new scheme
                                # The basic scheme shows the starting position of this line which is lastpos since that was read before re read that line
                                # Since we don't know end yet, we just set it to none
                                foundScheme = {
                                        'start': lastpos,
                                        'end': None
                                }
                        elif foundScheme and len(line.strip()) and line.strip()[0] == "}":
                                # If the scheme is found (Meaning we found the first { and the line we are on starts with a } then we have found its pair and need to fill in some information
                                # First we set the end to be the new position of the cursor (next line) -1 so we can get the last character of the previous line
                                foundScheme['end'] = newpos-1
                                # now we append this to the scheme list
                                schemeList.append(foundScheme)
                                # and reset the found scheme variable
                                foundScheme = False
                        # Since the new position is the start of the next line, we can just go ahead and set the last position to thatt
                        #  and only have to find the cursors position once from here on out
                        lastpos = newpos
                        # Now we read the line again and let it loop
                        line = f.readline()
                # Now that the list has been compiled, we need to loop through it
                for scheme in schemeList:
                        # First we seek the files cursor to the starting byte
                        f.seek(scheme['start'])
                        # Now we read the number of bytes we want (last byte - first byte) and clear any extra spaces off
                        j = f.read(scheme['end'] - scheme['start']).strip()
                        # If there were more items afterwards there would be a , after the } so we want to remove that so it doesn't break json's parsing
                        if j[-1] == ',': j = j[:-1]
                        try:
                                # Try to parse the json
                                arr = json.loads(j)
                        except:
                                # If it fails, then we fail the whole thing and tell what byte we started on so we can troubleshoot
                                print('Failed to parse json. Failed at byte: ' + str(scheme['start']))
                                break
                        # If it was able to parse it, then lets add it to the schemeData array that holds a dictionary of this information for later searching and editing
                        schemeData[arr['Name']] = scheme
                f.close()
        
        # First we check and see if they want it to just be returned, if so return it rather than saving the file
        if not ret:
                with open(SchemeProp, 'w') as w:
                        lines = []
                        for scheme in schemeData:
                                # Writes the file with the following format Name=Start,End
                                lines.append(str(scheme) + '=' + str(schemeData[scheme]['start']) + ',' + str(schemeData[scheme]['end']))
                        w.write("\n".join(lines))
                        w.close()
                return True
        return schemeData

# This functions loads the scheme info for the specified name
schemeInfo = {}
def getSchemeInfo(name, skipCache = False):
        if not (name in schemeInfo) or skipCache:
                with open(SchemeProp, 'r') as f:
                        line = f.readline()
                        while line:
                                if line.find("=") > -1:
                                        prop, val = line.split("=", 1)
                                        if prop == name:
                                                pstart, pend = val.split(',', 1)
                                                return {
                                                        'start': int(pstart),
                                                        'end': int(pend)
                                                }
                                line = f.readline()
        
        if name in schemeInfo:
                return schemeInfo[name]
        else:
                return None

def formatLargeText(text, maxLength = 100, padding = ''):
        lines = text.split("\n")
        nlines = []
        for line in lines:
                if len(line) > maxLength:
                        for x in range(0, len(line), maxLength):
                                nlines.append(str(padding) + line[x:x+maxLength] + str(padding))
                else: nlines.append(str(padding) + line + str(padding))
        return "\n".join(nlines)

def loadInfo(name):
        scheme = getSchemeInfo(name)
        if scheme:
                with open(InputJson, 'r') as f:
                        # Since the info was found in the scheme, we can go ahead and seek directly to where it starts
                        f.seek(scheme['start'])
                        # Read only the needed information
                        info = f.read(scheme['end'] - scheme['start']).strip()
                        # Clear out unwatned info
                        if info[-1] == ',': info = info[:-1]
                        # Parse JSON and return dictionary
                        parsedInfo = json.loads(info)
                        f.close()
                        return parsedInfo
        else:
                return None
                
def printInfo(info):
        if info:
                print('Name: ' + str(info['Name']))
                print('Description:')
                print(formatLargeText(str(info['Description']), padding=' '))
                print('')
                print('Implication:')
                print(formatLargeText(str(info['Implication']), padding=' '))
                print('')
                print('Solution:')
                print(formatLargeText(str(info['Solution']), padding=' '))
                print('')
                print('Likelihood: ' + str(info['Likelihood']))
                print('Impact: ' + str(info['Impact']))
                print('Risk: ' + str(info['Risk']))
                print('Types: ' + str(info['Types']))
        else:
                print('Failed to find info.')

def truncateLastLine():
        with open(InputJson, 'r+') as vulnDBFile:
                # Truncate the last line (should be "]" in the JSON file)
                vulnDBFile.seek(0, os.SEEK_END)
                pos = vulnDBFile.tell() - 1
                while(pos > 0 and vulnDBFile.read(1) != "\n"):
                        pos -= 1
                        vulnDBFile.seek(pos, os.SEEK_SET)
        
                if(pos > 0):
                        vulnDBFile.seek(pos, os.SEEK_SET)
                        vulnDBFile.truncate()

def readInput():
        name = raw_input('Vuln name: ')
        description = raw_input('Description: ')
        implication = raw_input('Implication: ')
        solution = raw_input('Solution: ')
        likelihood = raw_input('Likelihood: ')
        impact = raw_input('Impact: ')
        risk = raw_input('Risk: ')
        types = raw_input('Types: ')
        
        name = '        "Name": "' + name + '",\n'
        description = '        "Description": "' + description + '",\n'
        implication = '        "Implication": "' + implication + '",\n'
        solution = '        "Solution": "' + solution + '",\n'
        likelihood = '        "Likelihood": "' + likelihood + '",\n'
        impact = '        "Impact": "' + impact + '",\n'
        risk = '        "Risk": "' + risk + '",\n'
        types = '        "Types": "' + types + '"\n'
        
        rawJSONString = ",\n    {\n" + name + description + implication + solution + likelihood + impact + risk + types + "\n    }\n"
        
        return(rawJSONString)

def writeToFile(dataToWrite):
        with open(InputJson, 'a') as vulnDBFile:
                vulnDBFile.write(dataToWrite)

def fixFileCloser():
        with open(InputJson, 'a') as vulnDBFile:
                vulnDBFile.write("]")
        

if __name__ == '__main__':
        if sys.argv[1] == 'generate':
                genScheme()
        elif sys.argv[1] == 'find':
                findName = " ".join(sys.argv[2:]).strip()
                info = loadInfo(findName)
                printInfo(info)
        elif sys.argv[1] == 'add':
                # Hacky method. Delete last line, build JSON string, write to the file, then re-add
                # then re-add the closing bracket. This should be re-done properly.
                truncateLastLine()
                writeToFile(readInput())
                fixFileCloser()
