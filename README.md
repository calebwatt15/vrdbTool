# Vulnerability Reporting Database Tool

This is a tool written to help format data into the Vulnerability Reporting Database (vrdb - https://github.com/calebwatt15/vrdb ). The tool currently has three functions.

1. generate
2. find
3. add

## Usage
### python vrdbtool.py generate
This will generate the vrdb.properties file. This is used to search for vulnerabilities in the vrdb.json database. NOTE: There must be a vrdb.json file written before this function will work.

### python vrdbtool.py find [Vuln Name]
This will search for the given vulnerability name in the database. This is case sensitive.

### python vrdbtool.py add
This will prompt the user for the following information:
Name - The name of the vulnerability type (I.E. Buffer Overflow)
Description - A description of the vulnerability
Implication - The implication or effects of this vulnerability on a system
Solution - A brief recommendation for how to fix this issue
Likelihood - The likelhood this will be exploited (INFO, LOW, MEDIUM, HIGH, VERY HIGH)
Impact - The Impact this would have if it was exploited (INFO, LOW, MEDIUM, HIGH, VERY HIGH)
Risk - The overall risk (average of Likelihood and Impact)
Types - What types of systems can this vulnerability be found in? (I.E. Web or Thick)

Once each prompt is done, this is appended into the vrdb file.
