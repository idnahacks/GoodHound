# GoodHound

```
   ______                ____  __                      __
  / ____/___  ____  ____/ / / / /___  __  ______  ____/ /
 / / __/ __ \/ __ \/ __  / /_/ / __ \/ / / / __ \/ __  / 
/ /_/ / /_/ / /_/ / /_/ / __  / /_/ / /_/ / / / / /_/ /  
\____/\____/\____/\__,_/_/ /_/\____/\__,_/_/ /_/\__,_/   
                                                         
```
> Attackers think in graphs, defenders think in actions, management think in charts.

GoodHound operationalises Bloodhound by determining the busiest paths to high value targets and creating actionable output to prioritise remediation of attack paths.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/B0B7AAAK2)  
> I'm lucky enough to do this for a living. Any donations will be passed on to my local foodbank, animal sanctuary and animal rescue centres.

## Usage

### Quick Start
For a very quick start with most of the default options, make sure you have your neo4j server running and loaded with SharpHound data and run:
```
git clone https://github.com/idnahacks/GoodHound.git
cd GoodHound
pip install -r requirements.txt
python goodhound.py -p "neo4jpassword" -o csv -f .
```
This will process the data in neo4j and output 3 csv reports in the GoodHound directory.

![Demo](images/demo.gif)


### Default behaviour

All options are __optional__.  
The default behaviour is to connect to a neo4j server setup with the default location (bolt://localhost:7687) and credentials (neo4j:neo4j), calculate the busiest paths from non-admin users to highvalue targets, the "weakest links" (the links of an attack path that are seen across many paths), and some grandtotals.  
3 separate csv files will be created with details for each of these 3 sections.

The neo4j database will need to already have the Sharphound collector output uploaded using the Upload button in the Bloodhound GUI. An example Sharphound output collected using [Bad Blood](https://github.com/davidprowe/BadBlood) on a [Detection Labs](https://detectionlab.network/) can be found in this repo at [/Sample%20SharpHound%20Output](/Sample%20SharpHound%20Output).

## The Output
### Summary Report
The Summary report contains some high level information regarding the number of paths found, the number of enabled non-admin users that are exposed to an attack path, and the number of paths that have been seen before based on the entries in the GoodHound local database.  

The end goal is to reduce the number of exposed users, by taking a two pronged approach.  
Busiest paths will highlight attack paths that are exposed to the greatest number of users.  
Weakest links will highlight links that might help to close down the number of paths available.

### Busiest Paths Report
The output shows a total number of unique users that have a path to a HighValue target.  
It then breaks this down to individual paths, ordered by the risk score (more on this later).  
Each path is then displayed showing the starting group, the number of non-admin users within that path, the number of hops, the risk score, a text version of the path and also a Cypher query. This cypher query can be directly copied into the Raw Query bar in Bloodhound for a visual representation of the attack path. 

### Weakest Links Report
The weakest links report is a way to potentially find links of attack paths that repeatedly show up in the dataset. For each weak link shown the report will also tell you how many of the total attack paths that was seen in.


## Options

### Database settings
-s can be used to point GoodHound to a server other than the default localhost installation (bolt://localhost:7687)  
-u can be used to set the neo4j username  
-p can be used to set the neo4j password  

### Output formats
-o can be used to select from:  
- stdout -displays the output on screen
- csv saves a comma separated values file for use with reporting or MI (completing the graphs, actions, charts trifecta in the tagline)
- md or markdown to display a markdown formatted output  

-f an optional filepath for the csv output option  

-q supresses all output  
-v enables verbose output  
--debug enables debug output  

By default the output is csv in the current working directory.

### Number of results
-r can be used to select the amount of results to show. By default the top 5 busiest paths are displayed.  
-sort can be used to sort by:
 - number of users with the path (descending)
 - hop count (ascending)
 - risk score (descending)

### Schema
-sch select a file containing cypher queries to set a custom schema to alter the default Bloodhound schema. This can be useful if you want to set the 'highvalue' label on AD objects that are not covered as standard, helping to provide internal context.
For example, you want to add the highvalue label to 'dbserver01' because it contains all of your customer records. The schema file to load in could contain the following cypher query:  
```
match (c:Computer {name:'DBSERVER01@YOURDOMAIN.LOCAL'}) set c.highvalue=TRUE
```
The schema can contain multiple queries, each on a separate line. 

### SQLite Database
By default Goodhound stores all attack paths in a SQLite database called goodhound.db stored in the local directory. This gives the opportunity to query attack paths over time.  
--db-skip will skip logging anything to a local database  
--sql-path can be used to point Goodhound to a SQLite db file that is not stored in the default location. The db file will be created in the set location if it does not already exist.

## Performance

Larger datasets can take time to process.  
GoodHound does "warm-up" the database using the same query that the Warm-Up Database option in the Bloodhound GUI does, however the Neo4j documentation suggests that this is no longer necessary, and in practice I haven't seen it make any different on Neo4j 4.0 and greater.  
There are also many guides for tuning the neo4j database for increased performance which are out of scope here (although if I make any significant improvements I'll document the findings).

## Installation

### Pre-requisites
- Python and pip already installed.
- Both neo4j and bloodhound will need to be already installed. The docs at https://bloodhound.readthedocs.io/en/latest/#install explain this well.

### Downloading GoodHound
Either download using git or by downloading the zip file and extract to your chosen location.
```
git clone https://github.com/idnahacks/GoodHound.git
cd goodhound
```
__OR__
```
https://github.com/idnahacks/GoodHound/archive/refs/heads/main.zip
```

### Installing
- Install required Python modules.  
- Goodhound will install py2neo and pandas libraries, if you do not wish to change any local modules you already have installed it is recommended to use pipenv.  
```
pip install -r requirements.txt
```

## SQLite Database
By default Goodhound will insert all of attack paths that it finds into a local SQLite database located in a db directory inside the current working directory.  
This database can be then queried separately using the SQLite tools and queries. More details on that can be found [here](sqlqueries.md).

## Risk Score
The Risk Score is a mechanism to help prioritise remediation. It is calculated based on the Exploit Cost and the number of non-admin users exposed to that attack path. The more users that are exposed, and the lower the exploit cost, the higher the risk score.  
**It is not intended to be a risk assessment in and of itself, and the intention is not to assign severities such as Critical, High, Medium etc to certain scores.**

The score is calculated using the following formula:  
```
Risk Score = (MaxExploitCostPossible - ExploitCost) / MaxExploitCostPossible * %ofEnabledNon-AdminUserswiththepath
```

MaxExploitCostPossible is 3 * the maximum number of hops seen across all attack paths. 3 is chosen because it is the highest score any single hop in an attack path can have.

### Exploit Cost
Exploit Cost is an estimation of how noisy or complex a particular attack path might be.  (Kudos to the [ACLPWN](https://github.com/fox-it/aclpwn.py) project for this idea.)  
For example, if an attacker has compromised userA and userA is a member of groupB then that step in the attack path doesn't require any further exploitation or real opsec considerations.  
Conversely if an attacker has compromised a user's workstation which also has an admin user session on it, to exploit this the attacker would (possibly) need to elevate permissions on the workstation and run something like Mimikatz to extract credentials from memory. This would require OPSEC considerations around monitoring of LSASS processes and also potentially require endpoint protectionbypasses. All of which make the exploitation that little bit more difficult.

*These scores have been assigned based upon my personal best judgement. They are not set in stone and discussions around the scoring are welcome and will only help to improve this.**
The scores assigned to each exploit are:
| Relationship        | Target Node Type    | OPSEC Considerations | Possible Protections to Bypass | Possible Privesc Required | Cost |
|---------------------|---------------------|----------------------|--------------------------------|---------------------------|------|
| Memberof            | Group               | No                   | No                             | No                        | 0    |
| HasSession          | Any                 | Yes                  | Yes                            | Yes                       | 3    |
| CanRDP              | Any                 | No                   | No                             | No                        | 0    |
| Contains            | Any                 | No                   | No                             | No                        | 0    |
| GPLink              | Any                 | No                   | No                             | No                        | 0    |
| AdminTo             | Any                 | Yes                  | No                             | No                        | 1    |
| ForceChangePassword | Any                 | Yes                  | No                             | No                        | 1    |
| AllowedToDelegate   | Any                 | Yes                  | No                             | No                        | 1    |
| AllowedToAct        | Any                 | Yes                  | No                             | No                        | 1    |
| AddAllowedToAct     | Any                 | Yes                  | No                             | No                        | 1    |
| ReadLapsPassword    | Any                 | Yes                  | No                             | No                        | 1    |
| ReadGMSAPassword    | Any                 | Yes                  | No                             | No                        | 1    |
| HasSidHistory       | Any                 | Yes                  | No                             | No                        | 1    |
| CanPSRemote         | Any                 | Yes                  | No                             | No                        | 1    |
| ExecuteDcom         | Any                 | Yes                  | No                             | No                        | 1    |
| SqlAdmin            | Any                 | Yes                  | No                             | No                        | 1    |
| AllExtendedRights   | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| AddMember           | Group               | Yes                  | No                             | No                        | 1    |
| AddSelf             | Group               | Yes                  | No                             | No                        | 1    |
| GenericAll          | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| WriteDACL           | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| WriteOwner          | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| Owns                | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| GenericWrite        | Group/User/Computer | Yes                  | No                             | No                        | 1    |
| AllExtendedRights   | Domain              | Yes                  | Yes                            | No                        | 2    |
| GenericAll          | Domain              | Yes                  | Yes                            | No                        | 2    |
| WriteDACL           | Domain              | Yes                  | Yes                            | No                        | 2    |
| WriteOwner          | Domain              | Yes                  | Yes                            | No                        | 2    |
| Owns                | Domain              | Yes                  | Yes                            | No                        | 2    |
| GenericAll          | GPO/OU              | Yes                  | No                             | No                        | 1    |
| WriteDACL           | GPO/OU              | Yes                  | No                             | No                        | 1    |
| WriteOwner          | GPO/OU              | Yes                  | No                             | No                        | 1    |
| Owns                | GPO/OU              | Yes                  | No                             | No                        | 1    |
| WriteSPN            | User                | Yes                  | No                             | No                        | 1    |
| AddKeyCredentialLink| Any                 | Yes                  | Yes                            | No                        | 2    |


## Acknowledgments
- The [py2neo](https://py2neo.org) project which makes this possible.
- The [PlumHound](https://github.com/PlumHound/PlumHound) project which gave me the idea of creating something similar which suited my needs.
- The [aclpwn](https://github.com/fox-it/aclpwn.py) for the idea around exploit cost.
- The [Bloodhound Gang Slack channel](https://bloodhoundhq.slack.com) for Cypher help.
- The [BloodHound project](https://bloodhound.readthedocs.io/en/latest/index.html) for changing the world and for continuing their support for the Open-Source community even when having a commercial offering.
