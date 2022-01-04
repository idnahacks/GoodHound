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

## Usage

### Default behaviour

All options are __optional__. The default behaviour is to connect to a neo4j server setup with the default ip (http://localhost:7474) and credentials (neo4j:neo4j), calculate the busiest paths from non-admin users to highvalue targets as defined with the default Bloodhound setup, and print the ouput to the screen.

The neo4j database will need to already have the Sharphound collector output uploaded using the Upload button in the Bloodhound GUI. An example Sharphound output collected using [Bad Blood](https://github.com/davidprowe/BadBlood) on a [Detection Labs](https://detectionlab.network/) can be found in this repo at [/Sample%20SharpHound%20Output](/Sample%20SharpHound%20Output).

The output shows a total number of unique users that have a path to a HighValue target.  
It then breaks this down to individual paths, ordered by the risk score (more on this later).
Each path is then displayed showing the starting group, the number of non-admin users within that path, the number of hops, the risk score, a text version of the path and also a Cypher query. This cypher query can be directly copied into the Raw Query bar in Bloodhound for a visual representation of the attack path. 

![Example Output](images/example-output.png)  
![BloodHound Attack Path](images/bloodhound-raw-query.png)  


### Options

#### Database settings
-s can be used to point GoodHound to a server other than the default localhost installation  
-u can be used to set the neo4j username  
-p can be used to set the neo4j password  

#### Output formats
-o can be used to select from:  
- stdout -displays the output on screen
- csv saves a comma separated values file for use with reporting or MI (completing the graphs, actions, charts trifecta in the tagline)
- md or markdown to display a markdown formatted output  

-f an optional filename for the csv output option  
-v enables verbose output to display query times

#### Number of results
-r can be used to select the amount of results to show. By default the top 5 busiest paths are displayed.  
-sort can be used to sort by:
 - number of users with the path (descending)
 - hop count (ascending)
 - risk score (descending)

#### Schema
-sch select a file containing cypher queries to set a custom schema to alter the default Bloodhound schema. This can be useful if you want to set the 'highvalue' label on AD objects that are not covered as standard, helping to provide internal context.
For example, you want to add the highvalue label to 'dbserver01' because it contains all of your customer records. The schema file to load in could contain the following cypher query:  
```
match (c:Computer {name:'DBSERVER01@YOURDOMAIN.LOCAL'}) set c.highvalue=TRUE
```
The schema can contain multiple queries, each on a separate line.

#### Query
-q can be used to override the default query that is run to calculate the busiest path. This can be useful if your dataset is large and you want to temporarily load in a query that looks at a smaller set of your data in order to quickly try GoodHound out.  
Care should be taken to ensure that the query provides output in the same way as the built-in query, so it doesn't stop any other part of GoodHound running.  
The original query is :  
```
'match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) 
with reduce(totalscore = 0, rels in relationships(p) | totalscore + rels.pwncost) as cost, 
length(p) as hops, 
g.name as groupname, 
[node in nodes(p) | coalesce(node.name, "")] as nodeLabels,
[rel in relationships(p) | type(rel)] as relationshipLabels
with
reduce(path="", x in range(0,hops-1) | path + nodeLabels[x] + " - " + relationshipLabels[x] + " -> ") as path,
nodeLabels[hops] as final_node,
hops as hops, 
groupname as groupname, 
cost as cost,
nodeLabels as nodeLabels,
relationshipLabels as relLabels
return groupname, hops, min(cost) as cost, nodeLabels, relLabels, path + final_node as full_path'
```
and so an example to retrieve a subset might be:  
```
'match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) WHERE tolower(g.name) =~ 'admin.*' with reduce(totalscore = 0, rels in relationships(p) | totalscore + rels.pwncost) as cost, length(p) as hops, g.name as groupname, [node in nodes(p) | coalesce(node.name, '')] as nodeLabels, [rel in relationships(p) | type(rel)] as relationshipLabels with reduce(path='', x in range(0,hops-1) | path + nodeLabels[x] + ' - ' + relationshipLabels[x] + ' -> ') as path, nodeLabels[hops] as final_node, hops as hops, groupname as groupname, cost as cost, nodeLabels as nodeLabels, relationshipLabels as relLabels return groupname, hops, min(cost) as cost, nodeLabels, relLabels, path + final_node as full_path'
```

#### SQLite Database
By default Goodhound stores all attack paths in a SQLite database stored at db/goodhound.db. This gives the opportunity to query attack paths over time.  
--db-skip will skip logging anything to a local database  
--sql-path can be used to point Goodhound to a SQLite db file that is not stored in the default location.

### Performance

Larger datasets can take time to process. Some performance improvements can be seen by selecting to "warm-up" the database using the option in the Bloodhound GUI. There are also many guides for tuning the neo4j database for increased performance which are out of scope here (although if I make any significant improvements I'll document the findings).

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



## Acknowledgments
- The [py2neo](https://py2neo.org/2021.1/) project which makes this possible.
- The [PlumHound](https://github.com/PlumHound/PlumHound) project which gave me the idea of creating something similar which suited my needs.
- The [Bloodhound Gang Slack channel](bloodhoundhq.slack.com) for Cypher help.
- The [BloodHound project](https://bloodhound.readthedocs.io/en/latest/index.html) for changing the world.