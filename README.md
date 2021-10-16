# GoodHound

```
   ______                ____  __                      __
  / ____/___  ____  ____/ / / / /___  __  ______  ____/ /
 / / __/ __ \/ __ \/ __  / /_/ / __ \/ / / / __ \/ __  / 
/ /_/ / /_/ / /_/ / /_/ / __  / /_/ / /_/ / / / / /_/ /  
\____/\____/\____/\__,_/_/ /_/\____/\__,_/_/ /_/\__,_/   
                                                         
```

Uses neo4j and Sharphound output to determine the busiest paths to high value targets.

## Syntax
usage: goodhound.py [-h] [-u USERNAME] [-p PASSWORD] [-s SERVER] [-o {stdout,csv,md,markdown}] [-f OUTPUT_FILENAME] [-r RESULTS] [-q QUERY] [-sch SCHEMA]

BloodHound Wrapper to determine the Busiest Attack Paths to High Value targets.

optional arguments:
  -h, --help            show this help message and exit

Neo4jConnection:
  -u USERNAME, --username USERNAME
                        Neo4j Database Username (Default: neo4j)
  -p PASSWORD, --password PASSWORD
                        Neo4j Database Password (Default: neo4j)
  -s SERVER, --server SERVER
                        Neo4j server Default: bolt://localhost:7687)

Output Formats:
  -o {stdout,csv,md,markdown}, --output-format {stdout,csv,md,markdown}
                        Output formats supported: stdout, csv, md (markdown). Default: stdout.
  -f OUTPUT_FILENAME, --output-filename OUTPUT_FILENAME
                        File path and name to save the csv output.

Query Parameters:
  -r RESULTS, --results RESULTS
                        The number of busiest paths to process. The higher the number the longer the query will take. Default: 5
  -q QUERY, --query QUERY
                        Optionally add a custom query to replace the default busiest paths query. This can be used to run a query that perhaps does not take as long as the full run. The format should maintain the `'match p=shortestpath((g:Group)-[]->(n)) return distinct(g.name) as groupname, min(length(p)) as hops'` structure so that it doesn't derp up the rest of the script.
                        e.g.:
                        ```
                        'match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) WHERE tolower(g.name) =~ 'admin.*' return distinct(g.name) as groupname, min(length(p)) as hops'
                        ```

Schema:
  -sch SCHEMA, --schema SCHEMA
                        Optionally select a text file containing custom cypher queries to add labels to the neo4j database. e.g. Use this if you want to add the highvalue label to assets that do not have this by default in the BloodHound schema.

## Installation
TBD: Requires py2neo and pandas to be installed.

## Acknowledgments
- The py2neo project which makes this possible.
- The PlumHound project which gave me the idea of creating something similar which suited my needs.
- The Bloodhound Gang Slack channel for Cypher help.
- The BloodHound project for changing the world.

## To do
- [x] option to output cypher to load busiest path into Bloodhound for report screenshot
- [x] add lowest number of hops to HV as a metric
- [x] tidy up code
- [x] Enter neo4j creds as parameters
- [x] Allow user choice for output format
- [x] User choice of number of results displayed
- [x] Query overide options
- [x] Export to csv
- [ ] Documentation (requirements, pandas, py2neo)
- [ ] Limit query time counting to verbose mode (use loggy?)
- [ ] Query Performance (is threading or neo4j tuning an option?)
- [x] Add count of total distinct users that have any path
- [x] add ability to setup schema
- [ ] add ability to warm up database if possible.
- [ ] only the shortest path for each busiest path is displayed. If one pathway has many paths this will be hidden. Unsure if this is an issue or not.
- [x] can the hop count be done as part of the original shortestpath query?
- [ ] support encrypted neo4j connection.

