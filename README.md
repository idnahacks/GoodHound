# GoodHound
Uses neo4j and Sharphound output to determine the busiest paths to high value targets.

## To do
- [x] option to output cypher to load busiest path into Bloodhound for report screenshot
- [x] add lowest number of hops to HV as a metric
- [x] tidy up code
- [x] Enter neo4j creds as parameters
- [x] Allow user choice for output format
- [x] User choice of number of results displayed
- [ ] Query overide options
- [x] Export to csv
- [ ] Documentation (requirements, pandas, py2neo)
- [ ] Limit query time counting to verbose mode (use loggy?)
- [ ] Query Performance (is threading or neo4j tuning an option?)
- [x] Add count of total distinct users that have any path
- [ ] add ability to setup schema
- [ ] add ability to warm up database if possible.
- [ ] only the shortest path for each busiest path is displayed. If one pathway has many paths this will be hidden. Unsure if this is an issue or not.
- [x] can the hop count be done as part of the original shortestpath query?
- [ ] support encrypted neo4j connection.

