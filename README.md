# GoodHound
![PyPI - Downloads](https://img.shields.io/pypi/dm/goodhound)
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
pip install goodhound
goodhound -p "neo4jpassword"
```
This will process the data in neo4j and output 3 csv reports in the current working directory.

![Demo](images/demo.gif)

## Documentation
All documentation can be found in the [wiki](https://github.com/idnahacks/GoodHound/wiki)

## Acknowledgments
- The [py2neo](https://py2neo.org) project which makes this possible.
- The [PlumHound](https://github.com/PlumHound/PlumHound) project which gave me the idea of creating something similar which suited my needs.
- The [aclpwn](https://github.com/fox-it/aclpwn.py) for the idea around exploit cost.
- The [Bloodhound Gang Slack channel](https://bloodhoundhq.slack.com) for Cypher help.
- The [BloodHound project](https://bloodhound.readthedocs.io/en/latest/index.html) for changing the world and for continuing their support for the Open-Source community even when having a commercial offering.
