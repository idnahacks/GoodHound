import argparse
import os
import logging
from datetime import datetime
from goodhound import ghresults, sqldb, ghutils, paths, neodb

def arguments():
    argparser = argparse.ArgumentParser(description="BloodHound Wrapper to determine the Busiest Attack Paths to High Value targets.", add_help=True, epilog="Attackers think in graphs, Defenders think in actions, Management think in charts.")
    parsegroupdb = argparser.add_argument_group('Neo4jConnection')
    parsegroupdb.add_argument("-u", "--username", default="neo4j", help="Neo4j Database Username (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-p", "--password", default="neo4j", help="Neo4j Database Password (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-s", "--server", default="bolt://localhost:7687", help="Neo4j server Default: bolt://localhost:7687)", type=str)
    parsegroupoutput = argparser.add_argument_group('Output Formats')
    parsegroupoutput.add_argument("-o", "--output-format", default="csv", help="Output formats supported: stdout, csv, md (markdown). Default: csv.", type=str, choices=["stdout", "csv", "md", "markdown"])
    parsegroupoutput.add_argument("-f", "--output-filepath", default=os.getcwd(), help="File path to save the csv output. Defaults to current directory.", type=str)
    parsegroupoutput.add_argument("-v", "--verbose", help="Enables verbose output.", action="store_true")
    parsegroupqueryparams = argparser.add_argument_group('Query Parameters')
    parsegroupqueryparams.add_argument("-r", "--results", default="5", help="The number of busiest paths to process. The higher the number the longer the query will take. Default: 5", type=int)
    parsegroupqueryparams.add_argument("-sort", "--sort", default="risk", help="Option to sort results by number of users with the path, number of hops or risk score. Default: Risk Score", type=str, choices=["users", "hops", "risk"])
    parsegroupqueryparams.add_argument("-q", "--query", help="Optionally add a custom query to replace the default busiest paths query. This can be used to run a query that perhaps does not take as long as the full run. The format should maintain the 'match p=shortestpath((g:Group)-[]->(n)) return distinct(g.name) as groupname, min(length(p)) as hops' structure so that it doesn't derp up the rest of the script. e.g. 'match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) WHERE tolower(g.name) =~ 'admin.*' return distinct(g.name) as groupname, min(length(p)) as hops'", type=str)
    parsegroupschema = argparser.add_argument_group('Schema')
    parsegroupschema.add_argument("-sch", "--schema", help="Optionally select a text file containing custom cypher queries to add labels to the neo4j database. e.g. Use this if you want to add the highvalue label to assets that do not have this by default in the BloodHound schema.", type=str)
    parsegroupschema.add_argument("--patch41", help="A temporary option to patch a bug in Bloodhound 4.1 relating to the highvalue attribute.", action="store_true")
    parsegroupsql = argparser.add_argument_group('SQLite Database')
    parsegroupsql.add_argument("--db-skip", help="Skips the logging of attack paths to a local SQLite Database", action="store_true")
    parsegroupsql.add_argument("-sqlpath", "--sql-path", default=os.getcwd(), help="Sets the file path of the SQLite Database file goodhound.db", type=str)
    args = argparser.parse_args()
    return args

def main():
    args = arguments()
    if args.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    ghutils.banner()
    os = ghutils.getos()
    graph = neodb.db_connect(args)
    starttime = datetime.now()
    neodb.warmupdb(graph)
    if args.schema:
        neodb.schema(graph, args)
    neodb.cost(graph)
    if args.pathch41:
        neodb.bloodhound41patch(graph)
    neodb.set_hv_for_dcsyncers(graph)
    groupswithpath, userswithpath = paths.shortestgrouppath(graph, starttime, args)
    totalenablednonadminusers = neodb.totalusers(graph)
    uniquegroupswithpath = paths.getuniquegroupswithpath(groupswithpath)
    groupswithmembers = paths.processgroups(graph, uniquegroupswithpath)
    totaluniqueuserswithpath = paths.gettotaluniqueuserswithpath(groupswithmembers, userswithpath)
    results = ghresults.generateresults(groupswithpath, groupswithmembers, totalenablednonadminusers, userswithpath)
    new_path, seen_before, scandatenice = sqldb.db(results, graph, args, os)
    uniqueresults = ghresults.getuniqueresults(results)
    top_results = ghresults.sortresults(args, uniqueresults)
    totalpaths = len(groupswithpath+userswithpath)
    weakest_links = paths.weakestlinks(groupswithpath, totalpaths, userswithpath)
    grandtotalsdf, weakest_linkdf, busiestpathsdf = ghresults.grandtotals(totaluniqueuserswithpath, totalenablednonadminusers, totalpaths, new_path, seen_before, weakest_links, top_results)
    ghresults.output(args, grandtotalsdf, weakest_linkdf, busiestpathsdf, scandatenice, starttime, os)

if __name__ == "__main__":
    main()