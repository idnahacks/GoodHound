from py2neo import Graph
from datetime import datetime
import sys
import argparse
import pandas

def arguments():
    argparser = argparse.ArgumentParser(description="BloodHound Wrapper to determine the Busiest Attack Paths to High Value targets.", add_help=True, epilog="Attackers think in graphs, Defenders think in actions, Management think in charts.")
    parsegroupdb = argparser.add_argument_group('Neo4jConnection')
    parsegroupdb.add_argument("-u", "--username", default="neo4j", help="Neo4j Database Username (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-p", "--password", default="neo4j", help="Neo4j Database Password (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-s", "--server", default="bolt://localhost:7687", help="Neo4j server Default: bolt://localhost:7687)", type=str)
    parsegroupoutput = argparser.add_argument_group('Output Formats')
    parsegroupoutput.add_argument("-o", "--output-format", default="stdout", help="Output formats supported: stdout, csv, md (markdown).", type=str, choices=["stdout", "csv", "md", "markdown"])
    parsegroupoutput.add_argument("-f", "--output-filename", default="goodhound.csv", help="File path and name to save the csv output.", type=str)
    parsegroupqueryparams = argparser.add_argument_group('Query Parameters')
    parsegroupqueryparams.add_argument("-r", "--results", default="5", help=("The number of busiest paths to process. The higher the number the longer the query will take. Default: 5"), type=int)

    args = argparser.parse_args()
    return args

def db_connect(args):
    try:
        graph = Graph(args.server, user=args.username, password=args.password)
        return graph    
    except:
        print("Database connection failure.")
        sys.exit(1)

def shortestpath(graph, starttime):
    """Runs a shortest path query for all AD groups to high value targets. Returns a list of groups."""
    query_shortestpath="""match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) return distinct(g.name) as groupname, min(length(p)) as hops"""
    query_test="""match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) WHERE tolower(g.name) =~ 'admin.*' return distinct(g.name) as groupname, min(length(p)) as hops""" 
    print("Running query")
    groupswithpath=graph.run(query_shortestpath)
    querytime = round((datetime.now()-starttime).total_seconds() / 60)
    print("Finished query in : {} Minutes".format(querytime))
    return groupswithpath

def busiestpath(groupswithpath, graph, args):
    """Calculate the busiest paths by getting the number of users in the Groups that have a path to Highvalue, sorting the result, calculating some statistics and returns a list."""
    totalenablednonadminsquery="""match (u:User {highvalue:FALSE, enabled:TRUE}) return count(u)"""
    totalenablednonadminusers = int(graph.run(totalenablednonadminsquery).evaluate())
    usercount=[]
    grouploopstart = datetime.now()
    print("Starting group loop")
    for g in groupswithpath:
        group = g.get('groupname')
        hops = g.get('hops')
        print (f"Processing group: {group}................................................", end='\r')
        query_num_members = """match (u:User {highvalue:FALSE, enabled:TRUE})-[:MemberOf*1..]->(g:Group {name:"%s"}) return count(distinct(u))""" % group
        num_members = int(graph.run(query_num_members).evaluate())
        percentage=round(float((num_members/totalenablednonadminusers)*100), 1)
        result = [group, num_members, percentage, hops]
        usercount.append(result)
    
    top = (sorted(usercount, key=lambda i: -i[1])[0:args.results])
    grouploopfinishtime = datetime.now()
    grouplooptime = round((grouploopfinishtime-grouploopstart).total_seconds() / 60)
    print("\nFinished group loop in: {} minutes.".format(grouplooptime))
    return top

def query(top, starttime):
    """Generate a replayable query for each finding for Bloodhound visualisation."""
    results = []
    for t in top:
        group = t[0]
        num_users = int(t[1])
        percentage = float(t[2])
        hops = int(t[3])
        previous_hop = hops - 1
        query = """match p=((g:Group {name:"%s"})-[*%s..%s]->(n {highvalue:true})) return p""" %(group, previous_hop, hops)
        result = [group, num_users, percentage, hops, query]
        results.append(result)
    finish = datetime.now()
    totalruntime = round((finish - starttime).total_seconds() / 60)
    print("Total runtime: {} minutes.".format(totalruntime), end='\n\n')
    return results

def hopcount(top, graph, starttime, args):
    """Calculate the shortest number of hops for each of the busiest paths and produce a cypher query to enter into Bloodhound. Returns a list of results."""
    hoploopstart = datetime.now()
    print("\nStarted hop loop")
    num_hops = 0
    top_hops = []
    for t in top:
        group = t[0]
        num_users = int(t[1])
        percentage = float(t[2])
        for h in range(1,5):
            previous_hop = h - 1
            print (f"Trying hop number {h} for {group}............................", end='\r')
            query_num_hops = """match p=((g:Group {name:"%s"})-[*%s..%s]->(n {highvalue:true})) return p""" %(group, previous_hop, h)
            if (graph.run(query_num_hops).evaluate()):
                num_hops = int(h)
                result = [group, num_users, percentage, num_hops, query_num_hops]
                top_hops.append(result)
                break
            else:
                h += 1
    hoploopfinish = datetime.now()  
    hoplooptime = round((hoploopfinish - hoploopstart).total_seconds() / 60)
    print("\nFinished hop loop in: {} minutes.".format(hoplooptime))
    totalruntime = round((hoploopfinish - starttime).total_seconds() / 60)
    print("Total runtime: {} minutes.".format(totalruntime), end='\n\n')
    return top_hops

def output(results, args):
    pandas.set_option('display.max_colwidth', None)
    df = pandas.DataFrame(results)
    df.columns = ["Starting Group", "Number of Users with Path", "Percent of Total Enabled Non-Admins", "Number of Hops", "Bloodhound Query"]
    if args.output_format == "stdout":
        print (df.to_string(index=False))
    elif args.output_format == ("md" or "markdown"):
        print (df.to_markdown(index=False))
    else:
        df.to_csv(args.output_filename, index=False)

def main():
    args = arguments()
    graph = db_connect(args)
    starttime = datetime.now()
    groupswithpath = shortestpath(graph, starttime)
    top = busiestpath(groupswithpath, graph, args)
    #top_hops = hopcount(top, graph, starttime, args)
    results = query(top, starttime)
    output(results, args)

if __name__ == "__main__":
    main()