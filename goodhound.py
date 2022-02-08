from sqlite3.dbapi2 import Error
from py2neo import Graph
from datetime import datetime
import sys
import argparse
import pandas as pd
import logging
from collections import Counter
import sqlite3
import hashlib

def banner():
    print("""   ______                ____  __                      __""")
    print("""  / ____/___  ____  ____/ / / / /___  __  ______  ____/ /""")
    print(""" / / __/ __ \/ __ \/ __  / /_/ / __ \/ / / / __ \/ __  / """)
    print("""/ /_/ / /_/ / /_/ / /_/ / __  / /_/ / /_/ / / / / /_/ /  """)
    print(  "\____/\____/\____/\__,_/_/ /_/\____/\__,_/_/ /_/\__,_/   """)

def arguments():
    argparser = argparse.ArgumentParser(description="BloodHound Wrapper to determine the Busiest Attack Paths to High Value targets.", add_help=True, epilog="Attackers think in graphs, Defenders think in actions, Management think in charts.")
    parsegroupdb = argparser.add_argument_group('Neo4jConnection')
    parsegroupdb.add_argument("-u", "--username", default="neo4j", help="Neo4j Database Username (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-p", "--password", default="neo4j", help="Neo4j Database Password (Default: neo4j)", type=str)
    parsegroupdb.add_argument("-s", "--server", default="bolt://localhost:7687", help="Neo4j server Default: bolt://localhost:7687)", type=str)
    parsegroupoutput = argparser.add_argument_group('Output Formats')
    parsegroupoutput.add_argument("-o", "--output-format", default="stdout", help="Output formats supported: stdout, csv, md (markdown). Default: stdout.", type=str, choices=["stdout", "csv", "md", "markdown"])
    parsegroupoutput.add_argument("-f", "--output-filepath", default="~", help="File path to save the csv output.", type=str)
    parsegroupoutput.add_argument("-v", "--verbose", help="Enables verbose output.", action="store_true")
    parsegroupqueryparams = argparser.add_argument_group('Query Parameters')
    parsegroupqueryparams.add_argument("-r", "--results", default="5", help="The number of busiest paths to process. The higher the number the longer the query will take. Default: 5", type=int)
    parsegroupqueryparams.add_argument("-sort", "--sort", default="risk", help="Option to sort results by number of users with the path, number of hops or risk score. Default: Risk Score", type=str, choices=["users", "hops", "risk"])
    parsegroupqueryparams.add_argument("-q", "--query", help="Optionally add a custom query to replace the default busiest paths query. This can be used to run a query that perhaps does not take as long as the full run. The format should maintain the 'match p=shortestpath((g:Group)-[]->(n)) return distinct(g.name) as groupname, min(length(p)) as hops' structure so that it doesn't derp up the rest of the script. e.g. 'match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) WHERE tolower(g.name) =~ 'admin.*' return distinct(g.name) as groupname, min(length(p)) as hops'", type=str)
    parsegroupschema = argparser.add_argument_group('Schema')
    parsegroupschema.add_argument("-sch", "--schema", help="Optionally select a text file containing custom cypher queries to add labels to the neo4j database. e.g. Use this if you want to add the highvalue label to assets that do not have this by default in the BloodHound schema.", type=str)
    parsegroupsql = argparser.add_argument_group('SQLite Database')
    parsegroupsql.add_argument("--db-skip", help="Skips the logging of attack paths to a local SQLite Database", action="store_true")
    parsegroupsql.add_argument("-sqlpath", "--sql-path", default="goodhound.db", help="Sets the location of the SQLite Database", type=str)
    args = argparser.parse_args()
    return args

def db_connect(args):
    logging.info('Connecting to database.')
    try:
        graph = Graph(args.server, user=args.username, password=args.password)
        return graph    
    except:
        logging.warning("Database connection failure.")
        sys.exit(1)

def schema(graph, args):
    try:
        with open(args.schema,'r') as schema_query:
            line = schema_query.readline()
            logging.info('Writing schema.')
            while line:
                graph.run(line)
                line = schema_query.readline()
        logging.info("Written schema!")        
        return()
    except:
        logging.warning("Error setting custom schema.")
        sys.exit(1)

def cost(graph):
    cost=["MATCH (n)-[r:MemberOf]->(m:Group) SET r.pwncost = 0",
    "MATCH (n)-[r:HasSession]->(m) SET r.pwncost = 3",
    "MATCH (n)-[r:CanRDP|Contains|GpLink]->(m) SET r.pwncost = 0",
    "MATCH (n)-[r:AdminTo|ForceChangePassword|AllowedToDelegate|AllowedToAct|AddAllowedToAct|ReadLAPSPassword|ReadGMSAPassword|HasSidHistory]->(m) SET r.pwncost = 1",
    "MATCH (n)-[r:CanPSRemote|ExecuteDCOM|SQLAdmin ]->(m) SET r.pwncost = 1",
    "MATCH (n)-[r:AllExtendedRights|AddMember|AddMembers|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:Group) SET r.pwncost = 1",
    "MATCH (n)-[r:AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:User) SET r.pwncost = 1",
    "MATCH (n)-[r:AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:Computer) SET r.pwncost = 1",
    "MATCH (n)-[r:DCSync|GetChanges|GetChangesAll|AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns]->(m:Domain) SET r.pwncost = 2",
    "MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:GPO) SET r.pwncost = 1",
    "MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite ]->(m:OU) SET r.pwncost = 1"]
    print("Setting cost.")
    try:
        for c in cost:
            graph.run(c)
        return()
    except:
        logging.warning("Error setting cost!")
        sys.exit(1)

def shortestpath(graph, starttime, args):
    """Runs a shortest path query for all AD groups to high value targets. Returns a list of groups."""
    if args.query:
        query_shortestpath=f"%s" %args.query
    else:
        query_shortestpath="""match p=shortestpath((g:Group {highvalue:FALSE})-[*1..]->(n {highvalue:TRUE})) 
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
return groupname, hops, min(cost) as cost, nodeLabels, relLabels, path + final_node as full_path"""
    print("Running query, this may take a while.")
    try:
        groupswithpath=graph.run(query_shortestpath).data()
    except:
        logging.warning("There is a problem with the inputted query. If you have entered a custom query check the syntax.")
        sys.exit(1)
    querytime = round((datetime.now()-starttime).total_seconds() / 60)
    logging.info("Finished query in : {} Minutes".format(querytime))
    return groupswithpath

def busiestpath(groupswithpath, graph, args):
    """Calculate the busiest paths by getting the number of users in the Groups that have a path to Highvalue, sorting the result, calculating some statistics and returns a list."""
    totalenablednonadminsquery="""match (u:User {highvalue:FALSE, enabled:TRUE}) return count(u)"""
    totalenablednonadminusers = int(graph.run(totalenablednonadminsquery).evaluate())
    totalpaths = len(groupswithpath)
    paths=[]
    users=[]
    i=0
    # Get the maximum amount of hops in the dataset to be used as part of the risk score calculation
    maxhops=[]
    for sublist in groupswithpath:
        maxhops.append(sublist.get('hops'))
    maxcost = (max(maxhops))*3+1

    grouploopstart = datetime.now()
    print("Counting Users in Groups")
    for g in groupswithpath:
        i +=1
        group = g.get('groupname')
        hops = g.get('hops')
        cost = g.get('cost')
        fullpath = g.get('full_path')
        endnode = g.get('nodeLabels')[-1]
        uid = hashlib.md5(fullpath.encode()).hexdigest()
        if cost == None:
            # While debugging this should highlight edges without a score assigned.
            logging.info(f"Null edge cost found with {group} and {hops} hops.")
            cost = 0
        # Establishes if the group has already had the number of group members counted and skips it if so
        if (len(paths)==0) or (any(group == path[0] for path in paths) != True):
            print (f"Processing path {i} of {totalpaths}", end="\r")
            query_group_members = """match (u:User {highvalue:FALSE, enabled:TRUE})-[:MemberOf*1..]->(g:Group {name:"%s"}) return distinct(u.name) as members""" % group
            group_members = graph.run(query_group_members).data()
            num_members = len(group_members)
            if len(group_members) != 0:
                for m in group_members:
                    member = m.get('members')
                    users.append(member)
            percentage=round(float((num_members/totalenablednonadminusers)*100), 1)
            riskscore = round((((maxcost-cost)/maxcost)*percentage),1)
            result = [group, num_members, percentage, hops, cost, riskscore, fullpath, endnode, uid]
            paths.append(result)
        else:
            print (f"Processing path {i} of {totalpaths}", end="\r")
            for path in paths:
                if path[0] == group:
                    num_members = path[1]
                    percentage = path[2]
                    riskscore = round((((maxcost-cost)/maxcost)*percentage),1)
                    result = [group, num_members, percentage, hops, cost, riskscore, fullpath, endnode, uid]
                    paths.append(result)
                    break
    print("\n")
    # Calls the bh_query function to add the bloodhound path to the result
    allresults = bh_query(paths)
    # Removes duplicate starting groups from the results
    unique_groupswpath = []
    sorted_p = sorted(allresults, key=lambda i: (i[0], -i[5]))
    for p in sorted_p:
        group = p[0]
        num_members = p[1]
        percentage = p[2]
        hops = p[3]
        cost = p[4]
        riskscore = p[5]
        fullpath = p[6]
        query = p[7]
        uid = p[8]
        if (len(unique_groupswpath)==0) or (any(group == ugp[0] for ugp in unique_groupswpath) != True):
            unique = [group, num_members, percentage, hops, cost, riskscore, fullpath, query, uid]
            unique_groupswpath.append(unique)
    if args.sort == 'users':
        top_paths = (sorted(unique_groupswpath, key=lambda i: -i[2])[0:args.results])
    elif args.sort == 'hops':
        top_paths = (sorted(unique_groupswpath, key=lambda i: i[3])[0:args.results])
    else:
        top_paths = (sorted(unique_groupswpath, key=lambda i: (-i[5], i[4], i[3]))[0:args.results])
    # Processes the output into a dataframe
    total_unique_users = len((pd.Series(users, dtype="O")).unique())
    total_users_percentage = round(((total_unique_users/totalenablednonadminusers)*100),1)
    grandtotals = [{"Total Non-Admins with a Path":total_unique_users, "Percentage of Total Enabled Non-Admins":total_users_percentage, "Total Paths":totalpaths}]
    grouploopfinishtime = datetime.now()
    grouplooptime = round((grouploopfinishtime-grouploopstart).total_seconds() / 60)
    logging.info("Finished counting users in: {} minutes.".format(grouplooptime))
    return top_paths, grandtotals, totalpaths, allresults

#def commonnode(groupswithpath):
#    nodes = []
#    for path in groupswithpath:
#        steps = path.get('nodeLabels')[1:-1]
#        for step in steps:
#            nodes.append(step)
#    common_node = Counter(nodes).most_common(1)
#    return common_node

def commonlinks(groupswithpath, totalpaths):
    """Attempts to determine the most common weak links across all attack paths"""
    links = []
    for path in groupswithpath:
        nodes = path.get('nodeLabels')
        rels = path.get('relLabels')
        # assembles the nodes and rels into a chain
        chain = sum(zip(nodes, rels+[0]), ())[:-1]
        # Divides the chains into Node-Rel-Node-Rel-Node groups as attack paths are usually "This can do that to the other. The other can then do this."
        for c in chain[:-4:2]:
            endlink = int(chain.index(c))+5
            link = []
            for ch in chain[chain.index(c):endlink]:
                link.append(ch)
            # Makes it into a neat string
            link = '->'.join(link)
            links.append(link)
    common_link = list(Counter(links).most_common(5))
    weakest_links = []
    for x in common_link:
        l = list(x)
        pct = round(l[1]/totalpaths*100,1)
        l.append(pct)
        weakest_links.append(l)
    return weakest_links

    
    
def bh_query(paths):
    """Generate a replayable query for each finding for Bloodhound visualisation."""
    allresults = []
    for t in paths:
        group = t[0]
        num_users = int(t[1])
        percentage = float(t[2])
        hops = int(t[3])
        cost = int(t[4])
        riskscore = float(t[5])
        fullpath = str(t[6])
        endnode = str(t[7])
        uid = str(t[8])
        previous_hop = hops - 1
        query = """match p=((g:Group {name:'%s'})-[*%s..%s]->(n {name:'%s'})) return p""" %(group, previous_hop, hops, endnode)
        result = [group, num_users, percentage, hops, cost, riskscore, fullpath, query, uid]
        allresults.append(result)

    return allresults

def output(results, grandtotals, totalpaths, args, starttime, new_path, seen_before, weakest_links, scandatenice):
    finish = datetime.now()
    totalruntime = round((finish - starttime).total_seconds() / 60)
    logging.info("Total runtime: {} minutes.".format(totalruntime))
    pd.set_option('display.max_colwidth', None)
    grandtotals[0]["% of Paths Seen Before"] = seen_before/totalpaths*100
    grandtotals[0]["New Paths"] = new_path
    totaldf = pd.DataFrame(grandtotals)
    weakest_linkdf = pd.DataFrame(weakest_links, columns=["Weakest Link", "Number of Paths it appears in", "% of Total Paths"])
    resultsdf = pd.DataFrame(results, columns=["Starting Group", "Number of Enabled Non-Admins with Path", "Percent of Total Enabled Non-Admins with Path", "Number of Hops", "Exploit Cost", "Risk Score", "Path", "Bloodhound Query", "UID"])
    if args.output_format == "stdout":
        print("\n\nGRAND TOTALS")
        print("============")
        print(totaldf.to_string(index=False))
        print("\nBUSIEST PATHS")
        print("-------------\n")
        print (resultsdf.to_string(index=False))
        print("-------------\n")
        print("\nTHE WEAKEST LINKS")
        print (weakest_linkdf.to_string(index=False))
    elif args.output_format == ("md" or "markdown"):
        print("# GRAND TOTALS")
        print (totaldf.to_markdown(index=False))
        print("## BUSIEST PATHS")
        print (resultsdf.to_markdown(index=False))
        print("## THE WEAKEST LINKS")
        print (weakest_linkdf.to_markdown(index=False))
    else:
        summaryname = f"{args.output_filepath}\\" + f"{scandatenice}" + "_GoodHound_summary.csv"
        busiestpathsname = f"{args.output_filepath}\\" + f"{scandatenice}" + "_GoodHound_busiestpaths.csv"
        weakestlinkname = f"{args.output_filepath}\\" + f"{scandatenice}" + "_GoodHound_weakestlinks.csv"
        totaldf.to_csv(summaryname, index=False)
        resultsdf.to_csv(busiestpathsname, index=False)
        weakest_linkdf.to_csv(weakestlinkname, index=False)

def db(allresults, graph, args):
    """Inserts all of the attack paths found into a SQLite database"""
    table_sql = """CREATE TABLE IF NOT EXISTS paths (
	uid TEXT PRIMARY KEY,
	groupname TEXT NOT NULL,
	num_users INTEGER NOT NULL,
	percentage REAL NOT NULL,
	hops INTEGER NOT NULL,
	cost INTEGER NOT NULL,
    riskscore REAL NOT NULL,
    fullpath TEXT NOT NULL,
    query TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);"""
    #if args.sql_path == "goodhound.db":
     #   if not os.path.exists(os.path.join(os.getcwd(), 'db')):
      #      os.makedirs('db')
    conn = None
    try:
        conn = sqlite3.connect(args.sql_path)
        c = conn.cursor()
        c.execute(table_sql)
        # Find the date that the Sharphound collection was run based on the most recent lastlogondate timestamp of the Domain Controllers
        scandate_query="""WITH '(?i)ldap/.*' as regex_one WITH '(?i)gc/.*' as regex_two MATCH (n:Computer) WHERE ANY(item IN n.serviceprincipalnames WHERE item =~ regex_two OR item =~ regex_two ) return n.lastlogontimestamp as date order by date desc limit 1"""
        scandate = int(graph.run(scandate_query).evaluate())
        scandatenice = (datetime.fromtimestamp(scandate)).strftime("%Y-%m-%d")
        seen_before=0
        new_path=0
        for r in allresults:
            insertvalues = (r[8],r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],scandate,scandate,)
            insertpath_sql = 'INSERT INTO paths VALUES (?,?,?,?,?,?,?,?,?,?,?)'
            # Determines if the path has been previously logged in the database using the UID and updates the last_seen field
            updatevalues = {"last_seen":scandate, "uid":r[8]}
            updatepath_sql = 'UPDATE paths SET last_seen=:last_seen WHERE uid=:uid'
            # Determines if the path has not been seen before based on the UID and inserts it into the database
            c.execute("SELECT count(*) FROM paths WHERE uid = ?", (r[8],))
            data = c.fetchone()[0]
            if data==0:
                c.execute(insertpath_sql, insertvalues)
                new_path += 1
            else:
                # Catch to stop accidentally overwriting the database with older data
                c.execute("SELECT last_seen from paths WHERE uid = ?", (r[8],))
                pathlastseen = int(c.fetchone()[0])
                if pathlastseen < scandate:
                    c.execute(updatepath_sql, updatevalues)
                # update first_seen if an older dataset is loaded in
                c.execute("SELECT first_seen from paths WHERE uid = ?", (r[8],))
                pathfirstseen = int(c.fetchone()[0])
                if pathfirstseen > scandate:
                    c.execute("UPDATE paths SET first_seen=:first_seen WHERE uid=:uid", {"first_seen":scandate, "uid":r[8]})
                seen_before += 1
        conn.commit()
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()
    return new_path, seen_before, scandatenice


def main():
    args = arguments()
    if args.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    banner()
    graph = db_connect(args)
    starttime = datetime.now()
    if args.schema:
        schema(graph, args)
    cost(graph)
    groupswithpath = shortestpath(graph, starttime, args)
    top_paths, grandtotals, totalpaths, allresults = busiestpath(groupswithpath, graph, args)
    weakest_links = commonlinks(groupswithpath, totalpaths)
    if not args.db_skip:
        new_path, seen_before, scandatenice = db(allresults, graph, args)
        output(top_paths, grandtotals, totalpaths, args, starttime, new_path, seen_before, weakest_links, scandatenice)
    else:
        new_path = 0
        seen_before = 0
        scandate_query="""WITH '(?i)ldap/.*' as regex_one WITH '(?i)gc/.*' as regex_two MATCH (n:Computer) WHERE ANY(item IN n.serviceprincipalnames WHERE item =~ regex_two OR item =~ regex_two ) return n.lastlogontimestamp as date order by date desc limit 1"""
        scandate = int(graph.run(scandate_query).evaluate())
        scandatenice = (datetime.fromtimestamp(scandate)).strftime("%Y-%m-%d")
        output(top_paths, grandtotals, totalpaths, args, starttime, new_path, seen_before, weakest_links, scandatenice)

if __name__ == "__main__":
    main()