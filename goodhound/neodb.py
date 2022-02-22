from datetime import datetime
import logging
import sys
from py2neo import Graph

def db_connect(args):
    """Sets up the connection to the neo4j database"""
    logging.info('Connecting to database.')
    try:
        graph = Graph(args.server, user=args.username, password=args.password)
        return graph    
    except Exception as e:
        logging.error("Database connection failure.")
        logging.error(e.__context__)
        sys.exit(1)

def schema(graph, args):
    """Optionally runs cypher statements to add attributes to nodes or edges."""
    try:
        with open(args.schema,'r') as schema_query:
            line = schema_query.readline()
            logging.info('Writing schema.')
            while line:
                graph.run(line)
                line = schema_query.readline()
        logging.info("Written schema!")        
    except:
        logging.warning("Error setting custom schema.")
        sys.exit(1)

def bloodhound41patch(graph):
    """Bloodhound 4.1 doesn't automatically tag non highvalue items with the attribute."""
    logging.info('Patching for Bloodhound 4.1')
    hvpatch="""match (n:Base) where n.highvalue is NULL set n.highvalue = FALSE"""
    graph.run(hvpatch)

def set_hv_for_dcsyncers(graph):
    """Searches for AD principals that can perform a DCSync attack and sets their highvalue property to TRUE if they're not already a member of a HighValue group."""
    logging.info('Searching for paths to targets that can perform a DCSync attack.')
    hvusersquery="""match (n)-[:MemberOf*1..]->(g:Group {highvalue:true}) with n as hv match (hv {highvalue:false}) return distinct(hv.name) as name"""
    hvusers=graph.run(hvusersquery).data()
    dcsyncusersquery="""MATCH (n1)-[:MemberOf|GetChanges*1..]->(u:Domain) WITH n1,u MATCH (n1)-[:MemberOf|GetChangesAll*1..]->(u) WITH n1,u MATCH p = (n1)-[:MemberOf|GetChanges|GetChangesAll*1..]->(u) RETURN distinct(n1.objectid) as sid, n1.name as name"""
    dcsyncusers=graph.run(dcsyncusersquery).data()
    for u in dcsyncusers:
        name = u.get("name")
        sid = u.get("sid")
        #fix any objects that have a null name
        if name == None:
            name = sid
        if name not in hvusers:
            addhighvaluequery="""MATCH (n {name:"%s"}) set n.highvalue=true""" %name
            graph.run(addhighvaluequery)

def cost(graph):
    cost=["MATCH (n)-[r:MemberOf]->(m:Group) SET r.cost = 0",
    "MATCH (n)-[r:HasSession]->(m) SET r.cost = 3",
    "MATCH (n)-[r:CanRDP|Contains|GpLink]->(m) SET r.cost = 0",
    "MATCH (n)-[r:AdminTo|ForceChangePassword|AllowedToDelegate|AllowedToAct|AddAllowedToAct|ReadLAPSPassword|ReadGMSAPassword|HasSidHistory]->(m) SET r.cost = 1",
    "MATCH (n)-[r:CanPSRemote|ExecuteDCOM|SQLAdmin ]->(m) SET r.cost = 1",
    "MATCH (n)-[r:AllExtendedRights|AddMember|AddMembers|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite|AddSelf]->(m:Group) SET r.cost = 1",
    "MATCH (n)-[r:AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite|WriteSPN]->(m:User) SET r.cost = 1",
    "MATCH (n)-[r:AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:Computer) SET r.cost = 1",
    "MATCH (n)-[r:GetChanges|GetChangesAll|AllExtendedRights|GenericAll|WriteDacl|WriteOwner|Owns]->(m:Domain) SET r.cost = 2",
    "MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite]->(m:GPO) SET r.cost = 1",
    "MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner|Owns|GenericWrite ]->(m:OU) SET r.cost = 1",
    "MATCH (n)-[r:AddKeyCredentialLink]->(m) set r.cost = 2"]
    logging.info("Setting cost.")
    try:
        for c in cost:
            graph.run(c)
        return()
    except:
        logging.warning("Error setting cost!")
        sys.exit(1)

def totalusers(graph):
    """Calculate the total users in the dataset."""
    totalenablednonadminsquery="""match (u:User {highvalue:FALSE, enabled:TRUE}) return count(u)"""
    totalenablednonadminusers = int(graph.run(totalenablednonadminsquery).evaluate())
    return totalenablednonadminusers

def getscandate(graph):
    """Find the date that the Sharphound collection was run based on the most recent lastlogondate timestamp of the Domain Controllers"""
    scandate_query="""WITH '(?i)ldap/.*' as regex_one WITH '(?i)gc/.*' as regex_two MATCH (n:Computer) WHERE ANY(item IN n.serviceprincipalnames WHERE item =~ regex_two OR item =~ regex_two ) return n.lastlogontimestamp as date order by date desc limit 1"""
    scandate = int(graph.run(scandate_query).evaluate())
    scandatenice = (datetime.fromtimestamp(scandate)).strftime("%Y-%m-%d")
    return scandate, scandatenice

def warmupdb(graph, args):
    if not args.quiet:
        print("Warming up database")
    warmupdbquery = """MATCH (n) OPTIONAL MATCH (n)-[r]->() RETURN count(n.name) + count(r.isacl)"""
    graph.run(warmupdbquery)