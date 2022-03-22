import logging
from collections import Counter
from datetime import datetime
from sys import exit
from goodhound import ghutils

def fixnullobjectnames(paths):
    for p in paths:
        name = p.get("startnode")
        sid = p.get("SID")
        if name == None:
            p["startnode"] = sid

def shortestgrouppath(graph, starttime, args):
    """
    Runs a shortest path query for all AD groups to high value targets. Returns a list of groups.
    Respect to the Plumhound project https://github.com/PlumHound/PlumHound and BloodhoundGang Slack channel https://bloodhoundhq.slack.com for the influence and assistance with this.
    """
    query_shortestpath="""match p=shortestpath((g:Group {highvalue:FALSE})-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|WriteSPN|AddKeyCredentialLink|AddSelf*1..]->(n {highvalue:TRUE})) with reduce(totalscore = 0, rels in relationships(p) | totalscore + rels.cost) as cost, length(p) as hops, g.name as startnode, [node in nodes(p) | coalesce(node.name, "")] as nodeLabels, [rel in relationships(p) | type(rel)] as relationshipLabels, g.objectid as SID with reduce(path="", x in range(0,hops-1) | path + nodeLabels[x] + " - " + relationshipLabels[x] + " -> ") as path, nodeLabels[hops] as final_node, hops as hops, startnode as startnode, cost as cost, nodeLabels as nodeLabels, relationshipLabels as relLabels, SID as SID return startnode, hops, min(cost) as cost, nodeLabels, relLabels, path + final_node as full_path, SID as SID"""
    if not args.quiet:
        print("Sniffing out attack paths from groups, this may take a while.")
    try:
        groupswithpath=graph.run(query_shortestpath).data()
    except:
        logging.warning("There is a problem with the inputted query. If you have entered a custom query check the syntax.")
        exit(1)
    fixnullobjectnames(groupswithpath)
    if len(groupswithpath) == 0:
        userswithpath = shortestuserpath(graph, args)
    else:
        userswithpath=[]
    querytime = round((datetime.now()-starttime).total_seconds() / 60)
    logging.info("Finished group query in : {} Minutes".format(querytime))
    if (len(groupswithpath) + len(userswithpath)) == 0:
        print("You have no paths to high value targets. Congratulations!")
        exit(1)
    return groupswithpath, userswithpath

def shortestuserpath(graph, args):
    """Runs a shortest path query for all users where the path does not involve a group membership. This is to catch any potential outliers."""
    if not args.quiet:
        print("Digging for users with paths. This can also take some time.")
    userquerystarttime = datetime.now()
    query_shortestpath="""match p=shortestpath((u:User {highvalue:FALSE, enabled:TRUE})-[:HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|WriteSPN|AddKeyCredentialLink|AddSelf*1..]->(n {highvalue:TRUE})) with reduce(totalscore = 0, rels in relationships(p) | totalscore + rels.cost) as cost, length(p) as hops, u.name as startnode, [node in nodes(p) | coalesce(node.name, "")] as nodeLabels, [rel in relationships(p) | type(rel)] as relationshipLabels, u.objectid as SID with reduce(path="", x in range(0,hops-1) | path + nodeLabels[x] + " - " + relationshipLabels[x] + " -> ") as path, nodeLabels[hops] as final_node, hops as hops, startnode as startnode, cost as cost, nodeLabels as nodeLabels, relationshipLabels as relLabels, SID as SID return startnode, hops, min(cost) as cost, nodeLabels, relLabels, path + final_node as full_path, SID as SID"""
    userswithpath=graph.run(query_shortestpath).data()
    fixnullobjectnames(userswithpath)
    querytime = round((datetime.now()-userquerystarttime).total_seconds() / 60)
    logging.info("Finished user query in : {} Minutes".format(querytime))
    return userswithpath

def getmaxcost(groupswithpath):
    """Get the maximum amount of hops in the dataset to be used as part of the risk score calculation"""
    maxhops=[]
    for sublist in groupswithpath:
        maxhops.append(sublist.get('hops'))
    maxcost = (max(maxhops))*3+1
    return maxcost

def getdirectmembers(graph, group):
    """takes group gets direct enabled, non-admin members gives [members]"""
    logging.info(f"Finding direct members of {group}")
    query_group_members = """match (u:User {highvalue:FALSE, enabled:TRUE})-[:MemberOf]->(g:Group {name:"%s"}) return distinct(u.name) as members""" % group
    group_members = graph.run(query_group_members).data()
    if len(group_members) != 0:
        members = []
        for g in group_members:
            m = g.get("members")
            members.append(m)
    else:
        members = group_members
    return members

def getdirectgroupmembers(graph, group):
    """takes group gets direct non-highvalue group members gives [groups]"""
    logging.info(f"Finding direct group members of {group}")
    query_group_members = """match (g:Group {highvalue:FALSE})-[:MemberOf]->(g1:Group {name:"%s"}) return distinct(g.name) as groupmembers""" % group
    group_members = graph.run(query_group_members).data()
    if len(group_members) != 0:
        groups = []
        for g in group_members:
            m = g.get("groupmembers")
            groups.append(m)
    else:
        groups = group_members
    return groups

def processgroups(graph, uniquegroupswithpath, args):
    if not args.quiet:
        print("Fetching users of groups.")
    groupswithmembers = []
    #start to process all groups with path
    for startgroup in uniquegroupswithpath:
        if not any(group["groupname"] == startgroup for group in groupswithmembers):
            startgroupmembers = []
            subgroupstobeprocessed = []
            directmembers = getdirectmembers(graph, startgroup)
            if len(directmembers) != 0:
                for d in directmembers:
                    if d not in startgroupmembers:
                        startgroupmembers.append(d)
            directgroups = getdirectgroupmembers(graph, startgroup)
            if len(directgroups) != 0:
                for g in directgroups:
                    if not any(group["groupname"] == g for group in groupswithmembers):
                        subgroupstobeprocessed.append(g)
                        donotreprocessgroups = []
                        while len(subgroupstobeprocessed) != 0:
                            nestedmembers, subgroupstobeprocessed, donotreprocessgroups = recursivegroupsearch(graph, groupswithmembers, subgroupstobeprocessed, donotreprocessgroups)
                            for n in nestedmembers:
                                if n not in startgroupmembers:
                                    startgroupmembers.append(n)
                    else:
                        groupswithmembersindex = ghutils.getlistindex(groupswithmembers, "groupname", g)
                        nestedmembers = groupswithmembers[groupswithmembersindex]['groupmembers']
                        for n in nestedmembers:
                            if n not in startgroupmembers:
                                startgroupmembers.append(n)
            startgroupdict = {"groupname":startgroup, "groupmembers":startgroupmembers}
            groupswithmembers.append(startgroupdict)
    return groupswithmembers

def recursivegroupsearch(graph, groupswithmembers, subgroupstobeprocessed, donotreprocessgroups):
    if not any(group["groupname"] == subgroupstobeprocessed[0] for group in groupswithmembers):
        subgroup = subgroupstobeprocessed[0]
        members = []
        if subgroup not in donotreprocessgroups:
            subgroupmembers = getdirectmembers(graph, subgroup)
            if len(subgroupmembers) != 0:
                for m in subgroupmembers:
                    if m not in members:
                        members.append(m)
            subgroupgroupmembers = getdirectgroupmembers(graph, subgroup)
            if len(subgroupgroupmembers) != 0:
                for g in subgroupgroupmembers:
                    subgroupstobeprocessed.append(g)
            subgroupdone = subgroupstobeprocessed.pop(0)
            donotreprocessgroups.append(subgroupdone)
        if len(subgroupstobeprocessed) != 0:
            subgroupstobeprocessed.pop(0)
    else:
       subgroup = subgroupstobeprocessed[0]
       groupswithmembersindex = ghutils.getlistindex(groupswithmembers, "groupname", subgroup)
       members = groupswithmembers[groupswithmembersindex]['groupmembers']
       subgroupdone = subgroupstobeprocessed.pop(0)
       donotreprocessgroups.append(subgroupdone)
    return members, subgroupstobeprocessed, donotreprocessgroups

def gettotaluniqueuserswithpath(groupswithmembers, userswithpath):
    uniqueusers = []
    for g in groupswithmembers:
        members = g.get("groupmembers")
        for m in members:
            if m not in uniqueusers:
                uniqueusers.append(m)
    for u in userswithpath:
        user = u.get("startnode")
        if user not in uniqueusers:
            uniqueusers.append(user)
    totaluniqueuserswithpath = len(uniqueusers)
    return totaluniqueuserswithpath

def weakestlinks(groupswithpath, totalpaths, userswithpath, args):
    """Attempts to determine the most common weak links across all attack paths"""
    allpaths = groupswithpath + userswithpath
    linkstext, linkslist = breakpathsintolinks(allpaths)
    common_link = list(Counter(linkstext).most_common(args.results))
    # Now we have the most common links we need to formulate the output table for the report
    weakest_links = []
    for x in common_link:
        # convert to a list
        l = list(x)
        # calculate the percentage of all paths that this link is seen in
        pct = round(l[1]/totalpaths*100,1)
        l.append(pct)
        # change the text string back into a list
        l_list = l[0].split('->')
        # find the index of the corresponding item in the links list
        listindex = linkslist.index(l_list)
        #formulate the bloodhound query by getting the nodes and rels from the links list
        query = """match p1=shortestpath((g:Group {highvalue:FALSE})-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|WriteSPN|AddKeyCredentialLink|AddSelf*1..]->(n1 {name:'%s'})) where g<>n1 match p2=(n1)-[:%s]->(n2 {name:'%s'}) match p3=shortestpath((n2)-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|WriteSPN|AddKeyCredentialLink|AddSelf*1..]->(n3 {highvalue:true})) where n3<>n2 with p1, [p2,p3] as paths return reduce(acc = p1, x in paths | apoc.path.combine(acc, x))""" %(linkslist[listindex][0],linkslist[listindex][1],linkslist[listindex][2])
        l.append(query)
        weakest_links.append(l)
    return weakest_links

def breakpathsintolinks(allpaths):
    """Takes all the paths and breaks them apart in their constituent links."""
    linkstext = []
    linkslist = []
    for path in allpaths:
        nodes = path.get('nodeLabels')
        rels = path.get('relLabels')
        # assembles the nodes and rels into a chain
        path = sum(zip(nodes, rels+[0]), ())[:-1]
        # Divides the chains into Node-Rel-Node. Each link is 3 steps long so we end at 3 from the end of the list. We jump every other to avoid starting a link on a relationship.
        for step in path[:-3:2]:
            endlink = int(path.index(step))+3
            link = []
            for p in path[path.index(step):endlink]:
                link.append(p)
            # Makes it into a neat string
            linktext = '->'.join(link)
            linkstext.append(linktext) 
            linkslist.append(link)
    return linkstext, linkslist

#def weakestlinksold(groupswithpath, totalpaths, userswithpath):
#    """Attempts to determine the most common weak links across all attack paths"""
#    allpaths = groupswithpath + userswithpath
#    links = []
#    for path in allpaths:
#        nodes = path.get('nodeLabels')
#        rels = path.get('relLabels')
#        # assembles the nodes and rels into a chain
#        chain = sum(zip(nodes, rels+[0]), ())[:-1]
#        # Divides the chains into Node-Rel-Node-Rel-Node groups as attack paths are usually "This can do that to the other. The other can then do this."
#        for c in chain[:-4:2]:
#            endlink = int(chain.index(c))+5
#            link = []
#            for ch in chain[chain.index(c):endlink]:
#                link.append(ch)
#            # Makes it into a neat string
#            link = '->'.join(link)
#            links.append(link)
#    common_link = list(Counter(links).most_common(5))
#    weakest_links = []
#    for x in common_link:
#        l = list(x)
#        pct = round(l[1]/totalpaths*100,1)
#        l.append(pct)
#        weakest_links.append(l)
#    return weakest_links

def getuniquegroupswithpath(groupswithpath):
    """Gets a unique list of groups with a path"""
    uniquegroupswithpath=[]
    for g in groupswithpath:
        group = g.get('startnode')
        if group not in uniquegroupswithpath:
            uniquegroupswithpath.append(group)
    return uniquegroupswithpath