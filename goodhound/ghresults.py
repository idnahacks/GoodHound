from goodhound import paths, ghutils
import pandas as pd
from datetime import datetime
import logging
import hashlib
import sys
from pathlib import Path
import os

def generateresults(groupswithpath, groupswithmembers, totalenablednonadminusers, userswithpath):
    """combine the output of the paths query and the groups query"""
    maxcost = paths.getmaxcost(groupswithpath)
    results = []
    for g in groupswithpath:
        startnode = g.get('startnode')
        hops = g.get('hops')
        cost = g.get('cost')
        fullpath = g.get('full_path')
        endnode = g.get('nodeLabels')[-1]
        #query = bh_query(startnode, hops, endnode)
        query = bh_query(g)
        uid = hashlib.md5(fullpath.encode()).hexdigest()
        if cost == None:
            # While debugging this should highlight edges without a score assigned. CHECK ON THIS LOGIC, I'M NOT SURE IT'S CORRECT.
            logging.info(f"Null edge cost found with {startnode} and {hops} hops.")
            cost = 0
        # find the index of the relative group in groupswithmembers and pull results
        #groupindex = next((index for (index, groupname) in enumerate(groupswithmembers) if groupname["groupname"] == startnode), None)
        groupswithmembersindex = ghutils.getlistindex(groupswithmembers, "groupname", startnode)
        num_members = len(groupswithmembers[groupswithmembersindex]['groupmembers'])
        #num_members = len(groupswithmembers[groupindex]['combined'])
        percentage=round(float((num_members/totalenablednonadminusers)*100), 1)
        riskscore = round((((maxcost-cost)/maxcost)*percentage),1)
        result = [startnode, num_members, percentage, hops, cost, riskscore, fullpath, query, uid]
        results.append(result)
    for u in userswithpath:
        startnode = u.get('startnode')
        hops = u.get('hops')
        cost = u.get('cost')
        fullpath = u.get('full_path')
        endnode = u.get('nodeLabels')[-1]
        query = bh_query(u)
        uid = hashlib.md5(fullpath.encode()).hexdigest()
        if cost == None:
            # While debugging this should highlight edges without a score assigned. CHECK ON THIS LOGIC, I'M NOT SURE IT'S CORRECT.
            logging.info(f"Null edge cost found with {startnode} and {hops} hops.")
            cost = 0
        num_members = 1
        percentage=round(float((num_members/totalenablednonadminusers)*100), 1)
        riskscore = round((((maxcost-cost)/maxcost)*percentage),1)
        result = [startnode, num_members, percentage, hops, cost, riskscore, fullpath, query, uid]
        results.append(result)
    return results

def getuniqueresults(results):
    """This stops many paths appearing in the result from the same group which can happen. This doesn't feel like the best way of approaching this and should be looked at for improvement."""
    uniquegroupresults = []
    #sort by startnode and then risk score in order to take the top risk score result for each group with a path
    sorted_p = sorted(results, key=lambda i: (i[0], -i[5]))
    for p in sorted_p:
        startnode = p[0]
        num_members = p[1]
        percentage = p[2]
        hops = p[3]
        cost = p[4]
        riskscore = p[5]
        fullpath = p[6]
        query = p[7]
        uid = p[8]
        # check if there is already a path added for the current group and if not add it.
        if (len(uniquegroupresults)==0) or (any(startnode == ugp[0] for ugp in uniquegroupresults) != True):
            unique = [startnode, num_members, percentage, hops, cost, riskscore, fullpath, query, uid]
            uniquegroupresults.append(unique)
    return uniquegroupresults

def sortresults(args, results):
    """Sorts the results depending on the argument selected. By default this is by Risk Score.
    Also takes the number of results selected in the arguments. Default is 5."""
    if args.sort == 'users':
        top_results = (sorted(results, key=lambda i: -i[2])[0:args.results])
    elif args.sort == 'hops':
        top_results = (sorted(results, key=lambda i: i[3])[0:args.results])
    else:
        top_results = (sorted(results, key=lambda i: (-i[5], i[4], i[3]))[0:args.results])
    return top_results

def bh_query(path):
    """Generate a replayable query for each finding for Bloodhound visualisation."""
    query = """match p=(({name:'%s'})""" %path["nodeLabels"][0]
    n=1
    for r in path["relLabels"]:
        nextstring = "-[:%s]->({name:'%s'})" %(r, path["nodeLabels"][n])
        query = query + nextstring
        n += 1
    finalstring = ") return p"
    query = query + finalstring
    return query

def grandtotals(totaluniqueuserswithpath, totalenablednonadminusers, totalpaths, new_path, seen_before, weakest_links, top_results):
    total_users_percentage = round(((totaluniqueuserswithpath/totalenablednonadminusers)*100),1)
    grandtotals = [{"Total Non-Admins with a Path":totaluniqueuserswithpath, "Percentage of Total Enabled Non-Admins":total_users_percentage, "Total Paths":totalpaths, "% of Paths Seen Before":seen_before/totalpaths*100, "New Paths":new_path}]
    grandtotalsdf = pd.DataFrame(grandtotals)
    weakest_linkdf = pd.DataFrame(weakest_links, columns=["Weakest Link", "Number of Paths it appears in", "% of Total Paths", "Bloodhound Query"])
    busiestpathsdf = pd.DataFrame(top_results, columns=["Starting Node", "Number of Enabled Non-Admins with Path", "Percent of Total Enabled Non-Admins with Path", "Number of Hops", "Exploit Cost", "Risk Score", "Path", "Bloodhound Query", "UID"])
    busiestpathsdf = busiestpathsdf.drop(columns=["UID"])
    return grandtotalsdf, weakest_linkdf, busiestpathsdf

def output(args, grandtotalsdf, weakest_linkdf, busiestpathsdf, scandatenice, starttime):
    finish = datetime.now()
    totalruntime = round((finish - starttime).total_seconds() / 60)
    logging.info("Total runtime: {} minutes.".format(totalruntime))
    pd.set_option('display.max_colwidth', None)
    if args.output_format == "stdout":
        print("\n\nGRAND TOTALS")
        print("============")
        print(grandtotalsdf.to_string(index=False))
        print("\nBUSIEST PATHS")
        print("-------------\n")
        print (busiestpathsdf.to_string(index=False))
        print("-------------\n")
        print("\nTHE WEAKEST LINKS")
        print (weakest_linkdf.to_string(index=False))
    elif args.output_format == ("md" or "markdown"):
        print("# GRAND TOTALS")
        print (grandtotalsdf.to_markdown(index=False))
        print("## BUSIEST PATHS")
        print (busiestpathsdf.to_markdown(index=False))
        print("## THE WEAKEST LINKS")
        print (weakest_linkdf.to_markdown(index=False))
    else:
        htmlreportname = str(Path(args.output_dir)) + os.sep + f"{scandatenice}" + "_GoodHound_report.html"
        summaryname = str(Path(args.output_dir)) + os.sep + f"{scandatenice}" + "_GoodHound_summary.csv"
        busiestpathsname = str(Path(args.output_dir)) + os.sep + f"{scandatenice}" + "_GoodHound_busiestpaths.csv"
        weakestlinkname = str(Path(args.output_dir)) + os.sep + f"{scandatenice}" + "_GoodHound_weakestlinks.csv"
        #for each of the reports to be created, check if there's a file with the same name in existence
        outfiles = [htmlreportname, summaryname, busiestpathsname, weakestlinkname]
        i = 0
        for f in outfiles:
            outfiles[i] = ghutils.checkifoutfileexists(f)
            i += 1
        htmlreportname = outfiles[0]
        summaryname = outfiles[1]
        busiestpathsname = outfiles[2]
        weakestlinkname = outfiles[3]
        grandtotalshtml = grandtotalsdf.to_html(index=False)
        busiestpathshtml = busiestpathsdf.to_html(index=False)
        weakestlinkshtml = weakest_linkdf.to_html(index=False)
        html = htmlreport(grandtotalshtml, busiestpathshtml, weakestlinkshtml)
        #Write out files
        try:
            with open(htmlreportname, "w") as html_file:
                html_file.write(html)
            grandtotalsdf.to_csv(summaryname, index=False)
            busiestpathsdf.to_csv(busiestpathsname, index=False)
            weakest_linkdf.to_csv(weakestlinkname, index=False)
        except Exception as e:
            logging.error("Could not write file to location.")
            logging.error(e.__context__)
            sys.exit(1)

    if not args.quiet:
        print("Reports written to selected file path.")
        print("Attack Paths sniffed out. Woof woof!")

def htmlreport(grandtotalshtml, busiestpathshtml, weakestlinkshtml):
    html = """
<html>
<head>
    <title>GoodHound Report</title>
    <style>
body {
  background-color: linen;
}
table {
    border-collapse: collapse;
    font-family: helvetica;
    table-layout: auto;
    width: 100%s
}
th {border:  1px solid;
      padding: 10px;
      min-width: 100px;
      background: MediumSeaGreen;
      box-sizing: border-box;
      text-align: center;
      font-size: 16px
}

td {
  border:  1px solid;
      padding: 10px;
      min-width: 100px;
      background: white;
      box-sizing: border-box;
      text-align: center;
      font-size: 12px
}

h1 {
  font-size: 24px;
  font-family: helvetica;
  text-align: center;
}

h2 {
  font-size: large;
  font-family: helvetica;
  text-align: center;
}

.table-container-summary {
  position: relative;
  max-height:  300px;
  width: 1500px;
}

.table-container-detail {
  position: relative;
  max-height:  1500px;
  overflow: scroll;
}

.subtitle-link {
    text-align: center;
    font-family: helvetica;
    font-size: 16px;
}
</style>
</head>
<body>
<h1>GoodHound Attack Path Report</h1>
<p class="subtitle-link"><a href="https://github.com/idnahacks/GoodHound" target="_blank">https://github.com/idnahacks/GoodHound</a></p>
    <h2>Summary</h2>
      <div class="table-container-summary">
      %s
      </div>
    <h2>Busiest Paths</h2>
      <div class="table-container-detail">
      %s
      </div>
    <h2>Weakest Links</h2>
      <div class="table-container-detail">
      %s
      </div>
</body>

</html>""" %("%", grandtotalshtml, busiestpathshtml, weakestlinkshtml)
    return html