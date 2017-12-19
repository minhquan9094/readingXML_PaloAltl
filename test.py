import xml.etree.ElementTree as ET
import xml.etree.ElementPath as EP
import urllib.request
import ssl


reportDynamic=[
"top-attackers-summary",
"top-attacks-acc",
"top-blocked-url-categories-summary",
"top-blocked-url-summary",
"top-blocked-url-user-behavior-summary",
"top-data-dst-countries-summary",
"top-data-dst-summary",
"top-data-egress-zones-summary",
"top-data-filename-summary",
"top-data-filetype-summary",
"top-data-ingress-zones-summary",
"top-data-src-countries-summary",
"top-data-src-summary",
"top-data-type-summary",
"top-dst-countries-summary",
"top-dst-summary",
"top-egress-zones-summary",
"top-hip-objects-details",
"top-hip-objects-summary",
"top-hip-profiles-summary",
"top-hip-report-links",
"top-hr-applications-summary",
"top-ingress-zones-summary",
"top-rule-summary",
"top-spyware-phonehome-summary",
"top-spyware-threats-summary",
"top-src-countries-summary",
"top-src-summary",
"top-threat-egress-zones-summary",
"top-threat-ingress-zones-summary",
"top-threats-type-summary",
"top-url-categories-summary",
"top-url-summary",
"top-url-user-behavior-summary",
"top-victim-countries-summary",
"top-victims-summary",
"top-viruses-summary",
"top-vulnerabilities-summary",
"top-hip-profiles-details",
]

periodTime=[

"last-60-seconds",
"last-15-minutes",
"last-hour",
"last-12-hrs",
"last-24-hrs",
"last-calendar-day",
"last-7-days",
"last-7-calendar-days",
"last-calendar-week",
"last-30-days",
]


reportPredefined=[

"SaaS Application Usage",
"bandwidth-trend",
"botnet",
"hruser-top-applications",
"hruser-top-threats",
"hruser-top-url-categories",
"risk-trend",
"risky-users",
"spyware-infected-hosts",
"threat-trend",
"top-application-categories",
"top-applications",
"top-attackers",
"top-attackers-by-countries",
"top-attacks",
"top-blocked-url-categories",
"top-blocked-url-user-behavior",
"top-blocked-url-users",
"top-blocked-websites",
"top-connections",
"top-denied-applications",
"top-denied-destinations",
"top-denied-sources",
"top-destination-countries",
"top-destinations",
"top-egress-interfaces",
"top-egress-zones",
"top-http-applications",
"top-ingress-interfaces",
"top-ingress-zones",
"top-rules",
"top-source-countries",
"top-sources",
"top-spyware-threats",
"top-technology-categories",
"top-url-categories",
"top-url-user-behavior",
"top-url-users",
"top-users",
"top-victims",
"top-victims-by-countries",
"top-viruses",
"top-vulnerabilities",
"top-websites",
"unknown-tcp-connections",
"unknown-udp-connections",
"wildfire-file-digests"
]

#### set context cho SSL 
context = ssl._create_unverified_context()


### khai bao cac bien global
token_Account="LUFRPT1obE5zSnRBd29xMTB4TENudDF2akdPaHpKYTA9TnNKak8xbUVqaFRiOEErVTVZU0FPQT09"

link_Predefine="https://172.28.82.58/api/?type=report&reporttype=predefined&key="
link_Dynamic="https://172.28.82.58/api/?type=report&reporttype=dynamic&key="
link_custom="https://172.28.82.58/api/?type=report&reporttype=custom&key="

#fileLink=open("linkAPI_PaloAlto.txt","a")


# lay link APi get_Link_ReportPredefined
def get_Link_ReportPredefined():
    global link_custom, link_Dynamic, link_Predefine, token_Account,reportDynamic, reportPredefined
    fileLink=open("linkAPI_PaloAlto.txt","a")
   
    for i in range(0,len(reportDynamic)):
        fileLink.write("\n"+reportPredefined[i]+"\n")
        fileLink.write(link_Predefine + token_Account + "&reportname=" + reportPredefined[i])
    
    fileLink.close()



#lay link APi get_Link_ReportDynamic
def get_Link_ReportDynamic():
    global link_custom, link_Dynamic, link_Predefine, token_Account, reportDynamic, reportPredefined
    fileLink=open("linkAPI_PaloAlto.txt","a")
    
    for i in range(0,len(reportDynamic)):
        fileLink.write("\n"+reportDynamic[i]+"\n")
        fileLink.write(link_Dynamic + token_Account + "&reportname=" + reportDynamic[i])
    fileLink.close()



#### get Attacker summary
def getXML_Top_Attack_summary_FROM_FILE(xml_file):
    """
    Parse XML with ElementTree
    """
    tree = ET.ElementTree(file=xml_file)
    #print (tree.getroot())
    root = tree.getroot()
    print ("tag=%s, attrib=%s" % (root.tag, root.attrib),"\n")
    print (root)
    print (root.items())

    print ("*************************************")

    
    for child in root:
        print (child.tag, child.attrib,"\n")
        if child.tag == "report":
            for step_child in child:
                print (step_child.tag, step_child.attrib,"\n")
                # lay gia tri : step_child.get("name") ==> Top Attackers
                if step_child.tag == "result":
                    for second_child in step_child:
                        print (second_child.tag,second_child.attrib)
                    

                        if second_child.tag=="entry":
                            for third_child in second_child:
                                print (third_child.tag,third_child.text)
                        print ("\n")

'''
    # iterate over the entire tree
    print ("-" * 40)
    print ("Iterating using a tree iterator")
    print ("-" * 40)
    iter_ = tree.getiterator()
  
    for elem in iter_:
        print (elem.tag)

  

   # get the information via the children!
    print ("-" * 40)
    print ("Iterating using getchildren()")
    print ("-" * 40)
    appointments = root.getchildren()
    for appointment in appointments:
        appt_children = appointment.getchildren()
        for appt_child in appt_children:
            print ("%s=%s" % (appt_child.tag, appt_child.text)) '''

#link = "https://172.28.82.58/api/?type=report&reporttype=dynamic&key=LUFRPT1obE5zSnRBd29xMTB4TENudDF2akdPaHpKYTA9TnNKak8xbUVqaFRiOEErVTVZU0FPQT09&reportname=top-attackers-summary"
link="https://172.28.82.58/api/?type=report&reporttype=custom&key=LUFRPT1obE5zSnRBd29xMTB4TENudDF2akdPaHpKYTA9TnNKak8xbUVqaFRiOEErVTVZU0FPQT09&reportname=Threat_report_detail_1Day"
def getXML_Top_Attack_summary_FROM_URL(link):
    fp = urllib.request.urlopen(link,context=context)
    mybytes = fp.read()
    mystr = mybytes.decode("utf8")
    fp.close()
    root=ET.fromstring(mystr)
    print (root.tag, root.attrib)
    print (list(root))
    for child in root:
        print (child.tag, child.attrib,"\n")
        if child.tag == "report":
            for step_child in child:
                print (step_child.tag, step_child.attrib,"\n")
                # lay gia tri : step_child.get("name") ==> Top Attackers
                if step_child.tag == "result":
                    for second_child in step_child:
                        print (second_child.tag,second_child.attrib)
                        if second_child.tag=="entry":             
                            for third_child in second_child:
                                print (third_child.tag,third_child.text)
                        print ("\n")



getXML_Top_Attack_summary_FROM_URL(link)