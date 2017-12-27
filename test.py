import xml.etree.ElementTree as ET
import xml.etree.ElementPath as EP
import urllib.request
import ssl


reportDynamic=[
"acc-summary",
"custom-dynamic-report",
"top-app-summary",
"top-application-categories-summary",
"top-application-risk-summary",
"top-application-subcategories-summary",
"top-application-tech-summary",
"top-applications-summary",
"top-applications-trsum",
"top-attacker-countries-summary",
"top-attackers-summary",
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


#open - read - write database into Notepad
# syntax: 
#   num1 = {field1, field2, field3}
def openFile(pathFile,typeOpen):
    fileOP= open(pathFile,typeOpen)
    return fileOP








######## main chinh ################
# khai báo link Predefined

link_top_vulnerabilities=link_Predefine + token_Account + "&reportname=top-vulnerabilities"
link_top_applications=link_Predefine + token_Account +"&reportname=top-applications"
link_top_blocked_url_categories= link_Predefine + token_Account +"&reportname=top-blocked-url-categories"
link_top_blocked_websites=link_Predefine + token_Account +"&reportname=top-blocked-websites"
link_top_blocked_url_users=link_Predefine + token_Account + "&reportname=top-blocked-url-users"
link_top_http_applications= link_Predefine + token_Account + "&reportname=top-http-applications"
link_top_websites = link_Predefine + token_Account+ "&reportname=top-websites"



# khai báo link Dynamic

link_top_vulnerabilities_summary=link_Dynamic + token_Account + "&reportname=top-vulnerabilities-summary"
link_top_threats_type_summary=link_Dynamic + token_Account + "&reportname=top-threats-type-summary"
link_top_attacks_acc=link_Dynamic + token_Account + "&reportname=top-attacks-acc"
link_top_url_summary=link_Dynamic + token_Account +"&reportname=top-url-summary"
link_top_applications_summary=link_Dynamic + token_Account +"&reportname=top-applications-summary"
link_top_blocked_url_summary=link_Dynamic + token_Account +"&reportname=top-blocked-url-summary"


# khai báo link Custom
link_threat_report_detail_1Day=link_custom+ token_Account +"&reportname=Threat_report_detail_1Day"



#get XML for Dynamic
def read_XML_Dynamic(linkRP,dataFile,typeOpen):

    print ("Starting get Data XML from: \n\n%s\n\n" % linkRP)

    fp = urllib.request.urlopen(linkRP,context=context)
    mybytes = fp.read()
    mystr = mybytes.decode("utf8")
    fp.close()
    root=ET.fromstring(mystr)

    i =0
    file= openFile(dataFile,typeOpen)

    print ("root is: \n",root.tag, root.attrib)
    for child in root:
        print ("child is: \n", child.tag, child.attrib,"\n")
        if child.tag == "report":
            for first_child in child:
                print ("first_child is: \n",first_child.tag,first_child.attrib,"\n")
                # lay gia tri : step_child.get("name") ==> Top Attackers
                if first_child.tag == "result":
                    for second_child in first_child:
                        i = i+ 1
                        #print (second_child.tag,second_child.attrib)
                        if second_child.tag =="entry":
                            dataTemp=""
                            temp=0
                            for third_child in second_child:
                                if temp == 0:
                                    dataTemp=third_child.text
                                    temp=1
                                else:
                                    dataTemp=dataTemp + "," +  third_child.text
                                #print (third_child.tag,third_child.text)
                            dataWrite= "num%i{%s}" % (i,dataTemp )
                            print ("Writing into File: %s" % dataFile)
                            file.write(dataWrite + "\n")
                            print (dataWrite)
                            print ("\n")
                print ("So luong Entry: %i" % i)
                file.close()


#get XML for Predefine
def read_XML_Predefine(linkRP,dataFile,typeOpen):

    print ("Starting get Data XML from: \n\n%s\n\n" % linkRP)

    fp = urllib.request.urlopen(linkRP,context=context)
    mybytes = fp.read()
    mystr = mybytes.decode("utf8")
    fp.close()
    root=ET.fromstring(mystr)

    i =0
    file= openFile(dataFile,typeOpen)

    print ("root is: \n",root.tag, root.attrib)
    for child in root:
        print ("child is: \n", child.tag, child.attrib,"\n")
        if child.tag == "result":
            for first_child in child:
                print ("first_child is: \n",first_child.tag,first_child.attrib,"\n")
                # lay gia tri : step_child.get("name") ==> Top Attackers
                if first_child.tag == "entry":
                    i = i+ 1
                    dataTemp=""
                    temp=0
                    for second_child in first_child:
                        if temp == 0:
                            dataTemp=second_child.text
                            temp=1
                        else:
                            dataTemp=dataTemp + "," +  second_child.text
                                #print (third_child.tag,third_child.text)
                                
                    dataWrite= "num%i{%s}" % (i,dataTemp )
                    print ("Writing into File: %s" % dataFile)
                    file.write(dataWrite + "\n")
                    print (dataWrite)
                    print ("\n")
        print ("So luong Entry: %i" % i)
        file.close()

#get XML for Custom

def read_XML_Custom(linkRP,dataFile,typeOpen):
    fp = urllib.request.urlopen(link,context=context)
    mybytes = fp.read()
    mystr = mybytes.decode("utf8")
    fp.close()
    root=ET.fromstring(mystr)
    print (root.tag, root.attrib)
    i =0
    file= openFile(dataFile,typeOpen)
    for child in root:
        print (child.tag, child.attrib,"\n")
        if child.tag == "report":
            for first_child in child:
                print (first_child.tag, first_child.attrib,"\n")
                # lay gia tri : step_child.get("name") ==> Top Attackers
                if first_child.tag == "result":
                    for second_child in first_child:
                        i = i+ 1
                        #print (second_child.tag,second_child.attrib)
                        if second_child.tag =="entry":
                            dataTemp=""
                            temp=0
                            for third_child in second_child:
                                if temp == 0:
                                    dataTemp=third_child.text
                                    temp=1
                                else:
                                    dataTemp=dataTemp + "," +  str(third_child.text)
                                #print (third_child.tag,third_child.text)
                            dataWrite= "num%i{%s}" % (i,dataTemp )
                            print ("Writing into File: %s" % dataWrite)
                            file.write(dataWrite + "\n")
                            print (dataWrite)
                            print ("\n")
                print ("So luong Entry: %i" % i)
                file.close()




###### _____int________ main

read_XML_Dynamic(link_top_vulnerabilities_summary+"&period=" + periodTime[5],"top_vulnerabilities_summary.txt","w")
read_XML_Dynamic(link_top_threats_type_summary+"&period=" + periodTime[6],"top_threats_type_summary.txt","w")
read_XML_Dynamic(link_top_attacks_acc +"&period=" + periodTime[3],"top_attacks_acc.txt","w")
read_XML_Dynamic(link_top_applications_summary +"&period=" + periodTime[5],"top_applications_summary.txt","w")
read_XML_Dynamic(link_top_blocked_url_summary+"&period=" + periodTime[5],"top_blocked_url_summary.txt","w")

read_XML_Predefine(link_top_websites,"top_websites.txt","w")

read_XML_Custom(link_threat_report_detail_1Day,"threat_report_detail_1Day.txt","w")
