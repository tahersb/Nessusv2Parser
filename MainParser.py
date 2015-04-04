__author__ = 'tahersb'

"""
    Objective of this class is to parse the Nessus XML file and create an HTML table with chosen fields.
    Before that I need to address the problem of sorting the report items by vulnerability rather than hosts
    One way is to parse the XML file and create an array of reportItems.
"""
from xml.etree import ElementTree



reportItemsList = [] #reportItemsList will store all the reportItems elements in the XML file
reportHostsList = []
ET = ElementTree.parse('SampleNessusScan.xml')
xmlRootElement = ET.getroot()

class ReportItem:

    def __init__(self, host):
        self.host = host
        self.port = None
        self.svc_name = None
        self.protocol = None
        self.severity = None
        self.plugin_name = None
        self.risk_factor = None
        self.synopsis = None
        self.description = None
        self.solution = None
        self.plugin_output = None
        self.see_also = None
        self.cve = None
def populateReportItemsList():
    """
        This function will populate the reportHostsList & reportItemsList with items from the XML file
    """

    for reportHost in xmlRootElement.iter('ReportHost'):
        #Populate the reportHostsList - might need it
        reportHostsList.append(reportHost.get('name'))

        #create a newReportItem object of class ReportItem and populate the needed fields from the XML file
        for reportItem in reportHost.findall('ReportItem'):

            newReportItem = ReportItem(reportHost.get('name'))

            newReportItem.port = reportItem.get('port')
            newReportItem.svc_name = reportItem.find('svc_name')
            newReportItem.protocol = reportItem.get('protocol')
            newReportItem.severity = reportItem.find('severity')
            newReportItem.plugin_name = reportItem.find('plugin_name')
            newReportItem.risk_factor = reportItem.find('risk_factor')
            newReportItem.synopsis = reportItem.find('synopsis')
            newReportItem.description = reportItem.find('description')
            newReportItem.solution = reportItem.find('solution')
            newReportItem.plugin_output = reportItem.find('plugin_output')
            newReportItem.see_also = reportItem.find('see_also')
            if reportItem.find('cve') is not None:
                newReportItem.cve = reportItem.find('cve')
            reportItemsList.append(newReportItem)
    return

#At this point I have a list data structure populated with the information I need from the XML file
#Lets create an HTML table out of these data structures.

"""
    Sr. Vulnerabilty Name   Affected Hosts  Risk(risk_factor)    Observation(PluginOutput)  Solution

"""


def vulnList(RIList):
    """
    This function returns a list of unique vulnerabilities from the reportItemsList
    :param RIList: reportItemsList
    :return: set vulnSet
    """


    Vlist = []

    for item in RIList:
        if item.plugin_name.text not in Vlist:
                Vlist.append(item.plugin_name.text)
    return Vlist


def getAffectedHosts(vulnName):
    """
    This function will return a list of affected hosts for a given vulnerability name (plugin_name)
    :param vulnName: Vulnerability Name (plugin_name)
    :return: List of affected Hosts
    """


populateReportItemsList()
VulnerabilitiesList = vulnList(reportItemsList)





















