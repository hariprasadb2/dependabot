from urllib import response
import requests
import os 
import sys
import json
import datetime
from dateutil import parser

#implement grepping dependabot alerts through grpahql
class Dependapager(object):

    def __init__(self):
        self.github_token=os.environ["INPUT_GITHUB_PERSONAL_TOKEN"]
        #self.jira_token=os.environ("")
        self.slack_token=os.environ["INPUT_SLACK_TOKEN"]
        self.slack_channel=os.environ["INPUT_CHANNEL"]
        self.reponame=os.environ["GITHUB_REPOSITORY"].split("/")[-1]
        self.owner=os.environ["GITHUB_REPOSITORY_OWNER"]
        #self.dependabot_url="https://github.com/{}/{}/security/dependabot".format(self.owner,self.reponame)
        self.alerts={}
        self.total_alerts=0
        self.stats={"CRITICAL":0,"HIGH":0,"MODERATE":0,"LOW":0}
    
    def fetch_alerts(self):
        
        query= """
        {
            repository(name: "REPO_NAME", owner: "REPO_OWNER") {
                vulnerabilityAlerts(first: 100 states: OPEN) {
                    nodes {
                        createdAt
                        dismissedAt
                        securityVulnerability {
                            severity
                            package {
                                name
                            }
                            advisory {
                                 summary
                                 ghsaId
                                 permalink
                            }
                            
                        }
                    }
                }
            }
        }  """
        query=query.replace("REPO_NAME",self.reponame)
        query=query.replace("REPO_OWNER",self.owner)
        

        url="https://api.github.com/graphql"
        header= { "Authorization":"Bearer {}".format(self.github_token)}
        response=requests.post(url,headers=header,json={'query':query})

        # Check Response 
        if response.status_code==200:
            data=response.text
            data_dict=json.loads(data)
            return data_dict
        else :
            print(response.reason)
            sys.exit(1)
    
    def parse_data(self):

        data_dict=self.fetch_alerts()
        if data_dict["data"]["repository"]["vulnerabilityAlerts"]["nodes"]:
            for nodes in data_dict["data"]["repository"]["vulnerabilityAlerts"]["nodes"]:
                
                # Store data as {"ghsaid":["severity","advisory","advisory_url"]}
                created_at=nodes["createdAt"]
                package_name=nodes["securityVulnerability"]["package"]["name"]
                severity=nodes["securityVulnerability"]["severity"]
                advisory=nodes["securityVulnerability"]["advisory"]["summary"]
                ghsaid=nodes["securityVulnerability"]["advisory"]["ghsaId"]
                advisory_url=nodes["securityVulnerability"]["advisory"]["permalink"]

                #Create Alert Dictionary
                if not ghsaid in self.alerts.keys():
                    self.alerts[ghsaid]=[severity,advisory,advisory_url,created_at,package_name]
            
                
                # Calculating frequnecy of Each Alerts
                self.stats[severity]+=1 
            for keys in self.stats.keys():
                    self.total_alerts+=self.stats[keys] 
                
        else:
            print("no Vulnerabilites")
            sys.exit(0)
    
    def filter_new_alerts(self):

        """ This method helps to filter only the alerts that are created only within 7 Days """
       
        self.filtered_alerts={}
        self.parse_data()
        for ele in self.alerts:
            created_at=self.alerts[ele][3]
            date_formated=parser.parse(created_at)
            date_as_list=str(date_formated).split(" ")[0].split("-")
            converted_date=datetime.date(int(date_as_list[0]),int(date_as_list[1]),int(date_as_list[2]))
            today_date=datetime.date.today()
            date_diff_as_str=str(abs(converted_date - today_date))
            date_diff_as_number=int(date_diff_as_str.split(",")[0].split(" ")[0])
            
            if date_diff_as_number <= 7:
                self.filtered_alerts[ele]=self.alerts[ele]

    def send_slack_alert(self):
        self.filter_new_alerts()
        url="https://slack.com/api/chat.postMessage"
        header={"Authorization":"Bearer {}".format(self.slack_token)}
        blocks=[]

        for key in self.filtered_alerts:
            block= {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": "*Package Name:*\n{}".format(self.filtered_alerts[key][4])
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*Severity:*\n{}".format(self.filtered_alerts[key][0])
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*Summary:*\n{}".format(self.filtered_alerts[key][1])
                            }
                        ],
                        "accessory": {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "View Advisory",
                            
                            },
                            "value": "advisory",
                            "url":self.filtered_alerts[key][2],
                            "action_id": "button-action"
                        }
                        
                    }
            blocks.append(block)
            
        
        header_block={
                "channel":self.slack_channel,
                    
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "*Dependabot Alerts for repo:* {}".format("pwned-17")
                            }
                            
                        },
                        {
                            "type": "divider"
                        },
                    ]

        }
        header_response=requests.post(url,json=header_block,headers=header)
        data={
                    "channel":self.slack_channel,
                    "blocks": blocks
            }
        content_response=requests.post(url,json=data,headers=header)


        if (json.loads(content_response.text)["ok"])==True and content_response.status_code==200:
            print("Slakc Alert sent Successfully")
            sys.exit(0)
        else:
            print("Error Sending Slack Alert")
            sys.exit(1)
            
Dependapager().send_slack_alert()


