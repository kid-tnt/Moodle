import requests
import json
from bs4 import BeautifulSoup
listvul=[]
#436461-436456
#434582-434578
#432951-432947
#431103-431099
#429100-429095
#427107-427103
#424809-424797
#422315-422305
#419655-419650
#417171-417166
#413491-413935
#410843-410839
#407394-407391
#403513-403512
#398352-398350
#395953-
#393587-393582
#391031-
#391037-
#388571-388567
#386524-386521
#384015-384010
#381230-381228
#378731-
#376025-376023
#373371-373369
#371203-371199
#367939-367938
#364384-364381
#361784-
#358588-358585
#355557-554
#352356-352353
#349422-349419
#349419-
#345915-345911
#343277-275
#339361-336699-697
#333192-333186
#330182-330173
#326206-326205
#323237-323228
#320293-320287
#316665-316662
#313688-313681
#307387-380
#279956-
#278618-611
#275164-275146
#269591-269590
#264273-264261
#260366-361
#256425-256416
#252416-414
#244483-479
#238399-238393
#232503-232496
#228935-228930
#225348-225339
#220167-220157
#216161-216155
#211560-211555
#207156-207145
#203057-203041
#198632-198621
#non-cve
#194020-194008
#191762-191747
#188322-188309
#182743-182735
#175594-175588
#170012-170002
#169336-
#160858-
#160811
URI='https://moodle.org/mod/forum/discuss.php?d='
for page in range(160857,160856,-1):
    vul={}
    URL=URI+str(page)
    r=requests.get(URL)
    print(r.url)
    print(r.status_code)
    soup=BeautifulSoup(r.content,'html.parser')
    element=soup.find('div',class_='d-flex flex-column w-100')
    if(element is not None):
    #print(element)
        if (element.find('p') is not None):
            description=element.find('p').text
            vul['Description']=description
        if(element.find_all('td') is not None):
            tds=element.find_all('td')
            for i in range(0,len(tds)-1,2):
                vul[tds[i].text]=tds[i+1].text
        listvul.append(vul)
# Serializing json
json_object = json.dumps(listvul, indent=4)
# Writing to sample.json
with open("tooltest/non-cve.json", "a") as outfile:
    outfile.write(json_object)

