import requests
import json
from bs4 import BeautifulSoup
#making a GET request 
#output là một list các vul
listvul=[]
URL='https://moodle.org/security/index.php?o=3&p='
for page in range(15):
    r=requests.get(URL+str(page))
    print(r.url)
    print(r.status_code)
#khởi tạo kiểu dictionary cho từng vul
    result={}
#result['name'] = "value" add a key-value in dictionary

# Parsing the HTML, encode before print to solve 'charmap' codec can't encode character '\u200e' in position 77090: character maps to <undefined>
    soup = BeautifulSoup(r.content, 'html.parser')
#print(soup.prettify().encode('cp1252', errors='ignore'))
# Getting the title tag
#print(soup.title)
 
# Getting the name of the tag
#print(soup.title.name)
 
# Getting the name of parent tag
#print(soup.title.parent.name)
#s = soup.find('div',role='main')
#print(s)
#content = s.find_all('article',class_='forum-post-container mb-2')
#tìm các thành phần chứa các thông tin cần dùng. ok. test 1 thành phần. tìm hết sử dụng find All
#--elements=soup.findAll('div',class_='d-flex flex-column w-100')
#Sử dụng vòng lặp tại mỗi element để lấy ra tên lỗ hổng, độ nguy hiểm, version ảnh hưởng,version vá lỗi, CVE, change, tracker
# tên của lỗ hổng nằng trong thẻ p. ok
#--namevul=elements.find('p').text
#print(namevul)
#print(elements)
#test thuộc tính khác

#print(elements.findAll('td')) -> Check kiểu ->list
#--multitd=elements.findAll('td')

# print(len(multitd)) check length of multitd
#lấy thuộc tính cho result 

#--for i in range(0,len(multitd)-1,2):
#--    result[multitd[i].text]=multitd[i+1].text

    elements=soup.findAll('div',class_='d-flex flex-column w-100')
    for element in elements:
        namevul=element.find('p').text
        result['description']=namevul
        multitd=element.findAll('td')
        for i in range(0,len(multitd)-1,2):
            result[multitd[i].text]=multitd[i+1].text
        listvul.append(result)
    #print(listvul)
#From 1 to 16 write to file 
    with open("cve-0-15.json", "w") as outfile:
        json.dump(listvul, outfile)