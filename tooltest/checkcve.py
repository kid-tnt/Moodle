#365 vul CVE
import json
import re
v='Moodle v3.9.0'
f = open('D:/Moodle/tooltest/cve_1.json','r')
#nvul=0
listserious=[]
listminor=[]
jsond = json.load(f)
f.close()
#santize version to minimal x.y.z
def santize(versions):
    versions=(re.split('v|\-',v))
    for sub_ver in versions:
        if('.'in sub_ver):
            return sub_ver
#count Digit of numbers
def countDigit(n): 
    if n//10 == 0:
        return 1
    return 1 + countDigit(n // 10)
def isOlder(v1,v2):
    #return true nếu v1 is older than v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    for i in range(len(arr1)):
        #số chữ số nhỏ hơn thì x10 rồi sô sánh
        if(countDigit(arr1[i])>countDigit(arr2[i])): 
            if(arr1[i]<arr2[i]*10):
                return True
            else: return False
        elif (countDigit(arr1[i])<countDigit(arr2[i])):
            if(arr1[i]*10<arr2[i]):
                return True
            else: return False
        if arr1[i]<arr2[i]:
            return True
        elif arr1[i]>arr2[i]:
            return False
    return False
def isNewer(v1,v2):
    #return true if v1 is newer than v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    for i in range(len(arr1)):
        if(countDigit(arr1[i])>countDigit(arr2[i])): 
            if(arr1[i]>arr2[i]*10):
                return True
            else: return False
        elif (countDigit(arr1[i])<countDigit(arr2[i])):
            if(arr1[i]*10>arr2[i]):
                return True
            else: return False
        if arr1[i]>arr2[i]:
            return True
        elif arr1[i]<arr2[i]:
            return False
    return False
def equalver(v1,v2):
    #return true if v1 is the same v2.
    arr1 = v1.split(".")
    arr2 = v2.split(".")
    m = len(arr1)
    n = len(arr2)	
    # converts to integer from string
    try:
        arr1 = [int(i) for i in arr1]
        arr2 = [int(i) for i in arr2]
    except:
        return False
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m<n:
        for i in range(m, n):
            arr1.append(0)
    for i in range(len(arr1)):
        if arr1[i]>arr2[i]:
            return False
        elif arr2[i]>arr1[i]:
            return False
    return True
def Oldest(list):
    Oldest=list[0]
    for li in list:
        if(isOlder(li,Oldest)):
            Oldest=li
    return Oldest
def printcve(cve):
    print("")
    #if('Risk:' in cve and cve['Risk:'] is not None):
    if('CVE identifier:' in cve and cve['CVE identifier:'] is not None):
        print(cve['CVE identifier:'])
    if('Tracker issue:' in cve and cve['Tracker issue:'] is not None):
        print('Issues: '+cve['Tracker issue:'])
    if('Severity/Risk:' in cve and cve['Severity/Risk:'] is not None):
        print('Risk: '+cve['Severity/Risk:'])
    if('Reported by:' in cve and cve['Reported by:'] is not None):
        print('Reported by: '+cve['Reported by:'])
    if('Changes (master):' in cve and cve['Changes (master):'] is not None):
        print('Changes: '+cve['Changes (master):'])
    
vercheck=santize(v) #làm sạch version dạng x.y.z
for data in jsond:
    if('CVE identifier:' in data and data['CVE identifier:'] is not None and 'Versions affected:' in data and data['Versions affected:'] is not None and 'Severity/Risk:' in data and data['Severity/Risk:'] is not None):
        stringcheck=data['Versions affected:']
        if(vercheck in stringcheck):
            if( 'Serious' in data['Severity/Risk:']):
                listserious.append(data)
            if( 'Minor' in data['Severity/Risk:']):
                listminor.append(data)
            #nvul+=1
            #printcve(data)
            continue
        templist=[]
        affecteds=(re.split('and|\,',stringcheck)) #['4.0 to 4.0.4', ' 3.11 to 3.11.10', ' 3.9 to 3.9.17', ' ', ' earlier unsupported versions']
        for subs in affecteds:
            if('to' in subs):
                lissub=re.split('to',subs)
                #check(vercheck,lissub) # kiểm tra v trong lissub, gói thông tin và return luôn
                if(equalver(vercheck,lissub[0])or equalver(vercheck,lissub[1])):
                    if( 'Serious' in data['Severity/Risk:']):
                        listserious.append(data)
                    if( 'Minor' in data['Severity/Risk:']):
                        listminor.append(data)
                    # nvul+=1
                    # printcve(data)
                    break
                elif(isNewer(vercheck,lissub[0]) and isOlder(vercheck,lissub[1])):
                    if( 'Serious' in data['Severity/Risk:']):
                        listserious.append(data)
                    if( 'Minor' in data['Severity/Risk:']):
                        listminor.append(data)
                    # nvul+=1
                    # printcve(data)
                    break
                for sub in lissub:
                    templist.append(sub)
            #print(templist)
            if('earlier' in subs):
                if(isOlder(vercheck,Oldest(templist))):
                    if( 'Serious' in data['Severity/Risk:']):
                        listserious.append(data)
                    if( 'Minor' in data['Severity/Risk:']):
                        listminor.append(data)
                    # nvul+=1
                    # printcve(data)
                    break
ser=len(listserious)
minor=len(listminor)
total=ser+minor
print("\nYour Moodle version is related to " + str(total)+" CVE")
print(str(ser)+ " CVE with Serious Risk")
print(str(minor)+ " CVE with Minor Risk")
print("Check information for security your Moodle version: ")
print(150*'+')
print("SERIOUS: \n")
for cve in listserious:
    printcve(cve)
print(150*'+')
print("Minor: \n")
for cve in listminor:
    printcve(cve)
# print("\nSerious: " + str(1))
# print("\nMinor: " + str(2))
