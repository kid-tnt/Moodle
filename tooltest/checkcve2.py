#365 vul CVE
import re
v='Moodle v3.9.0-beta'
stringcheck='2.4 to 2.4.1, 2.3 to 2.3.4, 2.2 to 2.2.7, earlier unsupported versions'
nvul=0;
def santize(versions):
    versions=(re.split('v|\-',v))
    for sub_ver in versions:
        if('.'in sub_ver):
            return sub_ver
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
    arr1 = [int(i) for i in arr1]
    arr2 = [int(i) for i in arr2]
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    # returns 1 if version 1 is bigger and -1 if
    # version 2 is bigger and 0 if equal
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
    arr1 = [int(i) for i in arr1]
    arr2 = [int(i) for i in arr2]
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    # returns 1 if version 1 is bigger and -1 if
    # version 2 is bigger and 0 if equal
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
    # compares which list is bigger and fills
    # smaller list with zero (for unequal delimiters)
    if m>n:
        for i in range(n, m):
            arr2.append(0)
    elif m>n:
        for i in range(n, m):
            arr1.append(0)

    # returns 1 if version 1 is bigger and -1 if
    # version 2 is bigger and 0 if equal
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
    if('CVE identifier:' in cve and cve['CVE identifier:'] is not None):
        print('CVE identifier: '+cve['CVE identifier:'])
    if('Tracker issue:' in cve and cve['Tracker issue:'] is not None):
        print('Issues: '+cve['Tracker issue:'])
    if('Severity/Risk:' in cve and cve['Severity/Risk:'] is not None):
        print('Risk: '+cve['Severity/Risk:'])
    if('Reported by:' in cve and cve['Reported by:'] is not None):
        print('Reported by: '+cve['Reported by:'])
    if('Changes (master):' in cve and cve['Changes (master):'] is not None):
        print('Changes: '+cve['Changes (master):'])
    
vercheck=santize(v) #làm sạch version dạng x.y.z
if(vercheck in stringcheck):
    nvul+=1
    print('ok')
    # ghi ra thông tin của cve
else:
    templist=[]
    affecteds=(re.split('and|\,',stringcheck)) #['4.0 to 4.0.4', ' 3.11 to 3.11.10', ' 3.9 to 3.9.17', ' ', ' earlier unsupported versions']
    for subs in affecteds:
        if('to' in subs):
            lissub=re.split('to',subs)
            #check(vercheck,lissub) # kiểm tra v trong lissub, gói thông tin và return luôn
            if(equalver(vercheck,lissub[0])or equalver(vercheck,lissub[1])):
                nvul+=1
                printcve('ok')
                break
            elif(isNewer(vercheck,lissub[0]) and isOlder(vercheck,lissub[1])):
                nvul+=1
                printcve('ok')
                break
        for sub in lissub:
            templist.append(sub)
        #print(templist)
        if('earlier' in subs):
            if(isOlder(vercheck,Oldest(templist))):
                printcve('ok')
                break
print("\nVulnerabilities found: " + str(nvul))
