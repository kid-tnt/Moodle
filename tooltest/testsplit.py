string1='4.0 to 4.0.4, 3.11 to 3.11.10, 3.9 to 3.9.17, and earlier unsupported versions'
string2='4.0 to 4.0.4 and 3.11 to 3.11.10'
string3='3.11, 3.10 to 3.10.4, 3.9 to 3.9.7 and earlier unsupported versions'
string4='3.11'
string5='3.9 to 3.9.2'
string6='2.3 to 2.3.2+'
v='Moodle v3.9.2'
import re
from packaging import version

# def santize(versions):
#     for sub_ver in versions:
#         if('.'in sub_ver):
#             return sub_ver
# 3.9.0 to 3.9
# last is 0 remove
# def santize(versions): 
#     for sub_ver in versions:
#         if('.'in sub_ver):
#             s = re.sub(r"\.0$", "", sub_ver)
#             print(s)

# def printcve(cve):
#     print("")
#     print('CVE identifier: '+cve['CVE identifier:'])
#     print('Risk: '+cve['Severity/Risk:'])
#     print('Reported by:'+cve['Reported by:'])
#     print('Changes: '+cve['Changes (master):'])
#     print('Reference: '+cve['Tracker issue:'])


# def check(v,lissub):# kiểm tra v trong lissub, gói thông tin và return luôn
#      if(version.parse(lissub[0])<version.parse(v)<version.parse(lissub[1])):
#         printcve()

# vercheck=santize(v) #làm sạch version dạng x.y.z
# if(vercheck in string1):
#     printcve()# ghi ra thông tin của cve
# else:
#     templist=[]
#     affecteds=(re.split('and|\,',string1)) #['4.0 to 4.0.4', ' 3.11 to 3.11.10', ' 3.9 to 3.9.17', ' ', ' earlier unsupported versions']
#     for subs in affecteds:
#         if('to' in subs):
#             lissub=re.split('to',subs)
#             check(vercheck,lissub) # kiểm tra v trong lissub, gói thông tin và return luôn
#         for sub in lissub:
#             templist.append(sub)
#         #print(templist)
#         if('earlier' in subs):
#             min=templist[0]
#             for i in range(0,len(templist)):
#                 if(version.parse(templist[i])<version.parse(min)):
#                     min=templist[i]
#             if(vercheck<min):
#                 printcve()

#affecteds=(re.split('and|\,',string1))
# có ['4.0 to 4.0.4', ' 3.11 to 3.11.10', ' 3.9 to 3.9.17', ' ', ' earlier unsupported versions']

# xử lí mỗi  4.0 to 4.0.4
# subs='4.0 to 4.0.4'
# if('to' in subs):
#     sub=re.split('to',subs)
#     for i in sub:
#         templist.append(i)
# print(templist)
# if('earlier' in subs):
#     min=min()


#minversion from list version 
#def min
# min=templist[0]
# for i in range(0,len(templist)):
#     if(version.parse(templist[i])<version.parse(min)):
#         min=templist[i]
# print(min)

# Nếu có early thì tìm min : check < min thì đưa ra thông tin 




#print(version.split('v'))
#can use version to check
# from packaging import version
# print(version.parse('4.0')<version.parse('4.0.4'))


#làm sạch version dạng x.y.z
# import re
# versions=(re.split('v|\-',v))
# for sub_ver in versions:
#     if('.'in sub_ver):
#         print (sub_ver)

def santize(versions): 
    versions=(re.split('v|\-',versions))
    for sub_ver in versions:
        if('.'in sub_ver):
            sub_ver = re.sub(r"\.0$", "", sub_ver)
            return sub_ver

print(santize("4.0.4"))


#