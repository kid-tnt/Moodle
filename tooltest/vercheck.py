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
print(countDigit(17))
print(countDigit(0))
print(isNewer('3.9.2','3.9.17'))
#Your version is related to 100 CVE 
#50 CVE serious 
#50 CVE minor
