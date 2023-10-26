
import uuid
import sys



def XORcryptInt(str2xor):
    int2xor = []
    for i in str2xor:
        asdhuiagdyasgdiaudiasd=ord(i)
        if i=='`':
            asdhuiagdyasgdiaudiasd=10
        if i=='~':
            asdhuiagdyasgdiaudiasd=92
        int2xor.append(asdhuiagdyasgdiaudiasd ^ 1)
    return int2xor

def delatlineWITHINDEX(arggggg,fuckingindexxxx):
    ashdhasduagisdasudgaogdasd=fuckingindexxxx
    fuckingindexxxx=0
    string_to_be_obfuscated = arggggg
    # 有两种特殊情况需要处理，一种是\n，另一种是\\
    # 将前者替换成`，将后者替换成~
    string_to_be_obfuscated=string_to_be_obfuscated.replace(r'\n','`')
    string_to_be_obfuscated=string_to_be_obfuscated.replace(r'\\','~')
    intArray = XORcryptInt(string_to_be_obfuscated)

    fuckyoui=""
    for i in intArray:
        fuckyoui += str(i)
        fuckyoui += ","

    fuckyoui = fuckyoui[:-1]
    # print(fuckyoui)
    intvaname=str(uuid.uuid4())
    intvaname=intvaname.replace("-","_")
    fuckiiii = 'MYS_ecureZeroMemory((char*)_fuckingstring'+str(fuckingindexxxx)+',100);'

    indexxxxxxx=0
    for i in    intArray:
        fuckiiii+="_fuckingstring"+str(fuckingindexxxx)+'['+str(indexxxxxxx)+']'+'='+str(i)+';'
        indexxxxxxx=indexxxxxxx+1;


    fuckiiii+="_fuckingstring"+str(fuckingindexxxx)+'['+str(indexxxxxxx)+']'+'='+str(1)+';'
    return fuckiiii+'FBXorCrypt(_fuckingstring'+str(fuckingindexxxx)+', '+str(indexxxxxxx+1)+');char* _caoniamde'+str(ashdhasduagisdasudgaogdasd)+'=(char*)malloc(100);memcpy(_caoniamde'+str(ashdhasduagisdasudgaogdasd)+',_fuckingstring'+str(fuckingindexxxx)+',100);'
def delatline(arggggg):
    string_to_be_obfuscated = arggggg
    # 有两种特殊情况需要处理，一种是\n，另一种是\\
    # 将前者替换成`，将后者替换成~
    string_to_be_obfuscated=string_to_be_obfuscated.replace(r'\n','`')
    string_to_be_obfuscated=string_to_be_obfuscated.replace(r'\\','~')
    intArray = XORcryptInt(string_to_be_obfuscated)

    fuckyoui=""
    for i in intArray:
        fuckyoui += str(i)
        fuckyoui += ","

    fuckyoui = fuckyoui[:-1]
    # print(fuckyoui)
    intvaname=str(uuid.uuid4())
    intvaname=intvaname.replace("-","_")
    fuckiiii = 'MYS_ecureZeroMemory((char*)_fuckingstring,100);'

    indexxxxxxx=0
    for i in    intArray:
        fuckiiii+="_fuckingstring"+'['+str(indexxxxxxx)+']'+'='+str(i)+';'
        indexxxxxxx=indexxxxxxx+1;


    fuckiiii+="_fuckingstring"+'['+str(indexxxxxxx)+']'+'='+str(1)+';'
    return fuckiiii+'FBXorCrypt(_fuckingstring, '+str(indexxxxxxx+1)+');'



startrecording=0
recordarray=[]
fuckingindexxxxxx=0
with open(sys.argv[1], 'r') as file:
    for line in file:
        # 注释肯定是不用处理的
        fukcingtemp=line.strip()
        if fukcingtemp.__len__()>=2:
            if fukcingtemp.find("stringarray")!=-1:
                startrecording=1
                # 从下一行开始，都是动态内存分配
                # 我们需要把当前行和后面的行都记录下来
                recordarray.append(line)
                continue
            if fukcingtemp.find("endarray")!=-1:
                startrecording=0
                # 处理我们记录下来的行
                thisisfirstline=1
                thefuckingfistline=recordarray[0]
                fuckingrecordresult=''
                thisseconfuckarray=[]
                reocrdlennn= recordarray.__len__()
                counterrrrrrrr=0
                for fuckinglinnnnn in recordarray:
                    counterrrrrrrr=counterrrrrrrr+1
                    if thisisfirstline==1:
                       # print(fuckinglinnnnn)
                        thisisfirstline=0
                    else:
                        import re

                        # The string you want to search for a match in
                        text = fuckinglinnnnn

                        # Define a regular expression pattern
                        pattern = r'".*?"'

                        # Use re.search() to find the first match
                        match = re.search(pattern, text)

                        if match:
                            # If a match is found, you can access the matched text using group()
                            matched_text = match.group()
                            argsfordeal=matched_text[1:-1]
                            asdiaodhiohdioahdiahdias=delatlineWITHINDEX(argsfordeal,fuckingindexxxxxx)
                            fuckingrecordresult+= asdiaodhiohdioahdiahdias
                            if counterrrrrrrr!=reocrdlennn:
                                fuckinglinnnnn='_caoniamde'+str(fuckingindexxxxxx)+','+'\n'
                            else:
                                fuckinglinnnnn='_caoniamde'+str(fuckingindexxxxxx)+' '+'\n'
                            fuckingindexxxxxx+=1
                            thisseconfuckarray.append(fuckinglinnnnn)
                        else:
                            print("something really bad happened")
                            exit(-1)
                # 处理完成之后进行输出
                print(fuckingrecordresult)
                print(thefuckingfistline)
                for iiiiii in thisseconfuckarray:
                    print(iiiiii)
                print(line)
                recordarray=[]
                thisseconfuckarray=[]
                fuckingrecordresult=[]
                continue

            if startrecording==1:
                recordarray.append(line)
                continue
            if fukcingtemp.find("#pragma")!=-1:
                print(line)
                continue
            if fukcingtemp[0]=='/' and fukcingtemp[1]=='/':
                # 直接打印即可，不用处理
                print(line)
            else:
                # 检查是否有字符串，通过正则进行匹配
                import re

                # The string you want to search for a match in
                text = line

                # Define a regular expression pattern
                pattern = r'".*?"'

                # Use re.search() to find the first match
                match = re.search(pattern, text)

                if match:
                    # If a match is found, you can access the matched text using group()
                    matched_text = match.group()
                    argsfordeal=matched_text[1:-1]
                    asdiaodhiohdioahdiahdias=delatline(argsfordeal)
                    print( asdiaodhiohdioahdiahdias)
                    print(line.replace(matched_text,'_fuckingstring'))
                    #print("Match found:", matched_text)
                else:
                    print(line)
        else:
            print(line)

        #  delatline
       # print(line, end='')