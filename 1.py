import binascii
import sys
import os


# 先把1.txt给姐解析了，把时间戳什么的都写到res.,txtqu

fasdasdasdasdadasdads = open("res.txt", "w")
# fileyouwillenevdup1 = open('1.txt', 'r')
# Linesyouwillnevedup = fileyouwillenevdup1.readlines()
# locateindex=0
# nextlineisit=False
# yuserconerrqrq=0
# for lineLinesyouwillnevedup in Linesyouwillnevedup:
#   lineLinesyouwillnevedup=lineLinesyouwillnevedup.strip()
#   if nextlineisit:
#     nextlineisit=False
#     print("logon time:")
#     fasdasdasdasdadasdads.write("logon time:\n")
#     print("\t"+lineLinesyouwillnevedup)
#     fasdasdasdasdadasdads.write("\t"+lineLinesyouwillnevedup+"\n")
#     fasdasdasdasdadasdads.write("----------------------------------------------\n\n")
#
#     locateindex=0
#     continue
#   if lineLinesyouwillnevedup.find("___")!=-1:
#     if locateindex==0:
#       print("-------------------USER"+str(yuserconerrqrq)+"----------------------\n")
#       fasdasdasdasdadasdads.write("-------------------USER"+str(yuserconerrqrq)+"----------------------\n")
#       yuserconerrqrq=yuserconerrqrq+1
#       print("username:")
#       fasdasdasdasdadasdads.write("username:\n")
#       print("\t"+lineLinesyouwillnevedup.replace("_______username:",""))
#       fasdasdasdasdadasdads.write("\t"+lineLinesyouwillnevedup.replace("_______username:","")+"\n")
#       locateindex=locateindex+1
#       continue
#     if locateindex==1:
#       print("domain:")
#       fasdasdasdasdadasdads.write("domain:\n")
#       print("\t"+lineLinesyouwillnevedup.replace("_______domain:",""))
#       fasdasdasdasdadasdads.write("\t"+lineLinesyouwillnevedup.replace("_______domain:","")+"\n")
#       locateindex=locateindex+1
#       continue
#   if lineLinesyouwillnevedup.find("logon time")!=-1:
#     nextlineisit=True



file_size = os.path.getsize('3iaad')
keytlisyty=[]
byte = 9
lenasd=0
counter=0
alreadyreaded=0
firstkeycounter=True

while True:
  counter=0
  lenasd=0
  with open("3iaad", "rb") as f:
    if alreadyreaded!=0:
      byte = f.read(alreadyreaded)
    while byte != b"":
      # Do stuff with byte.
      if firstkeycounter:
        if counter==3:
          # 长度读取完毕，下面开始读取key
          alreadyreaded+=counter+1
          break
      else:
        if counter==4:
          # 长度读取完毕，下面开始读取key
          alreadyreaded+=counter
          firstkeycounter=False
          break
      byte = f.read(1)
      # 先读取4bytes的长度
      temp=int.from_bytes(byte, "big")
      temp=temp<<(8*counter)
      lenasd=lenasd+temp
      #print(lenasd)
      counter=counter+1

  counter=0
  keybytearray=[]
  with open("3iaad", "rb") as f:
    f.read(alreadyreaded)
    while True:
      # Do stuff with byte.
      if counter==lenasd:
        # 长度读取完毕，下面开始读取key
        alreadyreaded=alreadyreaded+counter
        break
      byte = f.read(1)
      # 先读取4bytes的长度
      keybytearray.append(byte)
      # temp=temp<<(8*counter)
      # lenasd=lenasd+temp
      # print(lenasd)
      counter=counter+1
  #print(lenasd)
  #print("[+] got DES key, length: " + str(lenasd))
  print(f'[+] got DES key, length: {lenasd:#0{4}x}')
  print("\t",end="")
  indexxxx=0
  lenarr=len(keybytearray)
  for bytttttin in keybytearray:
    indexxxx=indexxxx+1
    if lenarr!=indexxxx:
      #print(hex(),end=", ")
      print(f'{int.from_bytes(bytttttin, "big"):#0{4}x}',end=", ")
    else:
      print(f'{int.from_bytes(bytttttin, "big"):#0{4}x}')
  if keybytearray not in keytlisyty:
    # 只接受长度为24的deskey
    if len(keybytearray)==24:
      keytlisyty.append(keybytearray)
  #print(hex(alreadyreaded))
  if file_size<=alreadyreaded:
    break
print("[*] total "+str(len(keytlisyty)) +" key got")


print()
print()
print("==========================================================")
print()
print()




file_size = os.path.getsize('kiaad')
keytlisytys=[]
byte2 = 9
lenasd=0
counter=0
alreadyreaded=0
firsttimecount=True
while True:
  counter=0
  lenasd=0
  with open("kiaad", "rb") as f:
    if alreadyreaded!=0:
      byte2 = f.read(alreadyreaded)
    while byte2 != b"":
      # Do stuff with byte.
      if firsttimecount:
        if counter==3:
          # 长度读取完毕，下面开始读取key
          alreadyreaded=alreadyreaded+counter+1
          break
      else:
        if counter==4:
          # 长度读取完毕，下面开始读取key
          alreadyreaded=alreadyreaded+counter
          firsttimecount=False
          break
      byte2 = f.read(1)
      # 先读取4bytes的长度
      temp=int.from_bytes(byte2, "big")
      temp=temp<<(8*counter)
      lenasd=lenasd+temp
      #print(lenasd)
      counter=counter+1

  counter=0
  keybytearray=[]
  with open("kiaad", "rb") as f:
    f.read(alreadyreaded)
    while True:
      # Do stuff with byte.
      if counter==lenasd:
        # 长度读取完毕，下面开始读取key
        alreadyreaded=alreadyreaded+counter
        break
      byte2 = f.read(1)
      # 先读取4bytes的长度
      keybytearray.append(byte2)
      # temp=temp<<(8*counter)
      # lenasd=lenasd+temp
      # print(lenasd)
      counter=counter+1
  #print(lenasd)
  #print("[+] got DES key, length: " + str(lenasd))
  print(f'[+] got encrypted text, length: {lenasd:#0{4}x}')
  print("\t",end="")
  indexxxx=0
  lenarr=len(keybytearray)
  # for bytttttin in keybytearray:
  #     indexxxx=indexxxx+1
  #     if lenarr!=indexxxx:
  #         #print(hex(),end=", ")
  #         print(f'{int.from_bytes(bytttttin, "big"):#0{4}x}',end=", ")
  #     else:
  #         print(f'{int.from_bytes(bytttttin, "big"):#0{4}x}')
  if keybytearray not in keytlisytys:
    # 而且我发现enctext也都是0x1a8
    #if lenarr>=0x1a8:
    #keytlisytys.append(keybytearray[:0x1a8])
    # 这个长度并不是固定的，有的长有的短
    if len(keybytearray)>0x100:
      keytlisytys.append(keybytearray)
  #print(hex(alreadyreaded))
  if file_size<=alreadyreaded:
    break
print("[*] total "+str(len(keytlisytys)) +" encrypted text got")




print()
print()
print("==========================================================")
print()
print()


print("[*] begin decrypting...")


from Crypto.Cipher import DES3
from Crypto import Random
key = 'Sixteen byte key'
iv = Random.new().read(DES3.block_size) #DES3.block_size==8
cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)
plaintext = 'sona si latine loqueri  ' #padded with spaces so than len(plaintext) is multiple of 8
encrypted_text = cipher_encrypt.encrypt(plaintext.encode("utf8"))

cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv) #you can't reuse an object for encrypting or decrypting other data with the same key.

#print(cipher_decrypt.decrypt(encrypted_text))
# keytlisyty
#
allhashes=[]
from Crypto.Random import get_random_bytes
asdasdasdasd=get_random_bytes(24)
# keytlisytys
for enctext in keytlisytys:
  sdsdsssdsdsdsdsdbytess=b''
  for isdsdsdsdsiiii in enctext:
    sdsdsssdsdsdsdsdbytess=sdsdsssdsdsdsdsdbytess+isdsdsdsdsiiii
  for deskey in keytlisyty:
    key = 'Sixteen byte key'
    iv = Random.new().read(DES3.block_size) #DES3.block_size==8
    cipher_encrypt = DES3.new(key, DES3.MODE_OFB, iv)
    plaintext = 'sona si latine loqueri  ' #padded with spaces so than len(plaintext) is multiple of 8
    encrypted_text = cipher_encrypt.encrypt(plaintext.encode("utf8"))
    # values = bytearray(deskey)
    sdsdsbytess=b''
    for iiiii in deskey:
      sdsdsbytess=sdsdsbytess+iiiii
    try:
      keysssss = DES3.adjust_key_parity(sdsdsbytess)
    except:
      continue
    cipher_decrypt = DES3.new(keysssss, DES3.MODE_CBC, iv) #you can't reuse an object for encrypting or decrypting other data with the same key.



    hex_data = binascii.hexlify(sdsdsbytess)
    #print(sdsdsbytess.hex(' '))
    hex_data = binascii.hexlify(sdsdsssdsdsdsdsdbytess)
    #print(sdsdsssdsdsdsdsdbytess.hex(' '))
    try:
      decrypted = cipher_decrypt.decrypt(sdsdsssdsdsdsdsdbytess)
    except:
      continue
    print("enc key pair:")
    print(binascii.hexlify(sdsdsssdsdsdsdsdbytess).decode('utf-8')+'-----------'+binascii.hexlify(sdsdsbytess).decode('utf-8'))
    print("+++++++++++++++++++++++++++++++++++++++++++++++")
    #print(decrypted.decode('utf-16'))
    hex_data = binascii.hexlify(decrypted).decode('utf-8')
    pushmeintheheel=hex_data
    # 最好是把未经处理的hex_data也放上去，这样出错了也好对比
    import re
    if hex_data.find('740065007300740032000000')!=-1:
      asdasdqwhuei89123=0
    #hex_data='50bfe26dfae4d7203b2b058c22803fb680010000000000000200040000000000a001000000000000f025e25fff7f000000010001000000000000000000000000000000000000000000000000000000000000061c54f1f5311e1f47958465e16bab6500000000000000000000000000000000d2838e46be955bfc04c0db03c2028651377691db0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004400450053004b0054004f0050002d0046004a0050004d0045003300450000007800000000000000'
    #print(hex_data)
    if hex_data.find('61c54f1f5311e1f47958465e16ba')!=-1:
      asd12312=0
    print(hex_data)
    caonimadefuckasdhufa=hex_data
    # 将字节序列转换成ascii字符串
    finnastsldfusetrstr=''
    hex_data=hex_data.lower()
    if hex_data.find('1031969ec95888ef8180d700a6f433ab')!=-1:
      aasda2sdasd=1
    for i in range(0,len(hex_data),2):
      temppppppp=0
      temppppppp2=0
      if hex_data[i].isalpha():
        temppppppp=ord(hex_data[i])-97+10
      else:
        temppppppp=int(hex_data[i])
      if i+1<len(hex_data):
        if hex_data[i+1].isalpha():
          temppppppp2=ord(hex_data[i+1])-97+10
        else:
          temppppppp2=int(hex_data[i+1])
      tempinterr=temppppppp*16+temppppppp2
      # 可打印字符
      if tempinterr !=0:
        if tempinterr<32 or tempinterr>126 and tempinterr !=0:
          i=i+1
          continue
      print(tempinterr)
      if tempinterr==0:

        finnastsldfusetrstr+='.'
      else:
        finnastsldfusetrstr+=chr(tempinterr)
      print(finnastsldfusetrstr)
      i=i+1

    print(finnastsldfusetrstr)
    finnastsldfusetrstr=finnastsldfusetrstr.replace('..','__')
    finnastsldfusetrstr=finnastsldfusetrstr.replace('.','')
    hex_data =hex_data.replace("0000",'\n')
    import re
    match = re.search(r'^.{32,32}$', hex_data)


    import re

    regex = r"^.{32,32}$"

    test_str = ("50bfe26dfae4d7203b2b058c22803fb68\n"
                "1\n\n\n\n\n\n"
                "02\n"
                "04\n\n\n\n\n"
                "a\n"
                "1\n\n\n\n\n\n"
                "f025e25fff7f\n\n\n"
                "01\n"
                "01\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                "061c54f1f5311e1f47958465e16bab65\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                "d2838e46be955bfc04c0db03c2028651377691db\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
                "44\n"
                "45\n"
                "53\n"
                "4b\n"
                "54\n"
                "4f\n"
                "5\n"
                "02d\n"
                "46\n"
                "4a\n"
                "5\n"
                "04d\n"
                "45\n"
                "33\n"
                "45\n\n\n"
                "78\n\n\n\n\n\n\n")

    matches = re.finditer(regex, hex_data, re.MULTILINE)

    for matchNum, match in enumerate(matches, start=1):

      #print ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum = matchNum, start = match.start(), end = match.end(), match = match.group()))
      hashhhhhh=match.group()
      if hashhhhhh not in allhashes:

        # 同时追加对应的字符序列
        pass
        #allhashes.append(hashhhhhh+'++++++++++++++++++++++++++++++++++++++++++'+finnastsldfusetrstr+'fordebug'+pushmeintheheel)
      for groupNum in range(0, len(match.groups())):
        groupNum = groupNum + 1
    # 对于windows10版本，hash的偏移量是74，翻译成字节序列就是148，再加上primary.占用8字节，字节序列16，
    #￥最终偏移量就是148+16=164
    caonimadefuckasdhufa=caonimadefuckasdhufa[164:]
    caonimadefuckasdhufa=caonimadefuckasdhufa[:32]
    if caonimadefuckasdhufa not in allhashes:
      allhashes.append(caonimadefuckasdhufa+'++++++++++++++++++++++++++++++++++++++++++'+finnastsldfusetrstr+'fordebug'+pushmeintheheel)
print("[+] here is all here ntlm hash we got:")
fasdasdasdasdadasdads.write("\nAll possible ntlm hash:\n")
for h in allhashes:
  print("\t"+h)
  fasdasdasdasdadasdads.write('\t'+h.split('++++++++++++++++++++++++++++++++++++++++++',1)[0]+'\n')
  fasdasdasdasdadasdads.write('\t\t'+h.split('++++++++++++++++++++++++++++++++++++++++++',1)[1].split('fordebug',1)[0].replace('___________________','')+'\n')
  fasdasdasdasdadasdads.write('\t\t'+h.split('++++++++++++++++++++++++++++++++++++++++++',1)[1].split('fordebug',1)[1].replace('___________________','')+'\n')



"""
For MODE_ECB, MODE_CBC, and MODE_OFB, plaintext length (in bytes) must be a multiple of block_size.
For MODE_CFB, plaintext length (in bytes) must be a multiple of segment_size/8.
For MODE_CTR, plaintext can be of any length.
For MODE_OPENPGP, plaintext must be a multiple of block_size, unless it is the last chunk of the message.
key size (must be either 16 or 24 bytes long)
"""
"""
https://pythonhosted.org/pycrypto/Crypto.Cipher.DES3-module.html
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
"""
fasdasdasdasdadasdads.close()