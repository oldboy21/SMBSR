
import string 
import sys

def checkChar(x,counter):
	lower = set(string.ascii_lowercase)
	upper = set(string.ascii_uppercase)
	
	if x.isspace():
		return "(?=^.{" + str(counter) + "}[\s])"
	elif x.isalnum() is False:
		return "(?=^.{" + str(counter) + """}[!@#&_()–\[\{\}\]:;'%,?\/\*~\$\^\+="<>])""" 
	elif x in lower:
		return "(?=^.{" + str(counter) + "}[a-z])"
	elif x in upper: 
		return "(?=^.{" + str(counter) + "}[A-Z])"
	else: 
		return "(?=^.{" + str(counter) + "}[\d])"


filepath = input("Wordlist path, please: ")
final = []
lines = []	
result = ""
try: 
  with open(filepath, 'rb') as f:
    for line in f:
        try:
          lines.append(line.strip(b'\n'))
        except Exception as e:
           print ('Error while reading line in the wordlist' + str(e))
           continue
  f.close()    
except Exception as e:
     print (e)
     sys.exit(1)   
for line in lines:
	result = "" 
	try: 
		line = line.decode("utf-8")
	except Exception as e: 
		continue
	for element in range(0, len(line)):
    		result += checkChar(line[element],element)
	final.append(result)

final = list( dict.fromkeys(final) )

with open("regulars.txt", "a") as f:
   for x in final:
       f.write(x + "\n")
f.close()
	 
