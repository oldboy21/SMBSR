
import string 


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
result = ""
try: 
  with open(filepath) as f:
      lines = [line.rstrip() for line in f]
  f.close()    
except Exception as e:
     print (e)   
for line in lines:
	result = "" 
	for element in range(0, len(line)):
    		result += checkChar(line[element],element)
	final.append(result)

final = list( dict.fromkeys(final) )

for x in final:
	print (x) 
