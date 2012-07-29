#!/usr/bin/python3.2

import re
import sys
import time

#---------- GLOBAL VARS -------
lines=0
articles=0
#characters=0

f = open(sys.argv[1],"r")
article = ""

begin_text = re.compile('<text xml:space="preserve">')
end_text = re.compile('</text>')
within_article = False
dictionnary = {}

left_brackets = re.compile("\[\[")
right_brackets = re.compile("\]\]")
colon_brackets = re.compile("\[\[\S*:.*\]\]\n")
curly_brackets = re.compile("\{\{.*\}\}\n?")
#------------------------------


def print_temp_stats():
    print("Lines: " + str(lines),end="\r")
  

def clean_line(l):
  line = l
  line = re.sub(colon_brackets,'',line)
  line = re.sub(left_brackets,'',line)
  line = re.sub(right_brackets,'',line)
  line = re.sub(curly_brackets,'',line)
  return line

def processArticle(s):
  #global characters
  for elt in s:
    try:
      dictionnary[elt] += 1
    except KeyError: #Faster in execution than doing if dictionnary.get(elt) because triggered once for each new characters but after far faster..
      dictionnary[elt] = 1

    
def write_final():
  print()
  name = "RESULT-"+sys.argv[1]+".txt"
  fout = open(name,"w")
  l = sorted(dictionnary.items(),key=lambda x: x[1], reverse=True)
  for elt in l:
    e = elt[0]
    if e == " ":
      e = "[SPACE]"
    elif e == "\n":
      e = "[LF]"
    elif e == "\t":
      e = "[HTAB]"
    elif e == "\r":
      e = "[CR]"
    s = e + ": " + str(elt[1])
    fout.write(s+"\n")
  fout.close()
  print("Results in: "+name)

  
  
def print_final_stats():
  chars = 0
  for v in dictionnary.values():
    chars += v
  print("Articles: "+ str(articles) + "\tLines: " + str(lines) + "\tNumber characters: "+str(chars)+"\tDifferent characters: "+ str(len(dictionnary)))

    
    
if __name__ == "__main__":
  
  if len(sys.argv) <= 1:
    print("Usage: wiki-analysis.py wikipedia-filename")
    sys.exit(1)
  
  tdeb = time.time()
   
  while 1:
      line = f.readline()
      if line == "":
          break;
      lines += 1
  
      if not within_article:
          if re.search(begin_text,line):
              within_article = True
              articles += 1
              article += clean_line(re.sub(begin_text,"",line))
      else: #already in an article
          if re.search(end_text,line):
              within_article = False
              processArticle(article)
              article = ""
          else:
              article += clean_line(line)
              
      print_temp_stats()

    
  tfin=time.time()
  
  print("\nExecution time: "+str(tfin-tdeb) + " secondes")
  print_final_stats()
  write_final()
  sys.exit(0)