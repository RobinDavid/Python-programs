Introduction
------------

The wish to do a frequency analysis of wikipedia came from the lack of a good frequency table for french character that included every characters(space, tab, LF etc). All that, for performing frequency analysis for crypto challenges.
I took the Wikipedia content as it seems to be greatest source of text easily accessible and downloadable.

Dumps can be downloaded on [wikimedia](http://dumps.wikimedia.org/frwiki/latest/). The one I took for this test is the release of the 18th of February 2012 and weigh uncompressed 12.5 GB.


The code used is quite simple, the only thing I had to deal with was the xml and the wiki syntax. Indeed I wanted only articles content and not all xml tags which would have disguised results.

Thats why I filtered only the text contained into '&lt;text xml:space="preserve"&gt;' and '&lt;/text&gt;' which are the two markers for the begin and the end of an article. Moreover within an article I do some clean up that's why I remove all Wiki syntax tags(in a dirty way) otherwise it would also disguise results (and '[' would be for instance well ranked whereas it should not).

_Note: I have written this script in python 3 that support unicode which is crucial here._



Results
-------


The execution of my script took aproximately 3 hours and the output is:
``` python
bash$ ./wiki-analysis.py frwiki-latest-pages-meta-current.xml
Lines: 222669441
Execution time: 10033.887793064117 secondes                                                                                  
Articles: 3714740       Lines: 222669441        Number characters: 9217905119   Different characters: 27605

Results in: RESULT-frwiki-latest-pages-meta-current.xml.txt
```

You can download the output file with the complete table [here](https://github.com/RobinDavid/Python-programs/blob/master/wikipedia_frequency_analysis/RESULT-frwiki-latest-pages-meta-current.xml.txt).

As we could have supposed the **space** comes in first position with 1329412224 times, followed by "e" and "t". The LF comes in 16th position.
