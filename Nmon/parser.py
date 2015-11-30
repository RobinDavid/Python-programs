#!/usr/bin/python
# -*- coding: utf-8 -*-

import xml.etree.ElementTree as etree

def parsestring(s):
	return etree.fromstring(s)

def parsefile(f):
	return etree.parse(f).getroot()

def xml_to_dict(el):
	dict_root={}
	dict_content={}
	dict_root[el.tag] = dict_content
	if el.items():
		dict_root[el.tag] = tuplelist_to_dict(el.items())
	child = el.getchildren()
	if child:
		temp = map(xml_to_dict, child)
		#map renvoie un list de dictionnaire qui poeut contenir des elements avec le même nom (qui seraient écrasés dans le passage d'un seul et même dictionnaire.
		#On transforme donc la liste en dictionnaire, si le nom d'un element apparait plusieurs foison remplace la valeur de l'élément par une liste de dictionnaire
		temp_dict = {} #met doublons dans une liste
		for e in temp:
			if not temp_dict.has_key(e.keys()[0]):
				temp_dict.update(e)
			else:
				if (isinstance(temp_dict[e.keys()[0]], list)):
					temp_dict[e.keys()[0]].append(e)
				else:
					temp_dict[e.keys()[0]] = [{e.keys()[0]: temp_dict[e.keys()[0]]},e]
		dict_root[el.tag].update(temp_dict)
	return dict_root

def tuplelist_to_dict(l):
	di = {}
	for k,v in l:
		di[k] = v
	return di
