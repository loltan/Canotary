import zlib
import argparse
import os
import codecs
import sys
import re
from zipfile import ZipFile
import tempfile
import shutil

import lief

STREAM_OFFSET=793
MODE_DIRECTORY = 0x10

def findCanary(zipfile, zipinfo):
    foundCanary = False
    dirname = tempfile.mkdtemp()
    fname = zipfile.extract(zipinfo, dirname)
    
    with open(fname, 'r') as fd:
        if fd.read().find('http://canarytokens') != -1:
           foundCanary = True
    shutil.rmtree(dirname)
    
    return foundCanary

def analysePdf(fileName):
    f = open(fileName, 'rb')
    contents = f.read()
    f.close()
    
    try:
        stream_size = int(re.match(b'.*\/Length ([0-9]+)\/.*', contents[STREAM_OFFSET:]).group(1))
        stream_start = STREAM_OFFSET+contents[STREAM_OFFSET:].index(b'stream\r\n')+8
        stream = contents[stream_start:stream_start+stream_size]
        
        candidate_stream = zlib.decompress(stream)

        if re.search(b'canary', candidate_stream):
            print('The PDF is a canary token!')
        else: 
            print('The file is clean!')
    except:
        print('The file is clean!')

def analyseWordOrExcel(fileName):
    with ZipFile(fileName, 'r') as doc:
        for entry in doc.filelist:
            if entry.external_attr & MODE_DIRECTORY:
                continue
            
            canary = findCanary(zipfile=doc, zipinfo=entry)
            if canary:
                print('This MS Office document is a canary!')
                break
    
    if not canary:
        print('The file is clean!')

def analyseWinDir(folderName):
    canaryString = 'canary'
    
    try:
        for name in os.listdir(folderName):
            if name == 'desktop.ini':
                potentialCanary = os.path.join(folderName, 'desktop.ini')

        for line in codecs.open(potentialCanary, 'r', encoding='utf16'):
            if canaryStringFirst in line:
                print('The folder is a canarytoken!')
    except: 
        print('The folder is clean!')

def analyseDLLorEXE(fileName):
    f = open(fileName, 'rb')
    contents = f.read()
    f.close()

    pe = lief.parse(fileName)
    if len(pe.signatures) == 0:
        print('The binary is clean (binary not signed)!')
        sys.exit()

    signature = pe.signatures[0]
    if 'Thinkst Applied Research' in signature.signers[0].issuer:
        print('The file is a canarytoken!')

def main():
    parser = argparse.ArgumentParser(description='Scan some files.')
    parser.add_argument('--file', help='Single file to analyse')
    parser.add_argument('--folder', help='Folder to analyse')
    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print('File does not exist')
            sys.exit()

        if args.file.endswith('.docx') or args.file.endswith('.xlsx'):
            analyseWordOrExcel(args.file)
        elif args.file.endswith('.pdf'):
            analysePdf(args.file)
        elif args.file.endswith('.dll') or args.file.endswith('.exe'):
            analyseDLLorEXE(args.file)
        else:
            print("File format not supported!")

    if args.folder:
        if not os.path.isdir(args.folder):
            print('Folder does not exist')
            sys.exit()
        
        analyseWinDir(args.folder)

if __name__ == "__main__":
    main()