# Canotary
A script to detect Canarytokens without triggering them

## Supported tokens
Currently the script only supports the following tokens:
- Windows PE (EXE/DLL)
- Windows Folder
- PDF document
- Microsoft Office documents (xlsx/docx)

## Installing
The only non-standard library dependency of Canotary is 
[LIEF](https://github.com/lief-project/LIEF), which can be installed like so:

```pip install lief```

## Usage

```python canotary.py [--file | --folder] <file_to_be_analyzed>```

## TODO
- support for more file formats
- regex-based alert URL detection
- recursive checks on folders
- multi-file checks

