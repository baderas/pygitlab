# pygitlab
A tool that for creating multiple [GitLab](https://gitlab.com/) accounts and automatically add them to groups.
It uses [pycurl] (https://github.com/pycurl/pycurl) for account creation and the [GitLab API](http://docs.gitlab.com/ce/api/ci/README.html) via [python-gitlab] (https://github.com/gpocentek/python-gitlab) for adding accounts to user groups.

## Why not use [GitLab API] (http://docs.gitlab.com/ce/api/ci/README.html) for creating accounts?
The [GitLab API] (http://docs.gitlab.com/ce/api/ci/README.html) does only support creation of accounts with an password set. The HTTP interface of [GitLab](https://gitlab.com/) does suppoert this. As this is one of the main reasons for this tool, it is necessary to use the HTTP interface.
There is also an [issue on GitLab] (https://gitlab.com/gitlab-org/gitlab-ce/issues/1051) for this.

## Features
* Creates a given set of accounts (without the need of setting a password) and adds them to specified groups
* Adds existing accounts to specfied groups

## Usage

### Linux
```
pip3 install python-gitlab pycurl
git clone https://github.com/baderas/pygitlab.git
cd pygitlab.git 
chmod +x pygitlab.py
./pygitlab.py -h
```

### Windows
```
Open Admin CMD
"c:\Program Files\Python35\Scripts\pip.exe" install python-gitlab pycurl
Open Bash or CMD
git clone https://github.com/baderas/pygitlab.git
cd pygitlab.git 
"c:\Program Files\Python35\python.exe" pygitlab.py -h
```

## Synopsis
```
pygitlab.py [-h] -f CSVFILE [-a] [-g] [-d] [-c CONFIGFILE]

Reads a CSV file and adds new users to gitlab or adds users to groups.

optional arguments:
  -h, --help            show this help message and exit
  -f CSVFILE, --csvfile CSVFILE
                        CSV file to read from
  -a, --adduser         Create users.
  -g, --addtogroup      Add users to groups.
  -d, --dryrun          Only emulate what would be done.
  -c CONFIGFILE, --configfile CONFIGFILE
                        Config file to read from
```

## Config File Format
pygitlab uses a config file to store credentials. See [gitlab.cfg](gitlab.cfg).

Config Files of python-gitlab can not be used, they do not support log in with username and password.
```
[default]
url= # enter gitlab url without / at the end
email=
password=
ssl_verify=false
timeout=10
```

## CSV File Format
Important: The CSV file must be encoded in UTF-8. The column with "1" or "0" decides wheter a user can create groups or not.
See [test_addusers.csv](test_addusers.csv) and [test_addtogroup.csv](test_addtogroup.csv).

### Creating accounts
```
mail,username,realname,1,group1,guest,group2,owner,group3,reporter,group4,guest
mail,username,realname,0,group1,guest,group2,owner,group3,group4,guest
mail,username,realname,1,group1,group2,guest
mail,username,realname,0
mail,username,realname,1,group1
mail,username,realname,1,group1,group2
mail,username,realname,0,group1,group2,group3
```

### Adding accounts to groups
```
username,group1
username,group1,group2
username,group1,guest,group2,owner,group3,reporter,group4,guest
username,group1,guest,group2,owner,group3,group4,guest
username,group1,group2,group3
```
