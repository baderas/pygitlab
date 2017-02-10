#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import gitlab.exceptions
import argparse
import logging
import csv
import urllib
import http.cookiejar
import re
import configparser

__author__ = 'Andreas Bader'
__version__ = "0.01"

# C:\Python36\lib\site-packages\requests\packages\urllib3\connectionpool.py:852: InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
#   InsecureRequestWarning)
# can safely be ignored


# https://github.com/baderas/pygitlab.git

# requires python-gitlab3 https://github.com/alexvh/python-gitlab3
# requires pycurl
# certifi
# install with pip (python3 edition!): pip3 install python-gitlab pycurl certifi

# This tool has two functionalities:
# 1) It takes a CSV file as argument and creates the users and adds them to the given groups
#  CSV file format: mail,username,realname,canCreateGroups,group1,permission1,group2,permission2,group3,permission3,group4,permission4,..
# 2) It takes a CSV file and adds the users to the given Groups
#  CSV file format: username,group1,permission1,group2,permission2,group3,permission3,...
# If a permission is missing, 'Guest' will be used
# canCreateGroups must be 0 or 1
# Your private token can be found in Gitlab: "Profile Settings"->"Account"
# The CSV File must be encoded with UTF-8


default_permission = gitlab.objects.Group.GUEST_ACCESS
permission_types = {
                    "guest": gitlab.objects.Group.GUEST_ACCESS,
                    "reporter": gitlab.objects.Group.REPORTER_ACCESS,
                    "developer": gitlab.objects.Group.DEVELOPER_ACCESS,
                    "master": gitlab.objects.Group.MASTER_ACCESS,
                    "owner": gitlab.objects.Group.OWNER_ACCESS
                 }


def create_user(login_email, login_password, gitlab_url, full_name, user_name, user_email, can_create_group, log):
    username_encoded = urllib.parse.quote_plus(user_name.encode("UTF-8"))

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    response = opener.open(gitlab_url)
    content = response.read()
    # searching for authenticity token
    auth_token = re.search(r'<meta\s+name="csrf-token"\s+content=".*"\s+/>', content.decode('UTF-8'))
    if auth_token is not None:
        auth_token = auth_token.group().split('content="')[1].split('"')[:-1]
        auth_token = '-'.join(auth_token)  # if there is a " in the token
    else:
        log.error("Can not find authenticity token. User %s can not be created." % user_name)
        opener.close()
        return False

    encoded_data = urllib.parse.urlencode({"utf8": "&#x2713;", "authenticity_token": auth_token,
                                           "user[login]": login_email, "user[password]": login_password,
                                           "user[remember_me]": 1}).encode('UTF-8')
    response = opener.open(gitlab_url + "/users/sign_in", encoded_data)
    content = response.read()
    if re.search(r'Invalid\s+Login\s+or\s+password.', content.decode('UTF-8')) is not None:
        log.error("Login failed.")
        opener.close()
        return False
    # test if it was created
    existing = True
    try:
        response = opener.open(gitlab_url + "/admin/users/" + username_encoded)
    except urllib.error.HTTPError:
        existing = False
    content = response.read()
    if existing:
        log.error("User %s already exists." % user_name)
        # b.close()
        opener.close()
        return False
    # moving to new user page
    response = opener.open(gitlab_url + "/admin/")
    content = response.read()
    response = opener.open(gitlab_url + "/admin/users/new")
    content = response.read()
    # here a new authenticity token for the form is generated, ty to get it
    auth_token_for_form = re.search(r'<input\s+type="hidden"\s+name="authenticity_token"\s+value=".*"\s+/>',
                                    content.decode('UTF-8'))
    if auth_token_for_form is not None:
        auth_token_for_form = auth_token_for_form.group().split('value="')[1].split('"')[:-1]
        auth_token_for_form = '-'.join(auth_token_for_form)  # if there is a " in the token
    else:
        log.error("Can not find authenticity form token. User %s can not be created" % user_name)
        opener.close()
        return False
    encoded_data = urllib.parse.urlencode({"utf8": "&#x2713;", "authenticity_token": auth_token_for_form,
                                            "user[name]": full_name.encode("UTF-8"),
                                            "user[username]": user_name.encode("UTF-8"),
                                            "user[email]": user_email.encode("UTF-8"),
                                            "user[projects_limit]": "50",
                                            "user[can_create_group]": can_create_group,
                                            "user[admin]": "0",
                                            "user[external]": "0",
                                            "user[skype]": "",
                                            "user[linkedin]": "",
                                            "user[twitter]": "",
                                            "user[website_url]": ""}).encode('UTF-8')
    response = opener.open(gitlab_url + "/admin/users", encoded_data)
    content = response.read()

    # Use the following to debug:
    # look at a request from chromium/firefox
    # start a webserver on port 8000: nc -l 8000
    # curl.setopt(pycurl.URL, "localhost:8000")
    # curl.perform()
    if re.search(r'<title>The\s+change\s+you\s+requested\s+was\s+rejected\s+\(422\)</title>',
                 content.decode('UTF-8')) is not None or \
        re.search(r'<h4>The\s+form\s+contains\s+the\s+following\s+errors:</h4>',
                 content.decode('UTF-8')) is not None:
        log.error("User %s can not be created." % user_name)
        opener.close()
        return False
    # test if it was created
    existing = True
    try:
        response = opener.open(gitlab_url + "/admin/users/" + username_encoded)
    except urllib.error.HTTPError:
        existing = False
    content = response.read()
    if not existing:
        log.error("User %s was not created." % user_name)
        opener.close()
        return False
    log.info("User %s was successfully created." % user_name)
    opener.close()
    return True


def add_tser_to_groups(user_name, gp_dict, dryrun, gl_object, log):
    found_user = None
    if not dryrun:
        found_users = gl_object.users.search(user_name)
        if len(found_users) == 0:
            log.error("%s is not found in gitlab users." % user_name)
            return False
        elif len(found_users) > 1:
            solved = False
            for found_user in found_users:
                if found_user.name == user_name:
                    found_users = [found_user]
                    solved = True
                    break
            if not solved:
                log.error("More than one %s user found: %s." % (user_name, found_users))
                return False
        found_user = found_users[0]
    for index in range(0, len(gp_dict["names"])):
        if not dryrun:
            found_groups = gl_object.groups.search(gp_dict["names"][index])
            if len(found_groups) == 0:
                log.error("%s is not found in gitlab groups." % (gp_dict["names"][index]))
                continue
            elif len(found_groups) > 1:
                solved = False
                for group in found_groups:
                    if group.name == gp_dict["names"][index]:
                        found_groups = [group]
                        solved = True
                        break
                if not solved:
                    log.error("More than one %s group found: %s." % (gp_dict["names"][index], found_groups))
                    continue
            try:
                goup_creation = {
                    "group_id": found_groups[0].id,
                    "access_level": gp_dict["permissions"][index],
                    "user_id": found_user.id
                    }
                gl_object.group_members.create(goup_creation)
            except gitlab.exceptions:
                log.error("Could not add user %s to group %s as %s." %
                          (user_name, gp_dict["names"][index],
                           number_to_perm_type(permission_types,
                                               gp_dict["permissions"][index])), exc_info=True)
                continue
        log.info("Added user %s to group %s as %s." % (user_name, gp_dict["names"][index],
                                                       number_to_perm_type(permission_types,
                                                                           gp_dict["permissions"][index])))


def parse_groups_csv(cells, log):
    mode = 1
    # mode 1 -> next one must be a group name
    # mode 2 -> next one can be a role name or a group name (if not a known role)
    res = {"names": [], "permissions": []}
    for cell in cells:
        if mode == 1:
            res["names"].append(cell)
            mode = 2
        elif mode == 2:
            if cell.lower() in permission_types.keys():
                res["permissions"].append(permission_types[cell.lower()])
                mode = 1
            else:
                # if there is no permission given, the next cell will also contain a group and mode stays 2
                res["permissions"].append(default_permission)
                res["names"].append(cell)
    # Fix in case only groupnames are given
    while len(res["permissions"]) < len(res["names"]):
        res["permissions"].append(default_permission)
    if len(res["names"]) != len(res["permissions"]):
        log.error("Length of groupnames is not equal to grouppermissons.")
        return None
    return res


def number_to_perm_type(perm_types, perm_number):
    for key in perm_types.keys():
        if perm_types[key] == perm_number:
            return key
    return None

# Configure ArgumentParser
parser = argparse.ArgumentParser(prog="pygitlab.py",
                                 description="Reads a CSV file and adds new users to gitlab or adds users to groups. ",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog="")
parser.add_argument("-f", "--csvfile",  metavar="CSVFILE", required=True, type=str, help="CSV file to read from")
parser.add_argument("-a", "--adduser", action='store_true', help="Create users.")
parser.add_argument("-g", "--addtogroup", action='store_true', help="Add users to groups.")
parser.add_argument("-d", "--dryrun", action='store_true', help="Only emulate what would be done.")
parser.add_argument("-c", "--configfile",  metavar="CONFIGFILE", required=False, type=str,
                    help="Config file to read from")
args = parser.parse_args()

# Configure Logging
logLevel = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(logLevel)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
handler.setLevel(logLevel)
logger.addHandler(handler)

gl = None

try:
    cp = configparser.ConfigParser()
    cp.read(args.configfile)
except TypeError:
    logger.error("Can't read config from %s. Please specify another config file with -c <path>." % args.configfile)
    exit(-1)
try:
    password = cp.get("default", "password")
    email = cp.get("default", "email")
    url = cp.get("default", "url")
    ssl_verify = cp.getboolean("default", "ssl_verify")
    timeout = cp.getint("default", "timeout")
except (configparser.NoOptionError, ValueError):
    logger.error("Can't read config values from %s." % args.configfile, exc_info=True)
    exit(-1)

if not args.dryrun:
    try:
        gl = gitlab.Gitlab(url=url, email=email, password=password, ssl_verify=ssl_verify, timeout=timeout)
        # config files can't be used, they do not support user/password
        gl.credentials_auth()
    except (gitlab.config.GitlabDataError, gitlab.GitlabAuthenticationError):
        logger.error("Connection to gitlab failed.", exc_info=True)
        exit(-1)
logger.info("Connection to gitlab established.")

with open(args.csvfile, 'r') as csvfile:
    csvreader = csv.reader(csvfile, delimiter=',', quotechar='|')
    for row in csvreader:
        user = None
        if "" in row:
            logger.warning("Row '%s' contains an empty value." % row)
        if (len(row) < 4 and args.adduser) or len(row) < 2:
            logger.error("Row '%s' contains not enough values." % row)
            continue
        if args.adduser:
            if not args.dryrun:
                if not create_user(email, password, url, row[2], row[1], row[0], row[3], logger):
                    logger.error("Could not create user: '%s' '%s' '%s' '%s'" % (row[0], row[1], row[2], row[3]))
                    exit(-1)
            logger.info("Created user: '%s' '%s' '%s' '%s'" % (row[0], row[1], row[2], row[3]))
            if len(row) > 4:
                group_perm_dict = parse_groups_csv(row[4:], logger)
                if group_perm_dict is None:
                    exit(-1)
                add_tser_to_groups(row[1], group_perm_dict, args.dryrun, gl, logger)
        elif args.addtogroup:
            group_perm_dict = parse_groups_csv(row[1:], logger)
            if group_perm_dict is None:
                exit(-1)
            add_tser_to_groups(row[0], group_perm_dict, args.dryrun, gl, logger)
exit(0)
