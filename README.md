# SAML Authenticator for Ping Federate
Acquire temporary CLI credentials via SAML federation.

## Installation

```
$ pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
$ pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

More info:
[Boto config tutorial](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html)
```
Update with Ping Federate URL and if MFA is needed there are several lines to adjust. 

If MITM proxy used, add the ca_bundle.crt to the folder and adjust the script.
```
```
Ping Federate will parse AD groups and create assertion for role switcher.  

The OGNL file can be adjusted accordingly to parse the groups for the assertion.  

The current format for the AD groups is 
AWS-SSO-<AWS ROLE>-<AWS ACCOUNT NUMBER> 
and will populate the assertion to provide the role switcher.
```

## Usage

```
$ python saml_ping.py
```
```
usage: saml_ping.py [-h] [-d DURATION] [-p PROFILE]

Availity AWS SAML Role Selector

optional arguments:
  -h, --help   show this help message and exit
  -d DURATION  Session Token duration in seconds default 3600 or 1 hour,
               max=14400
  -p PROFILE   Credential profile to be utilized for this credential,
               default is [default].
```

## Compatibility

```
Should be compatible with python 2.x or 3.x.
```

## AWS Cli usage

```
$ aws [option] <command> 
```
## TODO
* Make installation cleaner
* Create profiles for all roles with single logon.

## Attribute Contract Fulfillment
```
https://aws.amazon.com/SAML/Attributes/SessionDuration	14400 (Text)
https://aws.amazon.com/SAML/Attributes/RoleSessionName	username (Adapter)
https://aws.amazon.com/SAML/Attributes/Role	#roleName = new java.util.ArrayList(), #groups = #this.get("ds.memberOf")!=null?#this.get("ds.memberOf").getValues():{}, #groups.{ #group = #this, #group = new javax.naming.ldap.LdapName(#group), #rdn = #group.getRdn(#group.size() - 1).getValue().toString(), #rdn.matches("(?i).*AWS-SSO-.*")?#roleName.add("arn:aws:iam::" + #group.getRdn(#group.size() - 1).getValue().toString().split("-")[3] + ":role/AWS_SSO_" + #group.getRdn(#group.size() - 1).getValue().toString().split("-")[2] + ",arn:aws:iam::" + #group.getRdn(#group.size() - 1).getValue().toString().split("-")[3] + ":saml-provider/pingfederate") : null }, new org.sourceid.saml20.adapter.attribute.AttributeValue(#roleName) (Expression)
SAML_SUBJECT	mail (LDAP)
```