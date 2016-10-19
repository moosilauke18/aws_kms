#!/usr/bin/python

DOCUMENTATION = '''  
---
module: aws_kms  
short_description: Encrypt and decrypt things using kms. 
'''

EXAMPLES = '''  
- name: Encyrpt a file data
  aws_kms:
    arn: "..."
    path: file_info_to_encyrpt
  register: result
'''  

from ansible.module_utils.basic import *

try:
    from boto import kms
except ImportError:
    print "failed=True msg='boto required for this module'"
    sys.exit(1)

def encrypt(data):
    fileinfo = open(data['path'])
    info = fileinfo.read()
    conn = kms.connect_to_region(data['region'])
    encrypted = conn.encrypt(
            key_id=data['arn'],
            plaintext=info
    )
    return True, encrypted['CiphertextBlob']

def decrypt(data):
    has_changed = False
    meta = {"present": "not yet implemented"}
    return (has_changed, meta)

def main():
    fields = {
        "path": {"required": True, "type": "str"},
        "arn": {"required": True, "type": "str"},
        "region": {"required": True, "type": "str"},
        "mode": {
            "default": "encrypt", 
            "choices": ['encrypt','decrypt'],
            "type": "str"
        },
    }
    choice_map = {
        "encrypt": encrypt,
        "decrypt": decrypt,
    }
    module = AnsibleModule(argument_spec=fields)
    has_changed, result = choice_map.get(module.params['mode'])(module.params)
    module.exit_json(changed=has_changed, value=result)

if __name__ == '__main__':
    main()
