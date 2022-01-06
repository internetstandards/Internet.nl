import re
# default_app_config = 'checks.apps.ChecksConfig'

DMARC_NON_SENDING_POLICY = re.compile(r'^v=DMARC1;\ *p=reject;?')
DMARC_NON_SENDING_POLICY_ORG = re.compile(r'v=DMARC1;(?:.*sp=reject|\ *p=reject(?!.*sp=))')
SPF_NON_SENDING_POLICY = re.compile(r'^v=spf1\ +(?:exp=[^ ]+\ +)?-all;?(?:\ +exp=[^ ]+)?$')