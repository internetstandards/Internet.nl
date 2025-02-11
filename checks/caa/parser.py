import textwrap
from urllib.parse import urlparse

from abnf.grammars.misc import load_grammar_rulelist
from abnf.parser import Rule as _Rule, ParseError, NodeVisitor


def get_parse_result_named_child(node, name):
    """Do a breadth-first search of the tree for addr-spec node.  If found,
    return its value."""
    queue = [node]
    while queue:
        n, queue = queue[0], queue[1:]
        if n.name == name:
            return n.value
        else:
            queue.extend(n.children)
    return None


# https://www.iana.org/assignments/acme/acme.xhtml#acme-validation-methods
ACME_VALIDATION_METHODS = {
    "http-01",
    "dns-01",
    "http-01",
    "tls-alpn-01",
    "tls-alpn-01",
    "email-reply-00",
    "tkauth-01",
}


class CAAParseError(ValueError):
    pass


@load_grammar_rulelist()
class CAAValidationMethodsGrammar(_Rule):
    """
    Grammar for validationmethods CAA parameter to the issue/issuewild property.
    Per RFC8657 4
    """

    grammar = textwrap.dedent(
        """
        value = [*(label ",") label]
        label = 1*(ALPHA / DIGIT / "-") 
    """
    )


def validate_issue_validation_methods(parameter_value: str) -> set[str]:
    parse_result = CAAValidationMethodsGrammar("value").parse_all(parameter_value)
    validation_methods = {label.value for label in parse_result.children}
    invalid_methods = validation_methods - ACME_VALIDATION_METHODS
    if invalid_methods:
        raise CAAParseError(f"Invalid validation methods in issue/issuewild parameter: {', '.join(invalid_methods)}")
    return validation_methods


@load_grammar_rulelist()
class CAAIssueGrammar(_Rule):
    """
    Grammar for issue/issuewild CAA property values.
    Per RFC8659 4.2
    # TODO: consider https://www.rfc-editor.org/errata/eid7139
    """

    grammar = textwrap.dedent(
        """
        issue-value = *WSP [issuer-domain-name *WSP]
           [";" *WSP [parameters *WSP]]
        
        issuer-domain-name = label *("." label)
        label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
        
        parameters = (parameter *WSP ";" *WSP parameters) / parameter
        parameter = tag *WSP "=" *WSP value
        tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
        value = *(%x21-3A / %x3C-7E)
    """
    )


class CAAIssueVisitor(NodeVisitor):
    def __init__(self):
        super().__init__()
        self.issuer_domain_name = None
        self.parameters = {}

    def visit_issue_value(self, node):
        for child_node in node.children:
            self.visit(child_node)

    def visit_issuer_domain_name(self, node):
        self.issuer_domain_name = node.value

    def visit_parameters(self, node):
        for child_node in node.children:
            self.visit(child_node)

    def visit_parameter(self, node):
        tag = get_parse_result_named_child(node, "tag")
        value = get_parse_result_named_child(node, "value")
        self.parameters[tag] = value


def validate_property_issue(value: str):
    parse_result = CAAIssueGrammar("issue-value").parse_all(value)
    visitor = CAAIssueVisitor()
    visitor.visit(parse_result)
    if "validationmethods" in visitor.parameters:
        validate_issue_validation_methods(visitor.parameters["validationmethods"])


def validate_property_iodef(value: str):
    """Validate iodef value per RFC8659 4.4"""
    try:
        url = urlparse(value)
    except ValueError:
        raise CAAParseError(f"Invalid URL in iodef property: {value}")
    if url.scheme in ["http", "https"]:
        # RFC refers to RFC6546, which is unclear on requirements. Let's assume a netloc is needed.
        if not url.netloc:
            raise CAAParseError(f"Invalid URL in iodef property: {value}")
    elif url.scheme == "mailto":
        # RFC does not prescribe what an email address is
        if "@" not in url.path:
            raise CAAParseError(f"Invalid email address in iodef property: {value}")
    else:
        raise CAAParseError(f"Invalid URL scheme in iodef property: {value}")


def validate_tag(tag: int):
    # RFC8659 4.1
    if tag not in [0, 128]:
        raise CAAParseError(f"Invalid tag value: {tag}")


# https://www.iana.org/assignments/pkix-parameters/pkix-parameters.xhtml#caa-properties
CAA_PROPERTY_VALIDATORS = {
    "issue": validate_property_issue,
    "issuewild": validate_property_issue,
    "iodef": validate_property_iodef,
    "auth": None,
    "path": None,
    "policy": None,
    "contactemail": None,
    "contactphone": None,
    "issuevmc": None,
    "issuemail": None,
}

def validate_caa(tag: int, name: str, value: str):
    validate_tag(tag)
    try:
        validator = CAA_PROPERTY_VALIDATORS[name]
        if validator:
            validator(value)
    except ParseError as e:
        raise CAAParseError(f'Syntax error in {name} value "{value}" at character {e.start} ({value[e.start]})')
    except KeyError:
        raise CAAParseError(f"Invalid CAA property: {name}")

# v = "letsencrypt.org; 💩"
v = "example.net; accounturi=https://example.net/account/1234; validationmethods=dns-01"
validate_caa(0, 'issue', v)
