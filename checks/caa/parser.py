import textwrap
from typing import Optional
from urllib.parse import urlparse

from abnf.grammars.misc import load_grammar_rulelist
from abnf.parser import Rule as _Rule, ParseError, NodeVisitor, Node

from checks.tasks.shared import TranslatableTechTableItem, validate_email


class CAAParseError(ValueError):
    def __init__(self, msg_id: str, context: dict[str, str]):
        self.msg_id = msg_id
        self.context = context

    def to_translatable_tech_table_item(self):
        return TranslatableTechTableItem(self.msg_id, self.context)


def node_get_named_child_value(node: Node, name: str) -> Optional[str]:
    """Search the tree from the node for a node with a certain name, return value."""
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

# RFC 8657 4
ACME_VALIDATION_CUSTOM_PREFIX = "ca-"


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
    """Validate the validationmethods parameter value for the issue/issuewild CAA property."""
    parse_result = CAAValidationMethodsGrammar("value").parse_all(parameter_value)
    # Careful: terms label/value are used as properties of the parse tree, but also as properties
    # in the original ABNF grammer, in opposite roles. Not confusing at all.
    validation_methods = {label.value for label in parse_result.children if label.name == "label"}
    for validation_method in validation_methods:
        if validation_method not in ACME_VALIDATION_METHODS and not validation_method.startswith(
            ACME_VALIDATION_CUSTOM_PREFIX
        ):
            raise CAAParseError(msg_id="invalid_property_issue_validation_method", context={"value": parameter_value})
    return validation_methods


@load_grammar_rulelist()
class CAAPropertyIssueGrammar(_Rule):
    """
    Grammar for issue/issuewild CAA property values.
    Per RFC8659 4.2
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


class CAAPropertyIssueVisitor(NodeVisitor):
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
        tag = node_get_named_child_value(node, "tag")
        value = node_get_named_child_value(node, "value")
        self.parameters[tag] = value


def validate_property_issue(value: str):
    parse_result = CAAPropertyIssueGrammar("issue-value").parse_all(value)
    visitor = CAAPropertyIssueVisitor()
    visitor.visit(parse_result)
    if "validationmethods" in visitor.parameters:
        validate_issue_validation_methods(visitor.parameters["validationmethods"])


def validate_property_iodef(value: str):
    """Validate iodef value per RFC8659 4.4"""
    try:
        url = urlparse(value)
    except ValueError:
        raise CAAParseError(msg_id="invalid_property_iodef_value", context={"value": value})
    if url.scheme in ["http", "https"]:
        # RFC8659 refers to RFC6546, which is unclear on requirements. Let's assume a netloc is needed.
        if not url.netloc:
            raise CAAParseError(msg_id="invalid_property_iodef_value", context={"value": value})
    elif url.scheme == "mailto":
        if not validate_email(url.path):
            raise CAAParseError(msg_id="invalid_property_iodef_value", context={"value": value})
    else:
        raise CAAParseError(msg_id="invalid_property_iodef_value", context={"value": value})


def validate_property_contactemail(value: str):
    """Validate contactemail per CAB BR 1.6.3, requiring a single RFC 6532 3.2 address."""
    if not validate_email(value):
        raise CAAParseError(msg_id="invalid_property_contactemail_value", context={"value": value})


@load_grammar_rulelist()
class PhoneNumberRule(_Rule):
    """
    Grammar for phone numbers per RFC3966.
    Includes https://www.rfc-editor.org/errata/eid203
    local-number-digits and its dependencies were stripped out,
    as the ABNF parser had issues with it, and they are not used by us now.
    """

    grammar = textwrap.dedent(
        """
   telephone-uri        = "tel:" telephone-subscriber
   telephone-subscriber = global-number
   global-number        = global-number-digits *par
   par                  = parameter / extension / isdn-subaddress
   isdn-subaddress      = ";isub=" 1*uric
   extension            = ";ext=" 1*phonedigit
   context              = ";phone-context=" descriptor
   descriptor           = domainname / global-number-digits
   global-number-digits = "+" *phonedigit DIGIT *phonedigit
   domainname           = *( domainlabel "." ) toplabel [ "." ]
   domainlabel          = alphanum
                          / alphanum *( alphanum / "-" ) alphanum
   toplabel             = ALPHA / ALPHA *( alphanum / "-" ) alphanum
   parameter            = ";" pname ["=" pvalue ]
   pname                = 1*( alphanum / "-" )
   pvalue               = 1*paramchar
   paramchar            = param-unreserved / unreserved / pct-encoded
   unreserved           = alphanum / mark
   mark                 = "-" / "_" / "." / "!" / "~" / "*" /
                          "'" / "(" / ")"
   pct-encoded          = "%" HEXDIG HEXDIG
   param-unreserved     = "[" / "]" / "/" / ":" / "&" / "+" / "$"
   phonedigit           = DIGIT / [ visual-separator ]
   phonedigit-hex       = HEXDIG / "*" / "#" / [ visual-separator ]
   visual-separator     = "-" / "." / "(" / ")"
   alphanum             = ALPHA / DIGIT
   reserved             = ";" / "/" / "?" / ":" / "@" / "&" /
                          "=" / "+" / "$" / ","
   uric                 = reserved / unreserved / pct-encoded
    """
    )


def validate_property_contactphone(value: str):
    """Validate contactphone per CAB SC014, requiring an RFC3966 5.1.4 global number."""
    parse_result = PhoneNumberRule("global-number").parse_all(value)
    if not parse_result:
        raise CAAParseError(msg_id="invalid_property_contactphone_value", context={"value": value})


@load_grammar_rulelist()
class CAAPropertyIssueMailRule(_Rule):
    """
    Grammar for CAA issuemail property per RFC9495.
    """

    grammar = textwrap.dedent(
        """
        issuemail-value = *WSP [issuer-domain-name *WSP]
            [";" *WSP [parameters *WSP]]

        issuer-domain-name = label *("." label)
        label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))

        parameters = (parameter *WSP ";" *WSP parameters) / parameter
        parameter = tag *WSP "=" *WSP value
        tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
        value = *(%x21-3A / %x3C-7E)
    """
    )


def validate_property_issuemail(value: str):
    """Validate issuemail property per RFC9495."""
    parse_result = CAAPropertyIssueMailRule("issuemail-value").parse_all(value)
    if not parse_result:
        raise CAAParseError(msg_id="invalid_property_issuemail_value", context={"value": value})


def validate_tag(tag: int):
    # RFC8659 4.1
    if tag not in [0, 128]:
        raise CAAParseError(msg_id="invalid_tag_reserved_bits", context={"value": str(tag)})


# https://www.iana.org/assignments/pkix-parameters/pkix-parameters.xhtml#caa-properties
CAA_PROPERTY_VALIDATORS = {
    "issue": validate_property_issue,
    "issuewild": validate_property_issue,
    "iodef": validate_property_iodef,
    "auth": None,
    "path": None,
    "policy": None,
    "contactemail": validate_property_contactemail,
    "contactphone": validate_property_contactphone,
    "issuevmc": validate_property_issue,
    "issuemail": validate_property_issuemail,
}


def validate_caa_record(tag: int, name: str, value: str):
    validate_tag(tag)
    try:
        validator = CAA_PROPERTY_VALIDATORS[name.lower()]
        if validator is None:
            raise CAAParseError(msg_id="invalid_reserved_property", context={"value": name})
        validator(value)
    except ParseError as e:
        raise CAAParseError(
            msg_id="invalid_property_syntax",
            context={
                "property_name": name,
                "property_value": value,
                "invalid_character_position": e.start,
                "invalid_character": value[e.start],
            },
        )
    except KeyError:
        raise CAAParseError(msg_id="invalid_unknown_property", context={"value": name})
