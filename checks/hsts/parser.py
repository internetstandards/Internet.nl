from dataclasses import dataclass

from abnf.grammars import rfc6797
from abnf.grammars.misc import load_grammar_rulelist
from abnf.parser import Node, NodeVisitor, ParseError, Rule as _Rule

from checks.tasks.shared import TranslatableTechTableItem

HSTS_PREFIX = "Strict-Transport-Security: "


class HSTSParseError(ValueError):
    """
    Error thrown for any HSTS parsing issues,
    with a message ID and context dict.
    """

    def __init__(self, msg_id: str, context: dict[str, str | int]):
        self.msg_id = msg_id
        self.context = context

    def to_translatable_tech_table_item(self):
        return TranslatableTechTableItem(self.msg_id, self.context)


@dataclass(frozen=True)
class HSTSRecommendation:
    msg_id: str
    context: dict[str, str | int]

    def to_translatable_tech_table_item(self) -> TranslatableTechTableItem:
        return TranslatableTechTableItem(self.msg_id, self.context)


@load_grammar_rulelist()
class HSTSMaxAgeRule(_Rule):
    grammar = "delta-seconds = 1*DIGIT"


class HSTSVisitor(NodeVisitor):
    """
    This ABNF visitor walks over the tree of a HSTS Grammar.
    """

    def __init__(self):
        super().__init__()
        self.directives: list[tuple[str, str | None]] = []

    def visit_Strict_Transport_Security(self, node: Node):
        for child_node in node.children:
            self.visit(child_node)

    def visit_directive(self, node: Node):
        # directive-name [ "=" directive-value ]
        name = node.children[0].value.lower()
        val = node.children[2].value if len(node.children) > 1 else None
        if val and val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        self.directives.append((name, val))


def validate_max_age(value: str | None, recommendations: list[HSTSRecommendation]) -> int:
    if value is None:
        raise HSTSParseError("invalid-max-age-missing-value", {})
    try:
        HSTSMaxAgeRule("delta-seconds").parse_all(value)
    except ParseError:
        raise HSTSParseError("invalid-max-age-value", {"directive_value": value})
    return int(value)


def validate_includesubdomains(value: str | None, recommendations: list[HSTSRecommendation]) -> bool:
    if value is not None:
        raise HSTSParseError("invalid-includesubdomains-value", {"directive_value": value})
    return True


def validate_preload(value: str | None, recommendations: list[HSTSRecommendation]) -> bool | str:
    if value is not None:
        recommendations.append(HSTSRecommendation("invalid-preload-value", {"directive_value": value}))
        return value
    return True


def validate_unknown_directive(name: str, value: str | None, recommendations: list[HSTSRecommendation]) -> bool | str:
    recommendations.append(
        HSTSRecommendation(
            "unknown-directive",
            {"directive_name": name, "directive_value": value or ""},
        )
    )
    return True if value is None else value


HSTS_DIRECTIVE_VALIDATORS = {
    "max-age": validate_max_age,
    "includesubdomains": validate_includesubdomains,
    "preload": validate_preload,
}


def parse_hsts_header(
    header_value: str,
) -> tuple[dict[str, int | bool | str], list[HSTSRecommendation]]:
    trimmed = header_value.rstrip(" \t")
    try:
        tree = rfc6797.Rule("Strict-Transport-Security").parse_all(f"{HSTS_PREFIX}{trimmed}")
    except ParseError as e:
        pos = max(0, e.start - len(HSTS_PREFIX))
        raise HSTSParseError(
            "invalid-syntax",
            {
                "header_value": header_value,
                "invalid_character_position": pos,
                "invalid_character": trimmed[pos] if pos < len(trimmed) else "",
            },
        )

    visitor = HSTSVisitor()
    visitor.visit(tree)

    directives: dict[str, int | bool | str] = {}
    recommendations: list[HSTSRecommendation] = []

    for name, raw_value in visitor.directives:
        if name in directives:
            raise HSTSParseError("invalid-duplicate-directive", {"directive_name": name})
        validator = HSTS_DIRECTIVE_VALIDATORS.get(name)
        if validator is not None:
            directives[name] = validator(raw_value, recommendations)
        else:
            directives[name] = validate_unknown_directive(name, raw_value, recommendations)

    if "max-age" not in directives:
        raise HSTSParseError("invalid-missing-max-age", {"header_value": header_value})

    return directives, recommendations
