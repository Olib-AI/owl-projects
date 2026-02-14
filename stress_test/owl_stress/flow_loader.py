"""Load and validate flow JSON files."""

import json
from pathlib import Path
from dataclasses import dataclass


REQUIRED_STEP_FIELD = "type"

KNOWN_STEP_TYPES = {
    "browser_navigate", "browser_wait_for_network_idle", "browser_click",
    "browser_type", "browser_extract_text", "browser_screenshot",
    "browser_wait_for_selector", "browser_wait", "browser_wait_for_url",
    "browser_scroll_by", "browser_scroll_to_bottom", "browser_scroll_to_top",
    "browser_scroll_to_element", "browser_press_key", "browser_submit_form",
    "browser_pick", "browser_hover", "browser_double_click", "browser_get_html",
    "browser_get_markdown", "browser_evaluate", "browser_reload",
    "browser_go_back", "browser_go_forward", "browser_clear_input",
    "browser_solve_captcha", "browser_get_page_info", "browser_ai_click",
    "browser_ai_type", "browser_nla", "browser_find_element",
}


@dataclass
class FlowStep:
    """A single step in a flow."""
    index: int
    type: str
    params: dict
    description: str = ""
    enabled: bool = True
    expected: dict | None = None


@dataclass
class Flow:
    """A parsed flow ready for execution."""
    name: str
    description: str
    steps: list[FlowStep]
    raw: dict

    @property
    def step_count(self) -> int:
        return len([s for s in self.steps if s.enabled])


def load_flow(path: str | Path) -> Flow:
    """Load a flow from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Flow file not found: {path}")

    with open(path, "r") as f:
        data = json.load(f)

    return parse_flow(data)


def parse_flow(data: dict) -> Flow:
    """Parse a flow dict into a Flow object."""
    if "steps" not in data:
        raise ValueError("Flow JSON must contain a 'steps' array")

    steps = []
    for i, step_data in enumerate(data["steps"]):
        if REQUIRED_STEP_FIELD not in step_data:
            raise ValueError(f"Step {i} missing required field '{REQUIRED_STEP_FIELD}'")

        # Check if step is disabled
        enabled = step_data.get("selected", True) and step_data.get("enabled", True)

        # Extract known meta-fields, rest are tool params
        params = {
            k: v for k, v in step_data.items()
            if k not in ("type", "description", "selected", "enabled", "expected")
        }

        steps.append(FlowStep(
            index=i,
            type=step_data["type"],
            params=params,
            description=step_data.get("description", ""),
            enabled=enabled,
            expected=step_data.get("expected"),
        ))

    return Flow(
        name=data.get("name", "Unnamed Flow"),
        description=data.get("description", ""),
        steps=steps,
        raw=data,
    )


def validate_flow(flow: Flow) -> list[str]:
    """Validate a flow and return a list of warnings (empty = all good)."""
    warnings = []

    if not flow.steps:
        warnings.append("Flow has no steps")
        return warnings

    enabled_steps = [s for s in flow.steps if s.enabled]
    if not enabled_steps:
        warnings.append("All steps are disabled")

    for step in enabled_steps:
        if step.type not in KNOWN_STEP_TYPES:
            warnings.append(f"Step {step.index}: unknown type '{step.type}'")

        if step.type == "browser_navigate" and "url" not in step.params:
            warnings.append(f"Step {step.index}: browser_navigate missing 'url'")

        if step.type == "browser_click" and "selector" not in step.params:
            warnings.append(f"Step {step.index}: browser_click missing 'selector'")

        if step.type == "browser_type":
            if "selector" not in step.params:
                warnings.append(f"Step {step.index}: browser_type missing 'selector'")
            if "text" not in step.params:
                warnings.append(f"Step {step.index}: browser_type missing 'text'")

    return warnings
