"""
Flow execution utilities for programmatic flow control with conditions.

This module provides functions for evaluating conditions and executing flows
with conditional branching support.
"""

import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .types import (
    ConditionOperator,
    FlowCondition,
    FlowStep,
    FlowStepStatus,
    FlowExecutionResult,
)
from .context import BrowserContext


def get_value_at_path(obj: Any, path: str) -> Any:
    """
    Get value at a dot-notation path (e.g., 'data.items.0.name').

    Args:
        obj: Object to traverse
        path: Dot-notation path

    Returns:
        Value at the path, or None if not found
    """
    if not path:
        return obj

    parts = path.split('.')
    current = obj

    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                index = int(part)
                current = current[index] if 0 <= index < len(current) else None
            except ValueError:
                return None
        else:
            current = getattr(current, part, None)

    return current


def evaluate_condition(condition: FlowCondition, value: Any) -> bool:
    """
    Evaluate a condition against a value.

    Args:
        condition: Condition to evaluate
        value: Value to check against

    Returns:
        Whether the condition is satisfied
    """
    check_value = get_value_at_path(value, condition.field) if condition.field else value

    operator = condition.operator
    compare_value = condition.value

    if operator == ConditionOperator.EQUALS:
        return check_value == compare_value
    elif operator == ConditionOperator.NOT_EQUALS:
        return check_value != compare_value
    elif operator == ConditionOperator.CONTAINS:
        if isinstance(check_value, str) and isinstance(compare_value, str):
            return compare_value in check_value
        if isinstance(check_value, list):
            return compare_value in check_value
        return False
    elif operator == ConditionOperator.NOT_CONTAINS:
        if isinstance(check_value, str) and isinstance(compare_value, str):
            return compare_value not in check_value
        if isinstance(check_value, list):
            return compare_value not in check_value
        return True
    elif operator == ConditionOperator.STARTS_WITH:
        return isinstance(check_value, str) and isinstance(compare_value, str) and check_value.startswith(compare_value)
    elif operator == ConditionOperator.ENDS_WITH:
        return isinstance(check_value, str) and isinstance(compare_value, str) and check_value.endswith(compare_value)
    elif operator == ConditionOperator.GREATER_THAN:
        return isinstance(check_value, (int, float)) and isinstance(compare_value, (int, float)) and check_value > compare_value
    elif operator == ConditionOperator.LESS_THAN:
        return isinstance(check_value, (int, float)) and isinstance(compare_value, (int, float)) and check_value < compare_value
    elif operator == ConditionOperator.IS_TRUTHY:
        return bool(check_value)
    elif operator == ConditionOperator.IS_FALSY:
        return not bool(check_value)
    elif operator == ConditionOperator.IS_EMPTY:
        if check_value is None:
            return True
        if isinstance(check_value, str):
            return len(check_value) == 0
        if isinstance(check_value, (list, dict)):
            return len(check_value) == 0
        return False
    elif operator == ConditionOperator.IS_NOT_EMPTY:
        if check_value is None:
            return False
        if isinstance(check_value, str):
            return len(check_value) > 0
        if isinstance(check_value, (list, dict)):
            return len(check_value) > 0
        return True
    elif operator == ConditionOperator.REGEX_MATCH:
        if isinstance(check_value, str) and isinstance(compare_value, str):
            try:
                return bool(re.search(compare_value, check_value))
            except re.error:
                return False
        return False

    return False


def execute_flow(
    context: BrowserContext,
    steps: List[FlowStep],
    on_step_start: Optional[Callable[[FlowStep], None]] = None,
    on_step_complete: Optional[Callable[[FlowStep], None]] = None,
    stop_on_error: bool = True,
    step_delay: float = 0.3,
) -> FlowExecutionResult:
    """
    Execute a flow with conditional branching support.

    Args:
        context: Browser context to execute on
        steps: Flow steps to execute
        on_step_start: Callback for step start
        on_step_complete: Callback for step completion
        stop_on_error: Stop on first error (default: True)
        step_delay: Delay between steps in seconds (default: 0.3)

    Returns:
        Flow execution result

    Example:
        >>> flow = [
        ...     FlowStep(id='1', type='navigate', params={'url': 'https://example.com'}),
        ...     FlowStep(id='2', type='is_visible', params={'selector': '.login-button'}),
        ...     FlowStep(
        ...         id='3',
        ...         type='condition',
        ...         condition=FlowCondition(source='previous', operator=ConditionOperator.IS_TRUTHY),
        ...         on_true=[FlowStep(id='3a', type='click', params={'selector': '.login-button'})],
        ...         on_false=[FlowStep(id='3b', type='navigate', params={'url': '/login'})]
        ...     )
        ... ]
        >>> result = execute_flow(context, flow)
    """
    start_time = time.time()
    executed_steps: List[FlowStep] = []

    def execute_step_list(
        step_list: List[FlowStep],
        previous_result: Any
    ) -> Tuple[bool, Any]:
        enabled_steps = [s for s in step_list if s.enabled]
        last_result = previous_result

        for i, step in enumerate(enabled_steps):
            step.status = FlowStepStatus.RUNNING
            if on_step_start:
                on_step_start(step)

            step_start = time.time()

            try:
                # Handle condition steps
                if step.type == 'condition' and step.condition:
                    condition_result = evaluate_condition(step.condition, last_result)
                    step.branch_taken = 'true' if condition_result else 'false'
                    step.result = {'conditionResult': condition_result, 'branchTaken': step.branch_taken}
                    step.status = FlowStepStatus.SUCCESS
                    step.duration = int((time.time() - step_start) * 1000)

                    executed_steps.append(step)
                    if on_step_complete:
                        on_step_complete(step)

                    # Execute the appropriate branch
                    branch_steps = step.on_true if condition_result else step.on_false
                    if branch_steps:
                        success, last_result = execute_step_list(branch_steps, last_result)
                        if not success and stop_on_error:
                            return False, last_result
                else:
                    # Regular step execution
                    result = execute_tool_on_context(context, step.type, step.params)

                    if result['success']:
                        step.status = FlowStepStatus.SUCCESS
                        step.result = result.get('result')
                    else:
                        step.status = FlowStepStatus.ERROR
                        step.error = result.get('error', 'Unknown error')

                    step.duration = int((time.time() - step_start) * 1000)
                    executed_steps.append(step)

                    if on_step_complete:
                        on_step_complete(step)

                    if step.status == FlowStepStatus.ERROR and stop_on_error:
                        return False, last_result

                    last_result = step.result

                # Delay between steps
                if i < len(enabled_steps) - 1 and step_delay > 0:
                    time.sleep(step_delay)

            except Exception as e:
                step.status = FlowStepStatus.ERROR
                step.error = str(e)
                step.duration = int((time.time() - step_start) * 1000)

                executed_steps.append(step)
                if on_step_complete:
                    on_step_complete(step)

                if stop_on_error:
                    return False, last_result

        return True, last_result

    success, _ = execute_step_list(steps, None)

    return FlowExecutionResult(
        success=success,
        steps=executed_steps,
        total_duration=int((time.time() - start_time) * 1000),
        error=next((s.error for s in executed_steps if s.status == FlowStepStatus.ERROR), None)
    )


def execute_tool_on_context(
    context: BrowserContext,
    tool_type: str,
    params: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a tool on a browser context.
    Maps tool types to context methods.

    Args:
        context: Browser context
        tool_type: Tool type name
        params: Tool parameters

    Returns:
        Dict with 'success', 'result', and optionally 'error'
    """
    try:
        # Strip 'browser_' prefix if present
        method = tool_type.replace('browser_', '', 1) if tool_type.startswith('browser_') else tool_type

        if method == 'navigate':
            context.goto(params.get('url', ''))
            return {'success': True}
        elif method == 'click':
            context.click(params.get('selector', ''))
            return {'success': True}
        elif method == 'type':
            context.type(params.get('selector', ''), params.get('text', ''))
            return {'success': True}
        elif method == 'pick':
            context.pick(params.get('selector', ''), params.get('value', ''))
            return {'success': True}
        elif method == 'screenshot':
            result = context.screenshot(
                mode=params.get('mode', 'viewport'),
                selector=params.get('selector')
            )
            return {'success': True, 'result': result}
        elif method == 'extract_text':
            text = context.extract_text(params.get('selector', ''))
            return {'success': True, 'result': text}
        elif method == 'wait':
            context.wait(params.get('timeout', 1000))
            return {'success': True}
        elif method == 'wait_for_selector':
            context.wait_for_selector(params.get('selector', ''), params.get('timeout'))
            return {'success': True}
        elif method == 'is_visible':
            visible = context.is_visible(params.get('selector', ''))
            return {'success': True, 'result': visible}
        elif method == 'is_enabled':
            enabled = context.is_enabled(params.get('selector', ''))
            return {'success': True, 'result': enabled}
        elif method == 'is_checked':
            checked = context.is_checked(params.get('selector', ''))
            return {'success': True, 'result': checked}
        elif method == 'get_attribute':
            value = context.get_attribute(params.get('selector', ''), params.get('attribute', ''))
            return {'success': True, 'result': value}
        elif method == 'evaluate':
            result = context.evaluate(params.get('script', ''))
            return {'success': True, 'result': result}
        elif method == 'scroll_to_top':
            context.scroll_to_top()
            return {'success': True}
        elif method == 'scroll_to_bottom':
            context.scroll_to_bottom()
            return {'success': True}
        elif method == 'scroll_by':
            context.scroll_by(params.get('x', 0), params.get('y', 0))
            return {'success': True}
        elif method == 'press_key':
            context.press_key(params.get('key', ''))
            return {'success': True}
        elif method == 'submit_form':
            context.submit_form()
            return {'success': True}
        elif method == 'hover':
            context.hover(params.get('selector', ''))
            return {'success': True}
        elif method == 'double_click':
            context.double_click(params.get('selector', ''))
            return {'success': True}
        elif method == 'right_click':
            context.right_click(params.get('selector', ''))
            return {'success': True}
        elif method == 'clear_input':
            context.clear_input(params.get('selector', ''))
            return {'success': True}
        elif method == 'focus':
            context.focus(params.get('selector', ''))
            return {'success': True}
        elif method == 'blur':
            context.blur(params.get('selector', ''))
            return {'success': True}
        elif method == 'select_all':
            context.select_all(params.get('selector', ''))
            return {'success': True}
        elif method == 'reload':
            context.reload(
                ignore_cache=params.get('ignore_cache', False),
                wait_until=params.get('wait_until', 'load'),
                timeout=params.get('timeout', 30000)
            )
            return {'success': True}
        elif method == 'go_back':
            context.go_back(
                wait_until=params.get('wait_until', 'load'),
                timeout=params.get('timeout', 30000)
            )
            return {'success': True}
        elif method == 'go_forward':
            context.go_forward(
                wait_until=params.get('wait_until', 'load'),
                timeout=params.get('timeout', 30000)
            )
            return {'success': True}
        elif method == 'get_page_info':
            info = context.get_page_info()
            return {'success': True, 'result': info}
        elif method == 'get_html':
            html = context.get_html(params.get('clean_level', 'basic'))
            return {'success': True, 'result': html}
        elif method == 'get_markdown':
            md = context.get_markdown(
                include_links=params.get('include_links', True),
                include_images=params.get('include_images', True),
                max_length=params.get('max_length', -1)
            )
            return {'success': True, 'result': md}
        elif method == 'query_page':
            answer = context.query_page(params.get('query', ''))
            return {'success': True, 'result': answer}
        elif method == 'summarize_page':
            summary = context.summarize_page(params.get('force_refresh', False))
            return {'success': True, 'result': summary}
        elif method == 'detect_captcha':
            detected = context.detect_captcha()
            return {'success': True, 'result': detected}
        elif method == 'solve_captcha':
            solved = context.solve_captcha(
                provider=params.get('provider'),
                max_attempts=params.get('max_attempts', 3)
            )
            return {'success': True, 'result': solved}
        else:
            return {'success': False, 'error': f'Unknown tool type: {tool_type}'}

    except Exception as e:
        return {'success': False, 'error': str(e)}
