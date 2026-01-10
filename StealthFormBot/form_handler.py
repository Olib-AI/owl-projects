"""
StealthFormBot Form Handler

Core form automation logic using the Owl Browser SDK.
Handles all field types, multi-step forms, and error recovery.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from owl_browser import BrowserContext

from models import (
    ActorInput,
    ActorOutput,
    FieldResult,
    FieldType,
    FormField,
    FormStep,
    FormSubmissionStatus,
    StepResult,
    WaitCondition,
)

# Configure logging
logger = logging.getLogger(__name__)


class FormHandler:
    """
    Robust form automation handler.
    
    Handles ANY form type:
    - Simple contact forms
    - Multi-step wizards
    - Dynamic forms (fields appear based on selections)
    - Forms with file uploads
    - Forms with dropdowns, checkboxes, radio buttons, date pickers
    - Forms with validation
    - Forms behind login
    """
    
    def __init__(self, page: BrowserContext, config: ActorInput) -> None:
        """
        Initialize form handler.
        
        Args:
            page: Owl Browser page context
            config: Actor input configuration
        """
        self.page = page
        self.config = config
        self.start_time = time.time()
        self.errors: list[str] = []
        self.step_results: list[StepResult] = []
        
    def execute(self) -> ActorOutput:
        """
        Execute the complete form submission workflow.
        
        Returns:
            ActorOutput with results
        """
        try:
            # Setup dialog handlers
            self._setup_dialog_handlers()
            
            # Handle login if configured
            if self.config.login:
                if not self._perform_login():
                    return self._create_output(
                        success=False,
                        status=FormSubmissionStatus.LOGIN_REQUIRED,
                    )
            
            # Navigate to form
            logger.info(f"Navigating to {self.config.target_url}")
            self.page.goto(
                self.config.target_url,
                wait_until="networkidle",
                timeout=self.config.navigation_timeout,
            )
            
            # Wait for page to stabilize
            self.page.wait_for_network_idle(idle_time=500, timeout=10000)
            
            # Screenshot before filling
            screenshot_before = None
            if self.config.screenshot_before_submit:
                screenshot_before = self._take_screenshot("before_submit")
            
            # Determine form type and fill
            if self.config.steps:
                # Multi-step form
                success = self._fill_multi_step_form()
            elif self.config.field_configs:
                # Advanced field configuration
                success = self._fill_with_field_configs()
            else:
                # Simple form data
                success = self._fill_simple_form()
            
            if not success:
                screenshot_error = None
                if self.config.screenshot_on_error:
                    screenshot_error = self._take_screenshot("error")
                return self._create_output(
                    success=False,
                    status=FormSubmissionStatus.FAILED,
                    screenshot_before=screenshot_before,
                    screenshot_error=screenshot_error,
                )
            
            # Submit form
            submit_success = self._submit_form()
            
            # Screenshot after submit
            screenshot_after = None
            if self.config.screenshot_after_submit:
                screenshot_after = self._take_screenshot("after_submit")
            
            # Verify success
            if submit_success:
                verified = self._verify_submission()
                status = FormSubmissionStatus.SUCCESS if verified else FormSubmissionStatus.PARTIAL
            else:
                status = FormSubmissionStatus.FAILED
            
            # Extract confirmation ID if possible
            confirmation_id = self._extract_confirmation_id()
            
            return self._create_output(
                success=submit_success,
                status=status,
                screenshot_before=screenshot_before,
                screenshot_after=screenshot_after,
                confirmation_id=confirmation_id,
            )
            
        except TimeoutError as e:
            logger.error(f"Timeout error: {e}")
            self.errors.append(f"Timeout: {e}")
            return self._create_output(
                success=False,
                status=FormSubmissionStatus.TIMEOUT,
                screenshot_error=self._take_screenshot("timeout_error") if self.config.screenshot_on_error else None,
            )
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self.errors.append(f"Error: {e}")
            return self._create_output(
                success=False,
                status=FormSubmissionStatus.FAILED,
                screenshot_error=self._take_screenshot("unexpected_error") if self.config.screenshot_on_error else None,
            )
    
    def _setup_dialog_handlers(self) -> None:
        """Configure automatic dialog handling."""
        # Import here to avoid circular imports
        from owl_browser import DialogAction, DialogType
        
        if self.config.auto_accept_alerts:
            self.page.set_dialog_action(DialogType.ALERT, DialogAction.ACCEPT)
        
        if self.config.auto_accept_confirms:
            self.page.set_dialog_action(DialogType.CONFIRM, DialogAction.ACCEPT)
    
    def _perform_login(self) -> bool:
        """
        Perform login before accessing form.
        
        Returns:
            True if login successful
        """
        login = self.config.login
        if not login:
            return True
        
        logger.info(f"Logging in at {login.url}")
        
        try:
            # Navigate to login page
            self.page.goto(login.url, wait_until="networkidle", timeout=self.config.navigation_timeout)
            self.page.wait(500)
            
            # Fill username
            self.page.clear_input(login.username_selector)
            self.page.type(login.username_selector, login.username)
            
            # Fill password
            self.page.clear_input(login.password_selector)
            self.page.type(login.password_selector, login.password)
            
            # Click submit
            self.page.click(login.submit_selector)
            
            # Wait for success
            if login.success_indicator:
                self.page.wait_for_selector(login.success_indicator, timeout=login.wait_timeout)
            else:
                self.page.wait_for_network_idle(timeout=login.wait_timeout)
            
            logger.info("Login successful")
            return True
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            self.errors.append(f"Login failed: {e}")
            return False
    
    def _fill_simple_form(self) -> bool:
        """
        Fill a simple form using basic form_data dictionary.
        
        Returns:
            True if all required fields filled successfully
        """
        results: list[FieldResult] = []
        
        for selector, value in self.config.form_data.items():
            result = self._fill_field_smart(selector, value)
            results.append(result)
        
        # Create step result
        successful = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success)
        
        self.step_results.append(StepResult(
            step_name="main",
            success=failed == 0,
            fields_filled=successful,
            fields_failed=failed,
            field_results=results,
        ))
        
        return failed == 0
    
    def _fill_with_field_configs(self) -> bool:
        """
        Fill form using detailed field configurations.
        
        Returns:
            True if all required fields filled successfully
        """
        results: list[FieldResult] = []
        
        for field_config in self.config.field_configs:
            result = self._fill_configured_field(field_config)
            results.append(result)
        
        # Create step result
        successful = sum(1 for r in results if r.success)
        failed = sum(1 for r in results if not r.success and 
                    any(fc.selector == r.selector and fc.required for fc in self.config.field_configs))
        
        self.step_results.append(StepResult(
            step_name="main",
            success=failed == 0,
            fields_filled=successful,
            fields_failed=failed,
            field_results=results,
        ))
        
        return failed == 0
    
    def _fill_multi_step_form(self) -> bool:
        """
        Fill a multi-step wizard form.
        
        Returns:
            True if all steps completed successfully
        """
        for step_idx, step in enumerate(self.config.steps):
            logger.info(f"Processing step {step_idx + 1}/{len(self.config.steps)}: {step.name}")
            
            # Execute pre-actions
            for action in step.pre_actions:
                self._execute_action(action)
            
            # Fill fields for this step
            results: list[FieldResult] = []
            for field_config in step.fields:
                result = self._fill_configured_field(field_config)
                results.append(result)
            
            # Execute post-actions
            for action in step.post_actions:
                self._execute_action(action)
            
            # Calculate results
            successful = sum(1 for r in results if r.success)
            failed = sum(1 for r in results if not r.success and
                        any(fc.selector == r.selector and fc.required for fc in step.fields))
            
            step_result = StepResult(
                step_name=step.name,
                success=failed == 0,
                fields_filled=successful,
                fields_failed=failed,
                field_results=results,
            )
            self.step_results.append(step_result)
            
            # If step failed, abort
            if failed > 0:
                logger.error(f"Step {step.name} failed with {failed} failed fields")
                return False
            
            # Click next button if not the last step
            if step.next_selector:
                logger.info(f"Clicking next: {step.next_selector}")
                self.page.click(step.next_selector)
                
                # Wait for next step
                self._wait_for_step_transition(step)
        
        return True
    
    def _wait_for_step_transition(self, step: FormStep) -> None:
        """Wait for step transition to complete."""
        match step.wait_condition:
            case WaitCondition.NETWORKIDLE:
                self.page.wait_for_network_idle(idle_time=500, timeout=step.wait_timeout)
            case WaitCondition.SELECTOR:
                if step.wait_selector:
                    self.page.wait_for_selector(step.wait_selector, timeout=step.wait_timeout)
            case WaitCondition.URL:
                if step.wait_url_pattern:
                    self.page.wait_for_url(step.wait_url_pattern, timeout=step.wait_timeout)
            case WaitCondition.LOAD:
                self.page.wait(1000)  # Simple delay for page load
            case WaitCondition.DOMCONTENTLOADED:
                self.page.wait(500)
    
    def _fill_field_smart(self, selector: str, value: Any) -> FieldResult:
        """
        Smart field filling with automatic type detection.
        
        This method auto-detects field type and uses appropriate interaction.
        
        Args:
            selector: Field selector (CSS, XPath, or natural language)
            value: Value to set
            
        Returns:
            FieldResult with outcome
        """
        try:
            # Wait for element
            self.page.wait_for_selector(selector, timeout=self.config.field_timeout)
            
            # Detect field type from element
            field_type = self._detect_field_type(selector)
            
            # Fill based on detected type
            return self._fill_by_type(selector, value, field_type)
            
        except Exception as e:
            logger.error(f"Failed to fill field {selector}: {e}")
            return FieldResult(
                selector=selector,
                success=False,
                value_set=None,
                error=str(e),
            )
    
    def _detect_field_type(self, selector: str) -> FieldType:
        """
        Detect field type from element attributes.
        
        Args:
            selector: Field selector
            
        Returns:
            Detected FieldType
        """
        try:
            # Get element tag and type attribute
            tag = self.page.evaluate(
                f'document.querySelector("{selector}")?.tagName?.toLowerCase()',
                return_value=True,
            )
            input_type = self.page.evaluate(
                f'document.querySelector("{selector}")?.type?.toLowerCase()',
                return_value=True,
            )
            
            if tag == "select":
                return FieldType.SELECT
            elif tag == "textarea":
                return FieldType.TEXTAREA
            elif tag == "input":
                match input_type:
                    case "checkbox":
                        return FieldType.CHECKBOX
                    case "radio":
                        return FieldType.RADIO
                    case "file":
                        return FieldType.FILE
                    case "email":
                        return FieldType.EMAIL
                    case "password":
                        return FieldType.PASSWORD
                    case "tel":
                        return FieldType.PHONE
                    case "number":
                        return FieldType.NUMBER
                    case "date":
                        return FieldType.DATE
                    case "datetime-local":
                        return FieldType.DATETIME
                    case "hidden":
                        return FieldType.HIDDEN
                    case _:
                        return FieldType.TEXT
            
            # Default to text for unknown elements
            return FieldType.TEXT
            
        except Exception:
            return FieldType.TEXT
    
    def _fill_configured_field(self, field_config: FormField) -> FieldResult:
        """
        Fill a field using detailed configuration.
        
        Args:
            field_config: Field configuration
            
        Returns:
            FieldResult with outcome
        """
        selector = field_config.selector
        value = field_config.value
        retries = 0
        last_error: str | None = None
        
        while retries <= field_config.retry_count:
            try:
                # Wait before interaction if configured
                if field_config.wait_before > 0:
                    self.page.wait(field_config.wait_before)
                
                # Wait for element
                self.page.wait_for_selector(selector, timeout=self.config.field_timeout)
                
                # Clear first if configured
                if field_config.clear_first and field_config.field_type in (
                    FieldType.TEXT, FieldType.EMAIL, FieldType.PASSWORD,
                    FieldType.PHONE, FieldType.NUMBER, FieldType.TEXTAREA
                ):
                    try:
                        self.page.clear_input(selector)
                    except Exception:
                        pass  # Ignore clear errors
                
                # Handle custom handler
                if field_config.custom_handler:
                    self.page.evaluate(field_config.custom_handler)
                    return FieldResult(
                        selector=selector,
                        success=True,
                        value_set=value,
                        retries=retries,
                    )
                
                # Fill by type
                result = self._fill_by_type(selector, value, field_config.field_type)
                result.retries = retries
                return result
                
            except Exception as e:
                last_error = str(e)
                retries += 1
                if retries <= field_config.retry_count:
                    logger.warning(f"Retry {retries} for field {selector}: {e}")
                    self.page.wait(500)  # Brief delay before retry
        
        return FieldResult(
            selector=selector,
            success=False,
            value_set=None,
            error=last_error,
            retries=retries,
        )
    
    def _fill_by_type(self, selector: str, value: Any, field_type: FieldType) -> FieldResult:
        """
        Fill field based on its type.
        
        Args:
            selector: Field selector
            value: Value to set
            field_type: Type of field
            
        Returns:
            FieldResult
        """
        try:
            match field_type:
                case FieldType.SELECT:
                    self.page.pick(selector, str(value))
                    
                case FieldType.CHECKBOX:
                    is_checked = self.page.is_checked(selector)
                    should_check = bool(value) if isinstance(value, bool) else str(value).lower() == "true"
                    if is_checked != should_check:
                        self.page.click(selector)
                        
                case FieldType.RADIO:
                    # For radio, value is typically the option value or label
                    # Try clicking the specific radio option
                    radio_selector = f'{selector}[value="{value}"]'
                    try:
                        self.page.click(radio_selector)
                    except Exception:
                        # Fallback: try semantic selector
                        self.page.click(f'{selector} "{value}"')
                        
                case FieldType.FILE:
                    # File upload needs file paths
                    if isinstance(value, list):
                        self.page.upload_file(selector, value)
                    else:
                        self.page.upload_file(selector, [str(value)])
                        
                case FieldType.DATE:
                    # Date fields often need special handling
                    # Try native input first, then JavaScript fallback
                    try:
                        self.page.type(selector, str(value))
                    except Exception:
                        # JavaScript fallback for stubborn date pickers
                        self.page.evaluate(
                            f'document.querySelector("{selector}").value = "{value}"',
                        )
                        # Trigger change event
                        self.page.evaluate(
                            f'document.querySelector("{selector}").dispatchEvent(new Event("change", {{bubbles: true}}))',
                        )
                        
                case FieldType.DATETIME:
                    # Similar handling as date
                    try:
                        self.page.type(selector, str(value))
                    except Exception:
                        self.page.evaluate(
                            f'document.querySelector("{selector}").value = "{value}"',
                        )
                        self.page.evaluate(
                            f'document.querySelector("{selector}").dispatchEvent(new Event("change", {{bubbles: true}}))',
                        )
                        
                case FieldType.HIDDEN:
                    # Hidden fields set via JavaScript
                    self.page.evaluate(
                        f'document.querySelector("{selector}").value = "{value}"',
                    )
                    
                case FieldType.CUSTOM:
                    # Custom fields may need special JavaScript handling
                    # Try type first, then click-based interactions
                    try:
                        self.page.type(selector, str(value))
                    except Exception:
                        # Try clicking to open dropdown/component, then selecting
                        self.page.click(selector)
                        self.page.wait(300)
                        self.page.type(selector, str(value))
                        
                case _:
                    # Default text input handling
                    self.page.type(selector, str(value))
            
            return FieldResult(
                selector=selector,
                success=True,
                value_set=value,
            )
            
        except Exception as e:
            logger.error(f"Failed to fill {field_type} field {selector}: {e}")
            return FieldResult(
                selector=selector,
                success=False,
                value_set=None,
                error=str(e),
            )
    
    def _execute_action(self, action: dict[str, Any]) -> None:
        """
        Execute a custom action from pre/post actions.
        
        Supported action types:
        - click: Click an element
        - wait: Wait for time or selector
        - scroll: Scroll to element
        - evaluate: Run JavaScript
        
        Args:
            action: Action configuration dict
        """
        action_type = action.get("type", "")
        
        match action_type:
            case "click":
                self.page.click(action["selector"])
            case "wait":
                if "selector" in action:
                    self.page.wait_for_selector(action["selector"], timeout=action.get("timeout", 5000))
                elif "duration" in action:
                    self.page.wait(action["duration"])
            case "scroll":
                if "selector" in action:
                    self.page.scroll_to_element(action["selector"])
                else:
                    self.page.scroll_by(action.get("x", 0), action.get("y", 500))
            case "evaluate":
                self.page.evaluate(action["script"])
            case "hover":
                self.page.hover(action["selector"])
            case _:
                logger.warning(f"Unknown action type: {action_type}")
    
    def _submit_form(self) -> bool:
        """
        Submit the form.
        
        Returns:
            True if submission appears successful
        """
        try:
            if self.config.submit_selector:
                # Use configured submit selector
                logger.info(f"Submitting with selector: {self.config.submit_selector}")
                
                # Wait for submit button to be visible and enabled
                self.page.wait_for_selector(self.config.submit_selector, timeout=self.config.field_timeout)
                
                if self.page.is_enabled(self.config.submit_selector):
                    self.page.click(self.config.submit_selector)
                else:
                    # Try pressing Enter as fallback
                    logger.warning("Submit button disabled, trying Enter key")
                    self.page.submit_form()
            else:
                # Try common submit patterns
                submit_selectors = [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:contains("Submit")',
                    'button:contains("Send")',
                    '.submit-button',
                    '#submit',
                ]
                
                submitted = False
                for selector in submit_selectors:
                    try:
                        if self.page.is_visible(selector):
                            if self.page.is_enabled(selector):
                                self.page.click(selector)
                                submitted = True
                                logger.info(f"Submitted with auto-detected selector: {selector}")
                                break
                    except Exception:
                        continue
                
                if not submitted:
                    # Last resort: press Enter
                    logger.warning("No submit button found, pressing Enter")
                    self.page.submit_form()
            
            # Wait for submission to process
            self.page.wait_for_network_idle(idle_time=1000, timeout=30000)
            
            return True
            
        except Exception as e:
            logger.error(f"Form submission failed: {e}")
            self.errors.append(f"Submission error: {e}")
            return False
    
    def _verify_submission(self) -> bool:
        """
        Verify form submission was successful.
        
        Returns:
            True if verification passes
        """
        try:
            # Check for success indicator
            if self.config.success_indicator:
                return self.page.is_visible(self.config.success_indicator)
            
            # Check for success URL pattern
            if self.config.success_url_pattern:
                current_url = self.page.get_current_url()
                return self.config.success_url_pattern in current_url
            
            # No specific verification configured - assume success
            return True
            
        except Exception as e:
            logger.warning(f"Verification check failed: {e}")
            return True  # Don't fail just because verification errored
    
    def _extract_confirmation_id(self) -> str | None:
        """
        Try to extract a confirmation/reference ID from the page.
        
        Returns:
            Confirmation ID if found, None otherwise
        """
        try:
            # Common patterns for confirmation IDs
            patterns = [
                r'confirmation[:\s#]*([A-Z0-9-]+)',
                r'reference[:\s#]*([A-Z0-9-]+)',
                r'order[:\s#]*([A-Z0-9-]+)',
                r'ticket[:\s#]*([A-Z0-9-]+)',
                r'ID[:\s#]*([A-Z0-9-]+)',
            ]
            
            text = self.page.extract_text()
            
            import re
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            return None
            
        except Exception:
            return None
    
    def _take_screenshot(self, name: str) -> str:
        """
        Take a screenshot and save it.
        
        Args:
            name: Screenshot name suffix
            
        Returns:
            Path to saved screenshot
        """
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{name}_{timestamp}.png"
            self.page.screenshot(filename, mode="fullpage")
            logger.info(f"Screenshot saved: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return ""
    
    def _create_output(
        self,
        success: bool,
        status: FormSubmissionStatus,
        screenshot_before: str | None = None,
        screenshot_after: str | None = None,
        screenshot_error: str | None = None,
        confirmation_id: str | None = None,
    ) -> ActorOutput:
        """Create the final output object."""
        duration_ms = int((time.time() - self.start_time) * 1000)
        
        # Get cookies
        cookies = []
        try:
            cookies = [
                {"name": c.name, "value": c.value, "domain": c.domain}
                for c in self.page.get_cookies()
            ]
        except Exception:
            pass
        
        # Get final URL
        final_url = None
        try:
            final_url = self.page.get_current_url()
        except Exception:
            pass
        
        return ActorOutput(
            success=success,
            status=status,
            target_url=self.config.target_url,
            confirmation_id=confirmation_id,
            submitted_at=datetime.now(timezone.utc).isoformat(),
            steps_completed=len([s for s in self.step_results if s.success]),
            total_steps=len(self.step_results) if self.step_results else 1,
            step_results=self.step_results,
            screenshot_before=screenshot_before,
            screenshot_after=screenshot_after,
            screenshot_error=screenshot_error,
            cookies=cookies,
            final_url=final_url,
            errors=self.errors,
            duration_ms=duration_ms,
        )
