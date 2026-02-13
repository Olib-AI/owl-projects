import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import os
import sys

# Add current directory to path so we can import main
sys.path.append(os.getcwd())

from main import run_browser_experience, _calculate_delay

class TestActorLogic(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Mock Actor
        self.actor_patcher = patch('main.Actor')
        self.mock_actor = self.actor_patcher.start()
        self.mock_actor.charge = AsyncMock()
        self.mock_actor.open_key_value_store = AsyncMock()
        self.mock_kvs = AsyncMock()
        self.mock_actor.open_key_value_store.return_value = self.mock_kvs

        # Mock OwlBrowser
        self.mock_browser = AsyncMock()
        self.mock_browser.execute = AsyncMock()

    async def asyncTearDown(self):
        self.actor_patcher.stop()

    def test_calculate_delay(self):
        self.assertEqual(_calculate_delay(None), 0)
        self.assertEqual(_calculate_delay(100), 100)
        self.assertEqual(_calculate_delay([]), 0)
        
        # Test range
        delay = _calculate_delay([100, 200])
        self.assertTrue(100 <= delay <= 200)

    async def test_retry_success(self):
        """Test that an action retries and eventually succeeds."""
        # Setup: Navigate fails twice, succeeds third time
        
        # Mock browser.execute side values
        # 1. create_context -> "ctx_1"
        # 2. navigate -> fail
        # 3. navigate -> fail
        # 4. navigate -> success
        # 5. close_context -> success
        
        self.mock_browser.execute.side_effect = [
            {"context_id": "ctx_1"}, # create context
            Exception("Fail 1"),
            Exception("Fail 2"),
            {"url": "http://example.com"}, # success
            None # close context
        ]

        input_data = {
            "region": "US",
            "actions": [
                {
                    "action": "navigate", 
                    "url": "http://example.com",
                    "retries": 2,
                    "retry_delay": 1 # tiny delay for test
                }
            ]
        }

        result = await run_browser_experience(self.mock_browser, input_data)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["actionsSucceeded"], 1)
        self.assertEqual(result["actionsFailed"], 0)
        # Check that execute was called 4 times (create + 3 attempts) + close = 5
        self.assertEqual(self.mock_browser.execute.call_count, 5)

    async def test_retry_fail_exhausted(self):
        """Test that action fails after exhausting retries."""
        self.mock_browser.execute.side_effect = [
            {"context_id": "ctx_1"},
            Exception("Fail 1"),
            Exception("Fail 2"),
            Exception("Fail 3"),
            None # close
        ]

        input_data = {
            "region": "US",
            "actions": [
                {
                    "action": "navigate", 
                    "url": "http://example.com",
                    "retries": 2,
                    "retry_delay": 1,
                    "on_error": "continue"
                }
            ]
        }

        result = await run_browser_experience(self.mock_browser, input_data)

        self.assertEqual(result["status"], "error") # 1 failed, 0 success -> error
        self.assertEqual(result["actionsFailed"], 1)

    async def test_if_selector_skips(self):
        """Test if_selector logic skips action if element missing."""
        self.mock_browser.execute.side_effect = [
            {"context_id": "ctx_1"},
            False, # evaluate if_selector -> False (not exist)
            None # close
        ]

        input_data = {
            "region": "US",
            "actions": [
                {
                    "action": "click", 
                    "selector": "#popup",
                    "if_selector": "#popup"
                }
            ]
        }

        result = await run_browser_experience(self.mock_browser, input_data)
        
        # Action skipped is not counted as success or fail in the counters?
        # My implementation appends to results with status="skipped".
        # failed_count counts status="error".
        # total_count is len(results).
        # So "skipped" is effectively "success" for the overall status check?
        # status="skipped" != "error", so failed_count=0.
        # overall_status = "success".
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["status"], "skipped")
        
        # Verify call args for evaluate
        call_args = self.mock_browser.execute.call_args_list[1]
        self.assertEqual(call_args[0][0], "browser_evaluate")
        self.assertIn("document.querySelector('#popup') !== null", call_args[1]['script'])

    async def test_on_error_break(self):
        """Test on_error='break' stops execution."""
        self.mock_browser.execute.side_effect = [
            {"context_id": "ctx_1"},
            Exception("Fail 1"), # Action 1 fails
            None # close
        ]

        input_data = {
            "region": "US",
            "actions": [
                {
                    "action": "navigate", 
                    "url": "http://bad.com",
                    "on_error": "break"
                },
                {
                    "action": "click",
                    "selector": "#btn"
                }
            ]
        }

        result = await run_browser_experience(self.mock_browser, input_data)

        # Should have 1 result (failed), 2nd action never runs.
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["status"], "error")
        self.assertEqual(result["status"], "error")

if __name__ == '__main__':
    unittest.main()
