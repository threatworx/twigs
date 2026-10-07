#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for the `trustmodel` mode of `twigs`.

Stdlib only (unittest + unittest.mock) to match the framework the rest of the
suite nominally uses and to avoid adding a test dependency to this repo.

Nothing here touches the network: a real evaluation consumes credits and the
API has no dry-run mode, so the SDK is mocked at the
`client.evaluations.get_result` / `client.ping` boundary with small fakes that
expose only the attributes each test needs.
"""

import argparse
import base64
import os
import shutil
import tempfile
import unittest
from unittest import mock

from trustmodel.exceptions import (
    APIError,
    AuthenticationError,
    InsufficientCreditsError,
    TrustModelError,
)

try:  # trustmodel >= 3.7.0 only. twigs supports >= 3.2, so this may be absent.
    from trustmodel.exceptions import ResponseParsingError
except ImportError:  # pragma: no cover - taken on older SDKs
    ResponseParsingError = None

from twigs import trustmodel_eval


class FakeResult(object):
    """Stand-in for the SDK's EvaluationResult, with only the fields read."""

    def __init__(self, status="processing", **kwargs):
        self.status = status
        self.id = kwargs.pop("id", 42)
        self.template_id = kwargs.pop("template_id", None)
        self.completion_percentage = kwargs.pop("completion_percentage", 0)
        self.poll_interval = kwargs.pop("poll_interval", 10)
        self.model_name = kwargs.pop("model_name", "gpt-4")
        self.model_identifier = kwargs.pop("model_identifier", "gpt-4")
        self.vendor_name = kwargs.pop("vendor_name", "openai")
        self.category_scores = kwargs.pop("category_scores", [])
        self.subcategory_scores = kwargs.pop("subcategory_scores", [])
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeClock(object):
    """Virtual clock. sleep() advances it, so grace and timeout windows are exact
    without any test taking real time."""

    def __init__(self, start=1000.0):
        self.start = start
        self.now = start
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    @property
    def elapsed(self):
        return self.now - self.start


def make_args(**overrides):
    """The argparse namespace twigs hands the module, with usable defaults."""
    values = {
        "handle": "tester@example.com",
        "trustmodel_api_key": "tm-test-key_secret",
        "assetid": None,
        "assetname": None,
        "model_identifier": None,
        "vendor_identifier": None,
        "api_key": None,
        "api_endpoint": None,
        "categories": None,
        "output_dir": None,
        "evaluation_id": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def make_client(results=None, get_result_side_effect=None):
    client = mock.Mock()
    if get_result_side_effect is not None:
        client.evaluations.get_result.side_effect = get_result_side_effect
    elif isinstance(results, list):
        client.evaluations.get_result.side_effect = results
    else:
        client.evaluations.get_result.return_value = results
    return client


class PollHarness(object):
    """Shared fixture for the poll-loop cases. Not a TestCase itself, so the
    cases below do not inherit and re-run each other's tests."""

    def setUp(self):
        self.clock = FakeClock()
        patchers = [
            mock.patch.object(trustmodel_eval.utils, "tw_exit", side_effect=SystemExit),
            mock.patch.object(trustmodel_eval.time, "time", self.clock.time),
            mock.patch.object(trustmodel_eval.time, "sleep", self.clock.sleep),
        ]
        for patcher in patchers:
            self.addCleanup(patcher.stop)
            patcher.start()

    def poll(self, client):
        return trustmodel_eval._poll_and_print_result(client, 42, make_args())

    def assertExits(self, client, level="ERROR"):
        """Run the poll loop, asserting it exits 1 and returning the log messages."""
        with self.assertLogs(level=level) as captured:
            with self.assertRaises(SystemExit):
                self.poll(client)
        return [record.getMessage() for record in captured.records]


class PollStatusTestCase(PollHarness, unittest.TestCase):
    """The poll state machine: one case per row of the status table (§3)."""

    def test_completed_returns_the_result(self):
        result = FakeResult("completed", completion_percentage=100)
        self.assertIs(self.poll(make_client(result)), result)

    def test_failed_exits_with_its_own_message(self):
        messages = self.assertExits(make_client(FakeResult("failed")))
        self.assertTrue(any("failed" in m for m in messages))
        self.assertFalse(any("cancelled" in m for m in messages))

    def test_cancelled_exits_with_its_own_message(self):
        messages = self.assertExits(make_client(FakeResult("cancelled")))
        self.assertTrue(any("cancelled" in m for m in messages))

    def test_terminal_failure_does_not_poll_first(self):
        client = make_client(FakeResult("cancelled"))
        self.assertExits(client)
        self.assertEqual(self.clock.sleeps, [])

    def test_payment_pending_exits_within_the_grace_window(self):
        messages = self.assertExits(make_client(FakeResult("payment_pending")), "WARNING")
        self.assertTrue(any("payment_pending" in m for m in messages))
        # The bug this replaces: three hours of polling, then the wrong reason.
        self.assertFalse(any("timed out after 3 hours" in m for m in messages))
        self.assertLess(self.clock.elapsed, 3 * 60 * 60)
        self.assertGreaterEqual(
            self.clock.elapsed, trustmodel_eval._NEEDS_ACTION_GRACE_SECONDS
        )

    def test_payment_failed_is_also_bounded(self):
        self.assertExits(make_client(FakeResult("payment_failed")), "WARNING")
        self.assertLess(self.clock.elapsed, 3 * 60 * 60)

    def test_payment_pending_that_clears_keeps_running(self):
        completed = FakeResult("completed")
        client = make_client(
            [FakeResult("payment_pending"), FakeResult("running"), completed]
        )
        with self.assertLogs(level="WARNING"):
            self.assertIs(self.poll(client), completed)

    def test_retryable_failure_is_treated_as_in_progress(self):
        completed = FakeResult("completed")
        client = make_client(
            [FakeResult("retryable_failure"), FakeResult("running"), completed]
        )
        self.assertIs(self.poll(client), completed)
        self.assertEqual(len(self.clock.sleeps), 2)

    def test_data_pull_pending_is_treated_as_in_progress(self):
        completed = FakeResult("completed")
        client = make_client([FakeResult("data_pull_pending"), completed])
        self.assertIs(self.poll(client), completed)

    def test_unknown_status_keeps_polling_and_warns_once(self):
        completed = FakeResult("completed")
        client = make_client(
            [FakeResult("some_new_status"), FakeResult("some_new_status"), completed]
        )
        with self.assertLogs(level="WARNING") as captured:
            self.assertIs(self.poll(client), completed)
        warnings = [
            r.getMessage() for r in captured.records if "some_new_status" in r.getMessage()
        ]
        self.assertEqual(len(warnings), 1)

    def test_enum_status_is_normalized(self):
        """str() on the SDK's str-Enum yields 'EvaluationStatus.COMPLETED'."""
        import enum

        class EvaluationStatus(str, enum.Enum):
            COMPLETED = "completed"

        result = FakeResult(EvaluationStatus.COMPLETED)
        self.assertIs(self.poll(make_client(result)), result)

    def test_timeout_still_bounds_an_endlessly_in_progress_run(self):
        messages = self.assertExits(make_client(FakeResult("running")))
        self.assertTrue(any("timed out after 3 hours" in m for m in messages))

    def test_server_poll_interval_is_honoured(self):
        client = make_client(
            [FakeResult("running", poll_interval=30), FakeResult("completed")]
        )
        self.poll(client)
        self.assertEqual(self.clock.sleeps, [30])


class PollErrorClassificationTestCase(PollHarness, unittest.TestCase):
    """Which SDK exceptions are worth retrying, and which are not (§2, §4)."""

    def test_unparseable_response_fails_cleanly(self):
        """An old SDK raises a bare pydantic error on a status it predates. It is
        not a TrustModelError, so it used to escape as a raw traceback."""
        client = make_client(get_result_side_effect=Exception("1 validation error"))
        messages = self.assertExits(client)
        self.assertTrue(any("pip install -U trustmodel" in m for m in messages))
        self.assertEqual(self.clock.sleeps, [])

    @unittest.skipIf(ResponseParsingError is None, "SDK predates 3.7.0")
    def test_new_sdk_parse_error_fails_cleanly_without_retrying(self):
        """The same failure as above, as trustmodel >= 3.7.0 reports it.

        3.7.0 wraps the pydantic error in ResponseParsingError, which IS a
        TrustModelError - so it is caught by the retry arm rather than the
        `except Exception` one. It is also an APIError carrying status_code 200,
        so the 404 test does not mark it fatal. Without an explicit check this
        deterministic failure is retried for three hours and then misreported as
        a timeout, which is the hang the status classification exists to prevent.
        """
        client = make_client(
            get_result_side_effect=ResponseParsingError(
                "Could not parse the API response into EvaluationResult: "
                "status (enum). This SDK may be out of date.",
                model_name="EvaluationResult",
            )
        )
        messages = self.assertExits(client)
        self.assertTrue(any("pip install -U trustmodel" in m for m in messages))
        self.assertEqual(self.clock.sleeps, [])

    @unittest.skipIf(ResponseParsingError is None, "SDK predates 3.7.0")
    def test_parse_error_is_an_api_error_with_a_non_404_status(self):
        """Pins why the fatal-error check alone does not catch it - so that if
        the SDK ever gives it a real HTTP status, this fails and gets re-thought
        rather than the guard silently becoming redundant."""
        error = ResponseParsingError("boom", model_name="EvaluationResult")
        self.assertIsInstance(error, APIError)
        self.assertIsInstance(error, TrustModelError)
        self.assertNotEqual(getattr(error, "status_code", None), 404)
        self.assertFalse(trustmodel_eval._is_fatal_poll_error(error))
        self.assertTrue(trustmodel_eval._is_unparseable_result_error(error))

    def test_parse_error_check_degrades_on_an_older_sdk(self):
        """The class is looked up by name, so an SDK without it reports False
        and the `except Exception` arm keeps handling the raw pydantic error."""
        import trustmodel.exceptions as tm_exceptions

        with mock.patch.object(tm_exceptions, "ResponseParsingError", None):
            self.assertFalse(
                trustmodel_eval._is_unparseable_result_error(Exception("boom"))
            )

    def test_authentication_error_fails_fast(self):
        client = make_client(get_result_side_effect=AuthenticationError("key revoked"))
        self.assertExits(client)
        self.assertEqual(self.clock.sleeps, [])

    def test_insufficient_credits_fails_fast(self):
        client = make_client(
            get_result_side_effect=InsufficientCreditsError("no credits", 10, 0)
        )
        self.assertExits(client)
        self.assertEqual(self.clock.sleeps, [])

    def test_not_found_fails_fast(self):
        client = make_client(get_result_side_effect=APIError("not found", 404))
        self.assertExits(client)
        self.assertEqual(self.clock.sleeps, [])

    def test_rate_limit_is_retried(self):
        completed = FakeResult("completed")
        client = make_client(
            get_result_side_effect=[APIError("slow down", 429), completed]
        )
        with self.assertLogs(level="WARNING"):
            self.assertIs(self.poll(client), completed)
        self.assertEqual(len(self.clock.sleeps), 1)

    def test_server_error_is_retried(self):
        completed = FakeResult("completed")
        client = make_client(get_result_side_effect=[APIError("boom", 503), completed])
        with self.assertLogs(level="WARNING"):
            self.assertIs(self.poll(client), completed)

    def test_base_error_is_retried(self):
        completed = FakeResult("completed")
        client = make_client(
            get_result_side_effect=[TrustModelError("connection reset"), completed]
        )
        with self.assertLogs(level="WARNING"):
            self.assertIs(self.poll(client), completed)


class GetResultCommandTestCase(unittest.TestCase):
    """--get_result reaches get_result() without the poll loop, so it needs the
    same parse guard."""

    def setUp(self):
        patcher = mock.patch.object(
            trustmodel_eval.utils, "tw_exit", side_effect=SystemExit
        )
        self.addCleanup(patcher.stop)
        patcher.start()

    def run_cmd(self, side_effect):
        client = mock.Mock()
        client.evaluations.get_result.side_effect = side_effect
        args = make_args(get_result=True, evaluation_id=42)
        with mock.patch.object(trustmodel_eval, "_init_client", return_value=client):
            with self.assertLogs(level="ERROR") as captured:
                with self.assertRaises(SystemExit):
                    trustmodel_eval._cmd_get_result(args)
        return [record.getMessage() for record in captured.records]

    def test_unparseable_response_fails_cleanly(self):
        messages = self.run_cmd(Exception("1 validation error"))
        self.assertTrue(any("pip install -U trustmodel" in m for m in messages))

    @unittest.skipIf(ResponseParsingError is None, "SDK predates 3.7.0")
    def test_new_sdk_parse_error_gets_the_same_message(self):
        """--get_result must fail identically whichever SDK is installed."""
        messages = self.run_cmd(
            ResponseParsingError("bad shape", model_name="EvaluationResult")
        )
        self.assertTrue(any("pip install -U trustmodel" in m for m in messages))

    def test_api_error_still_reports_the_server_message(self):
        messages = self.run_cmd(APIError("not found", 404))
        self.assertTrue(any("not found" in m for m in messages))

    def test_missing_evaluation_id_is_rejected(self):
        args = make_args(get_result=True, evaluation_id=None)
        with self.assertLogs(level="ERROR"):
            with self.assertRaises(SystemExit):
                trustmodel_eval._cmd_get_result(args)


class ScoreToRatingTestCase(unittest.TestCase):
    """TrustModel scores an asset 0-100 high-is-good; twigs rates 1-5 high-is-bad."""

    def test_boundaries(self):
        for score, rating in (
            (100, 1),
            (90, 1),
            (89.9, 2),
            (75, 2),
            (74.9, 3),
            (50, 3),
            (49.9, 4),
            (25, 4),
            (24.9, 5),
            (0, 5),
        ):
            self.assertEqual(trustmodel_eval._score_to_rating(score), rating, score)

    def test_missing_score_defaults_to_maximum_risk(self):
        """_build_asset_from_result passes cs.get("score", 0) — an absent score
        must not read as a good one."""
        self.assertEqual(trustmodel_eval._score_to_rating(0), 5)


class BuildAssetTestCase(unittest.TestCase):
    def test_public_model_attack_surface_label(self):
        """Locked verbatim: downstream ThreatWorx dashboards parse this string."""
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult("completed", vendor_name="openai", model_name="gpt-4"),
            make_args(),
        )
        self.assertEqual(asset["attack_surface_label"], "AI::AI Model::Public::openai::gpt-4")

    def test_custom_endpoint_attack_surface_label(self):
        """Locked verbatim: downstream ThreatWorx dashboards parse this string."""
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult(
                "completed",
                vendor_name="google_vertexai",
                credit_run_type="custom_endpoint",
            ),
            make_args(),
        )
        self.assertEqual(
            asset["attack_surface_label"], "AI::AI Model::Custom::google_vertexai"
        )

    def test_custom_model_name_is_disambiguated(self):
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult(
                "completed", model_name="Custom Model", model_identifier="llama-3-70b"
            ),
            make_args(),
        )
        self.assertEqual(asset["name"], "Custom Model llama-3-70b")

    def test_others_vendor_is_renamed(self):
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult("completed", vendor_name="Others"), make_args()
        )
        self.assertEqual(asset["type"], "Generic AI Platform")
        self.assertIn("Generic AI Platform", asset["tags"])

    def test_findings_are_built_from_both_score_levels(self):
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult(
                "completed",
                category_scores=[
                    {"category_id": "c1", "category": "Safety", "score": 95, "findings": "ok"}
                ],
                subcategory_scores=[
                    {
                        "subcategory_id": "s1",
                        "category": "Safety",
                        "subcategory": "Toxicity",
                        "score": 10,
                    }
                ],
            ),
            make_args(),
        )
        findings = asset["config_issues"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["rating"], "1")
        self.assertEqual(findings[1]["rating"], "5")
        self.assertEqual(findings[1]["object_id"], "Safety:Toxicity")

    def test_assetname_overrides_the_display_name(self):
        asset = trustmodel_eval._build_asset_from_result(
            FakeResult("completed"), make_args(assetname="my-model")
        )
        self.assertEqual(asset["name"], "my-model")


class WriteReportTestCase(unittest.TestCase):
    """--output_dir was accepted and silently ignored until now (§5)."""

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.output_dir, True)

    def write(self, report, output_dir=None, eval_id=7):
        encoded = base64.b64encode(report).decode("ascii") if report is not None else None
        result = FakeResult("completed", id=eval_id, report_base64=encoded)
        args = make_args(
            output_dir=self.output_dir if output_dir is None else output_dir
        )
        return trustmodel_eval._write_report(result, args)

    def test_html_report_is_written(self):
        path = self.write(b"<html><body>report</body></html>")
        self.assertTrue(path.endswith("trustmodel_evaluation_7.html"))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"<html><body>report</body></html>")

    def test_pdf_is_detected_by_magic_bytes(self):
        """The server prefers HTML and falls back to PDF, so the extension has to
        follow the bytes rather than an assumption."""
        path = self.write(b"%PDF-1.7\nbinary")
        self.assertTrue(path.endswith("trustmodel_evaluation_7.pdf"))

    def test_missing_directory_is_created(self):
        nested = os.path.join(self.output_dir, "a", "b")
        path = self.write(b"<html></html>", output_dir=nested)
        self.assertTrue(os.path.isfile(path))

    def test_absent_report_warns_and_writes_nothing(self):
        with self.assertLogs(level="WARNING") as captured:
            self.assertIsNone(self.write(None))
        self.assertTrue(
            any("No report available" in r.getMessage() for r in captured.records)
        )
        self.assertEqual(os.listdir(self.output_dir), [])

    def test_undecodable_report_warns_and_writes_nothing(self):
        result = FakeResult("completed", report_base64="not base64 !!!")
        with self.assertLogs(level="WARNING"):
            self.assertIsNone(
                trustmodel_eval._write_report(result, make_args(output_dir=self.output_dir))
            )
        self.assertEqual(os.listdir(self.output_dir), [])

    def test_unwritable_directory_warns_rather_than_failing_the_run(self):
        """The evaluation already cost credits; a bad path must not discard it."""
        with mock.patch.object(trustmodel_eval.os, "makedirs", side_effect=OSError("denied")):
            with self.assertLogs(level="WARNING"):
                self.assertIsNone(
                    self.write(b"<html></html>", output_dir=os.path.join(self.output_dir, "x"))
                )

    def test_no_flag_touches_the_filesystem(self):
        result = FakeResult("completed", report_base64=base64.b64encode(b"x").decode())
        with mock.patch.object(trustmodel_eval.os, "makedirs") as makedirs:
            with mock.patch.object(trustmodel_eval, "open", create=True) as opened:
                self.assertIsNone(trustmodel_eval._write_report(result, make_args()))
        makedirs.assert_not_called()
        opened.assert_not_called()

    def test_older_sdk_without_report_base64_degrades_quietly(self):
        class NoReportField(object):
            id = 7

        with self.assertLogs(level="WARNING"):
            self.assertIsNone(
                trustmodel_eval._write_report(
                    NoReportField(), make_args(output_dir=self.output_dir)
                )
            )


class GetInventoryTestCase(unittest.TestCase):
    """The dispatcher entry point, end to end with the SDK mocked."""

    def setUp(self):
        self.output_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.output_dir, True)

    def test_get_result_writes_the_report_and_returns_the_asset(self):
        result = FakeResult(
            "completed",
            id=7,
            vendor_name="openai",
            model_name="gpt-4",
            report_base64=base64.b64encode(b"<html>report</html>").decode("ascii"),
        )
        client = mock.Mock()
        client.evaluations.get_result.return_value = result
        args = make_args(get_result=True, evaluation_id=7, output_dir=self.output_dir)

        with mock.patch.object(trustmodel_eval, "_init_client", return_value=client):
            assets = trustmodel_eval.get_inventory(args)

        self.assertEqual(len(assets), 1)
        self.assertEqual(
            assets[0]["attack_surface_label"], "AI::AI Model::Public::openai::gpt-4"
        )
        self.assertEqual(
            os.listdir(self.output_dir), ["trustmodel_evaluation_7.html"]
        )

    def test_get_result_without_output_dir_still_returns_the_asset(self):
        client = mock.Mock()
        client.evaluations.get_result.return_value = FakeResult("completed", id=7)
        args = make_args(get_result=True, evaluation_id=7)

        with mock.patch.object(trustmodel_eval, "_init_client", return_value=client):
            assets = trustmodel_eval.get_inventory(args)

        self.assertEqual(len(assets), 1)
        self.assertEqual(os.listdir(self.output_dir), [])


class BuildAssetGuardTestCase(unittest.TestCase):
    """EvaluationResult's shape is outside the SDK's back-compat guarantee."""

    def setUp(self):
        patcher = mock.patch.object(
            trustmodel_eval.utils, "tw_exit", side_effect=SystemExit
        )
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_missing_field_exits_instead_of_raising(self):
        class Truncated(object):
            id = 7

        with self.assertLogs(level="ERROR") as captured:
            with self.assertRaises(SystemExit):
                trustmodel_eval._build_asset_or_exit(Truncated(), make_args())
        self.assertTrue(
            any("out of sync" in r.getMessage() for r in captured.records)
        )

    def test_intact_result_passes_through(self):
        asset = trustmodel_eval._build_asset_or_exit(
            FakeResult("completed"), make_args()
        )
        self.assertEqual(asset["id"], "42")


class PreflightTestCase(unittest.TestCase):
    """A bad key must be caught before an evaluation is created, so a doomed run
    never spends credits."""

    def setUp(self):
        patcher = mock.patch.object(
            trustmodel_eval.utils, "tw_exit", side_effect=SystemExit
        )
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_invalid_key_exits_before_creating_an_evaluation(self):
        client = mock.Mock()
        client.ping.side_effect = AuthenticationError("invalid key")
        args = make_args(model_identifier="gpt-4", vendor_identifier="openai")

        with mock.patch.object(trustmodel_eval, "_init_client", return_value=client):
            with self.assertLogs(level="ERROR"):
                with self.assertRaises(SystemExit):
                    trustmodel_eval._cmd_evaluate(args)

        client.evaluations.create.assert_not_called()
        client.evaluations.create_custom_endpoint.assert_not_called()
        client.evaluations.create_from_template.assert_not_called()


if __name__ == "__main__":
    unittest.main()
