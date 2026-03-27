"""
TrustModel module for twigs CLI.

Supports: ping, models, config, evaluate, list-evaluations, get-result.
"""

import sys
import time
import logging

from . import utils


def _init_client(args):
    try:
        from trustmodel import TrustModelClient
    except ImportError:
        logging.error(
            "trustmodel SDK is not installed. Install it with: pip install trustmodel"
        )
        utils.tw_exit(1)

    client_kwargs = {"api_key": args.trustmodel_api_key}
    if getattr(args, "base_url", None):
        client_kwargs["base_url"] = args.base_url
    elif getattr(args, "environment", None):
        client_kwargs["environment"] = args.environment
    try:
        return TrustModelClient(**client_kwargs)
    except Exception as e:
        logging.error("Failed to initialize TrustModel client: %s", str(e))
        utils.tw_exit(1)


def _cmd_ping(args):
    from trustmodel.exceptions import AuthenticationError, TrustModelError

    client = _init_client(args)
    try:
        client.ping()
        print("API key is valid.")
    except AuthenticationError:
        logging.error("Invalid API key.")
        utils.tw_exit(1)
    except TrustModelError as e:
        logging.error("Ping failed: %s", str(e))
        utils.tw_exit(1)


def _cmd_models(args):
    from trustmodel.exceptions import TrustModelError

    client = _init_client(args)
    try:
        models, api_sources = client.models.list()
    except TrustModelError as e:
        logging.error("Failed to list models: %s", str(e))
        utils.tw_exit(1)

    print("\n%-30s %-20s %-15s %-10s" % ("Model", "Vendor", "Platform Key", "BYOK"))
    print("-" * 80)
    for m in models:
        print(
            "%-30s %-20s %-15s %-10s"
            % (
                m.model_identifier,
                m.vendor_identifier,
                "Yes" if m.available_via_trust_model_key else "No",
                "Yes" if m.available_via_byok else "No",
            )
        )
    print("\nTotal: %d models" % len(models))


def _cmd_config(args):
    from trustmodel.exceptions import TrustModelError

    client = _init_client(args)
    try:
        config = client.config.get()
    except TrustModelError as e:
        logging.error("Failed to get config: %s", str(e))
        utils.tw_exit(1)

    print("\n--- Application Types ---")
    for at in config.application_types:
        print("  %s: %s" % (at.get("id", ""), at.get("name", "")))

    print("\n--- User Personas ---")
    for p in config.user_personas:
        print("  %s: %s" % (p.get("id", ""), p.get("name", "")))

    print("\n--- Domain Expert Options ---")
    for d in config.domain_expert_options:
        print("  %s: %s" % (d.get("id", ""), d.get("name", "")))

    print("\n--- Categories ---")
    for c in config.categories:
        print("  %s" % c)

    print("\n--- Defaults ---")
    for k, v in config.defaults.items():
        print("  %s: %s" % (k, v))

    print("\nCredits per category: %s" % config.credits_per_category)


def _cmd_evaluate(args):
    from trustmodel.exceptions import AuthenticationError, TrustModelError

    has_model_params = bool(getattr(args, "model_identifier", None))
    has_assetid = bool(getattr(args, "assetid", None))
    is_custom_endpoint = bool(getattr(args, "api_endpoint", None))

    # Validate required params based on evaluation mode
    if has_model_params:
        if is_custom_endpoint:
            if not getattr(args, "api_key", None):
                logging.error("--api_key is required for custom endpoint evaluation.")
                utils.tw_exit(1)
        else:
            if not getattr(args, "vendor_identifier", None):
                logging.error("--vendor_identifier is required for evaluate.")
                utils.tw_exit(1)
    elif not has_assetid:
        logging.error(
            "--model_identifier (with --vendor_identifier) or --assetid is required for evaluate."
        )
        utils.tw_exit(1)

    client = _init_client(args)

    # Validate TrustModel API key
    try:
        client.ping()
        logging.info("API key validated.")
    except AuthenticationError:
        logging.error("Invalid TrustModel API key.")
        utils.tw_exit(1)
    except TrustModelError as e:
        logging.error("Failed to validate API key: %s", str(e))
        utils.tw_exit(1)

    # Common optional kwargs
    extra_kwargs = {}
    if getattr(args, "model_config_name", None):
        extra_kwargs["model_config_name"] = args.model_config_name
    if getattr(args, "application_type", None):
        extra_kwargs["application_type"] = args.application_type
    if getattr(args, "user_personas", None):
        extra_kwargs["user_personas"] = [
            p.strip() for p in args.user_personas.split(",")
        ]
    if getattr(args, "application_description", None):
        extra_kwargs["application_description"] = args.application_description
    if getattr(args, "domain_expert_description", None):
        extra_kwargs["domain_expert_description"] = args.domain_expert_description
    if getattr(args, "assetname", None):
        extra_kwargs["template_name"] = args.assetname

    try:
        if has_model_params and is_custom_endpoint:
            # Custom endpoint evaluation
            logging.info(
                "Creating custom endpoint evaluation for '%s' at '%s'...",
                args.model_identifier,
                args.api_endpoint,
            )
            create_kwargs = {
                "api_endpoint": args.api_endpoint,
                "api_key": args.api_key,
                "model_identifier": args.model_identifier,
            }
            if args.vendor_identifier:
                create_kwargs["vendor_identifier"] = args.vendor_identifier
            if getattr(args, "model_name", None):
                create_kwargs["model_name"] = args.model_name
            create_kwargs.update(extra_kwargs)
            evaluation = client.evaluations.create_custom_endpoint(
                trigger_source="threatworx", **create_kwargs
            )
        elif has_model_params:
            # Public model evaluation (with optional BYOK)
            logging.info(
                "Creating evaluation for model '%s' (vendor: '%s')...",
                args.model_identifier,
                args.vendor_identifier,
            )
            create_kwargs = {
                "model_identifier": args.model_identifier,
                "vendor_identifier": args.vendor_identifier,
            }
            if args.categories:
                create_kwargs["categories"] = [
                    c.strip() for c in args.categories.split(",")
                ]
            if getattr(args, "api_key", None):
                create_kwargs["api_key"] = args.api_key
            if getattr(args, "evaluation_type", None):
                create_kwargs["evaluation_type"] = args.evaluation_type
            create_kwargs.update(extra_kwargs)
            evaluation = client.evaluations.create(
                trigger_source="threatworx", **create_kwargs
            )
        else:
            # Asset ID only — use it as template_id to look up existing template
            logging.info("Creating evaluation from template ID '%s'...", args.assetid)
            evaluation = client.evaluations.create_from_template(
                template_id=args.assetid, trigger_source="threatworx", **extra_kwargs
            )

        eval_id = evaluation.id
        logging.info("Evaluation created with ID: %s", eval_id)
    except TrustModelError as e:
        logging.error("Failed to create evaluation: %s", str(e))
        utils.tw_exit(1)

    # Poll for completion and return result
    return _poll_and_print_result(client, eval_id, args)


def _cmd_list_evaluations(args):
    from trustmodel.exceptions import TrustModelError

    client = _init_client(args)
    try:
        status_filter = getattr(args, "status_filter", None)
        evaluations = client.evaluations.list(status=status_filter)
    except TrustModelError as e:
        logging.error("Failed to list evaluations: %s", str(e))
        utils.tw_exit(1)

    if not evaluations:
        print("No evaluations found.")
        return

    print(
        "\n%-8s %-15s %-25s %-20s %-8s %-10s"
        % ("ID", "Status", "Model", "Vendor", "Score", "Progress")
    )
    print("-" * 90)
    for ev in evaluations:
        score_str = "%.1f" % ev.overall_score if ev.overall_score is not None else "-"
        vendor = ev.vendor_identifier or "-"
        print(
            "%-8s %-15s %-25s %-20s %-8s %s%%"
            % (
                ev.id,
                ev.status,
                ev.model_identifier,
                vendor,
                score_str,
                ev.completion_percentage,
            )
        )
    print("\nTotal: %d evaluations" % len(evaluations))


def _cmd_get_result(args):
    from trustmodel.exceptions import TrustModelError

    if not args.evaluation_id:
        logging.error("--evaluation_id is required for get-result.")
        utils.tw_exit(1)

    client = _init_client(args)
    try:
        result = client.evaluations.get_result(args.evaluation_id)
    except TrustModelError as e:
        logging.error("Failed to get result: %s", str(e))
        utils.tw_exit(1)

    return result


def _poll_and_print_result(client, eval_id, args):
    from trustmodel.exceptions import TrustModelError

    poll_interval = 10  # default, will be overridden by server response
    timeout_seconds = 3 * 60 * 60
    start_time = time.time()
    last_percentage = -1

    while True:
        if time.time() - start_time > timeout_seconds:
            logging.error("Evaluation timed out after 3 hours.")
            utils.tw_exit(1)

        try:
            result = client.evaluations.get_result(eval_id)
        except TrustModelError as e:
            logging.warning("Poll error: %s. Retrying...", str(e))
            time.sleep(poll_interval)
            continue

        # Use server-provided poll interval
        if hasattr(result, "poll_interval") and result.poll_interval:
            poll_interval = result.poll_interval

        if result.completion_percentage != last_percentage:
            print(
                "Status: %s | Progress: %d%%"
                % (result.status, result.completion_percentage)
            )
            last_percentage = result.completion_percentage

        if result.status == "completed":
            logging.debug("Evaluation %s completed successfully.", eval_id)
            return result
        elif result.status == "failed":
            logging.error("Evaluation failed.")
            utils.tw_exit(1)

        time.sleep(poll_interval)


def _score_to_rating(raw_score):
    """Scale TrustModel score (0-100) to twigs rating (1-5).

    TrustModel: higher score = lower risk. Twigs: higher rating = higher risk.
    So we invert: high TrustModel score -> low twigs rating.
    """
    if raw_score >= 90:
        return 1
    elif raw_score >= 75:
        return 2
    elif raw_score >= 50:
        return 3
    elif raw_score >= 25:
        return 4
    else:
        return 5


def _build_asset_from_result(result, args):
    """Build a twigs asset with findings from TrustModel evaluation result."""
    eval_id = str(result.id)
    asset_id = str(result.template_id or result.id)
    model_name = result.model_name or "Unknown Model"
    model_identifier = result.model_identifier or ""
    # For custom models, model_name is generic ("Custom Model") — include model_identifier
    if model_name == "Custom Model" and model_identifier:
        display_name = "%s %s" % (model_name, model_identifier)
    else:
        display_name = model_name
    vendor_name = result.vendor_name or ""
    if vendor_name.lower() == "others":
        vendor_name = "Generic AI Platform"

    findings = []

    # Build findings from category scores
    if result.category_scores:
        for cs in result.category_scores:
            category_id = cs.get("category_id", "")
            finding = {}
            finding["twc_id"] = category_id
            finding["asset_id"] = asset_id
            finding["twc_title"] = cs.get("category", "")
            finding["details"] = cs.get("findings", "")
            finding["rating"] = str(_score_to_rating(cs.get("score", 0)))
            finding["type"] = "AI Model Assessment"
            finding["object_id"] = cs.get("category", "")
            finding["object_meta"] = ""
            findings.append(finding)

    # Build findings from subcategory scores
    if result.subcategory_scores:
        for ss in result.subcategory_scores:
            subcategory_id = ss.get("subcategory_id", "")
            finding = {}
            finding["twc_id"] = subcategory_id
            finding["asset_id"] = asset_id
            finding["twc_title"] = ss.get("subcategory", "")
            finding["details"] = ss.get("findings", "")
            finding["rating"] = str(_score_to_rating(ss.get("score", 0)))
            finding["type"] = "AI Model Assessment"
            finding["object_id"] = "%s:%s" % (
                ss.get("category", ""),
                ss.get("subcategory", ""),
            )
            finding["object_meta"] = ""
            findings.append(finding)

    # Build tags
    tags = ["AI Model"]
    if vendor_name:
        tags.append(vendor_name)
    if display_name:
        tags.append(display_name)

    asset = {}
    asset["id"] = asset_id
    asset["name"] = getattr(args, "assetname", None) or display_name
    asset["type"] = vendor_name
    asset["owner"] = args.handle
    asset["products"] = []
    asset["tags"] = tags
    # Public model: AI::AI Model::Public::<VendorName>::<ModelName>
    # Custom model: AI::AI Model::Custom::<VendorName>
    is_custom = getattr(result, "credit_run_type", None) == "custom_endpoint"
    if is_custom:
        asset["attack_surface_label"] = "AI::AI Model::Custom::%s" % vendor_name
    else:
        asset["attack_surface_label"] = "AI::AI Model::Public::%s::%s" % (
            vendor_name,
            model_name,
        )
    asset["config_issues"] = findings

    return asset


def get_inventory(args):
    """Entry point called by twigs dispatcher."""
    if getattr(args, "ping", False):
        _cmd_ping(args)
    elif getattr(args, "models", False):
        _cmd_models(args)
    elif getattr(args, "config", False):
        _cmd_config(args)
    elif getattr(args, "evaluate", False):
        result = _cmd_evaluate(args)
        if result:
            return [_build_asset_from_result(result, args)]
    elif getattr(args, "list_evaluations", False):
        _cmd_list_evaluations(args)
    elif getattr(args, "get_result", False):
        result = _cmd_get_result(args)
        if result:
            return [_build_asset_from_result(result, args)]

    return []
